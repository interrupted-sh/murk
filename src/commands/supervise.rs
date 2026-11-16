// SPDX-FileCopyrightText: murk contributors
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Supervised child for `murk agent exec`: spawn the command with piped stdout
//! and stderr, mask the injected secret values in both streams, and pass the
//! child's exit status through.
//!
//! Plain `murk exec` still replaces itself with the child (`execve`), so it
//! never sees the output. Agent exec cannot: masking needs murk in the middle.
//! What that changes for the child:
//!
//! - **stdout and stderr are pipes, not the terminal.** Programs that check
//!   `isatty` may drop colour, progress bars, or line buffering. stdin is still
//!   inherited, so prompts that read the terminal keep working.
//! - **murk waits for both streams to close**, not only for the child to exit.
//!   A background process that keeps the pipes open keeps murk running; its
//!   output is masked too.
//! - **Signals.** On macOS, when murk is a foreground job on its terminal (it
//!   leads its process group, as under an interactive shell), the child gets
//!   a process group of its own and murk makes it the terminal's foreground
//!   group, as a shell does with a job. A key the terminal turns into a
//!   signal (Ctrl-C, Ctrl-\) then reaches the child alone, once. Ctrl-Z stops
//!   the child; murk then takes the terminal back and stops itself, so the
//!   shell sees the job stop, and resumes the child when it resumes.
//!   Otherwise (Linux, or on macOS no terminal, murk in the background, or
//!   murk sharing its parent's group, as under a script) the child stays in
//!   murk's group, so both get what the terminal sends that group. Linux
//!   tells such a signal apart and does not forward it again. macOS cannot,
//!   so there the child gets it twice (see `signals`). Either way, SIGINT,
//!   SIGTERM, SIGHUP and SIGQUIT sent to murk by another process
//!   (`kill <pid>`, a harness timeout, `docker stop` when murk is a
//!   container's PID 1) are forwarded to the child, or to its whole group
//!   when it has one of its own, also after a Ctrl-Z and `fg`. Once the child
//!   has exited, murk takes the terminal back and these signals get their
//!   default action back (one caught in between is re-raised), so murk stays
//!   killable while a background process still holds the pipes.
//! - **Exit status.** murk exits with the child's code. If the child died from
//!   a signal, murk re-raises that signal on itself (falling back to `128 + N`),
//!   so the caller sees the same status.
//!
//! The masking is an accident guard, not a boundary: see `murk_cli::mask`.

use super::die;
#[cfg(unix)]
use super::signals;
use murk_cli::mask::Masker;
use std::io::{self, Read, Write};
use std::process::{self, Command, ExitStatus, Stdio};
use zeroize::Zeroize;

/// Read size for each output stream. A read returns as soon as the child has
/// written anything, so this bounds a chunk, not the latency.
const CHUNK: usize = 8 * 1024;

/// Spawn `cmd` with masked stdout and stderr, wait for it, and exit the way it
/// did. Never returns.
pub(crate) fn run_masked(mut cmd: Command, masker: &Masker) -> ! {
    cmd.stdin(Stdio::inherit())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());

    #[cfg(unix)]
    signals::install();
    // macOS only: there murk cannot tell a terminal key from a `kill`, so the
    // app gets the terminal to itself. Linux tells them apart by the sender.
    #[cfg(target_os = "macos")]
    let job = signals::foreground_job();
    #[cfg(not(target_os = "macos"))]
    let job: Option<i32> = None;
    #[cfg(target_os = "macos")]
    if let Some(tty) = job {
        use std::os::unix::process::CommandExt;
        // SAFETY: the hook runs between fork and exec and makes only
        // async-signal-safe calls (setpgid, getpid, pthread_sigmask,
        // tcsetpgrp).
        unsafe {
            cmd.pre_exec(move || {
                libc::setpgid(0, 0);
                signals::give_terminal(tty, libc::getpid());
                Ok(())
            });
        }
    }

    let program = cmd.get_program().to_string_lossy().into_owned();
    let mut child = cmd
        .spawn()
        .unwrap_or_else(|e| die(&format_args!("{program}: {e}"), 1));
    // The env block in `cmd` holds plaintext values; it is not needed any more.
    drop(cmd);

    #[cfg(target_os = "macos")]
    if let Some(tty) = job {
        let pgid = child.id() as libc::pid_t;
        // Repeat both steps here, as a shell does, so it doesn't matter
        // whether the parent or the child gets there first.
        // SAFETY: plain syscall on our own child.
        unsafe {
            libc::setpgid(pgid, pgid);
        }
        signals::give_terminal(tty, pgid);
        // murk now writes the output from the background. Blocked, SIGTTOU
        // cannot stop it there (`stty tostop`); the output threads inherit
        // the mask, and the child already has its own.
        block_sigttou();
        signals::set_group(pgid);
    } else {
        signals::set_child(child.id());
    }
    #[cfg(all(unix, not(target_os = "macos")))]
    signals::set_child(child.id());

    let child_out = child.stdout.take().expect("stdout is piped");
    let child_err = child.stderr.take().expect("stderr is piped");

    // Drain both streams at once: reading one to EOF before the other deadlocks
    // as soon as the child fills the other pipe's buffer.
    let status = std::thread::scope(|s| {
        s.spawn(|| pump(child_out, io::stdout(), masker));
        s.spawn(|| pump(child_err, io::stderr(), masker));
        wait(&mut child, job)
    });

    exit_like(status)
}

/// Block SIGTTOU on this thread, and so on the threads it starts.
#[cfg(target_os = "macos")]
fn block_sigttou() {
    // SAFETY: plain syscalls on a stack-local signal set.
    unsafe {
        let mut set: libc::sigset_t = std::mem::zeroed();
        libc::sigemptyset(&raw mut set);
        libc::sigaddset(&raw mut set, libc::SIGTTOU);
        libc::pthread_sigmask(libc::SIG_BLOCK, &raw const set, std::ptr::null_mut());
    }
}

/// Copy `src` to `dst` through a [`MaskStream`](murk_cli::mask::MaskStream),
/// writing each chunk as soon as it is read. Stops early if `dst` fails (for
/// example a closed pipe): dropping `src` then closes the child's end, so the
/// child gets `SIGPIPE`/`EPIPE` on its next write, as it would have when it
fn pump(mut src: impl Read, mut dst: impl Write, masker: &Masker) {
    let mut stream = masker.stream();
    let mut buf = vec![0u8; CHUNK];
    loop {
        let n = match src.read(&mut buf) {
            Ok(0) => break,
            Ok(n) => n,
            Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
            Err(_) => break,
        };
        let out = stream.push(&buf[..n]);
        if dst.write_all(&out).and_then(|()| dst.flush()).is_err() {
            buf.zeroize();
            return;
        }
    }
    buf.zeroize();
    let _ = dst.write_all(&stream.finish());
    let _ = dst.flush();
}

/// Wait for the child. On Unix, stop forwarding signals before it is reaped,
/// so a forwarded signal can never reach a recycled pid, then hand the
/// forwarded signals back their default action. If the child had the
/// terminal (`job`), murk takes it back first, so a Ctrl-C reaches murk
/// while a background process still holds the output pipes.
fn wait(child: &mut process::Child, job: Option<i32>) -> ExitStatus {
    #[cfg(unix)]
    {
        signals::wait_exited(child.id(), job);
        if let Some(tty) = job {
            signals::take_terminal(tty, child.id() as libc::pid_t);
        }
    }
    #[cfg(not(unix))]
    let _ = job;
    let status = child
        .wait()
        .unwrap_or_else(|e| die(&format_args!("waiting for the command: {e}"), 1));
    #[cfg(unix)]
    signals::stop_forwarding();
    status
}

/// Exit with the child's status: its code, or its terminating signal.
fn exit_like(status: ExitStatus) -> ! {
    let _ = io::stdout().flush();
    let _ = io::stderr().flush();
    #[cfg(unix)]
    {
        use std::os::unix::process::ExitStatusExt;
        if let Some(sig) = status.signal() {
            signals::raise_default(sig);
            process::exit(128 + sig);
        }
    }
    process::exit(status.code().unwrap_or(1));
}
