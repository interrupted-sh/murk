// SPDX-FileCopyrightText: murk contributors
// SPDX-License-Identifier: MIT OR Apache-2.0

//! `murk agent exec` under a real controlling terminal. Every signal must
//! reach the app exactly once, on Linux and on macOS: a key the terminal
//! turns into a signal (Ctrl-C, Ctrl-\), a signal another process sends
//! murk, and a hangup. Job control (Ctrl-Z, then `fg`) must keep working,
//! and in a pipeline the other commands must keep their access to the
//! terminal.
//!
//! The app is this test binary, run as the `app_helper` test: it logs every
//! signal it gets, one line each, as soon as it gets it. A shell would merge
//! two copies that arrive close together into one trap.
#![cfg(unix)]

use std::fs;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicI32, Ordering};
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

use assert_fs::TempDir;

mod common;
use common::{MURK_CONTEXT_VARS, init_vault, murk};

/// `TERM` value that turns `app_helper` into the app. `agent exec` passes
/// only `PATH`, `HOME` and `TERM` to the app, so the marker rides in `TERM`
/// and the log goes in `HOME`.
const APP_TERM: &str = "murk-test-signal-app";
/// Env var that turns `shell_helper` into a session leader that runs murk
/// as its foreground job, the way an interactive shell does.
const SHELL_VAR: &str = "MURK_TEST_SHELL";

/// `TIOCSCTTY`, which the libc crate does not define for macOS.
#[cfg(target_os = "macos")]
const TIOCSCTTY: libc::c_ulong = 0x2000_7461;
#[cfg(not(target_os = "macos"))]
const TIOCSCTTY: libc::c_ulong = libc::TIOCSCTTY as libc::c_ulong;

static APP_LOG: AtomicI32 = AtomicI32::new(-1);

extern "C" fn log_signal(sig: libc::c_int) {
    let line: &[u8] = match sig {
        libc::SIGINT => b"INT\n",
        libc::SIGHUP => b"HUP\n",
        libc::SIGTERM => b"TERM\n",
        _ => b"QUIT\n",
    };
    // SAFETY: write(2) is async-signal-safe; the buffer is static.
    unsafe {
        libc::write(
            APP_LOG.load(Ordering::SeqCst),
            line.as_ptr().cast(),
            line.len(),
        );
    }
}

/// The app: log each INT, HUP, TERM and QUIT to `$HOME/signals`, write its
/// parent's pid (murk's) to `$HOME/murk.pid`, write `$HOME/group` (`own` if
/// it leads its process group, `murk's` if it shares murk's), write
/// `$HOME/ready` (after any terminal fd it inherited, one per line), and
/// run until `$HOME/stop` exists.
#[test]
fn app_helper() {
    if std::env::var("TERM").as_deref() != Ok(APP_TERM) {
        return;
    }
    let home = PathBuf::from(std::env::var("HOME").unwrap());
    let log = fs::File::create(home.join("signals")).unwrap();
    APP_LOG.store(log.as_raw_fd(), Ordering::SeqCst);
    for sig in [libc::SIGINT, libc::SIGHUP, libc::SIGTERM, libc::SIGQUIT] {
        // SAFETY: the handler only calls write(2) on an fd that stays open.
        unsafe {
            libc::signal(sig, log_signal as *const () as libc::sighandler_t);
        }
    }
    // SAFETY: plain syscalls.
    let (murk, group) = unsafe {
        let murk = libc::getppid();
        let group = if libc::getpgrp() == libc::getpgid(murk) {
            "murk's"
        } else if libc::getpgrp() == libc::getpid() {
            "own"
        } else {
            "other"
        };
        (murk, group)
    };
    fs::write(home.join("murk.pid"), murk.to_string()).unwrap();
    fs::write(home.join("group"), group).unwrap();
    // Terminal fds beyond stdin, stdout and stderr: murk's own must not leak.
    let leaked: String = (3..256)
        // SAFETY: isatty only inspects the fd number.
        .filter(|&fd| unsafe { libc::isatty(fd) } == 1)
        .map(|fd| format!("{fd}\n"))
        .collect();
    fs::write(home.join("ready.tmp"), leaked).unwrap();
    fs::rename(home.join("ready.tmp"), home.join("ready")).unwrap();
    let deadline = Instant::now() + Duration::from_secs(20);
    while !home.join("stop").exists() && Instant::now() < deadline {
        std::thread::sleep(Duration::from_millis(20));
    }
    drop(log);
}

/// What `shell_helper` does once murk runs as its foreground job.
#[derive(Clone, Copy)]
enum Shell {
    /// Exit once the app is ready. The kernel then hangs up the foreground
    /// group.
    Exits,
    /// Stay, like an interactive shell: wait for murk, and when murk stops
    /// (Ctrl-Z), take the terminal back, write `$HOME/stopped`, and once
    /// `$HOME/fg` exists give the terminal back to murk and continue it.
    Stays,
}

/// The session leader: run murk (the command after the first two lines of
/// `$SHELL_VAR`'s file: HOME and the mode) as a job in its own process
/// group and hand it the terminal, as an interactive shell does.
#[test]
fn shell_helper() {
    let Ok(spec) = std::env::var(SHELL_VAR) else {
        return;
    };
    let spec: Vec<String> = fs::read_to_string(spec)
        .unwrap()
        .lines()
        .map(str::to_owned)
        .collect();
    let (home, argv) = (PathBuf::from(&spec[0]), &spec[2..]);
    let mode = match spec[1].as_str() {
        "exits" => Shell::Exits,
        _ => Shell::Stays,
    };
    let mut cmd = Command::new(&argv[0]);
    cmd.args(&argv[1..]).env_remove(SHELL_VAR);
    // SAFETY: only async-signal-safe calls between fork and exec.
    unsafe {
        cmd.pre_exec(|| {
            if libc::setpgid(0, 0) < 0 {
                return Err(std::io::Error::last_os_error());
            }
            give_terminal(libc::getpid());
            Ok(())
        });
    }
    let job = cmd.spawn().unwrap().id() as libc::pid_t;
    match mode {
        Shell::Exits => {
            wait_for(&home.join("ready"), "the app starting");
            std::process::exit(0);
        }
        Shell::Stays => loop {
            let mut status = 0;
            // SAFETY: waitpid writes into `status`, which outlives the call.
            assert_eq!(
                unsafe { libc::waitpid(job, &raw mut status, libc::WUNTRACED) },
                job
            );
            if !libc::WIFSTOPPED(status) {
                std::process::exit(libc::WEXITSTATUS(status));
            }
            // SAFETY: plain syscall.
            give_terminal(unsafe { libc::getpgrp() });
            fs::write(home.join("stopped"), "").unwrap();
            wait_for(&home.join("fg"), "the test asking for fg");
            give_terminal(job);
            // SAFETY: plain syscall on our own job.
            unsafe {
                libc::kill(-job, libc::SIGCONT);
            }
        },
    }
}

/// Make `pgid` the foreground group of the terminal on stdin, as a shell
/// does. SIGTTOU is blocked so a background group may do it.
/// Async-signal-safe.
fn give_terminal(pgid: libc::pid_t) {
    // SAFETY: plain, async-signal-safe syscalls on stack-local signal sets.
    unsafe {
        let mut set: libc::sigset_t = std::mem::zeroed();
        let mut old: libc::sigset_t = std::mem::zeroed();
        libc::sigemptyset(&raw mut set);
        libc::sigaddset(&raw mut set, libc::SIGTTOU);
        libc::pthread_sigmask(libc::SIG_BLOCK, &raw const set, &raw mut old);
        libc::tcsetpgrp(0, pgid);
        libc::pthread_sigmask(libc::SIG_SETMASK, &raw const old, std::ptr::null_mut());
    }
}

/// A vault with `DB_URL` in `dir`, and a grant key for it.
fn grant_vault(dir: &TempDir) -> String {
    let (key, _) = init_vault(dir);
    murk(dir, &key)
        .args(["add", "DB_URL", "--vault", "test.murk"])
        .write_stdin("postgres://prod-sentinel\n")
        .assert()
        .success();
    let path = dir.path().join("exec.key");
    murk(dir, &key)
        .args([
            "agent", "grant", "--name", "exec", "--only", "DB_URL", "--out",
        ])
        .arg(&path)
        .args(["--vault", "test.murk"])
        .assert()
        .success();
    fs::read_to_string(path).unwrap().trim().to_string()
}

/// `murk agent exec` running [`app_helper`], as an argv.
fn murk_argv() -> Vec<String> {
    let me = std::env::current_exe().unwrap();
    [
        assert_cmd::cargo::cargo_bin!("murk").to_str().unwrap(),
        "agent",
        "exec",
        "--only",
        "DB_URL",
        "--vault",
        "test.murk",
        "--",
        me.to_str().unwrap(),
        "--exact",
        "app_helper",
        "--nocapture",
        "--test-threads=1",
    ]
    .map(str::to_owned)
    .to_vec()
}

/// The master side of a pseudo-terminal. A thread reads and discards what
/// the processes on it write, so a writer never blocks on a full buffer
/// and, on macOS, a session leader's exit never waits for its output to
/// drain. Dropping it hangs the terminal up.
struct Pty {
    master: OwnedFd,
    stop: Arc<AtomicBool>,
    drain: Option<JoinHandle<()>>,
}

impl Drop for Pty {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::SeqCst);
        if let Some(drain) = self.drain.take() {
            drain.join().unwrap();
        }
    }
}

/// A new pseudo-terminal: (master, slave).
fn open_pty() -> (Pty, OwnedFd) {
    // ptsname returns a shared buffer, and tests run on several threads.
    static PTSNAME: std::sync::Mutex<()> = std::sync::Mutex::new(());
    // SAFETY: plain libc calls; each returned fd is checked and owned once.
    let (master, slave) = unsafe {
        let master = libc::posix_openpt(libc::O_RDWR | libc::O_NOCTTY);
        assert!(master >= 0, "posix_openpt failed");
        let master = OwnedFd::from_raw_fd(master);
        assert_ne!(
            libc::fcntl(master.as_raw_fd(), libc::F_SETFD, libc::FD_CLOEXEC),
            -1
        );
        assert_eq!(libc::grantpt(master.as_raw_fd()), 0);
        assert_eq!(libc::unlockpt(master.as_raw_fd()), 0);
        let guard = PTSNAME.lock().unwrap();
        let name = libc::ptsname(master.as_raw_fd());
        assert!(!name.is_null(), "ptsname failed");
        let slave = libc::open(name, libc::O_RDWR | libc::O_NOCTTY | libc::O_CLOEXEC);
        drop(guard);
        assert!(slave >= 0, "opening the pty slave failed");
        // No echo: keys typed for a reader stay out of the output.
        let mut termios: libc::termios = std::mem::zeroed();
        assert_eq!(libc::tcgetattr(slave, &raw mut termios), 0);
        termios.c_lflag &= !(libc::ECHO | libc::ECHOCTL);
        assert_eq!(libc::tcsetattr(slave, libc::TCSANOW, &raw const termios), 0);
        (master, OwnedFd::from_raw_fd(slave))
    };
    let stop = Arc::new(AtomicBool::new(false));
    let fd = master.as_raw_fd();
    let drain = {
        let stop = Arc::clone(&stop);
        // The fd stays open until `Pty::drop` has joined this thread.
        std::thread::spawn(move || {
            let mut buf = [0u8; 4096];
            while !stop.load(Ordering::SeqCst) {
                let mut poll = libc::pollfd {
                    fd,
                    events: libc::POLLIN,
                    revents: 0,
                };
                // SAFETY: poll and read on a live fd into live buffers.
                unsafe {
                    if libc::poll(&raw mut poll, 1, 50) > 0
                        && libc::read(fd, buf.as_mut_ptr().cast(), buf.len()) <= 0
                    {
                        // Every slave fd is closed (EIO on Linux, EOF on
                        // macOS): nothing is left to drain.
                        break;
                    }
                }
            }
        })
    };
    let pty = Pty {
        master,
        stop,
        drain: Some(drain),
    };
    (pty, slave)
}

/// Run `program args` as the leader of a new session whose controlling
/// terminal is `slave` (its stdin, stdout and stderr), in `dir`, with the
/// grant key and HOME set.
fn spawn_in_session(cmd: &mut Command, dir: &TempDir, key: &str, slave: &OwnedFd) -> Child {
    for var in MURK_CONTEXT_VARS {
        cmd.env_remove(var);
    }
    cmd.current_dir(dir.path())
        .env("HOME", dir.path())
        .env("XDG_RUNTIME_DIR", dir.path())
        .env("TERM", APP_TERM)
        .env("MURK_KEY", key)
        .stdin(Stdio::from(slave.try_clone().unwrap()))
        .stdout(Stdio::from(slave.try_clone().unwrap()))
        .stderr(Stdio::from(slave.try_clone().unwrap()));
    // SAFETY: only async-signal-safe calls between fork and exec.
    unsafe {
        cmd.pre_exec(|| {
            if libc::setsid() < 0 || libc::ioctl(0, TIOCSCTTY as _, 0) < 0 {
                return Err(std::io::Error::last_os_error());
            }
            Ok(())
        });
    }
    cmd.spawn().unwrap()
}

/// murk as the session leader on a fresh terminal, running the app.
fn spawn_murk_on_terminal(dir: &TempDir, key: &str) -> (Child, Pty) {
    let (master, slave) = open_pty();
    let argv = murk_argv();
    let mut cmd = Command::new(&argv[0]);
    cmd.args(&argv[1..]);
    let child = spawn_in_session(&mut cmd, dir, key, &slave);
    wait_for(&dir.path().join("ready"), "the app starting");
    (child, master)
}

/// murk as the foreground job of [`shell_helper`] on a fresh terminal,
/// running the app: (shell, master, slave). The caller keeps the slave open
/// or drops it.
fn spawn_murk_under_shell(dir: &TempDir, key: &str, mode: Shell) -> (Child, Pty, OwnedFd) {
    let (master, slave) = open_pty();
    let mut cmd = shell_command(dir, mode);
    let shell = spawn_in_session(&mut cmd, dir, key, &slave);
    (shell, master, slave)
}

/// `script` run by `shell` (`bash` or `zsh`) with job control on, as at an
/// interactive prompt, as the session leader on a fresh terminal: (shell,
/// master, slave). `{murk}` in the script stands for murk running the app.
/// None if `shell` is not installed. zsh hands the terminal to a job only
/// when interactive (`-i`); bash does with `set -m`.
fn spawn_shell_script(
    dir: &TempDir,
    key: &str,
    shell: &str,
    script: &str,
) -> Option<(Child, Pty, OwnedFd)> {
    let installed = Command::new(shell)
        .args(["-c", "exit 0"])
        .status()
        .is_ok_and(|s| s.success());
    if !installed {
        eprintln!("{shell} is not installed; skipped");
        return None;
    }
    let murk: Vec<String> = murk_argv()
        .iter()
        .map(|arg| format!("'{}'", arg.replace('\'', r"'\''")))
        .collect();
    let script = script.replace("{murk}", &murk.join(" "));
    let (master, slave) = open_pty();
    let mut cmd = Command::new(shell);
    match shell {
        "zsh" => cmd.args(["-f", "-i", "-c", &script]),
        _ => cmd.args(["--norc", "--noprofile", "-c", &format!("set -m\n{script}")]),
    };
    let child = spawn_in_session(&mut cmd, dir, key, &slave);
    Some((child, master, slave))
}

/// [`shell_helper`] running murk in `mode`, as a command.
fn shell_command(dir: &TempDir, mode: Shell) -> Command {
    let spec = dir.path().join("shell-spec");
    let mode = match mode {
        Shell::Exits => "exits",
        Shell::Stays => "stays",
    };
    let mut lines = vec![dir.path().to_str().unwrap().to_owned(), mode.to_owned()];
    lines.extend(murk_argv());
    fs::write(&spec, lines.join("\n")).unwrap();
    let mut cmd = Command::new(std::env::current_exe().unwrap());
    cmd.args(["--exact", "shell_helper", "--nocapture", "--test-threads=1"])
        .env(SHELL_VAR, &spec);
    cmd
}

fn wait_for(path: &Path, what: &str) {
    let deadline = Instant::now() + Duration::from_secs(30);
    while !path.exists() {
        assert!(Instant::now() < deadline, "{what} never happened");
        std::thread::sleep(Duration::from_millis(20));
    }
}

/// Give a second copy time to arrive, stop the app, and return its log.
fn signals_after_settling(dir: &TempDir) -> String {
    std::thread::sleep(Duration::from_millis(500));
    fs::write(dir.path().join("stop"), "").unwrap();
    fs::read_to_string(dir.path().join("signals")).unwrap()
}

fn wait_exit(child: &mut Child) {
    let deadline = Instant::now() + Duration::from_secs(30);
    while child.try_wait().unwrap().is_none() {
        if Instant::now() > deadline {
            child.kill().unwrap();
            panic!("murk did not exit after the app stopped");
        }
        std::thread::sleep(Duration::from_millis(20));
    }
}

/// Type `keys` at the terminal, one at a time.
fn type_keys(pty: &Pty, keys: &[u8]) {
    for key in keys {
        // SAFETY: writes one byte from a live buffer to the pty master.
        let written =
            unsafe { libc::write(pty.master.as_raw_fd(), std::ptr::from_ref(key).cast(), 1) };
        assert_eq!(written, 1);
        std::thread::sleep(Duration::from_millis(200));
    }
}

/// The contents of `path` once it exists, or None after `limit`.
fn read_within(path: &Path, limit: Duration) -> Option<String> {
    let deadline = Instant::now() + limit;
    while !path.exists() {
        if Instant::now() > deadline {
            return None;
        }
        std::thread::sleep(Duration::from_millis(20));
    }
    std::thread::sleep(Duration::from_millis(100));
    Some(fs::read_to_string(path).unwrap())
}

/// Send each of `signals` to `pid`, one at a time.
fn send(pid: libc::pid_t, signals: &[libc::c_int]) {
    for &sig in signals {
        // SAFETY: plain syscall on a process this test started.
        assert_eq!(unsafe { libc::kill(pid, sig) }, 0);
        std::thread::sleep(Duration::from_millis(200));
    }
}

/// murk's pid, as the app recorded it.
fn murk_pid(dir: &TempDir) -> libc::pid_t {
    fs::read_to_string(dir.path().join("murk.pid"))
        .unwrap()
        .parse()
        .unwrap()
}

const CTRL_C: u8 = 0x03;
const CTRL_BACKSLASH: u8 = 0x1c;
const CTRL_Z: u8 = 0x1a;

/// The process group a foreground murk gives the app: its own on macOS,
/// where murk cannot tell a terminal key from a `kill`, murk's on Linux.
const FOREGROUND_GROUP: &str = if cfg!(target_os = "macos") {
    "own"
} else {
    "murk's"
};

fn app_group(dir: &TempDir) -> String {
    fs::read_to_string(dir.path().join("group")).unwrap()
}

/// Ctrl-C and Ctrl-\ at the terminal reach the app once each, with murk as
/// the session leader.
#[test]
fn terminal_keys_reach_the_app_once() {
    let dir = TempDir::new().unwrap();
    let key = grant_vault(&dir);
    let (mut murk_proc, master) = spawn_murk_on_terminal(&dir, &key);
    type_keys(&master, &[CTRL_C, CTRL_BACKSLASH, CTRL_C, CTRL_BACKSLASH]);
    assert_eq!(signals_after_settling(&dir), "INT\nQUIT\nINT\nQUIT\n");
    wait_exit(&mut murk_proc);
    assert_eq!(app_group(&dir), FOREGROUND_GROUP);
}

/// The same with murk as a shell's foreground job, the usual case.
#[test]
fn terminal_keys_reach_the_app_once_under_a_shell() {
    let dir = TempDir::new().unwrap();
    let key = grant_vault(&dir);
    let (mut shell, master, _slave) = spawn_murk_under_shell(&dir, &key, Shell::Stays);
    wait_for(&dir.path().join("ready"), "the app starting");
    type_keys(&master, &[CTRL_C, CTRL_BACKSLASH, CTRL_C, CTRL_BACKSLASH]);
    assert_eq!(signals_after_settling(&dir), "INT\nQUIT\nINT\nQUIT\n");
    wait_exit(&mut shell);
    assert_eq!(app_group(&dir), FOREGROUND_GROUP);
}

/// A signal another process sends murk while murk runs in the foreground
/// reaches the app once: the app did not get it from the terminal.
#[test]
fn signals_sent_to_a_foreground_murk_reach_the_app_once() {
    let dir = TempDir::new().unwrap();
    let key = grant_vault(&dir);
    let (mut shell, _master, _slave) = spawn_murk_under_shell(&dir, &key, Shell::Stays);
    wait_for(&dir.path().join("ready"), "the app starting");
    let murk_pid = murk_pid(&dir);
    send(
        murk_pid,
        &[libc::SIGINT, libc::SIGQUIT, libc::SIGTERM, libc::SIGHUP],
    );
    assert_eq!(signals_after_settling(&dir), "INT\nQUIT\nTERM\nHUP\n");
    wait_exit(&mut shell);
}

/// Ctrl-Z stops the job and hands the terminal back to the shell. After
/// `fg` the app runs in the foreground again and gets Ctrl-C once, and murk
/// still forwards a signal sent to it.
#[test]
fn ctrl_z_and_fg_keep_working() {
    let dir = TempDir::new().unwrap();
    let key = grant_vault(&dir);
    let (mut shell, master, _slave) = spawn_murk_under_shell(&dir, &key, Shell::Stays);
    wait_for(&dir.path().join("ready"), "the app starting");
    type_keys(&master, &[CTRL_Z]);
    wait_for(&dir.path().join("stopped"), "the shell seeing the job stop");
    fs::write(dir.path().join("fg"), "").unwrap();
    std::thread::sleep(Duration::from_millis(300));
    type_keys(&master, &[CTRL_C]);
    send(murk_pid(&dir), &[libc::SIGTERM]);
    assert_eq!(signals_after_settling(&dir), "INT\nTERM\n");
    wait_exit(&mut shell);
}

/// murk keeps an fd on its terminal for the signal handler; the app must not
/// inherit it.
#[test]
fn the_app_does_not_inherit_murks_terminal_fd() {
    let dir = TempDir::new().unwrap();
    let key = grant_vault(&dir);
    let (mut murk_proc, _master) = spawn_murk_on_terminal(&dir, &key);
    let leaked = fs::read_to_string(dir.path().join("ready")).unwrap();
    signals_after_settling(&dir);
    wait_exit(&mut murk_proc);
    assert_eq!(leaked, "", "terminal fds the app inherited");
}

/// The terminal hangs up (an ssh session drops) while murk leads the
/// session: the kernel sends the hangup to murk alone, so murk passes it on.
#[test]
fn a_hangup_to_murk_as_session_leader_reaches_the_app() {
    let dir = TempDir::new().unwrap();
    let key = grant_vault(&dir);
    let (mut murk_proc, master) = spawn_murk_on_terminal(&dir, &key);
    drop(master);
    assert_eq!(signals_after_settling(&dir), "HUP\n");
    wait_exit(&mut murk_proc);
}

/// murk runs as a foreground job and the session leader above it (the
/// shell) exits: the kernel hangs up the foreground group, then detaches
/// the terminal. The app gets the hangup once.
#[test]
fn a_hangup_when_the_session_leader_exits_reaches_the_app_once() {
    let dir = TempDir::new().unwrap();
    let key = grant_vault(&dir);
    let (mut shell, _master, slave) = spawn_murk_under_shell(&dir, &key, Shell::Exits);
    drop(slave);
    assert!(shell.wait().unwrap().success());
    assert_eq!(signals_after_settling(&dir), "HUP\n");
}

/// `murk agent exec -- app | reader` at an interactive prompt, where the
/// reader reads the terminal (as `less` or a prompt does). murk shares its
/// job's process group with the reader, so it must leave the terminal to
/// that group: the reader must not be stopped, and the keys typed for it
/// must reach it.
fn a_pipeline_reader_gets_the_terminal(shell: &str) {
    let dir = TempDir::new().unwrap();
    let key = grant_vault(&dir);
    let script = r#"{murk} | sh -c 'read x </dev/tty; echo "got=$x" >"$HOME/reader"'
echo $? >"$HOME/status""#;
    let Some((mut shell, pty, _slave)) = spawn_shell_script(&dir, &key, shell, script) else {
        return;
    };
    wait_for(&dir.path().join("ready"), "the app starting");
    std::thread::sleep(Duration::from_millis(300));
    // Not `type_keys`: if the reader was stopped, the shell may have exited
    // and hung up the terminal, and the assertions below say what happened.
    // SAFETY: writes from a live buffer to the pty master.
    unsafe {
        libc::write(pty.master.as_raw_fd(), b"typed\n".as_ptr().cast(), 6);
    }
    let reader = read_within(&dir.path().join("reader"), Duration::from_secs(5));
    fs::write(dir.path().join("stop"), "").unwrap();
    wait_exit(&mut shell);
    assert_eq!(
        reader.as_deref(),
        Some("got=typed\n"),
        "what the reader got"
    );
    assert_eq!(
        fs::read_to_string(dir.path().join("status")).unwrap(),
        "0\n",
        "pipeline status (148 to 150: stopped)"
    );
    assert_eq!(app_group(&dir), "murk's");
}

/// `murk agent exec -- app | cat` at an interactive prompt: the pipeline
/// runs to the end, never stopped, and `cat` gets the app's output.
fn a_pipeline_to_cat_runs_through(shell: &str) {
    let dir = TempDir::new().unwrap();
    let key = grant_vault(&dir);
    let script = r#"{murk} | cat >"$HOME/cat-out"
echo $? >"$HOME/status""#;
    let Some((mut shell, _pty, _slave)) = spawn_shell_script(&dir, &key, shell, script) else {
        return;
    };
    wait_for(&dir.path().join("ready"), "the app starting");
    std::thread::sleep(Duration::from_millis(300));
    fs::write(dir.path().join("stop"), "").unwrap();
    wait_exit(&mut shell);
    assert_eq!(
        fs::read_to_string(dir.path().join("status")).unwrap(),
        "0\n",
        "pipeline status (148 to 150: stopped)"
    );
    let out = fs::read_to_string(dir.path().join("cat-out")).unwrap();
    assert!(out.contains("app_helper"), "cat got: {out:?}");
    assert_eq!(app_group(&dir), "murk's");
}

#[test]
fn a_pipeline_reader_gets_the_terminal_under_bash() {
    a_pipeline_reader_gets_the_terminal("bash");
}

#[test]
fn a_pipeline_reader_gets_the_terminal_under_zsh() {
    a_pipeline_reader_gets_the_terminal("zsh");
}

#[test]
fn a_pipeline_to_cat_runs_through_under_bash() {
    a_pipeline_to_cat_runs_through("bash");
}

#[test]
fn a_pipeline_to_cat_runs_through_under_zsh() {
    a_pipeline_to_cat_runs_through("zsh");
}
