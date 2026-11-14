// SPDX-FileCopyrightText: murk contributors
// SPDX-License-Identifier: MIT OR Apache-2.0

//! `murk agent exec` under a real controlling terminal. The app stays in
//! murk's process group, so what the terminal sends that group reaches both;
//! murk must not deliver it a second time, and must pass on what reached
//! murk alone. Linux only: on macOS a terminal signal carries the pid of the
//! process writing to the terminal, and murk forwards it (a known double).
//!
//! The app is this test binary, run as the `app_helper` test: it logs every
//! signal it gets, one line each, as soon as it gets it. A shell would merge
//! two copies that arrive close together into one trap.
#![cfg(target_os = "linux")]

use std::fs;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicI32, Ordering};
use std::time::{Duration, Instant};

use assert_fs::TempDir;

mod common;
use common::{MURK_CONTEXT_VARS, init_vault, murk};

/// `TERM` value that turns `app_helper` into the app. `agent exec` passes
/// only `PATH`, `HOME` and `TERM` to the app, so the marker rides in `TERM`
/// and the log goes in `HOME`.
const APP_TERM: &str = "murk-test-signal-app";
/// Env var that turns `leader_helper` into a session leader that runs murk
/// as its foreground job, then exits.
const LEADER_VAR: &str = "MURK_TEST_SESSION_LEADER";

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

/// The app: log each INT, HUP, TERM and QUIT to `$HOME/signals`, write
/// `$HOME/ready` (after any terminal fd it inherited, one per line), and run
/// until `$HOME/stop` exists.
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

/// The session leader: run murk (the command after `--` in `$LEADER_VAR`'s
/// file) as a job in its own process group, hand it the terminal, and exit
/// once the app is ready. The kernel then hangs up the foreground group.
#[test]
fn leader_helper() {
    let Ok(spec) = std::env::var(LEADER_VAR) else {
        return;
    };
    let spec: Vec<String> = fs::read_to_string(spec)
        .unwrap()
        .lines()
        .map(str::to_owned)
        .collect();
    let (home, argv) = (PathBuf::from(&spec[0]), &spec[1..]);
    let mut cmd = Command::new(&argv[0]);
    cmd.args(&argv[1..])
        .env_remove(LEADER_VAR)
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    // SAFETY: only async-signal-safe calls between fork and exec. SIGTTOU is
    // blocked so a background group may take the terminal, as a shell does.
    unsafe {
        cmd.pre_exec(|| {
            let mut set: libc::sigset_t = std::mem::zeroed();
            let mut old: libc::sigset_t = std::mem::zeroed();
            libc::sigemptyset(&raw mut set);
            libc::sigaddset(&raw mut set, libc::SIGTTOU);
            libc::pthread_sigmask(libc::SIG_BLOCK, &raw const set, &raw mut old);
            if libc::setpgid(0, 0) < 0 || libc::tcsetpgrp(0, libc::getpid()) < 0 {
                return Err(std::io::Error::last_os_error());
            }
            libc::pthread_sigmask(libc::SIG_SETMASK, &raw const old, std::ptr::null_mut());
            Ok(())
        });
    }
    cmd.spawn().unwrap();
    wait_for(&home.join("ready"), "the app starting");
    std::process::exit(0);
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
        assert_cmd::cargo::cargo_bin("murk").to_str().unwrap(),
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

/// A new pseudo-terminal: (master, slave).
fn open_pty() -> (OwnedFd, OwnedFd) {
    // SAFETY: plain libc calls; each returned fd is checked and owned once.
    unsafe {
        let master = libc::posix_openpt(libc::O_RDWR | libc::O_NOCTTY | libc::O_CLOEXEC);
        assert!(master >= 0, "posix_openpt failed");
        let master = OwnedFd::from_raw_fd(master);
        assert_eq!(libc::grantpt(master.as_raw_fd()), 0);
        assert_eq!(libc::unlockpt(master.as_raw_fd()), 0);
        // ptsname_r: tests run on several threads, and ptsname's buffer is shared.
        let mut name = [0 as libc::c_char; 128];
        assert_eq!(
            libc::ptsname_r(master.as_raw_fd(), name.as_mut_ptr(), name.len()),
            0
        );
        let slave = libc::open(
            name.as_ptr(),
            libc::O_RDWR | libc::O_NOCTTY | libc::O_CLOEXEC,
        );
        assert!(slave >= 0, "opening the pty slave failed");
        (master, OwnedFd::from_raw_fd(slave))
    }
}

/// Run `program args` as the leader of a new session whose controlling
/// terminal is `slave` (its stdin), in `dir`, with the grant key and HOME set.
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
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    // SAFETY: only async-signal-safe calls between fork and exec.
    unsafe {
        cmd.pre_exec(|| {
            if libc::setsid() < 0 || libc::ioctl(0, libc::TIOCSCTTY as _, 0) < 0 {
                return Err(std::io::Error::last_os_error());
            }
            Ok(())
        });
    }
    cmd.spawn().unwrap()
}

/// murk as the session leader on a fresh terminal, running the app.
fn spawn_murk_on_terminal(dir: &TempDir, key: &str) -> (Child, OwnedFd) {
    let (master, slave) = open_pty();
    let argv = murk_argv();
    let mut cmd = Command::new(&argv[0]);
    cmd.args(&argv[1..]);
    let child = spawn_in_session(&mut cmd, dir, key, &slave);
    wait_for(&dir.path().join("ready"), "the app starting");
    (child, master)
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

/// Ctrl-C and Ctrl-\ at the terminal reach the app once each: the terminal
/// sends them to the foreground group, which murk and the app share.
#[test]
fn terminal_keys_reach_the_app_once() {
    let dir = TempDir::new().unwrap();
    let key = grant_vault(&dir);
    let (mut murk_proc, master) = spawn_murk_on_terminal(&dir, &key);
    for key in [b"\x03", b"\x1c"] {
        // SAFETY: writes one byte from a live buffer to the pty master.
        let written = unsafe { libc::write(master.as_raw_fd(), key.as_ptr().cast(), 1) };
        assert_eq!(written, 1);
        std::thread::sleep(Duration::from_millis(200));
    }
    assert_eq!(signals_after_settling(&dir), "INT\nQUIT\n");
    wait_exit(&mut murk_proc);
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
/// shell) exits: the kernel hangs up the whole foreground group, the app
/// included, then detaches the terminal. murk must not send a second copy.
#[test]
fn a_hangup_when_the_session_leader_exits_reaches_the_app_once() {
    let dir = TempDir::new().unwrap();
    let key = grant_vault(&dir);
    let (_master, slave) = open_pty();
    let spec = dir.path().join("leader-spec");
    let mut lines = vec![dir.path().to_str().unwrap().to_owned()];
    lines.extend(murk_argv());
    fs::write(&spec, lines.join("\n")).unwrap();

    let mut cmd = Command::new(std::env::current_exe().unwrap());
    cmd.args([
        "--exact",
        "leader_helper",
        "--nocapture",
        "--test-threads=1",
    ])
    .env(LEADER_VAR, &spec);
    let mut leader = spawn_in_session(&mut cmd, &dir, &key, &slave);
    drop(slave);
    assert!(leader.wait().unwrap().success());
    assert_eq!(signals_after_settling(&dir), "HUP\n");
}
