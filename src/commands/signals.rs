// SPDX-FileCopyrightText: murk contributors
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Signal forwarding for a child murk waits on (`murk agent exec`'s masked
//! command, `murk edit`'s editor).
//!
//! While installed, SIGINT, SIGTERM, SIGHUP and SIGQUIT do not kill murk. One
//! sent by another process (`kill <pid>`) is forwarded to the child, or to the
//! child's whole process group once [`set_group`] names one. A signal the
//! child sends murk is not echoed back to it, even one sent before murk
//! knows the child's pid. A child sharing murk's process group already got
//! what the terminal sends that group, so on Linux a signal the terminal
//! generated while that group holds the terminal (or as its session leader
//! exits) is not forwarded to it again. Any other signal with no sender pid,
//! such as one `docker stop` sends to murk as a container's PID 1, is
//! forwarded. On macOS a terminal signal carries the pid of the process that
//! writes to the terminal (the terminal emulator, sshd), so murk forwards it
//! and the child gets a terminal Ctrl-C or Ctrl-\ twice. [`stop_forwarding`]
//! restores the default actions and re-raises a signal caught while no child
//! was running.

use std::sync::atomic::{AtomicBool, AtomicI32, AtomicU64, Ordering};

/// The signals forwarded to the child.
const FORWARDED: [libc::c_int; 4] = [libc::SIGINT, libc::SIGTERM, libc::SIGHUP, libc::SIGQUIT];

/// Where a signal is forwarded, as a `kill(2)` target: the child's pid, the
/// negated id of its own process group, or 0 when there is none (not spawned
/// yet, or gone).
static CHILD: AtomicI32 = AtomicI32::new(0);
/// The last forwardable signal that arrived with no child to deliver it to,
/// packed with its sender by [`pack`] in one value, so a handler can never
/// pair one signal with another's sender; 0 when there is none. The sender
/// matters because a child that signals murk the moment it starts can do so
/// before murk knows its pid, and must not get the signal back.
///
/// This is one slot, not a queue: if several forwardable signals arrive
/// before the child is registered, the last one wins and earlier ones are
/// dropped.
///
/// Invariant: the value in the slot is acted on exactly once: delivered,
/// deliberately skipped as the child's own, or re-raised by
/// [`stop_forwarding`] when no child was ever registered for it. Whoever
/// claims it with `swap(0)` acts on it; the other side finds 0. A handler
/// that saw no child publishes the signal, then re-reads [`CHILD`];
/// [`set_target`] publishes the child, then claims [`PENDING`]. All four
/// accesses are SeqCst, so in their single total order at least one side
/// sees the other's write: a signal stored just after `set_target`'s swap
/// is claimed by the handler's own re-check, never left behind.
static PENDING: AtomicU64 = AtomicU64::new(0);

/// An fd on murk's controlling terminal, opened by [`install`] so the handler
/// can ask which process group holds the terminal; -1 when murk has no
/// controlling terminal.
static TTY: AtomicI32 = AtomicI32::new(-1);
/// Whether murk leads its session, recorded with [`TTY`]. The kernel sends a
/// terminal hangup to the session leader alone.
static LEADER: AtomicBool = AtomicBool::new(false);

/// One [`PENDING`] value: the sender's pid in the high half, the signal in
/// the low half (never 0, so a packed value is never 0 either).
fn pack(sig: libc::c_int, sender: libc::pid_t) -> u64 {
    (u64::from(sender as u32) << 32) | u64::from(sig as u32)
}

/// The signal and sender a non-zero [`PENDING`] value holds.
fn unpack(pending: u64) -> (libc::c_int, libc::pid_t) {
    (
        pending as u32 as libc::c_int,
        (pending >> 32) as u32 as libc::pid_t,
    )
}

/// The sender of the signal `info` describes; 0 for the kernel.
fn sender(info: *const libc::siginfo_t) -> libc::pid_t {
    if info.is_null() {
        return 0;
    }
    // SAFETY: with SA_SIGINFO the kernel passes a valid siginfo_t (null is
    // checked anyway); si_pid is defined for these signals.
    unsafe { (*info).si_pid() }
}

/// Whether the kernel generated the signal `info` describes, as it does for a
/// terminal key or hangup, rather than a process calling `kill(2)`.
fn sent_by_kernel(info: *const libc::siginfo_t) -> bool {
    if info.is_null() {
        return false;
    }
    // A process outside murk's pid namespace has no pid in it, so its
    // `kill(2)` arrives with sender 0 too, but with SI_USER (or SI_QUEUE,
    // SI_TKILL): every code a process sets is <= 0. The kernel's own signals
    // have a positive code (SI_KERNEL).
    #[cfg(any(target_os = "linux", target_os = "android"))]
    {
        // SAFETY: as in `sender`.
        unsafe { (*info).si_code > 0 }
    }
    // No pid namespaces: sender 0 is always the kernel.
    #[cfg(not(any(target_os = "linux", target_os = "android")))]
    {
        true
    }
}

/// murk's controlling terminal, as the handler sees it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Terminal {
    /// murk had no controlling terminal when forwarding was installed.
    None,
    /// murk's process group, and so a child in it, holds the terminal.
    Ours,
    /// Another process group holds it: murk runs in the background.
    Other,
    /// It is gone: hung up, or its session leader exited.
    Gone,
}

/// Which group holds murk's terminal now. Async-signal-safe: `tcgetpgrp`
/// and `getpgrp` are on POSIX's list.
fn terminal() -> Terminal {
    let tty = TTY.load(Ordering::SeqCst);
    if tty < 0 {
        return Terminal::None;
    }
    // SAFETY: plain syscalls; a hung-up terminal makes tcgetpgrp fail.
    match unsafe { libc::tcgetpgrp(tty) } {
        pgrp if pgrp < 0 => Terminal::Gone,
        // SAFETY: plain syscall.
        pgrp if pgrp == unsafe { libc::getpgrp() } => Terminal::Ours,
        _ => Terminal::Other,
    }
}

/// Whether a signal `sender` sent murk is the child's already, so forwarding
/// it to `target` would deliver it twice or echo it back: one the terminal
/// sent the foreground group the child shares with murk, or one the child
/// sent itself. `by_kernel` and `terminal` are only asked about a signal
/// with no sender pid; `leader` is whether murk leads its session.
fn child_has_it(
    sender: libc::pid_t,
    target: libc::pid_t,
    by_kernel: impl FnOnce() -> bool,
    terminal: impl FnOnce() -> Terminal,
    leader: bool,
) -> bool {
    if sender != 0 {
        return sender == target.abs();
    }
    // Only a child in murk's group (a pid target) got the terminal's signal;
    // a child leading its own group did not.
    if target <= 0 || !by_kernel() {
        return false;
    }
    match terminal() {
        Terminal::Ours => true,
        // A hangup murk gets as the session leader went to murk alone. When
        // another session leader exits, the kernel hangs up the foreground
        // group, murk and the child together, then detaches the terminal,
        // so by the time the handler asks, it is gone.
        Terminal::Gone => !leader,
        Terminal::None | Terminal::Other => false,
    }
}

/// Async-signal-safe handler: atomics, `kill(2)`, `tcgetpgrp` and `getpgrp`.
extern "C" fn forward(sig: libc::c_int, info: *mut libc::siginfo_t, _ctx: *mut libc::c_void) {
    let target = CHILD.load(Ordering::SeqCst);
    let sender = sender(info);
    // No child to deliver to (not spawned yet, or already exited): keep the
    // signal for `set_child` to forward or `stop_forwarding` to re-raise,
    // unless a child was registered meanwhile (see `PENDING`). A terminal
    // signal is kept too: it may have come before the child existed, and
    // skipping it would lose it, while forwarding risks a second copy.
    if target == 0 {
        PENDING.store(pack(sig, sender), Ordering::SeqCst);
        let target = CHILD.load(Ordering::SeqCst);
        if target != 0 {
            // No getpgid here: it is not async-signal-safe. So only the
            // group's leader counts as the child, and a signal another member
            // sent before `set_group` would be forwarded to the group.
            deliver_pending(target, PENDING.swap(0, Ordering::SeqCst), |_| false);
        }
        return;
    }
    let leader = LEADER.load(Ordering::SeqCst);
    if child_has_it(sender, target, || sent_by_kernel(info), terminal, leader) {
        return;
    }
    // SAFETY: kill(2) is async-signal-safe.
    unsafe {
        libc::kill(target, sig);
    }
}

/// Deliver a claimed [`PENDING`] value (0: nothing to do) to `target`,
/// unless the child sent it itself before murk knew its pid: the target's
/// pid or group leader, or, for a group, a sender `in_group` accepts.
/// Async-signal-safe if `in_group` is.
fn deliver_pending(target: libc::pid_t, pending: u64, in_group: impl Fn(libc::pid_t) -> bool) {
    if pending == 0 {
        return;
    }
    let (sig, from) = unpack(pending);
    if from != 0 && (from == target.abs() || (target < 0 && in_group(from))) {
        return;
    }
    // SAFETY: kill(2) is async-signal-safe; the target is our own, not yet
    // reaped, child or its group.
    unsafe {
        libc::kill(target, sig);
    }
}

/// Catch the forwarded signals so they don't kill murk while the child runs,
/// and open the controlling terminal for the handler to check. A caught
/// signal resets to its default in the child on exec. Call it before the
/// child is spawned, so nothing slow runs between the spawn and
/// [`set_child`].
pub(crate) fn install() {
    open_tty();
    for sig in FORWARDED {
        // SAFETY: a zeroed sigaction is a valid starting value; the handler
        // is async-signal-safe and lives for the whole process.
        unsafe {
            let mut action: libc::sigaction = std::mem::zeroed();
            action.sa_sigaction = forward as *const () as libc::sighandler_t;
            action.sa_flags = libc::SA_SIGINFO | libc::SA_RESTART;
            // A forwarded signal waits until the handler running on its
            // thread is done, rather than interrupting it mid-update.
            libc::sigemptyset(&raw mut action.sa_mask);
            for blocked in FORWARDED {
                libc::sigaddset(&raw mut action.sa_mask, blocked);
            }
            libc::sigaction(sig, &raw const action, std::ptr::null_mut());
        }
    }
}

/// Record the child's pid, then forward any signal that arrived first.
pub(crate) fn set_child(pid: u32) {
    set_target(pid as libc::pid_t);
}

/// Open murk's controlling terminal into [`TTY`], once, and record whether
/// murk leads its session. The fd stays open for the rest of the process: a
/// handler may be using it at any time. It is close-on-exec, so the child
/// never holds it.
fn open_tty() {
    if TTY.load(Ordering::SeqCst) >= 0 {
        return;
    }
    // SAFETY: a static NUL-terminated path; fails with ENXIO without a
    // controlling terminal. O_NOCTTY: never acquire one.
    let fd = unsafe {
        libc::open(
            c"/dev/tty".as_ptr(),
            libc::O_RDONLY | libc::O_NOCTTY | libc::O_CLOEXEC,
        )
    };
    if fd >= 0 {
        // SAFETY: plain syscalls on this process.
        let leader = unsafe { libc::getsid(0) == libc::getpid() };
        LEADER.store(leader, Ordering::SeqCst);
        TTY.store(fd, Ordering::SeqCst);
    }
}

/// Forward to the whole process group `pgid` (a child that leads its own
/// group), then forward any signal that arrived first. [`clear`] stops it.
pub(crate) fn set_group(pgid: libc::pid_t) {
    set_target(-pgid);
}

/// Stop forwarding; signals caught from now on are kept for
/// [`stop_forwarding`] to re-raise.
pub(crate) fn clear() {
    CHILD.store(0, Ordering::SeqCst);
}

fn set_target(target: libc::pid_t) {
    CHILD.store(target, Ordering::SeqCst);
    deliver_pending(target, PENDING.swap(0, Ordering::SeqCst), |from| {
        // SAFETY: plain syscall; a sender that has gone fails with -1.
        unsafe { libc::getpgid(from) == -target }
    });
}

/// Block until the child has exited, without reaping it, so the pid stays
/// ours until forwarding is turned off.
pub(crate) fn wait_exited(pid: u32) {
    loop {
        // SAFETY: waitid writes into `info`, which outlives the call.
        let rc = unsafe {
            let mut info: libc::siginfo_t = std::mem::zeroed();
            libc::waitid(
                libc::P_PID,
                pid as libc::id_t,
                &raw mut info,
                libc::WEXITED | libc::WNOWAIT,
            )
        };
        if rc == 0 || std::io::Error::last_os_error().kind() != std::io::ErrorKind::Interrupted {
            break;
        }
    }
    CHILD.store(0, Ordering::SeqCst);
}

/// The child is reaped: give the forwarded signals their default action
/// back, then re-raise one caught since the child exited. Default first, so
/// a signal arriving after the swap kills murk directly instead of landing
/// in `PENDING` unseen.
pub(crate) fn stop_forwarding() {
    for sig in FORWARDED {
        // SAFETY: plain syscall on this process.
        unsafe {
            libc::signal(sig, libc::SIG_DFL);
        }
    }
    let pending = PENDING.swap(0, Ordering::SeqCst);
    if pending != 0 {
        raise_default(unpack(pending).0);
    }
}

/// Die from `sig` the way the child did: default disposition, then raise.
/// Returns only if the signal did not end the process.
pub(crate) fn raise_default(sig: libc::c_int) {
    // SAFETY: plain syscalls on this process.
    unsafe {
        libc::signal(sig, libc::SIG_DFL);
        let mut set: libc::sigset_t = std::mem::zeroed();
        libc::sigemptyset(&raw mut set);
        libc::sigaddset(&raw mut set, sig);
        libc::pthread_sigmask(libc::SIG_UNBLOCK, &raw const set, std::ptr::null_mut());
        libc::raise(sig);
    }
}

#[cfg(test)]
mod tests {
    use super::{Terminal, child_has_it, sent_by_kernel};

    const CHILD_PID: libc::pid_t = 4242;
    fn yes() -> bool {
        true
    }
    fn no() -> bool {
        false
    }
    fn on(terminal: Terminal) -> impl FnOnce() -> Terminal {
        move || terminal
    }
    fn all_terminals() -> [Terminal; 4] {
        [
            Terminal::None,
            Terminal::Ours,
            Terminal::Other,
            Terminal::Gone,
        ]
    }

    #[test]
    fn a_terminal_key_the_foreground_child_got_is_not_forwarded() {
        for leader in [false, true] {
            assert!(child_has_it(0, CHILD_PID, yes, on(Terminal::Ours), leader));
        }
    }

    /// `docker stop` against murk as PID 1, with or without `-t`: sender 0,
    /// but sent by a process.
    #[test]
    fn a_kill_from_outside_the_pid_namespace_is_forwarded() {
        for terminal in all_terminals() {
            for leader in [false, true] {
                assert!(!child_has_it(0, CHILD_PID, no, on(terminal), leader));
            }
        }
    }

    /// No controlling terminal, or murk's group runs in the background: the
    /// terminal did not send the child this signal.
    #[test]
    fn a_kernel_signal_outside_the_foreground_is_forwarded() {
        for terminal in [Terminal::None, Terminal::Other] {
            assert!(!child_has_it(0, CHILD_PID, yes, on(terminal), false));
        }
    }

    /// The session leader murk runs under exited: the kernel hung up the
    /// foreground group, the child included, and detached the terminal.
    #[test]
    fn a_hangup_after_the_session_leader_exits_is_not_forwarded() {
        assert!(child_has_it(0, CHILD_PID, yes, on(Terminal::Gone), false));
    }

    /// The terminal hung up while murk leads the session: the kernel sent the
    /// hangup to murk alone.
    #[test]
    fn a_hangup_murk_gets_as_session_leader_is_forwarded() {
        assert!(!child_has_it(0, CHILD_PID, yes, on(Terminal::Gone), true));
    }

    /// A child leading its own group (the editor) is not in murk's group, so
    /// it did not get what the terminal sent murk.
    #[test]
    fn a_kernel_signal_is_forwarded_to_a_child_group() {
        for terminal in all_terminals() {
            assert!(!child_has_it(0, -CHILD_PID, yes, on(terminal), false));
        }
    }

    #[test]
    fn the_childs_own_signal_is_not_echoed() {
        assert!(child_has_it(
            CHILD_PID,
            CHILD_PID,
            no,
            on(Terminal::None),
            false
        ));
        assert!(child_has_it(
            CHILD_PID,
            -CHILD_PID,
            no,
            on(Terminal::None),
            false
        ));
    }

    #[test]
    fn another_process_signal_is_forwarded_whatever_holds_the_terminal() {
        for terminal in all_terminals() {
            assert!(!child_has_it(77, CHILD_PID, yes, on(terminal), false));
            assert!(!child_has_it(77, -CHILD_PID, yes, on(terminal), false));
        }
    }

    fn info_with_code(code: libc::c_int) -> libc::siginfo_t {
        // SAFETY: an all-zero siginfo_t is a valid value.
        let mut info: libc::siginfo_t = unsafe { std::mem::zeroed() };
        info.si_code = code;
        info
    }

    /// What tells `docker stop` (a process outside the pid namespace, so
    /// sender 0) apart from a terminal key on Linux.
    #[cfg(any(target_os = "linux", target_os = "android"))]
    #[test]
    fn only_a_kernel_code_counts_as_sent_by_the_kernel() {
        assert!(sent_by_kernel(&info_with_code(libc::SI_KERNEL)));
        for by_process in [libc::SI_USER, libc::SI_QUEUE, libc::SI_TKILL] {
            assert!(!sent_by_kernel(&info_with_code(by_process)), "{by_process}");
        }
        assert!(!sent_by_kernel(std::ptr::null()));
    }

    /// Without pid namespaces, sender 0 is the kernel whatever the code.
    #[cfg(not(any(target_os = "linux", target_os = "android")))]
    #[test]
    fn sender_zero_is_the_kernel_without_pid_namespaces() {
        assert!(sent_by_kernel(&info_with_code(0)));
        assert!(!sent_by_kernel(std::ptr::null()));
    }
}
