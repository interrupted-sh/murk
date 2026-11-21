// SPDX-FileCopyrightText: murk contributors
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Invariant rows: one scenario per row of the trust and merge harness, with
//! its state read from `tests/invariant_rows.tsv`.
//!
//! A row is written as its target: the behaviour murk must have once every
//! listed fix has landed. The table decides what the test demands of it:
//!
//! - `enforced`: the target holds, and the row's mutant (a patch under
//!   `tests/mutants/`) makes it fail. `tests/mutants/run.sh` checks that.
//! - `control`: the target holds today, but the guard that will keep it has
//!   not landed yet, so there is nothing to mutate. The fix that adds the
//!   guard flips the row to `enforced` and adds its patch.
//! - `known-violation`: murk breaks the target today. The row passes while
//!   the violation remains, as recorded by its `today` checks, and fails as
//!   soon as the target holds, so the fix must flip it to `enforced`.
//! - `pending`: the target needs behaviour that does not exist yet (format 4,
//!   lineage, the grant tombstone). The row is skipped in a normal run. With
//!   `MURK_ROWS=pending` only pending rows run; each one reports whether it
//!   reached its decisive step and whether its target holds, and never fails.
//!
//! Every row must reach its decisive step ([`Probe::reached`]) before any
//! target check counts, so no row passes because its scenario never ran.
//! Reaching it prints the row's [`decisive`] marker, which
//! `tests/mutants/run.sh` requires in a failing row's output before it counts
//! the row's mutant as caught: a row that fails in its setup proves nothing.

// Each integration binary compiles this module; most use only part of it.
#![allow(dead_code)]

use std::panic::{AssertUnwindSafe, catch_unwind};

/// The row table, shared with `tests/mutants/run.sh`.
pub const TABLE: &str = include_str!("../invariant_rows.tsv");

/// What the table says a row's test must show.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum State {
    Enforced,
    Control,
    KnownViolation,
    Pending,
}

impl State {
    pub fn parse(text: &str) -> Option<Self> {
        Some(match text {
            "enforced" => Self::Enforced,
            "control" => Self::Control,
            "known-violation" => Self::KnownViolation,
            "pending" => Self::Pending,
            _ => return None,
        })
    }
}

/// One line of the table.
#[derive(Clone, Debug)]
pub struct Row {
    /// The row id as the design names it, with `:arm` for one arm of a row.
    pub id: String,
    pub state: State,
    /// The change that flips the row (`-` for an enforced row).
    pub fix: String,
    /// The cargo test target: an integration test file's stem, or `lib`.
    pub binary: String,
    /// The test function's name (a unit test's last path segment).
    pub test: String,
    /// For an enforced row, the patch that disables its guard. Otherwise the
    /// guard to disable once the fix lands.
    pub mutant: String,
    /// Test-quality review findings the row also answers, or `-`.
    pub review: String,
    /// What the row checks, and for a known violation what murk does today.
    pub reason: String,
}

/// Every row in the table, in order. Panics on a malformed line.
pub fn table() -> Vec<Row> {
    TABLE
        .lines()
        .enumerate()
        .filter(|(_, l)| !l.trim().is_empty() && !l.starts_with('#'))
        .map(|(n, line)| {
            let cols: Vec<&str> = line.split('\t').collect();
            assert!(
                cols.len() == 8,
                "tests/invariant_rows.tsv line {}: want 8 tab-separated columns, got {}: {line:?}",
                n + 1,
                cols.len()
            );
            Row {
                id: cols[0].to_string(),
                state: State::parse(cols[1]).unwrap_or_else(|| {
                    panic!(
                        "tests/invariant_rows.tsv line {}: unknown state {:?}",
                        n + 1,
                        cols[1]
                    )
                }),
                fix: cols[2].to_string(),
                binary: cols[3].to_string(),
                test: cols[4].to_string(),
                mutant: cols[5].to_string(),
                review: cols[6].to_string(),
                reason: cols[7].to_string(),
            }
        })
        .collect()
}

/// The table line for `id`. A row run through [`check`] has exactly one.
pub fn row(id: &str) -> Row {
    let mut found = table().into_iter().filter(|r| r.id == id);
    let row = found
        .next()
        .unwrap_or_else(|| panic!("row {id} is not in tests/invariant_rows.tsv"));
    assert!(
        found.next().is_none(),
        "row {id} has more than one line in tests/invariant_rows.tsv"
    );
    row
}

/// Print the marker `ROW <id> DECISIVE` on stderr: the row reached the step
/// its mutant must fail on. A row test that does not run through [`check`]
/// calls this itself just before its decisive assertions. Keep the text in
/// step with `tests/mutants/run.sh`.
pub fn decisive(id: &str) {
    eprintln!("ROW {id} DECISIVE");
}

/// What a row's scenario observed.
#[derive(Debug, Default)]
pub struct Probe {
    id: String,
    reached: bool,
    target: Vec<(String, bool)>,
    today: Vec<(String, bool)>,
    notes: Vec<String>,
}

impl Probe {
    /// The decisive step ran: the attack (or the change under test) was made
    /// against a setup that the controls before it showed working.
    pub fn reached(&mut self) {
        if !self.reached {
            decisive(&self.id);
        }
        self.reached = true;
    }

    /// A setup step or control that must hold for the row to mean anything.
    /// A failure is a broken scenario, not a verdict on murk.
    pub fn require(&self, ok: bool, what: impl Into<String>) -> Result<(), String> {
        if ok { Ok(()) } else { Err(what.into()) }
    }

    /// One part of the row's target: what murk must do once fixed.
    pub fn target(&mut self, ok: bool, what: impl Into<String>) {
        assert!(
            self.reached,
            "a target check before the decisive step proves nothing: call reached() first"
        );
        self.target.push((what.into(), ok));
    }

    /// One part of the violation as murk shows it today. Only a
    /// `known-violation` row demands these; every one must hold.
    pub fn today(&mut self, ok: bool, what: impl Into<String>) {
        assert!(
            self.reached,
            "a violation check before the decisive step proves nothing: call reached() first"
        );
        self.today.push((what.into(), ok));
    }

    /// Context printed with the verdict (a refusal message, say).
    pub fn note(&mut self, text: impl Into<String>) {
        self.notes.push(text.into());
    }

    fn failed_target(&self) -> Vec<&str> {
        failed(&self.target)
    }
}

fn failed(checks: &[(String, bool)]) -> Vec<&str> {
    checks
        .iter()
        .filter(|(_, ok)| !ok)
        .map(|(w, _)| w.as_str())
        .collect()
}

fn pending_mode() -> bool {
    std::env::var("MURK_ROWS").is_ok_and(|v| v == "pending")
}

/// Run the scenario of row `id` and judge it by the row's state in the
/// table. `scenario` returns `Err` when its setup or a control failed.
pub fn check(id: &str, scenario: impl FnOnce(&mut Probe) -> Result<(), String>) {
    let row = row(id);
    let pending = row.state == State::Pending;
    if pending != pending_mode() {
        if pending {
            println!(
                "ROW {id} pending ({}): skipped; MURK_ROWS=pending runs it",
                row.fix
            );
        }
        return;
    }
    let mut probe = Probe {
        id: id.to_string(),
        ..Probe::default()
    };
    if pending {
        report_pending(&row, &mut probe, scenario);
        return;
    }
    let ran = scenario(&mut probe);
    let notes = probe.notes.join("\n  ");
    if let Err(e) = ran {
        panic!("row {id}: the scenario broke before its verdict: {e}\n  {notes}");
    }
    assert!(
        probe.reached,
        "row {id}: the decisive step never ran, so the row proves nothing\n  {notes}"
    );
    assert!(
        !probe.target.is_empty(),
        "row {id}: no target check, so the row proves nothing"
    );
    let unmet = probe.failed_target();
    match row.state {
        State::Enforced | State::Control => {
            assert!(
                unmet.is_empty(),
                "row {id} ({:?}) is violated: {}\n  {notes}",
                row.state,
                unmet.join("; ")
            );
        }
        State::KnownViolation => {
            assert!(
                !unmet.is_empty(),
                "row {id} is listed as a known violation, but its target now holds. \
                 If {} landed, flip the row to `enforced` in tests/invariant_rows.tsv, \
                 put a patch that reverts the fix in its mutant column, and delete its \
                 `today` checks.\n  {notes}",
                row.fix
            );
            assert!(
                !probe.today.is_empty(),
                "row {id}: a known violation must record what murk does today"
            );
            let changed = failed(&probe.today);
            assert!(
                changed.is_empty(),
                "row {id}: murk no longer shows the recorded violation ({}), yet the \
                 target still fails ({}). Re-check the row against today's behaviour.\n  {notes}",
                changed.join("; "),
                unmet.join("; ")
            );
            println!(
                "ROW {id} known violation ({}): target unmet as recorded: {}",
                row.fix,
                unmet.join("; ")
            );
        }
        State::Pending => unreachable!(),
    }
}

/// Run a pending row and print what it shows. Never panics.
fn report_pending(
    row: &Row,
    probe: &mut Probe,
    scenario: impl FnOnce(&mut Probe) -> Result<(), String>,
) {
    let id = &row.id;
    let outcome = catch_unwind(AssertUnwindSafe(|| scenario(probe)));
    let verdict = match outcome {
        Err(panic) => {
            let msg = panic
                .downcast_ref::<String>()
                .cloned()
                .or_else(|| panic.downcast_ref::<&str>().map(|s| s.to_string()))
                .unwrap_or_default();
            format!("scenario panicked before its verdict: {msg}")
        }
        Ok(Err(e)) if !probe.reached => format!("did not reach its decisive step: {e}"),
        Ok(Err(e)) => format!("broke after its decisive step: {e}"),
        Ok(Ok(())) if !probe.reached => "did not reach its decisive step".to_string(),
        Ok(Ok(())) if probe.target.is_empty() => "reached, but checks no target".to_string(),
        Ok(Ok(())) => {
            let unmet = probe.failed_target();
            if unmet.is_empty() {
                let msg = "TARGET HOLDS: flip it to `enforced` in tests/invariant_rows.tsv \
                           and give it a mutant patch"
                    .to_string();
                if std::env::var_os("GITHUB_ACTIONS").is_some() {
                    println!("::warning title=Pending row {id} now holds::{msg}");
                }
                msg
            } else {
                format!("target unmet: {}", unmet.join("; "))
            }
        }
    };
    println!("ROW {id} pending ({}): {verdict}", row.fix);
    for note in &probe.notes {
        println!("  {note}");
    }
}
