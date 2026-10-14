//! Invariant 103: a gateway that has not read the control plane's money state
//! admits nothing a budget governs.
//!
//! A restarted gateway learns four things from the control plane before its
//! ledgers mean what they say: each run's spend so far (invariant 70), each
//! unit's month (invariant 52), the budgets an operator set in the Cloud, and
//! the runs an operator killed there. Until 2026-10-14 the gateway asked once,
//! at startup, and a control plane that was not up yet cost one warning and a
//! ledger that started at zero "until the next restart". Measured that day on
//! forge (`systemctl restart docker`): the gateway started 60 ms before the
//! control plane, logged both warnings, and then admitted a call for a unit
//! already over its monthly cap and a call on a run already past its budget.
//!
//! This is the gate those two warnings now close. With a control plane
//! configured, the gate starts closed; `main.rs` opens it when the startup
//! seed reads all four, and otherwise `cloudsink::spawn_seed_retry` keeps
//! asking with [`backoff`] until it does. While it is closed, a call carrying
//! a run id (every such call has a budget: the header's, the policy's or the
//! built-in one) is refused in enforce with `503 seed_pending` and a
//! `retry-after`, and forwarded and marked in shadow and warn. A gateway with
//! no control plane configured has nothing to read and the gate is open from
//! the start, which is every deployment that predates the Cloud.
//!
//! 503 and not 402, `@claude` 2026-10-14: nothing about the run's money is
//! known to be exhausted, the dependency that holds it has not answered yet,
//! and the condition clears by itself in seconds once it does. A 402 is the
//! Breaker, which agents and SDKs treat as final for the run; a 503 with
//! `retry-after` is what the Anthropic and OpenAI client libraries already
//! retry on their own, so an agent that meets a restarting gateway usually
//! never sees the refusal at all. It is also not a new Breaker reason, so
//! nothing that mirrors the nine (the Cloud's `KNOWN_DECISIONS`, verdryx,
//! compliance evidence) has to move.

use std::collections::HashSet;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Mutex;
use std::time::Duration;

/// How many runs the once-per-run bus event remembers in one closed window.
/// Run ids are caller-chosen, so the set is bounded: past the cap it starts
/// over, which costs a repeated event and never memory.
pub const REPORTED_RUNS_CAP: usize = 8192;

/// The first retry waits this long; each later one doubles, up to [`BACKOFF_MAX`].
pub const BACKOFF_FIRST: Duration = Duration::from_millis(250);

/// The longest wait between two seed attempts. Short on purpose: every call a
/// budget governs is refused while the gate is closed, so a control plane that
/// comes back must be noticed within seconds, and one attempt is a handful of
/// small GETs.
pub const BACKOFF_MAX: Duration = Duration::from_secs(5);

/// The wait before retry number `attempt` (0 for the first retry).
pub fn backoff(attempt: u32) -> Duration {
    let first = BACKOFF_FIRST.as_millis() as u64;
    let max = BACKOFF_MAX.as_millis() as u64;
    let factor = 1u64.checked_shl(attempt.min(32)).unwrap_or(u64::MAX);
    Duration::from_millis(first.saturating_mul(factor).min(max))
}

/// Whether this gateway has read the control plane's money state.
#[derive(Debug)]
pub struct SeedGate {
    ready: AtomicBool,
    /// Why the last attempt did not complete, for the refusal and the event.
    reason: Mutex<String>,
    /// Runs already reported on the bus while the gate has been closed.
    reported: Mutex<HashSet<String>>,
    /// Calls the closed gate refused or marked, for the line that says it opened.
    touched: AtomicU64,
}

impl SeedGate {
    /// No control plane is configured: nothing to read, open from the start.
    pub fn open() -> Self {
        SeedGate {
            ready: AtomicBool::new(true),
            reason: Mutex::new(String::new()),
            reported: Mutex::new(HashSet::new()),
            touched: AtomicU64::new(0),
        }
    }

    /// A control plane is configured and has not yet answered the seed.
    pub fn closed(reason: impl Into<String>) -> Self {
        SeedGate {
            ready: AtomicBool::new(false),
            reason: Mutex::new(reason.into()),
            reported: Mutex::new(HashSet::new()),
            touched: AtomicU64::new(0),
        }
    }

    pub fn is_open(&self) -> bool {
        self.ready.load(Ordering::SeqCst)
    }

    /// `None` while the gate is open; otherwise why it is still closed.
    pub fn pending_reason(&self) -> Option<String> {
        if self.is_open() {
            return None;
        }
        Some(self.reason.lock().unwrap().clone())
    }

    /// Record why the latest attempt did not complete.
    pub fn set_reason(&self, reason: impl Into<String>) {
        *self.reason.lock().unwrap() = reason.into();
    }

    /// Count one call the closed gate refused or marked, and say whether it is
    /// the first for `run_id` since the gate closed, so the bus carries one
    /// event per run rather than one per retry.
    pub fn note_call(&self, run_id: &str) -> bool {
        self.touched.fetch_add(1, Ordering::SeqCst);
        let mut seen = self.reported.lock().unwrap();
        if seen.len() >= REPORTED_RUNS_CAP && !seen.contains(run_id) {
            seen.clear();
        }
        seen.insert(run_id.to_string())
    }

    /// Open the gate. Returns how many calls it refused or marked while closed
    /// when this call is the one that opened it, `None` when it was already open.
    pub fn open_now(&self) -> Option<u64> {
        if self.ready.swap(true, Ordering::SeqCst) {
            return None;
        }
        self.reported.lock().unwrap().clear();
        Some(self.touched.swap(0, Ordering::SeqCst))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_open_gate_names_no_reason() {
        let gate = SeedGate::open();
        assert!(gate.is_open());
        assert_eq!(gate.pending_reason(), None);
        assert_eq!(gate.open_now(), None, "already open, nothing opened it");
    }

    #[test]
    fn a_closed_gate_names_its_reason_until_it_opens() {
        let gate = SeedGate::closed("status 401");
        assert!(!gate.is_open());
        assert_eq!(gate.pending_reason().as_deref(), Some("status 401"));
        gate.set_reason("could not be reached");
        assert_eq!(
            gate.pending_reason().as_deref(),
            Some("could not be reached")
        );
        assert!(gate.note_call("r1"));
        assert!(!gate.note_call("r1"), "one event per run while closed");
        assert!(gate.note_call("r2"));
        assert_eq!(gate.open_now(), Some(3), "three calls met the closed gate");
        assert!(gate.is_open());
        assert_eq!(gate.pending_reason(), None);
        assert_eq!(gate.open_now(), None, "only the first opening reports");
    }

    #[test]
    fn the_reported_runs_are_bounded() {
        let gate = SeedGate::closed("x");
        for i in 0..REPORTED_RUNS_CAP {
            assert!(gate.note_call(&format!("run-{i}")));
        }
        assert!(
            gate.note_call("one-more"),
            "past the cap the set starts over"
        );
        assert!(gate.reported.lock().unwrap().len() <= REPORTED_RUNS_CAP);
    }

    #[test]
    fn backoff_doubles_from_a_quarter_second_and_stops_at_five() {
        assert_eq!(backoff(0), Duration::from_millis(250));
        assert_eq!(backoff(1), Duration::from_millis(500));
        assert_eq!(backoff(2), Duration::from_millis(1000));
        assert_eq!(backoff(4), Duration::from_millis(4000));
        assert_eq!(backoff(5), BACKOFF_MAX);
        assert_eq!(backoff(u32::MAX), BACKOFF_MAX, "no overflow, ever");
    }
}
