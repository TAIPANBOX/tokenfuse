//! The reserve → settle ledger (ADR-2).
//!
//! Before a call we atomically *reserve* its estimated cost against a run's
//! budget; after the response we *settle* the reservation with the real cost.
//! Reserve-then-settle is the only correct approach under concurrency: when an
//! agent fans out sub-agents, several calls race for the same budget, and a
//! naive "check spent, then add" would let them all pass the check at once.
//!
//! This in-process implementation guards the whole map with a `Mutex`, which
//! makes each reserve an atomic check-and-add. The raft backend
//! (`crates/gateway/src/raft_ledger.rs`) implements an older, narrower
//! contract; CLAUDE.md invariant 49 lists what it does not hold.

use crate::money::Microusd;
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::sync::Mutex;
use thiserror::Error;

/// A read-only view of a run's accounting state.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RunSnapshot {
    pub budget: Microusd,
    /// Estimated cost of calls that are reserved but not yet settled.
    pub reserved: Microusd,
    /// Real cost of calls that have completed and settled.
    pub spent: Microusd,
    /// Number of calls reserved so far (each reserve is one step).
    pub steps: u32,
}

impl RunSnapshot {
    /// Money committed or in flight — what a new reservation is checked against.
    pub fn in_flight(&self) -> Microusd {
        self.spent + self.reserved
    }

    /// Budget still available for new reservations (never negative).
    pub fn remaining(&self) -> Microusd {
        self.budget.saturating_sub(self.in_flight())
    }
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum BudgetError {
    #[error("unknown run: {run_id}")]
    UnknownRun { run_id: String },
    #[error("budget exceeded for run {run_id}: {would} would exceed budget {budget}")]
    Exceeded {
        run_id: String,
        budget: Microusd,
        spent: Microusd,
        would: Microusd,
    },
    /// D1: `run_id` (or an ancestor of it) declares `parent`, and this ledger has not opened
    /// `parent`. Nothing is admitted against a budget that cannot be checked.
    #[error("run {run_id} declares parent {parent}, which this ledger has not opened")]
    UnknownParent { run_id: String, parent: String },
    /// F01: the walk up from `run_id` collected `depth` ancestors and `next` was still
    /// unwalked. `at` is the last run that WAS walked. Refused rather than truncated.
    #[error(
        "budget chain from run {run_id} is deeper than {depth} ancestors; the walk stopped at {at} with {next} unchecked"
    )]
    ChainTooDeep {
        run_id: String,
        at: String,
        next: String,
        depth: usize,
    },
    /// `close_run` was called on `run_id` (the leaf or an ancestor); it admits nothing until
    /// reopened. Unreachable through HTTP (the proxy's `open_run` reopens); kept as a
    /// fail-closed arm, like `UnknownRun`.
    #[error("run {run_id} is closed and admits no spend")]
    RunClosed { run_id: String },
}

/// Why `open_run` refused. A refused open changes NOTHING (budget included).
#[derive(Debug, Error, PartialEq, Eq)]
pub enum OpenError {
    #[error(
        "run {run_id} already rolls up into {held}; a parent is never changed once set ({declared} was declared)"
    )]
    ParentChanged {
        run_id: String,
        held: String,
        declared: String,
    },
    #[error(
        "run {run_id} has already reserved against its budget chain; a parent cannot be adopted after that ({declared} was declared)"
    )]
    AdoptedTooLate { run_id: String, declared: String },
    #[error("run {run_id} declares itself as its own parent")]
    SelfParent { run_id: String },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ParentDisposition {
    /// Nothing declared, or the declaration matched what is held.
    Kept,
    /// First open of a fresh entry with a parent.
    Set,
    /// An existing parentless run with no admission ever, gained the declared parent (D2).
    Adopted,
}

/// What `open_run` did.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Opened {
    /// The run's generation after this call; fresh on a first open and on a reopen.
    pub generation: u64,
    /// The parent the ledger HOLDS after this call. This, never the header, is what a
    /// trace row records.
    pub parent: Option<String>,
    pub parent_disposition: ParentDisposition,
    /// `close_run` had been called and this open started a new generation.
    pub reopened: bool,
}

/// One run on an admitted chain, with the generation it had at admission.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ChainLink {
    pub run_id: String,
    pub generation: u64,
}

/// A successful reservation. Hand it back to [`Ledger::settle`] exactly once.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Reservation {
    /// Ledger-unique, monotonic from 1. Exactly-once completion is a membership test on it.
    pub id: u64,
    pub run_id: String,
    pub amount: Microusd,
    /// 1-based step index on the leaf.
    pub step: u32,
    /// The leaf's generation at admission; equal to `chain[0].generation`.
    pub generation: u64,
    /// Every run this reservation was admitted against, leaf first, each with the generation
    /// it had then. Settlement applies to these and only these.
    pub chain: Vec<ChainLink>,
}

/// What `settle` did. A no-op is observable, never silent.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Settlement {
    /// First completion. `links` chain entries were released and charged; `dropped` entries
    /// were skipped because the run no longer exists in the generation it was admitted in.
    Applied { links: usize, dropped: usize },
    /// A second completion of the same reservation, or a reservation this ledger did not
    /// issue. Nothing changed.
    NotOutstanding,
}

/// Facts `RunSnapshot` does not carry, for tests and operators. Read-only.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RunInfo {
    pub generation: u64,
    pub parent: Option<String>,
    pub closed: bool,
    /// True once any reservation was admitted on this run's own budget: its own or a
    /// descendant's. Gates adoption (D2). Never cleared except by a reopen.
    pub admitted_ever: bool,
}

#[derive(Debug, Clone)]
struct RunState {
    budget: Microusd,
    reserved: Microusd,
    spent: Microusd,
    steps: u32,
    /// Parent run this one rolls up into (hierarchical sub-agent budgets).
    parent: Option<String>,
    generation: u64,
    admitted_ever: bool,
    closed: bool,
}

/// Max ancestor depth walked when rolling reservations up a run tree — a guard
/// against accidental cycles or pathological nesting. Reaching it with a
/// further parent still unwalked is a refusal (F01).
const MAX_CHAIN_DEPTH: usize = 64;

/// Why a walk stopped before the root.
enum Stop {
    UnknownParent(String),
    Closed(String),
    TooDeep { at: String, next: String },
}

#[derive(Default)]
struct Inner {
    runs: HashMap<String, RunState>,
    next_generation: u64,  // pre-incremented: first issued value is 1
    next_reservation: u64, // pre-incremented: first issued value is 1
    outstanding: HashSet<u64>,
}

/// Bump a counter and return the new value. Pre-incremented: the first call
/// on a fresh (zero) counter returns 1, never 0 (the raft backend uses 0 for
/// "no generation").
fn bump(counter: &mut u64) -> u64 {
    *counter += 1;
    *counter
}

/// The chain from `run_id` up through its ancestors, leaf first, and why it stopped early if it
/// did. The leaf's own existence is checked by the caller.
fn walk(runs: &HashMap<String, RunState>, run_id: &str) -> (Vec<ChainLink>, Option<Stop>) {
    let mut links: Vec<ChainLink> = Vec::new();
    let mut cur = Some(run_id.to_string());
    while let Some(id) = cur {
        if links.iter().any(|l| l.run_id == id) {
            break; // a cycle: every member is already on the chain once, and checked once
        }
        if links.len() >= MAX_CHAIN_DEPTH {
            let at = links.last().map(|l| l.run_id.clone()).unwrap_or_default();
            return (links, Some(Stop::TooDeep { at, next: id }));
        }
        let Some(s) = runs.get(&id) else {
            return (links, Some(Stop::UnknownParent(id)));
        };
        if s.closed {
            return (links, Some(Stop::Closed(id)));
        }
        links.push(ChainLink {
            run_id: id,
            generation: s.generation,
        });
        cur = s.parent.clone();
    }
    (links, None)
}

fn stop_to_error(stop: Stop, run_id: &str) -> BudgetError {
    match stop {
        Stop::UnknownParent(parent) => BudgetError::UnknownParent {
            run_id: run_id.to_string(),
            parent,
        },
        Stop::Closed(id) => BudgetError::RunClosed { run_id: id },
        Stop::TooDeep { at, next } => BudgetError::ChainTooDeep {
            run_id: run_id.to_string(),
            at,
            next,
            depth: MAX_CHAIN_DEPTH,
        },
    }
}

/// The admission predicate, ONE copy for `reserve` and `would_exceed`. `None` fits;
/// `Some(would)` does not, `would` being the saturated sum for display. Overflow reads as
/// exceeded (F09): a sum that cannot be represented fits no budget.
fn exceeds(s: &RunState, estimate: Microusd) -> Option<Microusd> {
    match s
        .spent
        .checked_add(s.reserved)
        .and_then(|c| c.checked_add(estimate))
    {
        Some(would) if would <= s.budget => None,
        Some(would) => Some(would),
        None => Some(s.spent.saturating_add(s.reserved).saturating_add(estimate)),
    }
}

/// In-process reserve/settle ledger. Cheap to clone via `Arc` at the call site.
#[derive(Default)]
pub struct Ledger {
    inner: Mutex<Inner>,
}

impl Ledger {
    pub fn new() -> Self {
        Ledger::default()
    }

    /// Register a run with its budget and optional parent.
    ///
    /// A fresh entry (never seen, or previously closed) is created with a new
    /// generation and this budget and parent. An existing OPEN entry decides
    /// the parent first and the budget second, so a refusal changes nothing:
    /// no declared parent, or the same one already held, keeps it; a
    /// different held parent is `ParentChanged`; a parentless run that has
    /// never had a reservation admitted against it (its own or a
    /// descendant's) adopts the declared parent; a parentless run that HAS
    /// had one admitted is `AdoptedTooLate`. Declaring a run as its own
    /// parent is always refused, before anything else is touched.
    pub fn open_run(
        &self,
        run_id: impl Into<String>,
        budget: Microusd,
        parent: Option<&str>,
    ) -> Result<Opened, OpenError> {
        let run_id = run_id.into();
        if parent == Some(run_id.as_str()) {
            return Err(OpenError::SelfParent { run_id });
        }
        let mut inner = self.inner.lock().unwrap();

        enum Shape {
            Absent,
            Closed,
            Open,
        }
        let shape = match inner.runs.get(&run_id) {
            None => Shape::Absent,
            Some(s) if s.closed => Shape::Closed,
            Some(_) => Shape::Open,
        };

        match shape {
            Shape::Absent | Shape::Closed => {
                let reopened = matches!(shape, Shape::Closed);
                let generation = bump(&mut inner.next_generation);
                inner.runs.insert(
                    run_id.clone(),
                    RunState {
                        budget,
                        reserved: Microusd::ZERO,
                        spent: Microusd::ZERO,
                        steps: 0,
                        parent: parent.map(|p| p.to_string()),
                        generation,
                        admitted_ever: false,
                        closed: false,
                    },
                );
                Ok(Opened {
                    generation,
                    parent: parent.map(|p| p.to_string()),
                    parent_disposition: if parent.is_some() {
                        ParentDisposition::Set
                    } else {
                        ParentDisposition::Kept
                    },
                    reopened,
                })
            }
            Shape::Open => {
                let s = inner.runs.get_mut(&run_id).expect("checked open above");
                let disposition = match (s.parent.clone(), parent) {
                    (_, None) => ParentDisposition::Kept,
                    (Some(h), Some(d)) if h == d => ParentDisposition::Kept,
                    (Some(h), Some(d)) => {
                        return Err(OpenError::ParentChanged {
                            run_id,
                            held: h,
                            declared: d.to_string(),
                        });
                    }
                    (None, Some(d)) if s.admitted_ever => {
                        return Err(OpenError::AdoptedTooLate {
                            run_id,
                            declared: d.to_string(),
                        });
                    }
                    (None, Some(d)) => {
                        s.parent = Some(d.to_string());
                        ParentDisposition::Adopted
                    }
                };
                s.budget = budget;
                Ok(Opened {
                    generation: s.generation,
                    parent: s.parent.clone(),
                    parent_disposition: disposition,
                    reopened: false,
                })
            }
        }
    }

    /// Atomically reserve `estimate` against the run's budget *and every
    /// ancestor's* budget — so a sub-agent's spend rolls up into its parent's
    /// cap. Fails (reserving nothing) if any level would be exceeded, or if
    /// the chain cannot be fully checked (an unknown parent, a closed run, or
    /// a walk past the depth cap). Increments the leaf run's step counter and
    /// marks every link `admitted_ever` on success.
    pub fn reserve(&self, run_id: &str, estimate: Microusd) -> Result<Reservation, BudgetError> {
        let mut inner = self.inner.lock().unwrap();
        if !inner.runs.contains_key(run_id) {
            return Err(BudgetError::UnknownRun {
                run_id: run_id.to_string(),
            });
        }
        let (links, stop) = walk(&inner.runs, run_id);
        if let Some(stop) = stop {
            return Err(stop_to_error(stop, run_id));
        }

        // Check every level first (all-or-nothing).
        for link in &links {
            let s = &inner.runs[&link.run_id];
            if let Some(would) = exceeds(s, estimate) {
                return Err(BudgetError::Exceeded {
                    run_id: link.run_id.clone(),
                    budget: s.budget,
                    spent: s.spent,
                    would,
                });
            }
        }

        // Apply to every level; steps increments on the leaf only.
        for link in &links {
            let s = inner.runs.get_mut(&link.run_id).expect("in chain");
            s.reserved = s.reserved.saturating_add(estimate);
            s.admitted_ever = true;
        }
        let leaf = inner.runs.get_mut(run_id).expect("leaf");
        leaf.steps += 1;
        let step = leaf.steps;
        let generation = links[0].generation;
        let id = bump(&mut inner.next_reservation);
        inner.outstanding.insert(id);
        Ok(Reservation {
            id,
            run_id: run_id.to_string(),
            amount: estimate,
            step,
            generation,
            chain: links,
        })
    }

    /// The question `reserve` asks, answered without reserving: would
    /// `estimate` exceed this run's budget or any ancestor's, or does the
    /// chain fail to check at all (unknown parent, closed run, depth cap)?
    /// `None` for a run this ledger does not know (there is nothing to say
    /// about it) and for a call that fits. Shadow and warn modes ask this
    /// before `reserve_unchecked`, so what they record is the refusal enforce
    /// would have made, computed by the same rule rather than by a second one
    /// that could drift.
    pub fn would_exceed(&self, run_id: &str, estimate: Microusd) -> Option<BudgetError> {
        let inner = self.inner.lock().unwrap();
        inner.runs.contains_key(run_id).then_some(())?;
        let (links, stop) = walk(&inner.runs, run_id);
        if let Some(stop) = stop {
            return Some(stop_to_error(stop, run_id));
        }
        for link in &links {
            let s = &inner.runs[&link.run_id];
            if let Some(would) = exceeds(s, estimate) {
                return Some(BudgetError::Exceeded {
                    run_id: link.run_id.clone(),
                    budget: s.budget,
                    spent: s.spent,
                    would,
                });
            }
        }
        None
    }

    /// Reserve without a budget check across the whole chain. Used in
    /// shadow/warn modes, where a breach must be *recorded* (so spend and steps
    /// stay accurate) but must not block. Opens the run at zero budget if absent
    /// or closed. Unlike `reserve`, an unwalkable prefix does not refuse: the
    /// reservation is admitted on whatever of the chain IS walkable (an
    /// unknown parent stops it at the leaf; a too-deep chain at the cap; a
    /// closed ancestor before it) — this is the one place truncation is
    /// allowed, because shadow's job is to record what enforce would refuse
    /// (via `would_exceed`, asked first by the caller) and to account what it
    /// can.
    pub fn reserve_unchecked(&self, run_id: &str, estimate: Microusd) -> Reservation {
        let mut inner = self.inner.lock().unwrap();
        let needs_fresh = match inner.runs.get(run_id) {
            None => true,
            Some(s) => s.closed,
        };
        if needs_fresh {
            let generation = bump(&mut inner.next_generation);
            inner.runs.insert(
                run_id.to_string(),
                RunState {
                    budget: Microusd::ZERO,
                    reserved: Microusd::ZERO,
                    spent: Microusd::ZERO,
                    steps: 0,
                    parent: None,
                    generation,
                    admitted_ever: false,
                    closed: false,
                },
            );
        }
        let (links, _stop) = walk(&inner.runs, run_id);
        for link in &links {
            let s = inner.runs.get_mut(&link.run_id).expect("in chain");
            s.reserved = s.reserved.saturating_add(estimate);
            s.admitted_ever = true;
        }
        let leaf = inner.runs.get_mut(run_id).expect("leaf");
        leaf.steps += 1;
        let step = leaf.steps;
        let generation = leaf.generation;
        let id = bump(&mut inner.next_reservation);
        inner.outstanding.insert(id);
        Reservation {
            id,
            run_id: run_id.to_string(),
            amount: estimate,
            step,
            generation,
            chain: links,
        }
    }

    /// Settle a reservation with the real cost: release the reserved estimate
    /// and add the actual spend, on every link of the chain it was ADMITTED
    /// against (never the live tree, and never a second time). A link whose
    /// run no longer exists in the generation it was admitted in (closed and
    /// reopened since) is dropped rather than touched; a closed-but-not-
    /// reopened run is still touched (closing keeps the counters a late
    /// settlement needs). A reservation this ledger does not have outstanding
    /// (already settled, or not one it issued) is `NotOutstanding`: nothing
    /// changes, visibly.
    pub fn settle(&self, reservation: &Reservation, actual: Microusd) -> Settlement {
        let mut inner = self.inner.lock().unwrap();
        if !inner.outstanding.remove(&reservation.id) {
            return Settlement::NotOutstanding;
        }
        let mut links = 0;
        let mut dropped = 0;
        for link in &reservation.chain {
            match inner.runs.get_mut(&link.run_id) {
                Some(s) if s.generation == link.generation => {
                    s.reserved = s.reserved.saturating_sub(reservation.amount);
                    s.spent = s.spent.saturating_add(actual);
                    links += 1;
                }
                _ => dropped += 1,
            }
        }
        Settlement::Applied { links, dropped }
    }

    /// Snapshot a run's accounting state. Closed runs are included, with
    /// their final figures, until the next `open_run` reopens them.
    pub fn snapshot(&self, run_id: &str) -> Option<RunSnapshot> {
        let inner = self.inner.lock().unwrap();
        inner.runs.get(run_id).map(|s| RunSnapshot {
            budget: s.budget,
            reserved: s.reserved,
            spent: s.spent,
            steps: s.steps,
        })
    }

    /// Snapshot every known run (for observability / the `runs` endpoint).
    /// Closed runs are included, but `RunSnapshot` carries no `closed` field,
    /// so a closed run and an open one are indistinguishable in this list
    /// (and in `GET /v1/runs`); `run_info` is where `closed` can be read.
    pub fn list_runs(&self) -> Vec<(String, RunSnapshot)> {
        let inner = self.inner.lock().unwrap();
        inner
            .runs
            .iter()
            .map(|(id, s)| {
                (
                    id.clone(),
                    RunSnapshot {
                        budget: s.budget,
                        reserved: s.reserved,
                        spent: s.spent,
                        steps: s.steps,
                    },
                )
            })
            .collect()
    }

    /// Mark a run closed (idempotent) and return its snapshot at the moment
    /// of closing. Its counters, generation, parent and `admitted_ever` are
    /// all kept: a late settlement still needs them, and `open_run` reopens
    /// the run under a fresh generation rather than resurrecting this one.
    pub fn close_run(&self, run_id: &str) -> Option<RunSnapshot> {
        let mut inner = self.inner.lock().unwrap();
        let s = inner.runs.get_mut(run_id)?;
        s.closed = true;
        Some(RunSnapshot {
            budget: s.budget,
            reserved: s.reserved,
            spent: s.spent,
            steps: s.steps,
        })
    }

    /// Facts `RunSnapshot` does not carry: generation, parent, closed, and
    /// whether any reservation has ever been admitted on this run's budget
    /// (its own or a descendant's).
    pub fn run_info(&self, run_id: &str) -> Option<RunInfo> {
        let inner = self.inner.lock().unwrap();
        inner.runs.get(run_id).map(|s| RunInfo {
            generation: s.generation,
            parent: s.parent.clone(),
            closed: s.closed,
            admitted_ever: s.admitted_ever,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn usd(v: f64) -> Microusd {
        Microusd::from_usd(v)
    }

    #[test]
    fn reserve_unknown_run_errors() {
        let ledger = Ledger::new();
        let err = ledger.reserve("nope", usd(0.1)).unwrap_err();
        assert!(matches!(err, BudgetError::UnknownRun { .. }));
    }

    #[test]
    fn reserve_then_settle_tracks_spend_and_releases_reservation() {
        let ledger = Ledger::new();
        ledger.open_run("r1", usd(5.0), None).expect("opens");

        let res = ledger.reserve("r1", usd(1.0)).unwrap();
        let mid = ledger.snapshot("r1").unwrap();
        assert_eq!(mid.reserved, usd(1.0));
        assert_eq!(mid.spent, Microusd::ZERO);
        assert_eq!(mid.steps, 1);

        // Real cost came in lower than the estimate.
        ledger.settle(&res, usd(0.8));
        let after = ledger.snapshot("r1").unwrap();
        assert_eq!(after.reserved, Microusd::ZERO);
        assert_eq!(after.spent, usd(0.8));
        assert_eq!(after.remaining(), usd(4.2));
    }

    #[test]
    fn reservation_blocks_when_it_would_exceed_budget() {
        let ledger = Ledger::new();
        ledger.open_run("r1", usd(1.0), None).expect("opens");
        ledger.reserve("r1", usd(0.9)).unwrap();

        let err = ledger.reserve("r1", usd(0.2)).unwrap_err();
        match err {
            BudgetError::Exceeded { would, budget, .. } => {
                assert_eq!(budget, usd(1.0));
                assert_eq!(would, usd(1.1));
            }
            other => panic!("expected Exceeded, got {other:?}"),
        }
    }

    #[test]
    fn would_exceed_mirrors_reserve_without_reserving() {
        let ledger = Ledger::new();
        ledger.open_run("parent", usd(0.02), None).expect("opens");
        ledger
            .open_run("child", usd(1.0), Some("parent"))
            .expect("opens");
        // Fits: nothing to say, and asking reserves nothing.
        assert!(ledger.would_exceed("child", usd(0.01)).is_none());
        let before = ledger.snapshot("child").unwrap();
        assert_eq!(before.reserved, Microusd::ZERO);
        assert_eq!(before.steps, 0);
        // The parent's cap, not the child's own generous one, is what the checked
        // reserve would refuse on; would_exceed names the same run.
        match ledger.would_exceed("child", usd(0.03)) {
            Some(BudgetError::Exceeded { run_id, budget, .. }) => {
                assert_eq!(run_id, "parent");
                assert_eq!(budget, usd(0.02));
            }
            other => panic!("expected the parent's refusal, got {other:?}"),
        }
        // Still nothing reserved, on either level: this was a question.
        assert_eq!(ledger.snapshot("child").unwrap().reserved, Microusd::ZERO);
        assert_eq!(ledger.snapshot("parent").unwrap().reserved, Microusd::ZERO);
        // And it agrees with the checked reserve's verdict, both ways.
        assert!(ledger.reserve("child", usd(0.03)).is_err());
        assert!(ledger.reserve("child", usd(0.01)).is_ok());
        // That reservation is outstanding (nothing settled), and it counts: the
        // parent has 0.01 reserved of its 0.02, so another 0.015 would exceed
        // it even though nothing has been SPENT yet. A mirror that summed
        // spent + estimate and forgot reserved would say this fits.
        assert_eq!(ledger.snapshot("parent").unwrap().spent, Microusd::ZERO);
        match ledger.would_exceed("child", usd(0.015)) {
            Some(BudgetError::Exceeded { run_id, .. }) => assert_eq!(run_id, "parent"),
            other => panic!("an outstanding reservation must count, got {other:?}"),
        }
        assert!(ledger.would_exceed("child", usd(0.009)).is_none());
        // Meeting the budget exactly is not exceeding it: the line is the same
        // strict one reserve draws.
        let l2 = Ledger::new();
        l2.open_run("r", usd(1.0), None).expect("opens");
        assert!(l2.would_exceed("r", usd(1.0)).is_none());
        assert!(l2.would_exceed("r", Microusd(1_000_001)).is_some());
        // An unknown run is nothing to say, not a refusal.
        assert!(l2.would_exceed("nobody", usd(0.0)).is_none());
    }

    #[test]
    fn reserve_unchecked_records_past_budget_without_error() {
        let ledger = Ledger::new();
        ledger.open_run("r1", usd(1.0), None).expect("opens");
        // Reserve beyond budget: shadow mode records it, does not block.
        let res = ledger.reserve_unchecked("r1", usd(5.0));
        assert_eq!(res.step, 1);
        let snap = ledger.snapshot("r1").unwrap();
        assert_eq!(snap.reserved, usd(5.0));
        // The checked path, by contrast, would have refused this.
        assert!(ledger.reserve("r1", usd(0.1)).is_err());
    }

    #[test]
    fn subagent_spend_rolls_up_into_parent() {
        let ledger = Ledger::new();
        ledger.open_run("parent", usd(10.0), None).expect("opens");
        ledger
            .open_run("child", usd(8.0), Some("parent"))
            .expect("opens");

        let r = ledger.reserve("child", usd(3.0)).unwrap();
        ledger.settle(&r, usd(3.0));

        // The child's spend also shows up on the parent.
        assert_eq!(ledger.snapshot("child").unwrap().spent, usd(3.0));
        assert_eq!(ledger.snapshot("parent").unwrap().spent, usd(3.0));
        assert_eq!(ledger.snapshot("parent").unwrap().remaining(), usd(7.0));
    }

    #[test]
    fn child_reservation_blocked_by_parent_budget() {
        let ledger = Ledger::new();
        // Parent budget ($4) is tighter than the child's own ($100).
        ledger.open_run("parent", usd(4.0), None).expect("opens");
        ledger
            .open_run("child", usd(100.0), Some("parent"))
            .expect("opens");

        // Parent already spent $3 directly.
        let rp = ledger.reserve("parent", usd(3.0)).unwrap();
        ledger.settle(&rp, usd(3.0));

        // Child wants $2 — fits its own budget but not the parent's remaining $1.
        let err = ledger.reserve("child", usd(2.0)).unwrap_err();
        match err {
            BudgetError::Exceeded { run_id, .. } => assert_eq!(run_id, "parent"),
            other => panic!("expected parent Exceeded, got {other:?}"),
        }
        // Nothing was reserved anywhere (all-or-nothing).
        assert_eq!(ledger.snapshot("child").unwrap().reserved, Microusd::ZERO);
        assert_eq!(ledger.snapshot("parent").unwrap().reserved, Microusd::ZERO);
    }

    /// A child naming a parent this ledger has not opened is checked against
    /// nothing above itself, unless the checked reserve refuses to admit it
    /// at all (invariant 49, D1).
    #[test]
    fn a_child_of_an_unopened_parent_is_refused_and_reserves_nothing() {
        let l = Ledger::new();
        let opened = l
            .open_run("c", Microusd(1_000_000), Some("p"))
            .expect("opens");
        assert_eq!(opened.parent, Some("p".to_string()));
        assert_eq!(opened.parent_disposition, ParentDisposition::Set);

        let err = l.reserve("c", Microusd(400_000)).unwrap_err();
        assert_eq!(
            err,
            BudgetError::UnknownParent {
                run_id: "c".to_string(),
                parent: "p".to_string()
            }
        );

        let we = l.would_exceed("c", Microusd(1));
        assert_eq!(
            we,
            Some(BudgetError::UnknownParent {
                run_id: "c".to_string(),
                parent: "p".to_string()
            })
        );

        let snap = l.snapshot("c").unwrap();
        assert_eq!(snap.reserved, Microusd::ZERO);
        assert_eq!(snap.spent, Microusd::ZERO);
        assert_eq!(snap.steps, 0);
        assert!(l.snapshot("p").is_none());

        let info = l.run_info("c").unwrap();
        assert_eq!(info.parent, Some("p".to_string()));
        assert!(!info.admitted_ever);
    }

    /// Once the parent this ledger was missing opens, the same child is
    /// checked against it, and its own admission on the new ancestor is
    /// exactly as strict as any other reserve.
    #[test]
    fn a_child_of_an_unopened_parent_is_admitted_once_the_parent_opens() {
        let l = Ledger::new();
        l.open_run("c", Microusd(1_000_000), Some("p"))
            .expect("opens");
        l.open_run("p", Microusd(500_000), None).expect("opens");

        let r = l.reserve("c", Microusd(400_000)).unwrap();
        let c_mid = l.snapshot("c").unwrap();
        assert_eq!(c_mid.reserved, Microusd(400_000));
        assert_eq!(c_mid.steps, 1);
        let p_mid = l.snapshot("p").unwrap();
        assert_eq!(p_mid.reserved, Microusd(400_000));
        assert_eq!(p_mid.steps, 0);

        let err = l.reserve("c", Microusd(200_000)).unwrap_err();
        assert_eq!(
            err,
            BudgetError::Exceeded {
                run_id: "p".to_string(),
                budget: Microusd(500_000),
                spent: Microusd::ZERO,
                would: Microusd(600_000),
            }
        );

        let settlement = l.settle(&r, Microusd(300_000));
        assert_eq!(
            settlement,
            Settlement::Applied {
                links: 2,
                dropped: 0
            }
        );
        let c_after = l.snapshot("c").unwrap();
        assert_eq!(c_after.reserved, Microusd::ZERO);
        assert_eq!(c_after.spent, Microusd(300_000));
        let p_after = l.snapshot("p").unwrap();
        assert_eq!(p_after.reserved, Microusd::ZERO);
        assert_eq!(p_after.spent, Microusd(300_000));
    }

    /// A parent declared after a descendant's reservation has been admitted
    /// against a run is refused: the run's OWN steps can stay at zero while
    /// a child rolls up through it, so `admitted_ever` (not `steps == 0`) is
    /// the test D2 needs.
    #[test]
    fn a_parent_declared_after_a_descendants_admission_is_refused() {
        let l = Ledger::new();
        l.open_run("a", Microusd(1_000_000), None).expect("opens");
        l.open_run("b", Microusd(1_000_000), Some("a"))
            .expect("opens");
        let rb = l.reserve("b", Microusd(100_000)).unwrap();
        l.open_run("p", Microusd(1_000_000), None).expect("opens");

        let a_before = l.snapshot("a").unwrap();
        assert_eq!(a_before.reserved, Microusd(100_000));
        assert_eq!(a_before.steps, 0);
        assert!(l.run_info("a").unwrap().admitted_ever);

        let err = l.open_run("a", Microusd(1_000_000), Some("p")).unwrap_err();
        assert_eq!(
            err,
            OpenError::AdoptedTooLate {
                run_id: "a".to_string(),
                declared: "p".to_string()
            }
        );
        assert_eq!(l.run_info("a").unwrap().parent, None);

        let rb2 = l.reserve("b", Microusd(50_000)).unwrap();
        assert_eq!(l.snapshot("p").unwrap().reserved, Microusd::ZERO);

        l.settle(&rb, Microusd(100_000));
        l.settle(&rb2, Microusd(50_000));
        assert_eq!(l.snapshot("a").unwrap().spent, Microusd(150_000));
        assert_eq!(l.snapshot("b").unwrap().spent, Microusd(150_000));
        assert_eq!(l.snapshot("p").unwrap().spent, Microusd::ZERO);
    }

    /// The same admission-gates-adoption rule as above, but the admission is
    /// an UNCHECKED one (the shape shadow and warn produce): `reserve_unchecked`
    /// must mark `admitted_ever` too, or a run whose only spend went through
    /// the unchecked path could adopt a parent afterward while D2 says any
    /// mode refuses that.
    #[test]
    fn a_parent_declared_after_an_unchecked_admission_is_refused() {
        let l = Ledger::new();
        l.open_run("c", Microusd(1_000_000), None).expect("opens");
        l.open_run("p", Microusd(1_000_000), None).expect("opens");
        l.reserve_unchecked("c", Microusd(1));

        let err = l.open_run("c", Microusd(1_000_000), Some("p")).unwrap_err();
        assert_eq!(
            err,
            OpenError::AdoptedTooLate {
                run_id: "c".to_string(),
                declared: "p".to_string()
            }
        );
        assert_eq!(l.run_info("c").unwrap().parent, None);
    }

    /// A parent declared before any admission is adopted, and the adopted
    /// parent's budget is checked from the very next reserve.
    #[test]
    fn a_parent_declared_before_any_admission_is_adopted() {
        let l = Ledger::new();
        l.open_run("c", Microusd(1_000_000), None).expect("opens");
        l.open_run("p", Microusd(300_000), None).expect("opens");

        let opened = l
            .open_run("c", Microusd(1_000_000), Some("p"))
            .expect("adopts");
        assert_eq!(opened.parent, Some("p".to_string()));
        assert_eq!(opened.parent_disposition, ParentDisposition::Adopted);

        l.reserve("c", Microusd(200_000)).unwrap();
        assert_eq!(l.snapshot("p").unwrap().reserved, Microusd(200_000));
        assert_eq!(l.snapshot("c").unwrap().reserved, Microusd(200_000));

        let err = l.reserve("c", Microusd(200_000)).unwrap_err();
        match err {
            BudgetError::Exceeded { run_id, would, .. } => {
                assert_eq!(run_id, "p");
                assert_eq!(would, Microusd(400_000));
            }
            other => panic!("expected parent Exceeded, got {other:?}"),
        }
    }

    /// A parent, once set, is never changed; the held one stays in effect
    /// even after a refused declaration, and a refused `open_run` changes
    /// nothing else either (the budget included).
    #[test]
    fn a_changed_parent_is_refused_and_the_held_one_stays() {
        let l = Ledger::new();
        l.open_run("p1", Microusd(1_000_000), None).expect("opens");
        l.open_run("p2", Microusd(1_000_000), None).expect("opens");
        l.open_run("c", Microusd(1_000_000), Some("p1"))
            .expect("opens");

        let err = l
            .open_run("c", Microusd(5_000_000), Some("p2"))
            .unwrap_err();
        assert_eq!(
            err,
            OpenError::ParentChanged {
                run_id: "c".to_string(),
                held: "p1".to_string(),
                declared: "p2".to_string()
            }
        );
        assert_eq!(l.snapshot("c").unwrap().budget, Microusd(1_000_000));

        let opened = l.open_run("c", Microusd(2_000_000), None).expect("kept");
        assert_eq!(opened.parent, Some("p1".to_string()));
        assert_eq!(opened.parent_disposition, ParentDisposition::Kept);
        assert_eq!(l.snapshot("c").unwrap().budget, Microusd(2_000_000));

        l.reserve("c", Microusd(100_000)).unwrap();
        assert_eq!(l.snapshot("p1").unwrap().reserved, Microusd(100_000));
        assert_eq!(l.snapshot("p2").unwrap().reserved, Microusd::ZERO);
    }

    /// The F02 fix: a reservation settles on the chain it was ADMITTED
    /// against, not the live tree at settle time, so a parent that appears
    /// (or reopens) between a child's reserve and its settle cannot lose
    /// another call's reservation. `codex_f02` (moved into
    /// `tests/codex_money_review.rs`) is the review's own probe for the same
    /// fault; this is its shape plus the tail proving the chain keeps
    /// growing correctly once the parent exists.
    #[test]
    fn a_reservation_settles_on_the_chain_it_was_admitted_against() {
        let l = Ledger::new();
        l.open_run("child", Microusd(1_000_000), Some("parent"))
            .expect("opens");
        let child_r = l.reserve_unchecked("child", Microusd(800_000));
        assert_eq!(
            child_r
                .chain
                .iter()
                .map(|c| c.run_id.as_str())
                .collect::<Vec<_>>(),
            vec!["child"],
            "parent is not open yet, so the walkable prefix is the leaf alone"
        );
        l.open_run("parent", Microusd(1_000_000), None)
            .expect("opens");
        let parent_r = l.reserve("parent", Microusd(800_000)).unwrap();

        l.settle(&child_r, Microusd(100_000));
        let p = l.snapshot("parent").unwrap();
        assert_eq!(
            p.reserved,
            Microusd(800_000),
            "settle may only release what child_r itself reserved on that ancestor: nothing, \
             because parent was not on child_r's admitted chain"
        );
        assert_eq!(p.spent, Microusd::ZERO);
        let c = l.snapshot("child").unwrap();
        assert_eq!(c.reserved, Microusd::ZERO);
        assert_eq!(c.spent, Microusd(100_000));

        let extra = l.reserve("parent", Microusd(800_000));
        match extra {
            Err(BudgetError::Exceeded { run_id, would, .. }) => {
                assert_eq!(run_id, "parent");
                assert_eq!(would, Microusd(1_600_000));
            }
            other => panic!(
                "parent's own reservation is still outstanding, so 800000 more must not fit, got {other:?}"
            ),
        }

        l.settle(&parent_r, Microusd(800_000));
        let p_after = l.snapshot("parent").unwrap();
        assert_eq!(p_after.reserved, Microusd::ZERO);
        assert_eq!(p_after.spent, Microusd(800_000));

        // The tail: child's chain now correctly includes parent, since parent
        // opened before this later reserve.
        let r3 = l.reserve("child", Microusd(100_000)).unwrap();
        assert_eq!(
            r3.chain
                .iter()
                .map(|c| c.run_id.as_str())
                .collect::<Vec<_>>(),
            vec!["child", "parent"]
        );
        assert_eq!(l.snapshot("parent").unwrap().reserved, Microusd(100_000));

        l.settle(&r3, Microusd(100_000));
        assert_eq!(l.snapshot("parent").unwrap().spent, Microusd(900_000));
        assert_eq!(l.snapshot("child").unwrap().spent, Microusd(200_000));
    }

    /// `close_run` keeps a run's counters rather than deleting them, because
    /// a reservation still in flight settles after the run closes and its
    /// ancestors still need the release and the charge (`missed6`, moved
    /// into `tests/fable_missed.rs`). A second settlement of the same
    /// reservation is still a no-op after the run is closed.
    #[test]
    fn a_closed_run_keeps_the_counters_a_late_settlement_needs() {
        let l = Ledger::new();
        l.open_run("p", Microusd(1_000_000), None).expect("opens");
        l.open_run("c", Microusd(1_000_000), Some("p"))
            .expect("opens");
        let r = l.reserve("c", Microusd(100_000)).unwrap();

        let closed_snap = l.close_run("c").unwrap();
        assert_eq!(closed_snap.reserved, Microusd(100_000));
        assert_eq!(closed_snap.spent, Microusd::ZERO);
        assert_eq!(closed_snap.steps, 1);

        let settlement = l.settle(&r, Microusd(50_000));
        assert_eq!(
            settlement,
            Settlement::Applied {
                links: 2,
                dropped: 0
            }
        );
        let c = l.snapshot("c").unwrap();
        assert_eq!(c.reserved, Microusd::ZERO);
        assert_eq!(c.spent, Microusd(50_000));
        assert_eq!(c.steps, 1);
        assert!(l.run_info("c").unwrap().closed);
        let p = l.snapshot("p").unwrap();
        assert_eq!(p.reserved, Microusd::ZERO);
        assert_eq!(p.spent, Microusd(50_000));

        let err = l.reserve("c", Microusd(1)).unwrap_err();
        assert_eq!(
            err,
            BudgetError::RunClosed {
                run_id: "c".to_string()
            }
        );

        let second = l.settle(&r, Microusd(50_000));
        assert_eq!(second, Settlement::NotOutstanding);
        assert_eq!(l.snapshot("c").unwrap().spent, Microusd(50_000));
        assert_eq!(l.snapshot("p").unwrap().spent, Microusd(50_000));
    }

    /// A reopened run starts a fresh generation, and a settlement for a
    /// reservation taken under the OLD generation drops the leaf half of the
    /// settlement (the reopened run's own counters are untouched) while
    /// still applying to any ancestor whose generation did not change.
    #[test]
    fn an_old_settlement_never_touches_a_reopened_runs_counters() {
        let l = Ledger::new();
        l.open_run("p", Microusd(1_000_000), None).expect("opens");
        l.open_run("c", Microusd(1_000_000), Some("p"))
            .expect("opens");
        let r = l.reserve("c", Microusd(100_000)).unwrap();
        l.close_run("c");
        l.open_run("q", Microusd(1_000_000), None).expect("opens");

        let reopened = l
            .open_run("c", Microusd(1_000_000), Some("q"))
            .expect("reopens");
        assert!(reopened.reopened);
        assert_eq!(reopened.parent, Some("q".to_string()));
        assert_ne!(reopened.generation, r.generation);

        let settlement = l.settle(&r, Microusd(60_000));
        assert_eq!(
            settlement,
            Settlement::Applied {
                links: 1,
                dropped: 1
            }
        );

        let p = l.snapshot("p").unwrap();
        assert_eq!(p.reserved, Microusd::ZERO);
        assert_eq!(p.spent, Microusd(60_000));
        let q = l.snapshot("q").unwrap();
        assert_eq!(q.reserved, Microusd::ZERO);
        assert_eq!(q.spent, Microusd::ZERO);
        let c = l.snapshot("c").unwrap();
        assert_eq!(c.reserved, Microusd::ZERO);
        assert_eq!(c.spent, Microusd::ZERO);
        assert_eq!(c.steps, 0);
    }

    /// A second settlement of one reservation is an observable no-op: the
    /// run is charged once, and a sibling reservation on the same run is
    /// never touched by someone else's replay (`codex_f10`, moved into
    /// `tests/codex_money_review.rs`).
    #[test]
    fn a_second_settlement_of_one_reservation_is_an_observable_no_op() {
        let l = Ledger::new();
        l.open_run("r", Microusd(1_000_000), None).expect("opens");
        let first = l.reserve("r", Microusd(400_000)).unwrap();
        let other = l.reserve("r", Microusd(400_000)).unwrap();

        let s1 = l.settle(&first, Microusd(100_000));
        assert_eq!(
            s1,
            Settlement::Applied {
                links: 1,
                dropped: 0
            }
        );
        let after_first = l.snapshot("r").unwrap();
        assert_eq!(after_first.reserved, Microusd(400_000));
        assert_eq!(after_first.spent, Microusd(100_000));

        let replay = l.settle(&first, Microusd(100_000));
        assert_eq!(replay, Settlement::NotOutstanding);
        assert_eq!(
            l.snapshot("r").unwrap(),
            after_first,
            "a replayed settle changes nothing"
        );

        let s2 = l.settle(&other, Microusd(400_000));
        assert_eq!(
            s2,
            Settlement::Applied {
                links: 1,
                dropped: 0
            }
        );
        let final_snap = l.snapshot("r").unwrap();
        assert_eq!(final_snap.reserved, Microusd::ZERO);
        assert_eq!(final_snap.spent, Microusd(500_000));
        assert_eq!(final_snap.steps, 2);
    }

    /// Sixteen children race to reserve through a parent this ledger has not
    /// opened: every racer must be refused (nothing checked against nothing),
    /// and once the parent opens with only enough for five, a second race
    /// grants exactly five and settles exactly what they reserved.
    #[test]
    fn racing_children_with_a_late_parent_are_refused_until_it_opens() {
        use std::sync::{Arc, Barrier};
        use std::thread;

        let l = Arc::new(Ledger::new());
        let ids: Vec<String> = (0..16).map(|i| format!("child{i}")).collect();
        for id in &ids {
            l.open_run(id.clone(), Microusd(1000), Some("late"))
                .expect("opens");
        }

        // Race 1: the parent is not open yet. Nothing may be granted.
        let barrier = Arc::new(Barrier::new(16));
        let mut handles = Vec::new();
        for id in ids.clone() {
            let l = Arc::clone(&l);
            let barrier = Arc::clone(&barrier);
            handles.push(thread::spawn(move || {
                barrier.wait();
                l.reserve(&id, Microusd(3))
            }));
        }
        let race1: Vec<_> = handles.into_iter().map(|h| h.join().unwrap()).collect();
        assert!(
            race1.iter().all(|r| matches!(
                r,
                Err(BudgetError::UnknownParent { parent, .. }) if parent == "late"
            )),
            "every racer must be refused naming the unopened parent, got {race1:?}"
        );
        for id in &ids {
            let snap = l.snapshot(id).unwrap();
            assert_eq!(snap.reserved, Microusd::ZERO);
            assert_eq!(snap.steps, 0);
        }
        assert!(l.snapshot("late").is_none());

        // The parent opens with only enough for 5 of the 16 (17 / 3 = 5).
        l.open_run("late", Microusd(17), None).expect("opens");

        let barrier2 = Arc::new(Barrier::new(16));
        let mut handles2 = Vec::new();
        for id in ids.clone() {
            let l = Arc::clone(&l);
            let barrier2 = Arc::clone(&barrier2);
            handles2.push(thread::spawn(move || {
                barrier2.wait();
                l.reserve(&id, Microusd(3))
            }));
        }
        let race2: Vec<_> = handles2.into_iter().map(|h| h.join().unwrap()).collect();
        let grants: Vec<_> = race2.into_iter().filter_map(|r| r.ok()).collect();
        assert_eq!(grants.len(), 5, "17 / 3 = 5 grants");
        assert_eq!(l.snapshot("late").unwrap().reserved, Microusd(15));
        assert_eq!(l.snapshot("late").unwrap().steps, 0);

        for g in &grants {
            l.settle(g, Microusd(3));
        }
        let late_final = l.snapshot("late").unwrap();
        assert_eq!(late_final.reserved, Microusd::ZERO);
        assert_eq!(late_final.spent, Microusd(15));
        for g in &grants {
            assert_eq!(l.snapshot(&g.run_id).unwrap().spent, Microusd(3));
        }
    }

    /// A walk that reaches the depth cap with a further ancestor still
    /// unwalked refuses rather than truncates, naming the leaf, the last run
    /// walked, and the unchecked one (F01). A control chain one run shorter
    /// walks fully and is admitted, proving the cap is the actual reason.
    #[test]
    fn a_walk_that_reaches_the_depth_cap_refuses_and_names_the_unchecked_ancestor() {
        let l = Ledger::new();
        l.open_run("r0", Microusd(1_000_000), None).expect("opens");
        for i in 1..=64 {
            l.open_run(
                format!("r{i}"),
                Microusd(1_000_000),
                Some(&format!("r{}", i - 1)),
            )
            .expect("opens");
        }
        let err = l.reserve("r64", Microusd(100_000)).unwrap_err();
        assert_eq!(
            err,
            BudgetError::ChainTooDeep {
                run_id: "r64".to_string(),
                at: "r1".to_string(),
                next: "r0".to_string(),
                depth: MAX_CHAIN_DEPTH,
            }
        );
        for i in 0..=64 {
            assert_eq!(
                l.snapshot(&format!("r{i}")).unwrap().reserved,
                Microusd::ZERO
            );
        }

        // Control: 64 runs (r0..=r63) walk fully and are admitted.
        let control = Ledger::new();
        control
            .open_run("r0", Microusd(1_000_000), None)
            .expect("opens");
        for i in 1..=63 {
            control
                .open_run(
                    format!("r{i}"),
                    Microusd(1_000_000),
                    Some(&format!("r{}", i - 1)),
                )
                .expect("opens");
        }
        let r = control
            .reserve("r63", Microusd(100_000))
            .expect("a 64-run chain walks fully");
        assert_eq!(r.chain.len(), 64);
        for i in 0..=63 {
            assert_eq!(
                control.snapshot(&format!("r{i}")).unwrap().reserved,
                Microusd(100_000)
            );
        }
    }

    /// How many reservations a budget may grant, and how many racers ask.
    ///
    /// Everything is in whole microdollars so the arithmetic is exact: this is
    /// money, and a test that decided what "correct" means by way of a float
    /// would be arguing with the type the ledger deliberately uses.
    struct Race {
        what: &'static str,
        budget_micros: i64,
        unit_micros: i64,
        threads: usize,
        expected_grants: usize,
    }

    /// One budget, many racers, and the only number that may come out.
    ///
    /// This used to be a single case: fifty threads against ten dollars at a
    /// dollar a call, expecting ten. That case is real and it is the easy one,
    /// because the budget divides exactly and the answer is a round number that
    /// an off-by-one would still produce half the time. The cases that decide
    /// whether the accounting is right are the ones where it does not divide,
    /// where one unit costs more than the whole budget, and where there are far
    /// more racers than the budget could ever satisfy.
    ///
    /// The rule under test is the same in every row and does not mention
    /// interleaving: **granted is exactly `min(callers, budget / unit)`, and the
    /// reserved total never exceeds the budget.** Concurrency is what makes it
    /// hard to hold, not what defines it. Each thread asks exactly once, so the
    /// `min` matters in both directions: a budget can run out before the crowd
    /// does, and a crowd can run out before the budget does, and refusing
    /// somebody in the second case would be just as wrong as granting an
    /// eleventh call in the first.
    #[test]
    fn concurrent_reservations_grant_exactly_what_the_budget_covers() {
        use std::sync::Arc;
        use std::thread;

        let races = [
            Race {
                what: "the original case: a budget that divides exactly",
                budget_micros: 10_000_000,
                unit_micros: 1_000_000,
                threads: 50,
                expected_grants: 10,
            },
            Race {
                what: "a remainder too small to buy anything, which must not be spent",
                budget_micros: 10_500_000,
                unit_micros: 1_000_000,
                threads: 50,
                expected_grants: 10,
            },
            Race {
                what: "a remainder one microdollar short of another call",
                budget_micros: 10_999_999,
                unit_micros: 1_000_000,
                threads: 64,
                expected_grants: 10,
            },
            Race {
                what: "one call costs more than the whole budget",
                budget_micros: 1_000_000,
                unit_micros: 2_000_000,
                threads: 32,
                expected_grants: 0,
            },
            Race {
                what: "a budget worth exactly one call, with a crowd asking",
                budget_micros: 2_000_000,
                unit_micros: 2_000_000,
                threads: 128,
                expected_grants: 1,
            },
            Race {
                what: "far more racers than the budget can ever satisfy",
                budget_micros: 3,
                unit_micros: 1,
                threads: 200,
                expected_grants: 3,
            },
            Race {
                what: "a single caller asking once, so a failure here is not about racing",
                budget_micros: 5_000_000,
                unit_micros: 1_000_000,
                threads: 1,
                expected_grants: 1,
            },
            Race {
                what: "budget larger than the crowd, so refusing anybody would be the bug",
                budget_micros: 100_000_000,
                unit_micros: 1_000_000,
                threads: 8,
                expected_grants: 8,
            },
            Race {
                what: "many racers and a budget large enough for most of them",
                budget_micros: 100_000_000,
                unit_micros: 1_000_000,
                threads: 128,
                expected_grants: 100,
            },
            Race {
                what: "a unit that divides awkwardly, so every grant carries a remainder",
                budget_micros: 1_000_000,
                unit_micros: 300_000,
                threads: 40,
                expected_grants: 3,
            },
        ];

        for race in races {
            let ledger = Arc::new(Ledger::new());
            ledger
                .open_run("r1", Microusd(race.budget_micros), None)
                .expect("opens");

            let mut handles = Vec::new();
            for _ in 0..race.threads {
                let l = Arc::clone(&ledger);
                handles.push(thread::spawn(move || {
                    l.reserve("r1", Microusd(race.unit_micros)).is_ok()
                }));
            }
            let granted = handles
                .into_iter()
                .map(|h| h.join().expect("no racer panicked"))
                .filter(|&ok| ok)
                .count();

            let snapshot = ledger.snapshot("r1").expect("the run exists");

            assert_eq!(
                granted, race.expected_grants,
                "{}: {} threads against {} micros at {} each",
                race.what, race.threads, race.budget_micros, race.unit_micros
            );
            assert_eq!(
                snapshot.reserved,
                Microusd(race.unit_micros * race.expected_grants as i64),
                "{}: reserved total does not match the grants handed out",
                race.what
            );
            // The property that matters on its own, stated separately so a
            // failure says which half broke.
            assert!(
                snapshot.reserved.0 <= race.budget_micros,
                "{}: reserved {} exceeds the budget {}",
                race.what,
                snapshot.reserved.0,
                race.budget_micros
            );
        }
    }

    /// Reproduces the 2026-09-07 measurement: a run warmed with one ordinary
    /// reservation that is settled, then handed an absurd estimate. Before
    /// the fix, `s.spent + s.reserved + estimate` used `Microusd`'s plain,
    /// wrapping `Add` [now: `exceeds`'s `checked_add` reads the overflow as
    /// exceeded]: an `i64::MAX` estimate against spent=52 wraps
    /// negative, `would > budget` reads false, the absurd reservation is
    /// GRANTED, and it leaves the run's `reserved` counter at `i64::MAX`,
    /// a lasting credit rather than a one-call bypass. Everything reserved
    /// after that point rides on the same wrapped arithmetic, so a request
    /// that plainly does not fit (remaining headroom here is 9948, not
    /// 10000) is also granted, over and over, for as long as the run lives.
    #[test]
    fn an_absurd_estimate_does_not_leave_a_lasting_credit_for_a_later_ordinary_reservation() {
        let ledger = Ledger::new();
        ledger
            .open_run("r1", Microusd(10_000), None)
            .expect("opens");

        let warm = ledger.reserve("r1", Microusd(52)).unwrap();
        ledger.settle(&warm, Microusd(52));
        let warmed = ledger.snapshot("r1").unwrap();
        assert_eq!(
            warmed.spent,
            Microusd(52),
            "warm-up did not settle as expected"
        );
        assert_eq!(warmed.reserved, Microusd::ZERO);

        let absurd = ledger.reserve("r1", Microusd(i64::MAX));
        assert!(
            absurd.is_err(),
            "an i64::MAX estimate against a 10000-micro-usd budget must be refused, got {absurd:?}"
        );

        // Not a lasting credit: a request that plainly exceeds the true
        // remaining headroom (10000 - 52 = 9948) must still be refused after
        // the absurd one was rejected, not granted through a polluted
        // `reserved` counter left over from the rejected attempt.
        let ordinary = ledger.reserve("r1", Microusd(20_000));
        assert!(
            ordinary.is_err(),
            "a 20000 reservation on a 10000 budget with 52 already spent must be refused, got {ordinary:?}"
        );

        // And the ledger's state is genuinely untouched by the refused
        // attempt, not merely refusing by coincidence.
        let after = ledger.snapshot("r1").unwrap();
        assert_eq!(after.spent, Microusd(52));
        assert_eq!(after.reserved, Microusd::ZERO);
    }

    /// Reserving and settling at the same time, which is the shape production
    /// actually has: calls finish while others are still starting.
    ///
    /// A reservation is an estimate and settlement is the truth, so the two
    /// numbers move in opposite directions under contention. What must hold
    /// throughout is that the run never accounts for more than it was given.
    #[test]
    fn settling_while_others_reserve_never_exceeds_the_budget() {
        use std::sync::Arc;
        use std::thread;

        const UNIT: i64 = 1_000_000;
        const BUDGET: i64 = 40_000_000;

        let ledger = Arc::new(Ledger::new());
        ledger
            .open_run("r1", Microusd(BUDGET), None)
            .expect("opens");

        let mut handles = Vec::new();
        for i in 0..64 {
            let l = Arc::clone(&ledger);
            handles.push(thread::spawn(move || {
                if let Ok(reservation) = l.reserve("r1", Microusd(UNIT)) {
                    // Half the calls come in under their estimate, which is the
                    // ordinary case and the one that frees budget back up.
                    let actual = if i % 2 == 0 { UNIT / 2 } else { UNIT };
                    l.settle(&reservation, Microusd(actual));
                    true
                } else {
                    false
                }
            }));
        }
        for h in handles {
            h.join().expect("no racer panicked");
        }

        let snapshot = ledger.snapshot("r1").expect("the run exists");
        assert!(
            snapshot.spent.0 <= BUDGET,
            "spent {} exceeds the budget {}",
            snapshot.spent.0,
            BUDGET
        );
        assert!(
            snapshot.reserved.0 + snapshot.spent.0 <= BUDGET,
            "reserved {} plus spent {} exceeds the budget {}",
            snapshot.reserved.0,
            snapshot.spent.0,
            BUDGET
        );
    }
}
