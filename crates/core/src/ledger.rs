//! The reserve → settle ledger (ADR-2).
//!
//! Before a call we atomically *reserve* its estimated cost against a run's
//! budget; after the response we *settle* the reservation with the real cost.
//! Reserve-then-settle is the only correct approach under concurrency: when an
//! agent fans out sub-agents, several calls race for the same budget, and a
//! naive "check spent, then add" would let them all pass the check at once.
//!
//! This in-process implementation guards the whole map with a `Mutex`, which
//! makes each reserve an atomic check-and-add. The fleet/HA backends (Redis,
//! then embedded raft) implement the same contract behind the same API.

use crate::money::Microusd;
use std::collections::HashMap;
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
}

/// A successful reservation. Hand it back to [`Ledger::settle`] with the real
/// cost once the call completes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Reservation {
    pub run_id: String,
    pub amount: Microusd,
    /// 1-based step index this reservation represents.
    pub step: u32,
}

#[derive(Debug, Clone)]
struct RunState {
    budget: Microusd,
    reserved: Microusd,
    spent: Microusd,
    steps: u32,
    /// Parent run this one rolls up into (hierarchical sub-agent budgets).
    parent: Option<String>,
}

/// Max ancestor depth walked when rolling reservations up a run tree — a guard
/// against accidental cycles or pathological nesting.
const MAX_CHAIN_DEPTH: usize = 64;

/// In-process reserve/settle ledger. Cheap to clone via `Arc` at the call site.
#[derive(Default)]
pub struct Ledger {
    runs: Mutex<HashMap<String, RunState>>,
}

impl Ledger {
    pub fn new() -> Self {
        Ledger::default()
    }

    /// Register a run with its budget and optional parent. Idempotent for the
    /// budget; existing counters (and the parent, once set) are preserved so
    /// re-declaring a run mid-flight is safe.
    pub fn open_run(&self, run_id: impl Into<String>, budget: Microusd, parent: Option<&str>) {
        let mut runs = self.runs.lock().unwrap();
        runs.entry(run_id.into())
            .and_modify(|s| s.budget = budget)
            .or_insert(RunState {
                budget,
                reserved: Microusd::ZERO,
                spent: Microusd::ZERO,
                steps: 0,
                parent: parent.map(|p| p.to_string()),
            });
    }

    /// The chain of run ids from `run_id` up through its ancestors (leaf first).
    /// Missing ancestors and cycles terminate the walk. Assumes the lock is held.
    fn chain(runs: &HashMap<String, RunState>, run_id: &str) -> Vec<String> {
        let mut ids = Vec::new();
        let mut cur = Some(run_id.to_string());
        while let Some(id) = cur {
            if ids.contains(&id) || ids.len() >= MAX_CHAIN_DEPTH {
                break;
            }
            match runs.get(&id) {
                Some(s) => {
                    let parent = s.parent.clone();
                    ids.push(id);
                    cur = parent;
                }
                None => break,
            }
        }
        ids
    }

    pub fn snapshot(&self, run_id: &str) -> Option<RunSnapshot> {
        let runs = self.runs.lock().unwrap();
        runs.get(run_id).map(|s| RunSnapshot {
            budget: s.budget,
            reserved: s.reserved,
            spent: s.spent,
            steps: s.steps,
        })
    }

    /// Atomically reserve `estimate` against the run's budget *and every
    /// ancestor's* budget — so a sub-agent's spend rolls up into its parent's
    /// cap. Fails (reserving nothing) if any level would be exceeded.
    /// Increments the leaf run's step counter on success.
    pub fn reserve(&self, run_id: &str, estimate: Microusd) -> Result<Reservation, BudgetError> {
        let mut runs = self.runs.lock().unwrap();
        if !runs.contains_key(run_id) {
            return Err(BudgetError::UnknownRun {
                run_id: run_id.to_string(),
            });
        }
        let ids = Self::chain(&runs, run_id);

        // Check every level first (all-or-nothing).
        for id in &ids {
            let s = &runs[id];
            let would = s.spent + s.reserved + estimate;
            if would > s.budget {
                return Err(BudgetError::Exceeded {
                    run_id: id.clone(),
                    budget: s.budget,
                    spent: s.spent,
                    would,
                });
            }
        }

        // Apply to every level; steps increments on the leaf only.
        for id in &ids {
            let s = runs.get_mut(id).expect("in chain");
            s.reserved = s.reserved + estimate;
        }
        let leaf = runs.get_mut(run_id).expect("leaf");
        leaf.steps += 1;
        Ok(Reservation {
            run_id: run_id.to_string(),
            amount: estimate,
            step: leaf.steps,
        })
    }

    /// Reserve without a budget check across the whole chain. Used in
    /// shadow/warn modes, where a breach must be *recorded* (so spend and steps
    /// stay accurate) but must not block. Opens the run at zero budget if absent.
    pub fn reserve_unchecked(&self, run_id: &str, estimate: Microusd) -> Reservation {
        let mut runs = self.runs.lock().unwrap();
        runs.entry(run_id.to_string()).or_insert(RunState {
            budget: Microusd::ZERO,
            reserved: Microusd::ZERO,
            spent: Microusd::ZERO,
            steps: 0,
            parent: None,
        });
        let ids = Self::chain(&runs, run_id);
        for id in &ids {
            let s = runs.get_mut(id).expect("in chain");
            s.reserved = s.reserved + estimate;
        }
        let leaf = runs.get_mut(run_id).expect("leaf");
        leaf.steps += 1;
        Reservation {
            run_id: run_id.to_string(),
            amount: estimate,
            step: leaf.steps,
        }
    }

    /// Settle a reservation with the real cost: release the reserved estimate
    /// and add the actual spend, at the leaf *and every ancestor*. Over- or
    /// under-estimates self-correct here.
    pub fn settle(&self, reservation: &Reservation, actual: Microusd) {
        let mut runs = self.runs.lock().unwrap();
        let ids = Self::chain(&runs, &reservation.run_id);
        for id in &ids {
            if let Some(s) = runs.get_mut(id) {
                s.reserved = s.reserved.saturating_sub(reservation.amount);
                s.spent = s.spent + actual;
            }
        }
    }

    /// Snapshot every known run (for observability / the `runs` endpoint).
    pub fn list_runs(&self) -> Vec<(String, RunSnapshot)> {
        let runs = self.runs.lock().unwrap();
        runs.iter()
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

    /// Remove a run and return its final snapshot.
    pub fn close_run(&self, run_id: &str) -> Option<RunSnapshot> {
        let mut runs = self.runs.lock().unwrap();
        runs.remove(run_id).map(|s| RunSnapshot {
            budget: s.budget,
            reserved: s.reserved,
            spent: s.spent,
            steps: s.steps,
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
        ledger.open_run("r1", usd(5.0), None);

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
        ledger.open_run("r1", usd(1.0), None);
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
    fn reserve_unchecked_records_past_budget_without_error() {
        let ledger = Ledger::new();
        ledger.open_run("r1", usd(1.0), None);
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
        ledger.open_run("parent", usd(10.0), None);
        ledger.open_run("child", usd(8.0), Some("parent"));

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
        ledger.open_run("parent", usd(4.0), None);
        ledger.open_run("child", usd(100.0), Some("parent"));

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
            ledger.open_run("r1", Microusd(race.budget_micros), None);

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
        ledger.open_run("r1", Microusd(BUDGET), None);

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
