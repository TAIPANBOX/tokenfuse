//! Raft type configuration and the replicated budget-ledger domain.
//!
//! The state machine *is* a budget ledger: `Reserve` and `Settle` are applied
//! as raft log entries, so the affordability check is linearized across every
//! node. A leader can never oversubscribe a budget even if two sub-agents race
//! against different nodes — the check happens once, in log order, on the
//! committed state machine.

use std::collections::BTreeMap;
use std::io::Cursor;

use openraft::BasicNode;
use serde::{Deserialize, Serialize};

/// Cluster node identity.
pub type NodeId = u64;

openraft::declare_raft_types!(
    /// TokenFuse's raft types: budget ops in, an accept/deny response out.
    pub TypeConfig:
        D = Request,
        R = Response,
        NodeId = NodeId,
        Node = BasicNode,
        Entry = openraft::Entry<TypeConfig>,
        SnapshotData = Cursor<Vec<u8>>,
        AsyncRuntime = openraft::TokioRuntime,
);

/// A write against the replicated ledger. Amounts are integer **microdollars**
/// (µUSD), matching `tokenfuse-core::Money` — no floats in the consensus path.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub enum Request {
    /// Create (or reset) a run with a hard budget ceiling.
    Open { run: String, budget_micros: u64 },
    /// Reserve headroom before a call. Accepted only if it still fits.
    Reserve { run: String, micros: u64 },
    /// Settle a prior reservation with the actual spend.
    Settle {
        run: String,
        reserved_micros: u64,
        actual_micros: u64,
    },
}

/// The result of applying a [`Request`] to the committed state machine.
#[derive(Clone, Debug, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct Response {
    /// Whether the operation was accepted (a `Reserve` that fit the budget).
    pub accepted: bool,
    /// Committed spend after applying (settled dollars only).
    pub spent_micros: u64,
    /// Currently outstanding reservations.
    pub reserved_micros: u64,
    /// The run's hard ceiling.
    pub budget_micros: u64,
    /// Human-readable reason when `accepted == false`.
    pub reason: String,
}

/// Per-run accounting held in the replicated state machine.
#[derive(Clone, Debug, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct RunState {
    pub budget_micros: u64,
    pub reserved_micros: u64,
    pub spent_micros: u64,
}

impl RunState {
    /// Total committed against the budget: settled spend plus live reservations.
    pub fn committed(&self) -> u64 {
        self.spent_micros.saturating_add(self.reserved_micros)
    }
}

/// The full replicated state: the ledger plus raft bookkeeping needed for
/// snapshots (last applied log id and the active membership).
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct LedgerState {
    pub runs: BTreeMap<String, RunState>,
}

impl LedgerState {
    /// Apply one request in log order, returning the response for that entry.
    /// This is the single point where a budget is enforced across the cluster.
    pub fn apply(&mut self, req: &Request) -> Response {
        match req {
            Request::Open { run, budget_micros } => {
                let e = self.runs.entry(run.clone()).or_default();
                e.budget_micros = *budget_micros;
                Response {
                    accepted: true,
                    spent_micros: e.spent_micros,
                    reserved_micros: e.reserved_micros,
                    budget_micros: e.budget_micros,
                    reason: String::new(),
                }
            }
            Request::Reserve { run, micros } => {
                let e = self.runs.entry(run.clone()).or_default();
                let would = e.committed().saturating_add(*micros);
                if would <= e.budget_micros {
                    e.reserved_micros = e.reserved_micros.saturating_add(*micros);
                    Response {
                        accepted: true,
                        spent_micros: e.spent_micros,
                        reserved_micros: e.reserved_micros,
                        budget_micros: e.budget_micros,
                        reason: String::new(),
                    }
                } else {
                    Response {
                        accepted: false,
                        spent_micros: e.spent_micros,
                        reserved_micros: e.reserved_micros,
                        budget_micros: e.budget_micros,
                        reason: format!(
                            "budget_exceeded: need {would} µUSD > budget {} µUSD",
                            e.budget_micros
                        ),
                    }
                }
            }
            Request::Settle {
                run,
                reserved_micros,
                actual_micros,
            } => {
                let e = self.runs.entry(run.clone()).or_default();
                e.reserved_micros = e.reserved_micros.saturating_sub(*reserved_micros);
                e.spent_micros = e.spent_micros.saturating_add(*actual_micros);
                Response {
                    accepted: true,
                    spent_micros: e.spent_micros,
                    reserved_micros: e.reserved_micros,
                    budget_micros: e.budget_micros,
                    reason: String::new(),
                }
            }
        }
    }
}
