//! `GET /v1/agent-ids`: which producers are sending an `agent_id` the envelope
//! rejects, so somebody can go and fix them.
//!
//! # WHY THIS ENDPOINT EXISTS
//!
//! The gateway has counted non-conforming ids since it started emitting events.
//! Nothing outside a test ever read that count, and even read it would not have
//! helped: "418 events had a bad agent_id" says a problem exists and nothing
//! about where.
//!
//! The cost is not theoretical. The `aws-comparable-176` benchmark campaign
//! emitted all twelve of its events with `agent_id: "aws-comparable-agent"`, no
//! `agent://` prefix, and a console ingesting them quarantines every one. The
//! agent then looks idle rather than broken, and every count about it is
//! correct and describes nothing that happened. That was found on 2026-07-16
//! and was still true here on 2026-08-11.
//!
//! So this names the ids. An id names the producer that sent it, which is the
//! smallest thing that makes the fault actionable.
//!
//! # WHY IT REPORTS RATHER THAN REFUSES, BY DEFAULT
//!
//! The emission path is fail-open on purpose (SPEC.md §3): an id the envelope
//! rejects is still a real event about a real agent, and refusing to record it
//! would empty the log for exactly the operator who needs to see the fault.
//!
//! [`AgentIdMode::Enforce`] exists for an operator who has read this report,
//! fixed their producers, and wants the door shut behind them. It is off by
//! default, and turning it on without reading this first would refuse live
//! traffic for a header nobody had looked at yet. That is the same migration
//! shape `identitymap::StrictMode` uses, for the same reason.

use axum::{extract::State, Json};
use serde::Serialize;

use crate::state::AppState;

/// What the gateway does about an `agent_id` the envelope would reject.
///
/// Mirrors [`crate::identitymap::StrictMode`] deliberately: an operator who has
/// migrated one of these has migrated both, and a second vocabulary for the
/// same three-step rollout would be a second thing to learn for no reason.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum AgentIdMode {
    /// Record it and count it. The historical behaviour, and the default.
    #[default]
    Off,
    /// Record it, count it, and log a warning naming the id.
    Warn,
    /// Refuse the request with 400 before it reaches a provider.
    Enforce,
}

impl std::str::FromStr for AgentIdMode {
    type Err = String;

    /// Case-insensitive `off`/`warn`/`enforce`. A mistyped mode is an error
    /// rather than a guess, matching `StrictMode`: the caller decides what an
    /// unrecognized value means at startup, and this will not silently pick the
    /// permissive one.
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.trim().to_lowercase().as_str() {
            "off" => Ok(AgentIdMode::Off),
            "warn" => Ok(AgentIdMode::Warn),
            "enforce" => Ok(AgentIdMode::Enforce),
            other => Err(format!(
                "unknown agent-id mode {other:?} (expected off, warn or enforce)"
            )),
        }
    }
}

impl AgentIdMode {
    pub fn as_str(self) -> &'static str {
        match self {
            AgentIdMode::Off => "off",
            AgentIdMode::Warn => "warn",
            AgentIdMode::Enforce => "enforce",
        }
    }
}

/// Which producers are sending ids the envelope rejects.
#[derive(Debug, Serialize)]
pub struct AgentIdReport {
    pub mode: &'static str,
    /// Events emitted with a non-conforming id since this process started.
    pub nonconforming_events: u64,
    /// The distinct ids, capped by
    /// [`tokenfuse_core::agent_event::NONCONFORMING_SAMPLE_CAP`]. The COUNT
    /// above stays exact whatever this drops.
    pub nonconforming_ids: Vec<String>,
    /// The grammar an id has to match, so the fix does not need a doc lookup.
    pub expected: &'static str,
    /// One sentence naming what is wrong and what it costs, so an operator
    /// reading a failed check does not reconstruct it from numbers. The same
    /// contract `policyplane::PolicyPlaneReport::detail` keeps.
    pub detail: String,
}

pub const EXPECTED_GRAMMAR: &str = "agent://<trust-domain>/<name>, lowercase";

pub async fn agent_ids(State(st): State<AppState>) -> Json<AgentIdReport> {
    let n = st.events.nonconforming_agent_id_count();
    let ids = st.events.nonconforming_agent_ids();
    let mode = st.agent_id_mode;

    let detail = if n == 0 {
        "Every agent_id this gateway has emitted matches the envelope grammar. A producer that starts sending a bare name will appear here, and its events would otherwise be quarantined by any consumer that validates them.".to_string()
    } else {
        format!(
            "{n} event(s) were emitted with an agent_id the envelope rejects, from {} distinct id(s). A consumer that validates the envelope quarantines every one, so those agents look idle rather than broken and every count about them is correct and describes nothing. Fix the producer to send {EXPECTED_GRAMMAR}; set TOKENFUSE_AGENT_ID_MODE=enforce once it does.",
            ids.len()
        )
    };

    Json(AgentIdReport {
        mode: mode.as_str(),
        nonconforming_events: n,
        nonconforming_ids: ids,
        expected: EXPECTED_GRAMMAR,
        detail,
    })
}
