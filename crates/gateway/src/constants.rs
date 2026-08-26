//! The constants this repository publishes to the rest of the stack, as one
//! versioned, machine-readable file: `contracts/tokenfuse-constants.json`.
//!
//! ## Why a file exists at all
//!
//! Other repositories in the estate consume TokenFuse's wire vocabulary, and
//! every one of them has consumed it BY VALUE: somebody read the Rust, retyped
//! the strings in their own language, and the two copies agreed for exactly as
//! long as nobody added a case. That is not a hypothesis about how the estate
//! works. Reported 2026-08-06: verdryx's blocked-decision mirror carried seven
//! wire strings while [`BreakerReason`] had had nine since 2026-07-23, so for
//! eleven days avoided estimates were counted as real spend. This repository
//! cannot check that claim and does not try to; what it can do is stop being
//! the reason the next copy is wrong.
//!
//! The copy was not wrong when it was written. Nothing was watching it. That is
//! the same shape as invariant 12 (a number a document states about itself) one
//! level up: a value with no owner and no clock, correct on the day and drifting
//! from the next commit that never opens the consumer's file.
//!
//! ## Generated, never hand-maintained
//!
//! Every value below is read from the live Rust definition at generation time.
//! Nothing here is retyped, including in this module: the breaker strings come
//! from [`BreakerReason::as_wire_str`], the blocked-decision set from
//! [`tokenfuse_core::outcomes::is_blocked_decision`], the severities from
//! [`EventType::severity`], the columns from [`ParquetSink`]'s own two schemas,
//! and the prices from [`crate::pricebook::default_price_book`]. A hand-written
//! constants file is the original defect one level up: a file that can disagree
//! with the constants it names.
//!
//! The committed file is a projection, and `scripts/constants.sh` fails when
//! the projection and the source disagree. So there is one source of truth (the
//! Rust) and one published form (the JSON), and the second cannot drift from
//! the first without CI saying so in the commit that did it.
//!
//! ## What a consumer does with it
//!
//! Reads `contracts/tokenfuse-constants.json` out of a checkout pinned to a tag,
//! or over raw HTTP at that same tag. `schema_version` is the compatibility
//! signal: a consumer that pins a version and finds a higher one has been told
//! to look, which is the whole thing a retyped copy could never do. The path
//! deliberately carries NO version, because a versioned filename is how a
//! consumer keeps reading the old file forever after a bump without ever
//! noticing there was one.
//!
//! ## What is deliberately NOT here
//!
//! The stack's fixed local port map. This repository is not its owner: it owns
//! only its own defaults (`TOKENFUSE_ADDR`, `TOKENFUSE_MCP_ADDR`), while the
//! port ASSIGNMENTS that make services agree with each other are decided by the
//! local orchestrators, `taipan` and `stack-up`, which is also where the
//! collisions get resolved (idryx moved off `:8080` because Cloud was there).
//! Publishing a copy of somebody else's map from here would recreate this
//! module's own defect with the arrow pointing the other way.

use datafusion::arrow::datatypes::Schema;
use serde_json::json;
use tokenfuse_core::agent_event::{EventType, SCHEMA as AGENT_EVENT_SCHEMA, SOURCE};
use tokenfuse_core::breaker::BreakerReason;
use tokenfuse_core::outcomes::is_blocked_decision;

use crate::pricebook::default_price_book;
use crate::sink::ParquetSink;

/// The artifact's own schema id, in the estate's existing form (compare
/// `taipanbox.dev/agent-event/v0.1`). Bump [`SCHEMA_VERSION`] with it.
pub const SCHEMA: &str = "taipanbox.dev/tokenfuse-constants/v1";

/// The integer a consumer compares against. Additive changes (a new section, a
/// new entry inside one) keep this number; removing or renaming anything
/// already published raises it.
pub const SCHEMA_VERSION: u32 = 1;

/// Where the generated artifact is committed, relative to the repository root.
/// Named here rather than only in the script so the test below and the failure
/// messages cannot disagree about which file is meant.
pub const ARTIFACT_PATH: &str = "contracts/tokenfuse-constants.json";

/// Every [`BreakerReason`] there is. An exhaustive `match` in
/// [`breaker_reasons`] fails to compile when a variant is added, which is what
/// makes this list unable to go stale the way a consumer's copy did: the
/// compiler refuses the commit that would have published eight of nine.
const ALL_BREAKER_REASONS: [BreakerReason; 9] = [
    BreakerReason::BudgetExceeded,
    BreakerReason::PolicyViolation,
    BreakerReason::LoopDetected,
    BreakerReason::Killed,
    BreakerReason::WasmPolicy,
    BreakerReason::TaintBlocked,
    BreakerReason::DlpBlocked,
    BreakerReason::UnitBudgetExceeded,
    BreakerReason::IdentityMismatch,
];

/// Every [`EventType`] this repository can emit, same discipline as
/// [`ALL_BREAKER_REASONS`]: [`exhaustiveness_guard`] fails to compile when a
/// variant is added.
const ALL_EVENT_TYPES: [EventType; 17] = [
    EventType::BudgetExhausted,
    EventType::SustainedLoop,
    EventType::SpendSpike,
    EventType::FanoutExplosion,
    EventType::BudgetThreshold,
    EventType::RunKilled,
    EventType::BreakerTripped,
    EventType::DlpBlock,
    EventType::TaintBlock,
    EventType::McpDrift,
    EventType::IdentityMismatch,
    EventType::UnitCapExceeded,
    EventType::PolicyDeny,
    EventType::ToolCall,
    EventType::DependencyFailed,
    EventType::TaintShadow,
    EventType::TaintRaised,
];

/// The half of the two lists above that the compiler holds.
///
/// A hand-written array of variants has exactly the failure this whole module
/// exists to prevent: somebody adds a tenth reason and the array keeps naming
/// nine, silently. These two matches make that a compile error, because a new
/// variant is not covered and there is no wildcard arm to absorb it. The
/// function is never called; its existence is the check.
///
/// It cannot be `#[cfg(test)]`: a compile error that only appears under
/// `cargo test` is one a `cargo build` can ship past.
#[allow(dead_code)]
fn exhaustiveness_guard(reason: BreakerReason, event: EventType) -> (usize, usize) {
    let r = match reason {
        BreakerReason::BudgetExceeded => 0,
        BreakerReason::PolicyViolation => 1,
        BreakerReason::LoopDetected => 2,
        BreakerReason::Killed => 3,
        BreakerReason::WasmPolicy => 4,
        BreakerReason::TaintBlocked => 5,
        BreakerReason::DlpBlocked => 6,
        BreakerReason::UnitBudgetExceeded => 7,
        BreakerReason::IdentityMismatch => 8,
    };
    let e = match event {
        EventType::BudgetExhausted => 0,
        EventType::SustainedLoop => 1,
        EventType::SpendSpike => 2,
        EventType::FanoutExplosion => 3,
        EventType::BudgetThreshold => 4,
        EventType::RunKilled => 5,
        EventType::BreakerTripped => 6,
        EventType::DlpBlock => 7,
        EventType::TaintBlock => 8,
        EventType::McpDrift => 9,
        EventType::IdentityMismatch => 10,
        EventType::UnitCapExceeded => 11,
        EventType::PolicyDeny => 12,
        EventType::ToolCall => 13,
        EventType::DependencyFailed => 14,
        EventType::TaintShadow => 15,
        EventType::TaintRaised => 16,
    };
    (r, e)
}

/// One entry per Breaker reason: the `error.type` string on the wire, the HTTP
/// status that carries it, and whether a trace row with that `decision` is a
/// block (so its `cost_microusd` is an AVOIDED estimate, never settled spend).
fn breaker_reasons() -> serde_json::Value {
    json!(ALL_BREAKER_REASONS
        .iter()
        .map(|r| json!({
            "wire": r.as_wire_str(),
            "http_status": r.http_status(),
            "blocked_decision": is_blocked_decision(r.as_wire_str()),
        }))
        .collect::<Vec<_>>())
}

/// The flat list a consumer needs to answer "is this trace row a block": the
/// exact set verdryx mirrors. Filtered through the real predicate rather than
/// written out again, so it cannot say something the predicate does not.
fn blocked_decisions() -> serde_json::Value {
    json!(ALL_BREAKER_REASONS
        .into_iter()
        .map(|r| r.as_wire_str())
        .filter(|d| is_blocked_decision(d))
        .collect::<Vec<_>>())
}

/// The agent-event envelope's fixed vocabulary: every `type` this repository
/// emits with the severity that type always carries. Severity is not
/// caller-supplied here (see [`EventType::severity`]), so a consumer can rely
/// on the pairing rather than reading it off each event.
fn agent_events() -> serde_json::Value {
    json!({
        "schema": AGENT_EVENT_SCHEMA,
        "source": SOURCE,
        "types": ALL_EVENT_TYPES
            .iter()
            .map(|t| json!({ "type": t.as_wire_str(), "severity": t.severity() }))
            .collect::<Vec<_>>(),
    })
}

/// Column name, Arrow type and nullability, in the schema's own order.
fn columns(schema: &Schema) -> serde_json::Value {
    json!(schema
        .fields()
        .iter()
        .map(|f| json!({
            "name": f.name(),
            "type": format!("{:?}", f.data_type()),
            "nullable": f.is_nullable(),
        }))
        .collect::<Vec<_>>())
}

/// Both Parquet schemas, because the difference between them IS the contract
/// (invariant 6): a column appended to the trace is non-nullable in what this
/// gateway writes and nullable in what any reader must accept, so files written
/// before the column existed still read. A consumer given only one of the two
/// would build a reader that rejects the estate's own older segments.
fn trace_parquet() -> serde_json::Value {
    json!({
        "write_schema": columns(&ParquetSink::schema()),
        "read_schema": columns(&ParquetSink::read_schema()),
    })
}

/// The price book `tokenfuse serve` uses when no external feed is wired in,
/// in microdollars per million tokens (the integer the code actually holds; a
/// float would round differently in each consumer's language).
fn price_book() -> serde_json::Value {
    let book = default_price_book();
    let entry = |p: tokenfuse_core::ModelPrice| {
        json!({
            "input_per_mtok_microusd": p.input_per_mtok.0,
            "output_per_mtok_microusd": p.output_per_mtok.0,
            "cache_read_per_mtok_microusd": p.cache_read_per_mtok.0,
            "cache_write_per_mtok_microusd": p.cache_write_per_mtok.0,
        })
    };
    json!({
        "units": "microusd_per_mtok",
        "models": book
            .entries()
            .into_iter()
            .map(|(model, p)| {
                let mut row = entry(p);
                row["model"] = json!(model);
                row
            })
            .collect::<Vec<_>>(),
        // ADR-8: an unrecognised model prices at (a margin above) the most
        // expensive known one, so it can never under-reserve.
        "fallback": book.fallback().map(entry),
    })
}

/// The whole published document.
pub fn document() -> serde_json::Value {
    json!({
        "schema": SCHEMA,
        "schema_version": SCHEMA_VERSION,
        "source_repo": "TAIPANBOX/tokenfuse",
        "generated_by": "tokenfuse constants (crates/gateway/src/constants.rs)",
        "regenerate_with": "./scripts/constants.sh --write",
        "breaker_reasons": breaker_reasons(),
        "blocked_decisions": blocked_decisions(),
        "agent_events": agent_events(),
        "trace_parquet": trace_parquet(),
        "price_book": price_book(),
    })
}

/// The exact bytes of the committed artifact: pretty-printed with the trailing
/// newline every other text file in this repository ends with, so `diff` and
/// every editor agree the file is complete.
pub fn render() -> String {
    let mut s = serde_json::to_string_pretty(&document()).expect("constants document serialises");
    s.push('\n');
    s
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The fast half of the gate. `scripts/constants.sh` is the CI check and
    /// the regeneration entry point; this is the same comparison inside
    /// `cargo test --all`, so drift is caught in the loop a contributor
    /// actually runs rather than only after a push.
    #[test]
    fn the_published_artifact_matches_the_rust_source() {
        let path = concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../",
            "contracts/tokenfuse-constants.json"
        );
        let committed = std::fs::read_to_string(path).unwrap_or_else(|e| {
            panic!("{ARTIFACT_PATH} could not be read ({e}); regenerate with ./scripts/constants.sh --write")
        });
        assert_eq!(
            committed,
            render(),
            "{ARTIFACT_PATH} disagrees with the Rust it is generated from. \
             Regenerate it with ./scripts/constants.sh --write and commit the \
             result in the same commit as the change that moved it."
        );
    }

    /// The artifact is only worth anything if it carries the case that was
    /// missed downstream, so the expectation is WRITTEN OUT here rather than
    /// read off [`ALL_BREAKER_REASONS`], which is what the artifact is
    /// generated from.
    ///
    /// That distinction was not academic. The first version of this test took
    /// its count from that array, and on 2026-08-06 a mutation removing a
    /// variant from it passed: a test whose expectation comes from the thing
    /// under test cannot fail. This list is the independent witness. Adding a
    /// tenth reason fails here, which is the point: somebody then adds it in
    /// both places and regenerates.
    #[test]
    fn every_breaker_reason_reaches_the_artifact() {
        let doc = document();
        let published: Vec<&str> = doc["breaker_reasons"]
            .as_array()
            .unwrap()
            .iter()
            .map(|r| r["wire"].as_str().unwrap())
            .collect();
        assert_eq!(
            published,
            [
                "budget_exceeded",
                "policy_violation",
                "loop_detected",
                "killed",
                "wasm_policy",
                "taint_blocked",
                "dlp_blocked",
                // The two verdryx's mirror was short of.
                "unit_budget_exceeded",
                "identity_mismatch",
            ],
            "the artifact does not publish the Breaker reasons this repository \
             has. If a reason was added, add it to ALL_BREAKER_REASONS and to \
             this list, and regenerate with ./scripts/constants.sh --write."
        );
    }

    /// The flat list is the predicate's own answer, not a second opinion.
    #[test]
    fn the_blocked_decision_list_is_the_predicate_not_a_copy() {
        let doc = document();
        let published: Vec<&str> = doc["blocked_decisions"]
            .as_array()
            .unwrap()
            .iter()
            .map(|d| d.as_str().unwrap())
            .collect();
        for reason in ALL_BREAKER_REASONS {
            let wire = reason.as_wire_str();
            assert_eq!(
                published.contains(&wire),
                is_blocked_decision(wire),
                "{wire}: the artifact and is_blocked_decision disagree"
            );
        }
        assert!(!published.contains(&"allow"));
        assert!(!published.contains(&"cache_hit"));
    }

    /// This repository has the same mirror inside it that the estate has
    /// between its repositories: `core::outcomes` and `gateway::focusexport`
    /// each hold their own array of the reasons that count as a block. Both
    /// read the wire strings off `BreakerReason`, so neither can hold a wrong
    /// STRING; both can hold a wrong SET, which is precisely the fault that was
    /// found downstream. Nothing else compares them.
    #[test]
    fn the_two_in_repo_blocked_decision_lists_agree() {
        for reason in ALL_BREAKER_REASONS {
            let wire = reason.as_wire_str();
            assert_eq!(
                is_blocked_decision(wire),
                crate::focusexport::is_blocked_decision(wire),
                "{wire}: core::outcomes and gateway::focusexport disagree about \
                 whether this decision is a block"
            );
        }
    }

    /// Severity is fixed per type, and a consumer is being invited to rely on
    /// that pairing rather than reading it off each event. Written out for the
    /// same reason as the reasons above: the first version counted
    /// [`ALL_EVENT_TYPES`] against itself and passed while a variant was
    /// deleted from it.
    #[test]
    fn every_event_type_reaches_the_artifact_with_its_own_severity() {
        let doc = document();
        let published: Vec<(&str, &str)> = doc["agent_events"]["types"]
            .as_array()
            .unwrap()
            .iter()
            .map(|r| (r["type"].as_str().unwrap(), r["severity"].as_str().unwrap()))
            .collect();
        assert_eq!(
            published,
            [
                ("budget_exhausted", "critical"),
                ("sustained_loop", "high"),
                ("spend_spike", "high"),
                ("fanout_explosion", "high"),
                ("budget_threshold", "medium"),
                ("run_killed", "high"),
                ("breaker_tripped", "medium"),
                ("dlp_block", "high"),
                ("taint_block", "high"),
                ("mcp_drift", "critical"),
                ("identity_mismatch", "high"),
                ("unit_cap_exceeded", "high"),
                ("policy_deny", "high"),
                ("tool_call", "low"),
                ("dependency_failed", "high"),
                ("taint_shadow", "medium"),
                ("taint_raised", "low"),
            ],
            "the artifact does not publish the agent-event vocabulary this \
             repository emits. If a type was added or a severity moved, update \
             ALL_EVENT_TYPES and this list, and regenerate with \
             ./scripts/constants.sh --write."
        );
    }

    /// Both schemas, and the difference between them, which is the part a
    /// consumer cannot infer: appended columns are non-nullable in the write
    /// schema and nullable in the read schema (invariant 6).
    #[test]
    fn both_parquet_schemas_are_published_and_differ_where_they_must() {
        let doc = document();
        let write = doc["trace_parquet"]["write_schema"].as_array().unwrap();
        let read = doc["trace_parquet"]["read_schema"].as_array().unwrap();
        assert_eq!(write.len(), read.len());
        let names: Vec<&str> = write.iter().map(|c| c["name"].as_str().unwrap()).collect();
        for expected in [
            "ts_millis",
            "run_id",
            "decision",
            "key_id",
            "unit",
            "tool_calls",
        ] {
            assert!(names.contains(&expected), "{expected} column is missing");
        }
        let write_unit = write.iter().find(|c| c["name"] == "unit").unwrap();
        let read_unit = read.iter().find(|c| c["name"] == "unit").unwrap();
        assert_eq!(write_unit["nullable"], serde_json::json!(false));
        assert_eq!(read_unit["nullable"], serde_json::json!(true));
    }

    /// A units error here is the one this repository has always been most
    /// afraid of: a 1e6 slip turns a milli-dollar estimate into a
    /// multi-thousand-dollar one, and now it would do so in every consumer at
    /// once.
    #[test]
    fn prices_are_published_as_the_integers_the_code_holds() {
        let doc = document();
        let models = doc["price_book"]["models"].as_array().unwrap();
        let haiku = models
            .iter()
            .find(|m| m["model"] == "claude-haiku-4-5")
            .expect("claude-haiku-4-5 is in the default book");
        // $1.00 per Mtok in, $5.00 out.
        assert_eq!(haiku["input_per_mtok_microusd"], 1_000_000);
        assert_eq!(haiku["output_per_mtok_microusd"], 5_000_000);
        assert_eq!(
            doc["price_book"]["fallback"]["output_per_mtok_microusd"],
            75_000_000
        );
        assert_eq!(doc["price_book"]["units"], "microusd_per_mtok");
    }

    /// Rendering is deterministic, or the gate is a coin toss.
    #[test]
    fn rendering_is_stable_across_calls() {
        assert_eq!(render(), render());
        assert!(render().ends_with("}\n"));
    }
}
