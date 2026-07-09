//! Agent-event NDJSON replay reader (read-only, additive).
//!
//! `RunAgg` in `crates/cloud/src/store.rs` is an AGGREGATE only: it has no
//! ordered per-call list. The ordered, per-call timeline for `GET
//! /v1/replay/{run}` instead comes from the append-only agent-event NDJSON
//! export (agent-passport SPEC.md §6, schema `taipanbox.dev/agent-event/v0.1`
//! today, forward-compatible with `v0.2`) that a gateway writes via
//! `TOKENFUSE_EVENTS_PATH` (see `tokenfuse_core::agent_event`). The control
//! plane reads that same export (or a copy of it) from a second, independent
//! path, `TOKENFUSE_CLOUD_REPLAY_EVENTS`, and never writes to it.
//!
//! This module owns exactly one job: parse that file and pull out one run's
//! events, ts-ascending, tolerating malformed lines the way the rest of this
//! codebase's file readers do (see `crates/gateway/src/router.rs::load_rules_file`,
//! `crates/gateway/src/mcpclient.rs::parse_sse_frames`).

use std::fs::File;
use std::io::{BufRead, BufReader};

use serde::{Deserialize, Serialize};
use utoipa::ToSchema;

/// One parsed NDJSON line from the agent-event export.
///
/// A cloud-local mirror of `tokenfuse_core::agent_event::AgentEvent`'s wire
/// shape, not the core type itself: that struct derives `Serialize` only (no
/// `Deserialize`), and keeping this mirror here also matches this repo's rule
/// that core types reach the Cloud API surface only via cloud-local DTOs.
///
/// Every field is best-effort (`#[serde(default)]`), so an envelope from an
/// older or newer schema revision still parses; only a line that isn't even a
/// valid JSON object counts as malformed (see `read_run_events`).
#[derive(Debug, Clone, Default, PartialEq, Deserialize, Serialize, ToSchema)]
pub struct ReplayEvent {
    #[serde(default)]
    pub schema: String,
    #[serde(default)]
    pub ts: String,
    #[serde(default)]
    pub source: String,
    #[serde(rename = "type", default)]
    pub kind: String,
    #[serde(default)]
    pub severity: Option<String>,
    #[serde(default)]
    pub agent_id: String,
    #[serde(default)]
    pub run_id: Option<String>,
    #[serde(default)]
    pub on_behalf_of: Option<Vec<String>>,
    #[serde(default)]
    #[schema(value_type = Option<Object>)]
    pub data: Option<serde_json::Value>,
    #[serde(default)]
    pub prev_hash: Option<String>,
}

/// Read `path` line by line (NDJSON: one JSON object per line), keep only the
/// events whose `run_id` is exactly `run`, and return them ts-ascending, plus
/// a count of lines that failed to parse.
///
/// Fail-open like the rest of this codebase's optional file inputs: a missing
/// or unreadable file yields zero events (never an error), since `/v1/replay`
/// must still return the store-derived incidents/audit even when no event
/// export is configured or reachable.
///
/// Sorting by the RFC 3339 `ts` string (rather than parsing it into a
/// timestamp) is exact for this format: `ts_millis_to_rfc3339_millis` always
/// emits a fixed-width, zero-padded, UTC (`Z`-suffixed) string, which sorts
/// lexicographically in the same order as the instants it encodes.
pub fn read_run_events(path: &str, run: &str) -> (Vec<ReplayEvent>, usize) {
    let mut events = Vec::new();
    let mut malformed = 0usize;

    let Ok(file) = File::open(path) else {
        return (events, malformed);
    };
    for line in BufReader::new(file).lines() {
        let Ok(line) = line else {
            malformed += 1;
            continue;
        };
        if line.trim().is_empty() {
            continue;
        }
        match serde_json::from_str::<ReplayEvent>(&line) {
            Ok(ev) if ev.run_id.as_deref() == Some(run) => events.push(ev),
            // Valid event, just not for this run: not a parse failure.
            Ok(_) => {}
            Err(_) => malformed += 1,
        }
    }
    events.sort_by(|a, b| a.ts.cmp(&b.ts));
    (events, malformed)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    /// A scratch NDJSON file under a per-test, per-process directory (mirrors
    /// `crates/core/src/agent_event.rs`'s test convention) so parallel test
    /// runs never collide.
    fn write_temp(name: &str, lines: &[&str]) -> std::path::PathBuf {
        let dir =
            std::env::temp_dir().join(format!("tf-replay-test-{}-{name}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("events.ndjson");
        let mut f = File::create(&path).unwrap();
        for l in lines {
            writeln!(f, "{l}").unwrap();
        }
        path
    }

    #[test]
    fn missing_file_yields_zero_events_not_an_error() {
        let (events, malformed) = read_run_events("/nonexistent/tf-replay-xyz.ndjson", "run-1");
        assert!(events.is_empty());
        assert_eq!(malformed, 0);
    }

    #[test]
    fn keeps_only_the_matching_run_ts_ascending() {
        let path = write_temp(
            "match",
            &[
                r#"{"schema":"taipanbox.dev/agent-event/v0.1","ts":"2026-07-09T03:12:44.300Z","source":"tokenfuse","type":"breaker_tripped","severity":"critical","agent_id":"a1","run_id":"run-1","data":{"n":2}}"#,
                r#"{"schema":"taipanbox.dev/agent-event/v0.1","ts":"2026-07-09T03:12:44.100Z","source":"tokenfuse","type":"dlp_block","severity":"high","agent_id":"a1","run_id":"run-1","data":{"n":1}}"#,
                r#"{"schema":"taipanbox.dev/agent-event/v0.1","ts":"2026-07-09T03:12:44.200Z","source":"tokenfuse","type":"taint_block","severity":"high","agent_id":"a1","run_id":"run-2","data":{"n":9}}"#,
            ],
        );
        let (events, malformed) = read_run_events(path.to_str().unwrap(), "run-1");
        assert_eq!(malformed, 0);
        assert_eq!(events.len(), 2);
        // ts-ascending: the 03:12:44.100Z line before the .300Z line.
        assert_eq!(events[0].kind, "dlp_block");
        assert_eq!(events[1].kind, "breaker_tripped");
        assert!(events.iter().all(|e| e.run_id.as_deref() == Some("run-1")));

        std::fs::remove_dir_all(path.parent().unwrap()).ok();
    }

    #[test]
    fn malformed_lines_are_skipped_and_counted() {
        let path = write_temp(
            "malformed",
            &[
                r#"{"ts":"2026-07-09T03:12:44.100Z","type":"dlp_block","agent_id":"a1","run_id":"run-1"}"#,
                "not json at all {{{",
                "",
                r#"{"ts":"2026-07-09T03:12:44.200Z","type":"taint_block","agent_id":"a1","run_id":"run-1"}"#,
            ],
        );
        let (events, malformed) = read_run_events(path.to_str().unwrap(), "run-1");
        assert_eq!(events.len(), 2);
        // The blank line is skipped silently; only the truly invalid line counts.
        assert_eq!(malformed, 1);

        std::fs::remove_dir_all(path.parent().unwrap()).ok();
    }

    #[test]
    fn tolerates_a_line_missing_optional_fields() {
        // A minimal envelope (no severity/data/prev_hash/on_behalf_of) still
        // parses; forward-compat with schema drift is the point.
        let path = write_temp(
            "minimal",
            &[r#"{"ts":"t1","type":"mcp_drift","run_id":"run-9"}"#],
        );
        let (events, malformed) = read_run_events(path.to_str().unwrap(), "run-9");
        assert_eq!(malformed, 0);
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].kind, "mcp_drift");
        assert!(events[0].severity.is_none());
        assert!(events[0].data.is_none());

        std::fs::remove_dir_all(path.parent().unwrap()).ok();
    }
}
