//! Agent-event NDJSON exporter wiring for the gateway (agent-passport
//! SPEC.md §6). The envelope, severity mapping, NDJSON serialization, and the
//! fail-open file writer all live in `tokenfuse_core::agent_event` — see that
//! module's doc for why (short version: the OTHER four event kinds this
//! phase wires up, `budget_exhausted`/`sustained_loop`/`spend_spike`/
//! `fanout_explosion`, are raised in `crates/cloud/src/store.rs`, a sibling
//! crate that can't depend on `gateway`, so the shared mechanics had to live
//! in `tokenfuse-core`, which both depend on).
//!
//! This module is the gateway's OWN piece: reading `TOKENFUSE_EVENTS_PATH`
//! once at gateway startup (never per-request — see [`from_env`]) and the
//! call sites that are only observable from inside a running gateway
//! process:
//!   - `crate::proxy` — `breaker_tripped` (all five Breaker 402 sites, via
//!     `emit_breaker_event`), `dlp_block`, `taint_block`.
//!   - `crate::mcpbroker` — `mcp_drift` (the live rug-pull check).
//!
//! `crates/cloud/src/store.rs` wires its own four incident kinds directly
//! against `tokenfuse_core::agent_event::Exporter`, reading the SAME
//! `TOKENFUSE_EVENTS_PATH` env var at ITS OWN process startup (the gateway
//! and the Cloud control plane are separate deployables, each opens its own
//! file handle).
//!
//! Fail-open, end to end: `TOKENFUSE_EVENTS_PATH` unset ⇒ [`EventExporter`]
//! is `disabled()` and `emit` is a single branch, no I/O, no allocation — the
//! stated design goal ("zero cost on the hot path" when off). When enabled, a
//! write error is logged and dropped by the call site (see `crate::proxy`),
//! never surfaced as a request failure.

pub use tokenfuse_core::agent_event::{EmitOutcome, EventType, Exporter as EventExporter};

/// Read [`tokenfuse_core::agent_event::EVENTS_PATH_ENV`] once and build the
/// exporter, logging the outcome. Call this exactly once, at gateway startup
/// (`crate::main`) — never per-request.
pub fn from_env() -> EventExporter {
    match std::env::var(tokenfuse_core::agent_event::EVENTS_PATH_ENV) {
        Ok(path) if !path.is_empty() => match EventExporter::open(&path) {
            Ok(exp) => {
                // Chain continuity is worth one honest startup line (SPEC
                // §6.5): resumed = one unbroken chain across the restart;
                // fresh = a new head (empty file, or an unusable tail).
                match exp.resumed_from() {
                    Some(h) => tracing::info!(
                        %path,
                        resumed_from = %&h[..h.len().min(19)],
                        "agent-event NDJSON export enabled (prev_hash chain resumed)"
                    ),
                    None => tracing::info!(
                        %path,
                        "agent-event NDJSON export enabled (fresh prev_hash chain)"
                    ),
                }
                exp
            }
            Err(e) => {
                tracing::warn!(%path, "could not open TOKENFUSE_EVENTS_PATH: {e}");
                EventExporter::disabled()
            }
        },
        _ => EventExporter::disabled(),
    }
}

/// Log the outcome of an [`EventExporter::emit`] call. Every call site in
/// `crate::proxy`/`crate::mcpbroker` routes through this so skip/error
/// counts are logged uniformly (this crate has `tracing`; `tokenfuse-core`
/// deliberately does not, see its Cargo.toml).
pub fn log_outcome(event_type: EventType, outcome: EmitOutcome) {
    match outcome {
        EmitOutcome::Disabled | EmitOutcome::Written => {}
        EmitOutcome::SkippedNoAgentId { skipped_total } => {
            tracing::warn!(
                event = event_type.as_wire_str(),
                skipped_total,
                "agent-event skipped: no agent_id on the request"
            );
        }
        EmitOutcome::WriteError {
            errors_total,
            message,
        } => {
            tracing::warn!(
                event = event_type.as_wire_str(),
                errors_total,
                "agent-event NDJSON write failed: {message}"
            );
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    use std::sync::{Mutex, MutexGuard, OnceLock};

    /// Every test in this module mutates one process-wide environment variable,
    /// and cargo runs tests in the same binary on parallel threads. Without a
    /// lock they race, and the loser reads a value another test set. The two
    /// original tests here had that race latent; adding four more would have
    /// made it bite, and a flaky test is worse than no test.
    fn env_lock() -> MutexGuard<'static, ()> {
        static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
        LOCK.get_or_init(|| Mutex::new(()))
            .lock()
            .unwrap_or_else(|e| e.into_inner())
    }

    /// A unique directory per test, since the pid alone is shared by every test
    /// in the binary.
    fn temp_dir(tag: &str) -> std::path::PathBuf {
        let dir = std::env::temp_dir().join(format!("tf-gw-events-{}-{tag}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    fn emit_once(exp: &EventExporter, agent: Option<&str>) -> EmitOutcome {
        exp.emit(
            EventType::BreakerTripped,
            1_785_000_000_000,
            agent,
            Some("run-1"),
            None,
            json!({"probe": true}),
        )
    }

    #[test]
    fn from_env_disabled_when_unset() {
        let _g = env_lock();
        std::env::remove_var(tokenfuse_core::agent_event::EVENTS_PATH_ENV);
        let exp = from_env();
        assert!(!exp.is_enabled());
    }

    #[test]
    fn from_env_enabled_when_set_to_a_writable_path() {
        let _g = env_lock();
        let dir = temp_dir("writable");
        let path = dir.join("events.ndjson");
        std::env::set_var(
            tokenfuse_core::agent_event::EVENTS_PATH_ENV,
            path.to_str().unwrap(),
        );
        let exp = from_env();
        assert!(exp.is_enabled());
        std::env::remove_var(tokenfuse_core::agent_event::EVENTS_PATH_ENV);
        std::fs::remove_dir_all(&dir).ok();
    }

    // ---------------------------------------------------------------------
    // Invariant 6 of CLAUDE.md makes the exporter two promises, and until now
    // only its CONSTRUCTION was tested. These hold the promises themselves.
    //
    // Both stop being true quietly. Nothing crashes when a disabled exporter
    // starts doing work; it just gets slower, in production, per request. And
    // nothing warns when a broken path stops being fail-open; the gateway
    // simply refuses to start, on somebody else's machine, because an OPTIONAL
    // audit export could not open a file.

    /// Promise one: unset means zero cost, not "writes nowhere".
    #[test]
    fn a_disabled_exporter_does_no_work_at_all() {
        let exp = EventExporter::disabled();
        assert!(
            matches!(
                emit_once(&exp, Some("agent://x.example/a")),
                EmitOutcome::Disabled
            ),
            "a disabled exporter must return Disabled before building anything. \
             Any other outcome means it serialized an event nobody asked for, on \
             the request path, for every request."
        );
        // Twice, because an exporter that lazily initialised on first use would
        // still pass a single call.
        assert!(matches!(
            emit_once(&exp, Some("agent://x.example/a")),
            EmitOutcome::Disabled
        ));
    }

    /// An empty value is not a path. Treating it as one would try to open ""
    /// on every start.
    #[test]
    fn an_empty_path_is_treated_as_unset() {
        let _g = env_lock();
        std::env::set_var(tokenfuse_core::agent_event::EVENTS_PATH_ENV, "");
        let exp = from_env();
        std::env::remove_var(tokenfuse_core::agent_event::EVENTS_PATH_ENV);
        assert!(!exp.is_enabled());
        assert!(matches!(
            emit_once(&exp, Some("agent://x.example/a")),
            EmitOutcome::Disabled
        ));
    }

    /// Promise two, and the one that matters in production: a path that cannot
    /// be opened must cost a warning and nothing else. A missing directory, a
    /// path with no write permission, or a typo in a deployment manifest must
    /// not stop the gateway.
    #[test]
    fn an_unopenable_path_falls_back_to_disabled_rather_than_failing() {
        let _g = env_lock();
        std::env::set_var(
            tokenfuse_core::agent_event::EVENTS_PATH_ENV,
            "/nonexistent-directory-for-tokenfuse-tests/deep/events.ndjson",
        );
        let exp = from_env();
        std::env::remove_var(tokenfuse_core::agent_event::EVENTS_PATH_ENV);
        assert!(
            !exp.is_enabled(),
            "an unopenable events path must degrade to disabled. A gateway that \
             refuses to start because its optional audit export could not open a \
             file has turned a nice-to-have into a hard dependency."
        );
        assert!(matches!(
            emit_once(&exp, Some("agent://x.example/a")),
            EmitOutcome::Disabled
        ));
    }

    /// The same class, and a realistic typo: TOKENFUSE_EVENTS_PATH=/var/log/tokenfuse
    /// instead of .../events.ndjson.
    #[test]
    fn a_directory_as_the_events_path_is_also_fail_open() {
        let _g = env_lock();
        let dir = temp_dir("isadir");
        std::env::set_var(
            tokenfuse_core::agent_event::EVENTS_PATH_ENV,
            dir.to_str().unwrap(),
        );
        let exp = from_env();
        std::env::remove_var(tokenfuse_core::agent_event::EVENTS_PATH_ENV);
        std::fs::remove_dir_all(&dir).ok();
        assert!(!exp.is_enabled(), "a directory is not a file to append to");
    }

    /// The exporter never fabricates an agent_id: a request without one is
    /// skipped and counted, not invented and not fatal. The enabled path is
    /// exercised in the same test so a skip cannot be the exporter simply
    /// being broken.
    #[test]
    fn a_missing_agent_id_is_skipped_and_counted_never_invented() {
        let _g = env_lock();
        let dir = temp_dir("skip");
        let path = dir.join("events.ndjson");
        std::env::set_var(
            tokenfuse_core::agent_event::EVENTS_PATH_ENV,
            path.to_str().unwrap(),
        );
        let exp = from_env();
        std::env::remove_var(tokenfuse_core::agent_event::EVENTS_PATH_ENV);

        match emit_once(&exp, None) {
            EmitOutcome::SkippedNoAgentId { skipped_total } => assert_eq!(skipped_total, 1),
            other => panic!("expected SkippedNoAgentId, got {other:?}"),
        }
        assert!(matches!(
            emit_once(&exp, Some("agent://x.example/a")),
            EmitOutcome::Written
        ));
        std::fs::remove_dir_all(&dir).ok();
    }
}
