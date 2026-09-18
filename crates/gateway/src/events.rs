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

pub use tokenfuse_core::agent_event::{
    EmitOutcome, EventType, Exporter as EventExporter, Startup, StartupLine,
};

/// Read [`tokenfuse_core::agent_event::EVENTS_PATH_ENV`] once and build the
/// exporter, logging the outcome. Call this exactly once, at gateway startup
/// (`crate::main`) — never per-request.
///
/// The read, the open and the words are `tokenfuse_core`'s
/// (`Exporter::from_env`, `Startup::line`); this function only picks the
/// `tracing` level the line asks for. The Cloud's `main.rs` does the same
/// three lines, so both processes say one thing about one fault
/// (tokenfuse#292: the Cloud used to say nothing at all).
pub fn from_env() -> EventExporter {
    let (exp, startup) = EventExporter::from_env();
    log_startup(&startup);
    exp
}

/// Log what [`EventExporter::from_env`] found: nothing for an unset
/// variable, one info line for an opened file (SPEC §6.5 chain continuity is
/// worth saying: resumed, or a fresh head), one warn line for a path that
/// could not be opened, naming the path and the error and saying the export
/// is off.
pub fn log_startup(startup: &Startup) {
    match startup.line() {
        None => {}
        Some(StartupLine::Info(line)) => tracing::info!("{line}"),
        Some(StartupLine::Warn(line)) => tracing::warn!("{line}"),
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
        EmitOutcome::WrittenNonconformingAgentId {
            nonconforming_total,
        } => {
            // Written, not dropped: the line is on the bus and a consumer
            // validating the envelope will reject it. Warned so the operator
            // learns that from us rather than from the consumer's silence.
            tracing::warn!(
                event = event_type.as_wire_str(),
                nonconforming_total,
                "agent-event written with an agent_id outside the Agent Passport \
                 grammar (agent://<trust-domain>/<name>); a consumer validating \
                 the envelope will reject it"
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
    /// An id the envelope rejects is written, counted and reported.
    ///
    /// Written on purpose: refusing would empty the log for exactly the
    /// operator who needs to see the fault, and the line being there is what
    /// lets a consumer reject it loudly instead of the fault being invisible
    /// on both sides. This is engram's and verdryx's decision for the same
    /// problem.
    #[test]
    fn a_nonconforming_agent_id_is_written_counted_and_reported() {
        let _g = env_lock();
        let dir = temp_dir("nonconforming");
        let path = dir.join("events.ndjson");
        std::env::set_var(
            tokenfuse_core::agent_event::EVENTS_PATH_ENV,
            path.to_str().unwrap(),
        );
        let exp = from_env();
        std::env::remove_var(tokenfuse_core::agent_event::EVENTS_PATH_ENV);

        match emit_once(&exp, Some("planner")) {
            EmitOutcome::WrittenNonconformingAgentId {
                nonconforming_total,
            } => assert_eq!(nonconforming_total, 1),
            other => panic!("expected a nonconforming report, got {other:?}"),
        }

        let written = std::fs::read_to_string(&path).expect("the line is on disk");
        assert!(
            written.contains(r#""agent_id":"planner""#),
            "written unchanged rather than repaired: {written}"
        );
        assert_eq!(exp.nonconforming_agent_id_count(), 1);
        assert_eq!(
            exp.skipped_count(),
            0,
            "a malformed id is not an absent one"
        );

        std::fs::remove_dir_all(&dir).ok();
    }

    /// The overeager guard. A check that fires on correct input gets deleted by
    /// whoever is unblocking CI, so the canonical case is pinned beside it.
    #[test]
    fn a_canonical_agent_id_is_written_without_a_report() {
        let _g = env_lock();
        let dir = temp_dir("conforming");
        let path = dir.join("events.ndjson");
        std::env::set_var(
            tokenfuse_core::agent_event::EVENTS_PATH_ENV,
            path.to_str().unwrap(),
        );
        let exp = from_env();
        std::env::remove_var(tokenfuse_core::agent_event::EVENTS_PATH_ENV);

        match emit_once(&exp, Some("agent://acme.example/support/tier1-bot")) {
            EmitOutcome::Written => {}
            other => panic!("a canonical id must report nothing, got {other:?}"),
        }
        assert_eq!(exp.nonconforming_agent_id_count(), 0);

        std::fs::remove_dir_all(&dir).ok();
    }

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

    // ---------------------------------------------------------------------
    // tokenfuse#292: the words in the warning are the contract, because the
    // log line is the only signal an operator gets that the bus will stay
    // empty. The Cloud had no line at all; this gateway had one that named
    // the path and did not say what it meant for the export.

    /// A `MakeWriter` that appends formatted tracing output to a shared
    /// buffer, the shape `crate::cloudsink`'s tests use. Scoped to this
    /// thread with `with_default` rather than installed globally: `from_env`
    /// does its work on the calling thread, so a thread-local subscriber sees
    /// every line it writes.
    #[derive(Clone)]
    struct Captured(std::sync::Arc<Mutex<Vec<u8>>>);

    impl std::io::Write for Captured {
        fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
            self.0.lock().unwrap().extend_from_slice(buf);
            Ok(buf.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    impl<'a> tracing_subscriber::fmt::MakeWriter<'a> for Captured {
        type Writer = Captured;
        fn make_writer(&'a self) -> Self::Writer {
            self.clone()
        }
    }

    /// Run `f` under a subscriber that captures everything at DEBUG and up,
    /// and hand back the text an operator would have read.
    fn captured_log<T>(f: impl FnOnce() -> T) -> (T, String) {
        let buf = std::sync::Arc::new(Mutex::new(Vec::new()));
        let subscriber = tracing_subscriber::fmt()
            .with_writer(Captured(std::sync::Arc::clone(&buf)))
            .with_ansi(false)
            .with_max_level(tracing::Level::DEBUG)
            .finish();
        let out = tracing::subscriber::with_default(subscriber, f);
        let text = String::from_utf8_lossy(&buf.lock().unwrap()).into_owned();
        (out, text)
    }

    /// RED-FIRST on the wording: the line this gateway wrote named the path
    /// and the error and did not say the export was off, so the last
    /// assertion failed against it. The fixture is the launchers' directory
    /// as seen by a process in the wrong group: readable, searchable, not
    /// writable. Unix only, because the fault is a mode bit and so is the
    /// fixture; a root user is not bound by it, and the test says so rather
    /// than passing.
    #[cfg(unix)]
    #[test]
    fn an_unwritable_directory_is_named_at_warn_and_the_export_is_off() {
        use std::os::unix::fs::PermissionsExt;
        let _g = env_lock();
        let dir = temp_dir("unwritable");
        let path = dir.join("events.ndjson");
        let path_str = path.to_str().unwrap().to_string();
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o500)).unwrap();
        std::env::set_var(tokenfuse_core::agent_event::EVENTS_PATH_ENV, &path_str);

        let (exp, log) = captured_log(from_env);

        std::env::remove_var(tokenfuse_core::agent_event::EVENTS_PATH_ENV);
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700)).ok();
        let created = path.exists();
        std::fs::remove_dir_all(&dir).ok();

        assert!(
            !created,
            "the file was created inside a 0500 directory, so this ran as a user the \
             mode bits do not bind (root) and measured nothing"
        );
        assert!(
            !exp.is_enabled(),
            "an unopenable events path must degrade to disabled, never stop the gateway"
        );
        assert!(matches!(
            emit_once(&exp, Some("agent://x.example/a")),
            EmitOutcome::Disabled
        ));
        let warnings: Vec<&str> = log
            .lines()
            .filter(|l| l.contains("WARN") && l.contains(&path_str))
            .collect();
        assert_eq!(
            warnings.len(),
            1,
            "exactly one line at WARN names the path. Log:\n{log}"
        );
        let line = warnings[0];
        assert!(
            line.contains("TOKENFUSE_EVENTS_PATH"),
            "the warning does not name the variable the operator has to fix: {line}"
        );
        assert!(
            line.to_ascii_lowercase().contains("permission denied") || line.contains("os error"),
            "the warning does not carry the operating system's error, which is what \
             distinguishes a mode from an owner from a typo: {line}"
        );
        assert!(
            line.to_ascii_lowercase().contains("export is off"),
            "the warning names the path and does not say what it means: that the \
             export is off and the bus will stay empty. An operator reading \
             'could not open' alone has to infer the consequence: {line}"
        );
        assert!(
            !log.contains("export enabled"),
            "the log also claims the export is enabled. Log:\n{log}"
        );
    }
}
