//! Agent-event NDJSON envelope and exporter (agent-passport SPEC.md §6,
//! schema `taipanbox.dev/agent-event/v0.1`).
//!
//! Lives in `tokenfuse-core` (not the gateway) because TokenFuse's existing
//! incident taxonomy is raised from TWO different deployables that both
//! depend on this crate but not on each other:
//!   - `crates/gateway` — per-request enforcement (`breaker_tripped`,
//!     `dlp_block`, `taint_block`) and the MCP broker (`mcp_drift`).
//!   - `crates/cloud` — the fleet-aggregate incident detectors added in P2
//!     (`budget_exhausted`, `sustained_loop`, `spend_spike`,
//!     `fanout_explosion`), which need a cross-run/cross-org window neither
//!     a single gateway process nor `tokenfuse-core` (I/O-free, single-call
//!     scope) can compute alone.
//!
//! Putting the envelope + severity mapping + NDJSON line serialization + the
//! fail-open file writer here — using nothing but `std::fs`/`std::io` and the
//! `serde`/`serde_json` this crate already depends on — lets both products
//! share ONE implementation without a dependency inversion (`cloud` and
//! `gateway` are siblings) and without adding a crate dependency. Each
//! product still owns its OWN call sites, its own `TOKENFUSE_EVENTS_PATH`
//! read at its own process startup, and its own `Exporter` instance — see
//! `crates/gateway/src/events.rs` and `crates/cloud/src/store.rs`.

use serde::Serialize;

use crate::timefmt::ts_millis_to_rfc3339_millis;

/// `schema` field value (agent-passport SPEC.md §8.4 — final for v0.1).
pub const SCHEMA: &str = "taipanbox.dev/agent-event/v0.1";
/// `source` field value: every event this crate builds is TokenFuse's own.
pub const SOURCE: &str = "tokenfuse";

/// `severity` enum (SPEC.md §6.1: `info` | `low` | `medium` | `high` |
/// `critical`). Re-exported from [`crate::mcpreport`], which already defines
/// exactly this set (used for `mcp-scan` findings and, today, cloud incident
/// severity) — one severity vocabulary for the whole crate rather than a
/// second copy.
pub use crate::mcpreport::Severity;

/// TokenFuse's event-type taxonomy (agent-passport SPEC.md §6.2, `source =
/// "tokenfuse"` row): the P2 incident kinds, the per-call kinds the gateway
/// raises, and the cloud's control-plane signals. Each variant's own doc says
/// which deployable raises it and why it carries the severity it does. A count
/// is deliberately not stated here: this list grows, and a number in prose is
/// the half that goes stale first.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EventType {
    /// Existing cloud incident (P2, PR #90): raised in
    /// `crates/cloud/src/store.rs::ingest_at` when a run hits ≥ N
    /// budget-protection blocks.
    BudgetExhausted,
    /// Existing cloud incident (P2, PR #90): raised when a run repeats
    /// `loop_detected` ≥ N times in-window.
    SustainedLoop,
    /// Existing cloud incident (P2, PR #90): raised when an org's burn rate
    /// crosses the configured per-minute threshold.
    SpendSpike,
    /// Existing cloud incident (P2, PR #90): raised when one `agent_id`
    /// drives ≥ N distinct runs in-window.
    FanoutExplosion,
    /// New cloud incident: a run's `spent/budget` crossed the configured
    /// alert fraction (`TOKENFUSE_CLOUD_ALERT_PCT`, default 0.8). The
    /// "approaching the line" signal, raised in
    /// `crates/cloud/src/store.rs::ingest_at`.
    ///
    /// This one is deliberately `medium`, not `high`: nothing has gone wrong
    /// yet, and a consumer that pages on it at the same weight as an
    /// exhausted budget teaches its operator to ignore both. It exists so a
    /// consumer OUTSIDE this process can learn about a budget before it is
    /// gone; `/v1/alerts` has always had the same fact as state, but state is
    /// not something an alerting pipeline can subscribe to.
    BudgetThreshold,
    /// New: a run was killed (`Store::kill`/`kill_audited`, i.e. the
    /// `/v1/kill` control or an internal stop). The loudest thing the money
    /// plane does to an agent, and until now the only one visible solely on
    /// the in-process stream: a reader of the shared event log could not tell
    /// a killed run from one that simply stopped calling.
    ///
    /// `data.actor` carries who asked, when the kill came through the audited
    /// path, so a consumer can tell an operator's own kill from an automatic
    /// one instead of paging them about their own click.
    RunKilled,
    /// New: any Breaker 402 (`tokenfuse_core::breaker::BreakerReason`) —
    /// budget, policy, loop, kill, or WASM-policy trip. Raised at the
    /// gateway's `breaker_error_response` call sites.
    BreakerTripped,
    /// New: a DLP (secret-scanning) 403 block. Raised at the gateway's
    /// `dlp_block` call site.
    DlpBlock,
    /// New: an agent-firewall (taint) 403 block. Raised at the gateway's
    /// `firewall_block` call site.
    TaintBlock,
    /// New: the MCP broker's live rug-pull check found a
    /// `tokenfuse_core::mcp::Drift::Changed` entry against the pinned lock.
    McpDrift,
    /// New (docs/20, identity map): a strict-mode 403 because the presented
    /// client credential may not speak as the claimed `x-fuse-agent-id`.
    /// Raised at the gateway's identity gate. Severity `high`, the same
    /// auth-family band as `dlp_block`/`taint_block`.
    IdentityMismatch,
    /// A business unit's MONTHLY cap is gone (docs/20). Every call attributed
    /// to that unit is refused until somebody raises the cap or the month
    /// rolls, so the blast radius is wider than the run that happened to hit
    /// it first.
    ///
    /// Exists because `breaker_tripped` dropped to `medium` on 2026-08-03,
    /// which is right for a refusal whose reason has its own type, and this
    /// reason did not have one. A unit that has stopped spending for the rest
    /// of the month is not a per-call audit line.
    UnitCapExceeded,
    /// A call refused by the GATEWAY'S OWN policy engine, either the built-in
    /// evaluator or a wasm module, in enforce mode.
    ///
    /// The same wire type wardryx uses for a refusal at the policy plane, on
    /// purpose: to whoever reads the mail it is the same fact, an action
    /// refused by policy, and `source` says which plane decided. Added for the
    /// same reason as [`EventType::UnitCapExceeded`].
    PolicyDeny,
    /// New (docs/23, mcp-broker v2): one MCP `tools/call` that passed through
    /// the broker's Wardryx policy gate. `data` carries `{tool, upstream,
    /// decision}` where `decision` is the PDP's own `allow|deny|hold` (or
    /// `would-<decision>` in shadow mode). Severity `low`: this is a
    /// per-action audit signal, not an alert on its own -- a denied call is
    /// visible in the `decision` field, not in the event's fixed severity, so
    /// an operator can count and audit tool actions without every allowed one
    /// paging like a `high` incident. Only emitted when the broker's Wardryx
    /// gate is active and the request carried an `agent_id` (never fabricated,
    /// see [`build`]).
    ToolCall,
}

impl EventType {
    /// The exact `type` wire string (agent-passport SPEC.md §6.2 — these are
    /// TokenFuse's registry entries verbatim, zero renaming for the four P2
    /// incident kinds).
    pub fn as_wire_str(self) -> &'static str {
        match self {
            EventType::BudgetExhausted => "budget_exhausted",
            EventType::SustainedLoop => "sustained_loop",
            EventType::SpendSpike => "spend_spike",
            EventType::FanoutExplosion => "fanout_explosion",
            EventType::BudgetThreshold => "budget_threshold",
            EventType::RunKilled => "run_killed",
            EventType::BreakerTripped => "breaker_tripped",
            EventType::DlpBlock => "dlp_block",
            EventType::TaintBlock => "taint_block",
            EventType::McpDrift => "mcp_drift",
            EventType::IdentityMismatch => "identity_mismatch",
            EventType::UnitCapExceeded => "unit_cap_exceeded",
            EventType::PolicyDeny => "policy_deny",
            EventType::ToolCall => "tool_call",
        }
    }

    /// Fixed severity per event type — NOT caller-supplied, so no emission
    /// site can misclassify an event. Mapping:
    /// `budget_exhausted` / `mcp_drift` = `critical`;
    /// `sustained_loop` / `spend_spike` / `fanout_explosion` / `dlp_block` /
    /// `taint_block` / `identity_mismatch` (docs/20) / `run_killed` /
    /// `unit_cap_exceeded` / `policy_deny` = `high`;
    /// `budget_threshold` / `breaker_tripped` = `medium`;
    /// `tool_call` = `low`.
    ///
    /// `breaker_tripped` was `critical` until 2026-08-03, which meant every
    /// enforced 402 paged a human at the top band. A refused call is this
    /// product working exactly as sold: enforcement, not observability. Paging
    /// for the design succeeding is how an operator learns to filter the
    /// sender, and then misses the one that mattered. It also sat a band ABOVE
    /// `sustained_loop`, which is a genuine anomaly.
    ///
    /// Nothing is lost for most refusals, because the reason usually has its
    /// own type at `high` or above: budget exhaustion, a loop, a kill, a DLP
    /// or taint block, an identity mismatch. The generic event stays as the
    /// per-call audit record with the reason in `data`. What this DOES lower
    /// is the two refusal kinds that have no other type, a unit cap and a
    /// gateway-local wasm policy; see CLAUDE.md, which records that rather
    /// than leaving it to be discovered.
    ///
    /// Lowered by the user's decision 2026-08-03.
    ///
    /// Note this is deliberately independent of `cloud::store::Incident`'s
    /// own `severity` field (used for `/v1/incidents` today, e.g.
    /// `sustained_loop` is `Medium` there) — that field predates this
    /// envelope and this phase does not change it; the envelope's severity is
    /// its own, newly-specified mapping.
    pub fn severity(self) -> Severity {
        match self {
            EventType::BudgetExhausted | EventType::McpDrift => Severity::Critical,
            EventType::SustainedLoop
            | EventType::SpendSpike
            | EventType::FanoutExplosion
            | EventType::DlpBlock
            | EventType::TaintBlock
            | EventType::IdentityMismatch
            | EventType::RunKilled
            | EventType::UnitCapExceeded
            | EventType::PolicyDeny => Severity::High,
            // An early warning, on purpose one band below the incident it
            // warns about: the run is still inside its budget. Beside it, the
            // per-call record of a refusal that already happened, which is the
            // enforcement path doing its job rather than an incident.
            EventType::BudgetThreshold | EventType::BreakerTripped => Severity::Medium,
            // A per-action audit signal, not an alert: the allow/deny/hold is
            // in `data.decision`, so allowed calls do not page like incidents.
            EventType::ToolCall => Severity::Low,
        }
    }
}

/// One agent-event envelope (agent-passport SPEC.md §6). Field order matches
/// the spec's example exactly, which `serde_json` preserves on serialize
/// (struct fields are emitted in declaration order, not sorted).
#[derive(Debug, Clone, Serialize, PartialEq)]
pub struct AgentEvent {
    pub schema: &'static str,
    pub ts: String,
    pub source: &'static str,
    #[serde(rename = "type")]
    pub kind: &'static str,
    pub severity: Severity,
    pub agent_id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub run_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub on_behalf_of: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub data: Option<serde_json::Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub prev_hash: Option<String>,
}

/// Build one envelope, or `None` when `agent_id` is absent/empty.
///
/// The envelope schema REQUIRES `agent_id` (SPEC.md §6.1); rather than
/// fabricate a placeholder, the caller must skip the event entirely and count
/// the skip (see `Exporter::emit`, which does exactly that). This function is
/// the single place that enforces the rule, so no call site can accidentally
/// emit an event with a synthesized identity.
///
/// `on_behalf_of`: `None`/empty is treated as "omit" (SPEC.md §5: "An
/// empty/absent chain means the agent acts autonomously" — distinct from
/// serializing an empty JSON array).
///
/// `prev_hash` is deliberately NOT a parameter: the chain link belongs to the
/// [`Exporter`], the stream's single serialization point, which stamps it
/// under the same lock that orders the writes (SPEC.md §6.5). A built event
/// starts unchained; `Exporter::emit` links it.
/// SPEC.md §3.1's `agent://<trust-domain>/<name>` grammar and the cap the
/// envelope puts on it, as the shared schema states them.
///
/// A local copy of two values agent-passport owns, which is the shape this
/// estate is repeatedly bitten by, and **nothing in this repository checks it**.
///
/// A test comparing it against the canonical schema was written and removed:
/// this repository's CI does not check out the sibling, so it would have taken
/// its own skip path and passed having measured nothing, which is the exact
/// failure the gates here exist to refuse. Saying that plainly is worth more
/// than a check that reports green in the only place it runs unattended.
///
/// The cross-repo comparison belongs in `estate-gates`, beside C2, which
/// already holds vendored schema FILES byte-identical and does not yet look at
/// a rule copied into code. Recorded as G4.2 in its `GAPS.md`.
pub const AGENT_ID_MAX_LENGTH: usize = 255;

/// Whether `agent_id` is one a consumer validating the envelope accepts.
///
/// The same question the shared schema asks, in the same two parts: the grammar
/// and the length cap. A regex is compiled once, the way `crate::dlp` does it,
/// because this runs per emitted event.
pub fn is_canonical_agent_id(agent_id: &str) -> bool {
    static PATTERN: std::sync::OnceLock<regex::Regex> = std::sync::OnceLock::new();
    let re = PATTERN.get_or_init(|| {
        regex::Regex::new(r"^agent://[a-z0-9.-]+/[a-z0-9._/-]+$")
            .expect("the agent_id pattern is a literal and compiles")
    });
    agent_id.len() <= AGENT_ID_MAX_LENGTH && re.is_match(agent_id)
}

pub fn build(
    event_type: EventType,
    ts_millis: i64,
    agent_id: Option<&str>,
    run_id: Option<&str>,
    on_behalf_of: Option<&[String]>,
    data: serde_json::Value,
) -> Option<AgentEvent> {
    let agent_id = agent_id.filter(|s| !s.is_empty())?;
    Some(AgentEvent {
        schema: SCHEMA,
        ts: ts_millis_to_rfc3339_millis(ts_millis),
        source: SOURCE,
        kind: event_type.as_wire_str(),
        severity: event_type.severity(),
        agent_id: agent_id.to_string(),
        run_id: run_id.filter(|s| !s.is_empty()).map(|s| s.to_string()),
        on_behalf_of: on_behalf_of
            .filter(|chain| !chain.is_empty())
            .map(|chain| chain.to_vec()),
        data: if data.is_null() { None } else { Some(data) },
        prev_hash: None,
    })
}

/// The SPEC.md §6.5 chain hash of one event: `"sha256:" + hex(sha256(C))`
/// where `C` is the RFC 8785 canonical serialization (see [`crate::jcs`]) of
/// the event with its `prev_hash` field removed. This is the value the NEXT
/// event in a chained stream carries - and it is independent of the event's
/// own `prev_hash` by construction, so a chained and an unchained copy of
/// the same event hash identically.
pub fn chain_hash(event: &AgentEvent) -> Option<String> {
    let value = serde_json::to_value(event).ok()?;
    Some(chain_hash_value(value))
}

/// [`chain_hash`] over an already-parsed JSON value (used to resume a chain
/// from a file tail, where the previous event exists only as a line of
/// JSON). Removes any `prev_hash` member before canonicalizing.
fn chain_hash_value(mut value: serde_json::Value) -> String {
    if let Some(map) = value.as_object_mut() {
        map.remove("prev_hash");
    }
    use sha2::{Digest, Sha256};
    let digest = Sha256::digest(crate::jcs::canonicalize(&value).as_bytes());
    let mut hex = String::with_capacity(7 + 64);
    hex.push_str("sha256:");
    for b in digest {
        use std::fmt::Write;
        let _ = write!(hex, "{b:02x}");
    }
    hex
}

/// Serialize one envelope as a single NDJSON line (no trailing newline).
/// `serde_json::to_string` over this struct cannot fail in practice (no
/// non-UTF8 map keys, no non-finite floats produced by this module's own
/// callers) — an error is treated as "nothing to write" rather than a panic,
/// keeping this on the same fail-open footing as [`Exporter::emit`].
pub fn to_ndjson_line(event: &AgentEvent) -> Option<String> {
    serde_json::to_string(event).ok()
}

/// The env var every product reads, ONCE, at process startup, to enable the
/// exporter (absent/empty ⇒ disabled, zero per-request cost).
pub const EVENTS_PATH_ENV: &str = "TOKENFUSE_EVENTS_PATH";

/// Fail-open NDJSON append-only exporter. `disabled()` is the zero-cost
/// default (no file handle, `emit` returns immediately); `from_env` opens
/// `TOKENFUSE_EVENTS_PATH` once and keeps the handle for the process
/// lifetime. Every write is best-effort: an I/O error is logged (by the
/// caller — this module has no logging dependency, see `emit`'s return value)
/// and dropped, never surfaced as a request failure.
#[derive(Debug)]
pub struct Exporter {
    sink: Option<std::sync::Mutex<ChainSink>>,
    skipped: std::sync::atomic::AtomicU64,
    write_errors: std::sync::atomic::AtomicU64,
    nonconforming: std::sync::atomic::AtomicU64,
}

/// The open file plus the chain state that must advance in lockstep with it
/// (SPEC.md §6.5: one file = one chain, one serialization point).
#[derive(Debug)]
struct ChainSink {
    file: std::fs::File,
    /// `prev_hash` for the NEXT event; `None` at a chain head.
    next: Option<String>,
    /// What the chain resumed from at open (`None` = started fresh).
    resumed_from: Option<String>,
}

/// The outcome of one [`Exporter::emit`] call, for the caller to log (this
/// module intentionally has no `tracing`/logging dependency of its own).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EmitOutcome {
    /// Disabled (no path configured) — the common case, zero cost.
    Disabled,
    /// Wrote one NDJSON line.
    Written,
    /// Skipped: no `agent_id` was available. Carries the running total.
    SkippedNoAgentId { skipped_total: u64 },
    /// Wrote one NDJSON line whose `agent_id` does not match SPEC.md §3.1's
    /// grammar, so a consumer validating the envelope will reject it. Carries
    /// the running total.
    ///
    /// A separate variant rather than a field on [`Self::Written`], for the
    /// reason this crate applies to refusals: a fact somebody may need to act
    /// on gets a type of its own, and adding a variant makes every existing
    /// `match` state what it does about this case instead of inheriting the
    /// healthy branch by accident.
    WrittenNonconformingAgentId { nonconforming_total: u64 },
    /// The file write failed (fail-open: the request is unaffected). Carries
    /// the running total and a message for the caller to log.
    WriteError { errors_total: u64, message: String },
}

impl Exporter {
    /// The always-off exporter: no file, `emit` is a single branch away from
    /// a no-op, so a disabled exporter costs nothing on the hot path.
    pub fn disabled() -> Self {
        Exporter {
            sink: None,
            skipped: std::sync::atomic::AtomicU64::new(0),
            write_errors: std::sync::atomic::AtomicU64::new(0),
            nonconforming: std::sync::atomic::AtomicU64::new(0),
        }
    }

    /// Open `path` for append and seed the SPEC.md §6.5 chain from the last
    /// well-formed event line already in the file, so one file stays one
    /// chain across process restarts. An empty file, or an unreadable or
    /// malformed tail, starts a FRESH chain rather than refusing to open
    /// (fail-open, the exporter's standing posture) - `agent-conform -chain`
    /// then reports the restart honestly instead of the process going quiet.
    ///
    /// Returns `Err` with a message the caller should log (and then fall
    /// back to [`Exporter::disabled`]) - opening the file is a one-time
    /// startup concern, not a per-request one, so this is the one place
    /// allowed to return a hard error.
    pub fn open(path: &str) -> Result<Self, String> {
        let mut file = std::fs::OpenOptions::new()
            .create(true)
            .read(true)
            .append(true)
            .open(path)
            .map_err(|e| format!("could not open '{path}': {e}"))?;
        let resumed = tail_chain_hash(&mut file);
        Ok(Exporter {
            sink: Some(std::sync::Mutex::new(ChainSink {
                file,
                next: resumed.clone(),
                resumed_from: resumed,
            })),
            skipped: std::sync::atomic::AtomicU64::new(0),
            write_errors: std::sync::atomic::AtomicU64::new(0),
            nonconforming: std::sync::atomic::AtomicU64::new(0),
        })
    }

    /// The chain hash this exporter resumed from at open, or `None` when it
    /// started fresh (disabled exporter, empty file, or an unusable tail).
    /// For the startup log line, so an operator can see chain continuity.
    pub fn resumed_from(&self) -> Option<String> {
        self.sink
            .as_ref()
            .and_then(|s| s.lock().ok())
            .and_then(|s| s.resumed_from.clone())
    }

    /// Read [`EVENTS_PATH_ENV`] ONCE and open it, or return the disabled
    /// exporter when absent/empty. On an open error, ALSO returns the
    /// disabled exporter (fail-open at startup too) — the caller should log
    /// the `Err` case's message via the `Result`-returning [`Exporter::open`]
    /// directly if it wants a startup warning; `from_env` is the convenience
    /// path for callers that just want "on or off, never a crash".
    pub fn from_env() -> Self {
        match std::env::var(EVENTS_PATH_ENV) {
            Ok(path) if !path.is_empty() => Self::open(&path).unwrap_or_else(|_| Self::disabled()),
            _ => Self::disabled(),
        }
    }

    pub fn is_enabled(&self) -> bool {
        self.sink.is_some()
    }

    /// Build, chain-link, and (best-effort) write one event. Returns what
    /// happened so the caller can log it (this crate has no logging
    /// dependency); every branch is fail-open - this call NEVER returns an
    /// error the caller must propagate.
    ///
    /// The SPEC.md §6.5 link is stamped INSIDE the sink lock, the stream's
    /// single serialization point, so concurrent emitters cannot fork the
    /// chain; on a failed write the chain does not advance, and the next
    /// successful write re-links to the last line actually on disk.
    pub fn emit(
        &self,
        event_type: EventType,
        ts_millis: i64,
        agent_id: Option<&str>,
        run_id: Option<&str>,
        on_behalf_of: Option<&[String]>,
        data: serde_json::Value,
    ) -> EmitOutcome {
        let Some(sink) = &self.sink else {
            return EmitOutcome::Disabled;
        };
        let Some(mut event) = build(event_type, ts_millis, agent_id, run_id, on_behalf_of, data)
        else {
            let n = self
                .skipped
                .fetch_add(1, std::sync::atomic::Ordering::Relaxed)
                + 1;
            return EmitOutcome::SkippedNoAgentId { skipped_total: n };
        };

        // Checked here rather than in `build`: an id the envelope rejects is
        // still a real event about a real agent, and refusing to build it would
        // empty the log for exactly the operator who needs to see the fault.
        // Written, counted, and reported, which is engram's and verdryx's
        // decision for the same problem.
        let nonconforming = !is_canonical_agent_id(&event.agent_id);

        let mut sink = sink.lock().unwrap();
        event.prev_hash = sink.next.clone();
        let Some(mut line) = to_ndjson_line(&event) else {
            // Unreachable in practice (see `to_ndjson_line`'s doc); treat as a
            // write error rather than panicking on the hot path.
            let n = self
                .write_errors
                .fetch_add(1, std::sync::atomic::Ordering::Relaxed)
                + 1;
            return EmitOutcome::WriteError {
                errors_total: n,
                message: "event serialization failed".to_string(),
            };
        };
        line.push('\n');
        use std::io::Write;
        match sink.file.write_all(line.as_bytes()) {
            Ok(()) => {
                // chain_hash is prev-hash-independent, so this is the same
                // value a verifier recomputes from the line on disk.
                sink.next = chain_hash(&event);
                if nonconforming {
                    // Counted only once the line is actually on the bus. A write
                    // that failed is reported as a WriteError, which is louder,
                    // and counting it here too would report one fault twice.
                    let n = self
                        .nonconforming
                        .fetch_add(1, std::sync::atomic::Ordering::Relaxed)
                        + 1;
                    return EmitOutcome::WrittenNonconformingAgentId {
                        nonconforming_total: n,
                    };
                }
                EmitOutcome::Written
            }
            Err(e) => {
                let n = self
                    .write_errors
                    .fetch_add(1, std::sync::atomic::Ordering::Relaxed)
                    + 1;
                EmitOutcome::WriteError {
                    errors_total: n,
                    message: e.to_string(),
                }
            }
        }
    }

    pub fn skipped_count(&self) -> u64 {
        self.skipped.load(std::sync::atomic::Ordering::Relaxed)
    }

    /// How many emitted events carried an `agent_id` the envelope rejects.
    pub fn nonconforming_agent_id_count(&self) -> u64 {
        self.nonconforming
            .load(std::sync::atomic::Ordering::Relaxed)
    }

    pub fn write_error_count(&self) -> u64 {
        self.write_errors.load(std::sync::atomic::Ordering::Relaxed)
    }
}

/// The chain hash of the last well-formed JSON line in `file`, reading at
/// most the final 1 MiB (a real envelope is hundreds of bytes; the window is
/// orders of magnitude of slack). `None` for an empty file, an I/O error, or
/// a tail that does not parse - all of which mean "start a fresh chain".
fn tail_chain_hash(file: &mut std::fs::File) -> Option<String> {
    use std::io::{Read, Seek, SeekFrom};

    const WINDOW: u64 = 1 << 20;
    let len = file.metadata().ok()?.len();
    if len == 0 {
        return None;
    }
    let start = len.saturating_sub(WINDOW);
    file.seek(SeekFrom::Start(start)).ok()?;
    let mut buf = Vec::with_capacity((len - start) as usize);
    file.read_to_end(&mut buf).ok()?;

    let mut last: Option<&[u8]> = None;
    for (i, line) in buf.split(|b| *b == b'\n').enumerate() {
        // A mid-file cut leaves the first scanned "line" partial; skip it.
        if i == 0 && start > 0 {
            continue;
        }
        let trimmed = line.trim_ascii();
        if !trimmed.is_empty() {
            last = Some(trimmed);
        }
    }
    let value: serde_json::Value = serde_json::from_slice(last?).ok()?;
    value.as_object()?;
    Some(chain_hash_value(value))
}

#[cfg(test)]
mod tests {
    use super::*;

    // -- severity mapping --------------------------------------------------

    #[test]
    fn severity_mapping_matches_the_documented_table() {
        for t in [EventType::BudgetExhausted, EventType::McpDrift] {
            assert_eq!(t.severity(), Severity::Critical, "{t:?}");
        }
        for t in [
            EventType::SustainedLoop,
            EventType::SpendSpike,
            EventType::FanoutExplosion,
            EventType::DlpBlock,
            EventType::TaintBlock,
            EventType::IdentityMismatch,
            EventType::RunKilled,
            EventType::UnitCapExceeded,
            EventType::PolicyDeny,
        ] {
            assert_eq!(t.severity(), Severity::High, "{t:?}");
        }
    }

    #[test]
    fn budget_threshold_is_one_band_below_the_incident_it_warns_about() {
        // The early warning must not page at the same weight as the exhausted
        // budget it precedes, or an operator learns to ignore both.
        assert_eq!(EventType::BudgetThreshold.severity(), Severity::Medium);
        // A refused call is the enforcement path working, not an incident, and
        // a notifier with a `high` floor must leave it in the daily digest
        // rather than mail it. This was `critical` until 2026-08-03.
        assert_eq!(EventType::BreakerTripped.severity(), Severity::Medium);
        // The two that exist BECAUSE breaker_tripped is medium: a refusal
        // whose reason has no other event must still be able to reach a
        // person. See `gateway::proxy::specific_event_for`.
        assert_eq!(
            EventType::UnitCapExceeded.as_wire_str(),
            "unit_cap_exceeded"
        );
        assert_eq!(EventType::PolicyDeny.as_wire_str(), "policy_deny");
        assert_eq!(EventType::BudgetExhausted.severity(), Severity::Critical);
    }

    #[test]
    fn wire_strings_match_the_spec_registry_verbatim() {
        let cases = [
            (EventType::BudgetExhausted, "budget_exhausted"),
            (EventType::SustainedLoop, "sustained_loop"),
            (EventType::SpendSpike, "spend_spike"),
            (EventType::FanoutExplosion, "fanout_explosion"),
            (EventType::BreakerTripped, "breaker_tripped"),
            (EventType::DlpBlock, "dlp_block"),
            (EventType::TaintBlock, "taint_block"),
            (EventType::McpDrift, "mcp_drift"),
            (EventType::IdentityMismatch, "identity_mismatch"),
            (EventType::ToolCall, "tool_call"),
            (EventType::BudgetThreshold, "budget_threshold"),
            (EventType::RunKilled, "run_killed"),
        ];
        for (t, s) in cases {
            assert_eq!(t.as_wire_str(), s);
        }
    }

    #[test]
    fn tool_call_is_a_low_severity_audit_signal() {
        // A per-action audit event, not an alert: allowed tool calls must not
        // carry a high/critical severity that would page like an incident.
        assert_eq!(EventType::ToolCall.severity(), Severity::Low);
        assert_eq!(EventType::ToolCall.as_wire_str(), "tool_call");
    }

    // -- build() / envelope shape -------------------------------------------

    #[test]
    #[test]
    fn an_id_outside_the_grammar_is_not_canonical() {
        assert!(is_canonical_agent_id(
            "agent://acme.example/support/tier1-bot"
        ));
        assert!(!is_canonical_agent_id("planner"));
        assert!(!is_canonical_agent_id("agent://Acme.Example/Support"));
        assert!(!is_canonical_agent_id("user://acme.example/j.doe"));
    }

    /// Both halves of the rule, not only the grammar. The cap is the half a
    /// regex alone would miss.
    #[test]
    fn an_over_long_id_matches_the_grammar_and_is_still_not_canonical() {
        let long = format!("agent://acme.example/{}", "a".repeat(300));
        assert!(long.len() > AGENT_ID_MAX_LENGTH);
        assert!(!is_canonical_agent_id(&long));
    }

    fn build_returns_none_without_agent_id() {
        assert!(build(
            EventType::BreakerTripped,
            0,
            None,
            Some("run-1"),
            None,
            serde_json::Value::Null,
        )
        .is_none());
        assert!(build(
            EventType::BreakerTripped,
            0,
            Some(""),
            Some("run-1"),
            None,
            serde_json::Value::Null,
        )
        .is_none());
    }

    #[test]
    fn build_full_envelope_matches_spec_shape() {
        let ev = build(
            EventType::BudgetExhausted,
            1_783_566_764_100, // 2026-07-09T03:12:44.100Z
            Some("agent://acme-bank.example/support/tier1-bot"),
            Some("run-8842"),
            Some(&["user://acme-bank.example/j.doe".to_string()]),
            serde_json::json!({ "budget_usd": 2.00, "spent_usd": 2.00, "action": "blocked_402" }),
        )
        .unwrap();
        assert_eq!(ev.schema, SCHEMA);
        assert_eq!(ev.ts, "2026-07-09T03:12:44.100Z");
        assert_eq!(ev.source, "tokenfuse");
        assert_eq!(ev.kind, "budget_exhausted");
        assert_eq!(ev.severity, Severity::Critical);
        assert_eq!(ev.agent_id, "agent://acme-bank.example/support/tier1-bot");
        assert_eq!(ev.run_id.as_deref(), Some("run-8842"));
        assert_eq!(
            ev.on_behalf_of,
            Some(vec!["user://acme-bank.example/j.doe".to_string()])
        );
        assert!(ev.prev_hash.is_none());
    }

    #[test]
    fn build_omits_on_behalf_of_when_absent_or_empty() {
        let ev = build(
            EventType::McpDrift,
            0,
            Some("agent://acme.example/bot"),
            None,
            None,
            serde_json::Value::Null,
        )
        .unwrap();
        assert!(ev.on_behalf_of.is_none());

        let ev2 = build(
            EventType::McpDrift,
            0,
            Some("agent://acme.example/bot"),
            None,
            Some(&[]),
            serde_json::Value::Null,
        )
        .unwrap();
        assert!(ev2.on_behalf_of.is_none());
    }

    // -- NDJSON line golden shape --------------------------------------------

    #[test]
    fn ndjson_line_golden_shape_and_key_order() {
        let ev = build(
            EventType::BreakerTripped,
            1_783_566_764_100,
            Some("agent://acme-bank.example/support/tier1-bot"),
            Some("run-8842"),
            None,
            serde_json::json!({ "reason": "budget_exceeded" }),
        )
        .unwrap();
        let line = to_ndjson_line(&ev).unwrap();
        let want = concat!(
            r#"{"schema":"taipanbox.dev/agent-event/v0.1","#,
            r#""ts":"2026-07-09T03:12:44.100Z","#,
            r#""source":"tokenfuse","#,
            r#""type":"breaker_tripped","#,
            // Follows the mapping, which this test does not own: `medium`
            // since 2026-08-03. What is golden here is the SHAPE and the key
            // order, not this value.
            r#""severity":"medium","#,
            r#""agent_id":"agent://acme-bank.example/support/tier1-bot","#,
            r#""run_id":"run-8842","#,
            r#""data":{"reason":"budget_exceeded"}}"#,
        );
        assert_eq!(line, want);
        // Valid, single-line JSON (NDJSON contract): parses back and round-trips
        // the required fields the JSON Schema (agent-event.schema.json) checks.
        let v: serde_json::Value = serde_json::from_str(&line).unwrap();
        assert_eq!(v["schema"], "taipanbox.dev/agent-event/v0.1");
        assert!(v.get("ts").is_some());
        assert_eq!(v["source"], "tokenfuse");
        assert_eq!(v["type"], "breaker_tripped");
        assert!(v.get("agent_id").is_some());
        assert!(!line.contains('\n'));
    }

    #[test]
    fn ndjson_line_omits_null_optionals() {
        let ev = build(
            EventType::TaintBlock,
            0,
            Some("agent://acme.example/bot"),
            None,
            None,
            serde_json::Value::Null,
        )
        .unwrap();
        let line = to_ndjson_line(&ev).unwrap();
        let v: serde_json::Value = serde_json::from_str(&line).unwrap();
        assert!(v.get("run_id").is_none());
        assert!(v.get("on_behalf_of").is_none());
        assert!(v.get("data").is_none());
        assert!(v.get("prev_hash").is_none());
    }

    // -- Exporter: disabled / skip / write -----------------------------------

    #[test]
    fn disabled_exporter_is_a_pure_no_op() {
        let exp = Exporter::disabled();
        assert!(!exp.is_enabled());
        let outcome = exp.emit(
            EventType::BreakerTripped,
            0,
            Some("agent://acme.example/bot"),
            None,
            None,
            serde_json::Value::Null,
        );
        assert_eq!(outcome, EmitOutcome::Disabled);
        assert_eq!(exp.skipped_count(), 0);
    }

    #[test]
    fn from_env_is_disabled_when_var_unset() {
        std::env::remove_var(EVENTS_PATH_ENV);
        let exp = Exporter::from_env();
        assert!(!exp.is_enabled());
    }

    #[test]
    fn emit_without_agent_id_is_skipped_and_counted() {
        let dir = std::env::temp_dir().join(format!("tf-agent-event-{}-a", std::process::id()));
        let path = dir.join("events.ndjson");
        std::fs::create_dir_all(&dir).unwrap();
        let exp = Exporter::open(path.to_str().unwrap()).unwrap();

        let outcome = exp.emit(
            EventType::DlpBlock,
            0,
            None,
            Some("run-1"),
            None,
            serde_json::Value::Null,
        );
        assert_eq!(outcome, EmitOutcome::SkippedNoAgentId { skipped_total: 1 });
        assert_eq!(exp.skipped_count(), 1);
        // Nothing written to the file for a skipped event.
        let contents = std::fs::read_to_string(&path).unwrap_or_default();
        assert_eq!(contents, "");

        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn emit_appends_one_ndjson_line_per_call() {
        let dir = std::env::temp_dir().join(format!("tf-agent-event-{}-b", std::process::id()));
        let path = dir.join("events.ndjson");
        std::fs::create_dir_all(&dir).unwrap();
        let exp = Exporter::open(path.to_str().unwrap()).unwrap();

        for i in 0..3 {
            let outcome = exp.emit(
                EventType::TaintBlock,
                i,
                Some("agent://acme.example/bot"),
                Some("run-1"),
                None,
                serde_json::Value::Null,
            );
            assert_eq!(outcome, EmitOutcome::Written);
        }
        let contents = std::fs::read_to_string(&path).unwrap();
        let lines: Vec<&str> = contents.lines().collect();
        assert_eq!(lines.len(), 3);
        for line in lines {
            let v: serde_json::Value = serde_json::from_str(line).unwrap();
            assert_eq!(v["type"], "taint_block");
        }

        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn open_nonexistent_directory_errors_cleanly() {
        let err = Exporter::open("/nonexistent/tf-agent-event-dir-xyz/events.ndjson").unwrap_err();
        assert!(err.contains("nonexistent"), "{err}");
    }

    // -- the SPEC §6.5 prev_hash chain ---------------------------------------

    /// The cross-language pinned vectors
    /// (agent-stack-go/event/testdata/chain-vectors.json): the Go and Python
    /// implementations pin the SAME canonical bytes and hashes, so the three
    /// cannot drift silently. Pinned at the JSON-value level because the
    /// vector events carry other services' source/schema values, which
    /// `AgentEvent` (source "tokenfuse", schema v0.1) deliberately cannot
    /// represent - the canonicalize+hash pipeline is what must agree.
    #[test]
    fn cross_language_chain_vectors_pin() {
        let cases = [
            (
                serde_json::json!({
                    "schema": "taipanbox.dev/agent-event/v0.2",
                    "ts": "2026-07-24T12:00:00Z",
                    "source": "wardryx",
                    "type": "policy_deny",
                    "agent_id": "agent://acme.example/support/tier1-bot",
                    "severity": "high",
                    "run_id": "run-0001",
                    "data": { "policy": "finance-guard", "reason": "deny_tool: shell" }
                }),
                r#"{"agent_id":"agent://acme.example/support/tier1-bot","data":{"policy":"finance-guard","reason":"deny_tool: shell"},"run_id":"run-0001","schema":"taipanbox.dev/agent-event/v0.2","severity":"high","source":"wardryx","ts":"2026-07-24T12:00:00Z","type":"policy_deny"}"#,
                "sha256:b43502c0ed6893238f2635be7a909cde89df1c2eecaef4d84871b83cf21cb31b",
            ),
            (
                serde_json::json!({
                    "schema": "taipanbox.dev/agent-event/v0.2",
                    "ts": "2026-07-24T12:00:01Z",
                    "source": "tokenfuse",
                    "type": "budget_exhausted",
                    "agent_id": "agent://acme.example/support/tier1-bot",
                    "severity": "critical",
                    "run_id": "run-0001",
                    "on_behalf_of": ["user://acme.example/alice", "agent://acme.example/orchestrator"],
                    "data": { "budget_usd": 12.5, "n": 3, "note": "обмеження діє", "nested": { "b": 2, "a": 1 } }
                }),
                r#"{"agent_id":"agent://acme.example/support/tier1-bot","data":{"budget_usd":12.5,"n":3,"nested":{"a":1,"b":2},"note":"обмеження діє"},"on_behalf_of":["user://acme.example/alice","agent://acme.example/orchestrator"],"run_id":"run-0001","schema":"taipanbox.dev/agent-event/v0.2","severity":"critical","source":"tokenfuse","ts":"2026-07-24T12:00:01Z","type":"budget_exhausted"}"#,
                "sha256:488f1017967bf9510c62d7c31b9d5a0086ff2000d90a7d4266f171a131430243",
            ),
            (
                serde_json::json!({
                    "schema": "taipanbox.dev/agent-event/v0.2",
                    "ts": "2026-07-24T12:00:02Z",
                    "source": "qryx",
                    "type": "evidence_signed",
                    "agent_id": "agent://acme.example/support/tier1-bot",
                    "severity": "info",
                    "data": { "algo": "ML-DSA-87" }
                }),
                r#"{"agent_id":"agent://acme.example/support/tier1-bot","data":{"algo":"ML-DSA-87"},"schema":"taipanbox.dev/agent-event/v0.2","severity":"info","source":"qryx","ts":"2026-07-24T12:00:02Z","type":"evidence_signed"}"#,
                "sha256:998cbc146b07e115318ce378e0579fcd1927066ef4316900ec7d66ba157e7c4b",
            ),
        ];
        for (i, (value, want_canonical, want_hash)) in cases.iter().enumerate() {
            let got_canonical = crate::jcs::canonicalize(value);
            assert_eq!(&got_canonical, want_canonical, "vector {} canonical", i + 1);
            let got_hash = chain_hash_value(value.clone());
            assert_eq!(&got_hash, want_hash, "vector {} hash", i + 1);
        }
    }

    #[test]
    fn chain_hash_is_independent_of_the_events_own_prev_hash() {
        let mut ev = build(
            EventType::BreakerTripped,
            1_783_566_764_100,
            Some("agent://acme.example/bot"),
            Some("run-1"),
            None,
            serde_json::json!({ "reason": "budget_exceeded" }),
        )
        .unwrap();
        let unchained = chain_hash(&ev).unwrap();
        ev.prev_hash = Some(
            "sha256:ababababababababababababababababababababababababababababababababab".into(),
        );
        assert_eq!(chain_hash(&ev).unwrap(), unchained);
    }

    #[test]
    fn emit_chains_lines_and_resumes_across_reopen() {
        let dir = std::env::temp_dir().join(format!("tf-agent-event-{}-c", std::process::id()));
        let path = dir.join("events.ndjson");
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::remove_file(&path).ok();

        let exp = Exporter::open(path.to_str().unwrap()).unwrap();
        assert!(exp.resumed_from().is_none(), "fresh file, fresh chain");
        for i in 0..2 {
            assert_eq!(
                exp.emit(
                    EventType::TaintBlock,
                    i,
                    Some("agent://acme.example/bot"),
                    Some("run-1"),
                    None,
                    serde_json::Value::Null,
                ),
                EmitOutcome::Written
            );
        }

        let contents = std::fs::read_to_string(&path).unwrap();
        let lines: Vec<&str> = contents.lines().collect();
        assert_eq!(lines.len(), 2);
        let first: serde_json::Value = serde_json::from_str(lines[0]).unwrap();
        let second: serde_json::Value = serde_json::from_str(lines[1]).unwrap();
        assert!(first.get("prev_hash").is_none(), "head is unchained");
        assert_eq!(
            second["prev_hash"].as_str().unwrap(),
            chain_hash_value(first.clone()),
            "line 2 links to line 1"
        );

        // Reopen: the chain resumes from the tail, no second head.
        let exp2 = Exporter::open(path.to_str().unwrap()).unwrap();
        assert_eq!(
            exp2.resumed_from().as_deref(),
            Some(chain_hash_value(second.clone()).as_str())
        );
        assert_eq!(
            exp2.emit(
                EventType::TaintBlock,
                2,
                Some("agent://acme.example/bot"),
                Some("run-1"),
                None,
                serde_json::Value::Null,
            ),
            EmitOutcome::Written
        );
        let contents = std::fs::read_to_string(&path).unwrap();
        let third: serde_json::Value =
            serde_json::from_str(contents.lines().last().unwrap()).unwrap();
        assert_eq!(
            third["prev_hash"].as_str().unwrap(),
            chain_hash_value(second),
            "the chain continues across a restart"
        );

        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn a_malformed_tail_starts_a_fresh_chain_fail_open() {
        let dir = std::env::temp_dir().join(format!("tf-agent-event-{}-d", std::process::id()));
        let path = dir.join("events.ndjson");
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(&path, "{not json at all\n").unwrap();

        let exp = Exporter::open(path.to_str().unwrap()).unwrap();
        assert!(exp.resumed_from().is_none(), "unusable tail = fresh chain");
        assert_eq!(
            exp.emit(
                EventType::DlpBlock,
                0,
                Some("agent://acme.example/bot"),
                None,
                None,
                serde_json::Value::Null,
            ),
            EmitOutcome::Written
        );
        let contents = std::fs::read_to_string(&path).unwrap();
        let last: serde_json::Value =
            serde_json::from_str(contents.lines().last().unwrap()).unwrap();
        assert!(last.get("prev_hash").is_none(), "fresh head after garbage");

        std::fs::remove_dir_all(&dir).ok();
    }
}
