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
    /// One of THIS BOX'S OWN dependencies failed: the model provider could not
    /// be reached or died mid-answer, or the policy plane could not be asked.
    ///
    /// The first type in this taxonomy that is not about an agent. Every
    /// variant above it is either the agent misbehaving or this gateway
    /// refusing it, which is what made the gap worth a type rather than a log
    /// line: measured 2026-08-25 against a gateway whose upstream was pointed
    /// at a dead port, the refusal degraded correctly (502, no hang, no
    /// invented answer, reservation released at zero) and **nothing anywhere
    /// in the estate recorded that it had happened**. `mockryx`'s
    /// `provider-outage-game-day` drill fails on exactly that and keeps
    /// failing until this is emitted.
    ///
    /// **One type, with `data.dependency` saying which one**, rather than
    /// `upstream_failure` beside a later `policy_plane_unreachable`. The same
    /// decision SPEC.md §6.2 records for idryx's `identity_finding`: one name a
    /// consumer routes on, the detail in `data`, instead of a row in the
    /// registry and an entry in every consumer's render catalogue per
    /// dependency. This box has more than two dependencies and will grow more.
    ///
    /// `data` carries `{dependency, stage, effect, detail}`:
    /// `dependency` is `provider` | `policy_plane`; `stage` is where in the
    /// call it happened (`send` | `stream` | `response_body` | `decide`);
    /// `detail` is the transport error, capped at
    /// [`DEPENDENCY_DETAIL_MAX_CHARS`]; and `effect` is what this gateway then
    /// DID, which is the member a consumer must not skip:
    ///
    /// - `call_failed` — the call did not complete. The agent got an error.
    /// - `allowed_ungoverned` — the policy plane could not be reached and
    ///   `failmode=open` (the default) let the call proceed. **Nothing
    ///   governed this call**, and a consumer that files this beside an
    ///   ordinary outage is filing a governance gap as a provider problem.
    /// - `denied_unasked` — the policy plane could not be reached and
    ///   `failmode=closed` refused the call. Not the same fact as a policy
    ///   denying it, and `policy_deny` would say the wrong one.
    ///
    /// Severity `high`, and `high` rather than `critical` for the reason
    /// `breaker_tripped` was lowered on 2026-08-03: `critical` is where
    /// `budget_exhausted` and `mcp_drift` live, and a provider having a bad
    /// afternoon does not belong in the band an operator has reserved for
    /// money gone and a rug-pull. `high` clears heraldyx's default floor and
    /// stack-up's `medium` one, so a person is told either way.
    ///
    /// The severity is one value for a type that covers a provider outage and
    /// a silently ungoverned call, and that is deliberate rather than
    /// unfinished: severity is fixed per type in this crate precisely so no
    /// emission site can pick one, and splitting the band would mean splitting
    /// the type. Which case it was is in `effect`, where a consumer can read
    /// it, rather than in a number two cases have to share.
    DependencyFailed,
    /// The agent firewall WOULD have refused an action, and did not, because
    /// it is running in shadow mode (`TOKENFUSE_FIREWALL=shadow`).
    ///
    /// Added 2026-08-26. Before it, a would-block set the `x-fuse-taint`
    /// response header and emitted nothing, so the only party ever told was
    /// the agent that had just been talked into the action. docs/07 B.9 makes
    /// shadow the documented on-ramp ("shadow mode for the remaining rules
    /// during the first week"); a week of it produced no material to decide
    /// on, which is the same shape of gap `dependency_failed` closed one day
    /// earlier: the thing happened, correctly, and nothing wrote it down.
    ///
    /// `medium`, and the band is the whole judgement in this variant, so it is
    /// worth stating what it is NOT. It is not `low`: in shadow the dangerous
    /// action was PERMITTED, the response carrying it reaches the client, and
    /// the client executes it, so this is a thing that HAPPENED rather than a
    /// refusal that worked. It is not `high` either, and that is the harder
    /// call: `high` is where `taint_block` sits, and a shadow week emitting at
    /// `taint_block`'s band would page an operator for every finding during
    /// precisely the week they were told to watch quietly. An operator who
    /// turns the sender off in week one never gets to week two. `medium`
    /// clears stack-up's floor, so it is not silence.
    ///
    /// `data` is [`taint_verdict_data`], identical in shape to
    /// `taint_block`'s: the same question was asked and answered, and only
    /// `mode` differs. A consumer counting rule hits should be able to read
    /// both with one code path, which is also what makes a shadow-to-enforce
    /// comparison arithmetic rather than a migration.
    TaintShadow,
    /// A run picked up a taint label it did not have before: it read the web,
    /// opened an upload, called an unknown tool, or the caller declared it.
    ///
    /// Added 2026-08-26, and it is the beginning of the story whose end
    /// `taint_block` already recorded. Without it an operator reads "blocked,
    /// context was [web, file]" and has no way at all to learn WHERE the web
    /// came from: taint is monotonic and accumulates silently across a run's
    /// whole history, so by the time anything is refused the acquisition is
    /// many calls in the past and was never written anywhere.
    ///
    /// `low`, the same band as `tool_call` and for the same reason: this is a
    /// per-action audit signal and nothing has gone wrong. Bounded per run by
    /// construction, since taint only ever grows and a label is new once.
    ///
    /// `data` is [`taint_raised_data`]: `{stage, added, from_tools, carrying,
    /// unit}`. `carrying` is the full set AFTER the addition, so a reader
    /// following a run forward never has to re-derive the running total.
    TaintRaised,
}

/// How much of a transport error's text travels in `data.detail`.
///
/// Capped because the string comes from whatever the HTTP client had to say
/// about a failure, and an unbounded field on a per-call event is a line of
/// NDJSON whose length an operator's upstream chose. What it holds is the
/// error text and the configured upstream host, never a request body: nothing
/// on the failure paths that emit this has parsed the body into the error.
pub const DEPENDENCY_DETAIL_MAX_CHARS: usize = 200;

/// Which of the box's own dependencies failed (`data.dependency`).
///
/// An enum rather than a `&str` at the call site for the reason the severity
/// mapping is not caller-supplied: two emission sites spelling the same
/// dependency differently would put two names for one thing on a shared bus,
/// and every downstream count of them would be wrong.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Dependency {
    /// The model provider this gateway forwards to.
    Provider,
    /// The policy decision point (wardryx).
    PolicyPlane,
}

impl Dependency {
    pub fn as_wire_str(self) -> &'static str {
        match self {
            Dependency::Provider => "provider",
            Dependency::PolicyPlane => "policy_plane",
        }
    }
}

/// Where in the call the dependency failed (`data.stage`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DependencyStage {
    /// The request could not be sent, or the send returned an error.
    Send,
    /// The answer had started and the stream broke partway through.
    Stream,
    /// The answer arrived and its body could not be collected.
    ResponseBody,
    /// The policy plane could not be asked for a decision.
    Decide,
}

impl DependencyStage {
    pub fn as_wire_str(self) -> &'static str {
        match self {
            DependencyStage::Send => "send",
            DependencyStage::Stream => "stream",
            DependencyStage::ResponseBody => "response_body",
            DependencyStage::Decide => "decide",
        }
    }
}

/// What this gateway did about it (`data.effect`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DependencyEffect {
    /// The call did not complete and the caller got an error.
    CallFailed,
    /// The policy plane was unreachable and `failmode=open` let the call
    /// through. Nothing governed it.
    AllowedUngoverned,
    /// The policy plane was unreachable and `failmode=closed` refused the
    /// call. Nobody was asked; no policy denied it.
    DeniedUnasked,
}

impl DependencyEffect {
    pub fn as_wire_str(self) -> &'static str {
        match self {
            DependencyEffect::CallFailed => "call_failed",
            DependencyEffect::AllowedUngoverned => "allowed_ungoverned",
            DependencyEffect::DeniedUnasked => "denied_unasked",
        }
    }
}

/// The `data` object for [`EventType::DependencyFailed`], built in one place.
///
/// A constructor rather than a `json!` at each of the five emission sites: the
/// member names are the published contract (SPEC.md §6.2), four call sites
/// spelling them by hand is four chances to write `dep` or `reason` on a bus
/// three other repositories parse, and this is the shape invariant 14 is about
/// one scale down.
pub fn dependency_failed_data(
    dependency: Dependency,
    stage: DependencyStage,
    effect: DependencyEffect,
    detail: &str,
) -> serde_json::Value {
    serde_json::json!({
        "dependency": dependency.as_wire_str(),
        "stage": stage.as_wire_str(),
        "effect": effect.as_wire_str(),
        "detail": truncate_detail(detail),
    })
}

/// Cut `detail` to [`DEPENDENCY_DETAIL_MAX_CHARS`] on a CHARACTER boundary.
///
/// By characters and not by bytes: `&s[..200]` panics in the middle of a
/// multi-byte sequence, and an error message is somebody else's text, which
/// means it can carry any UTF-8 at all. A truncated value ends with `…` so a
/// reader can tell a cut string from a short one.
fn truncate_detail(detail: &str) -> String {
    if detail.chars().count() <= DEPENDENCY_DETAIL_MAX_CHARS {
        return detail.to_string();
    }
    let mut out: String = detail.chars().take(DEPENDENCY_DETAIL_MAX_CHARS).collect();
    out.push('…');
    out
}

/// A stable identifier for the instruction an agent was given this turn.
///
/// `sha384:<hex>` over the LAST user message's text, or `None` when the
/// request carries none. SHA-384 because that is the width trailryx's records
/// use, so if the two ever have to be joined they join without a re-hash.
///
/// # The last user message, not the whole history
///
/// Hashing the conversation would produce a value that changes on every turn
/// and therefore groups nothing, which is the opposite of what the identifier
/// is for. What `@yurii` asked on 2026-08-26 was "після яких саме промтів агент
/// почав робити аномалії", and answering it means being able to say that four
/// incidents came from ONE instruction, or that the instruction changed at the
/// turn things went wrong. Only the newest instruction has that property.
///
/// # A hash, and only a hash
///
/// This is not a step towards putting prompts in the record, and it is useful
/// without one: identical prompts collapse, a changed prompt is visible at the
/// turn it changed, and a prompt somebody still has can be confirmed against
/// it. What it cannot do is tell you what the text said, which is the point.
/// Nothing here holds content, so nothing here needs erasing.
///
/// Both request shapes are read: Anthropic's `messages[].content` as a string
/// or as an array of `{"type":"text","text":...}` blocks, and OpenAI's flat
/// string. A shape neither of those covers hashes to `None` rather than to
/// something: an identifier computed over a structure this function did not
/// understand would group unrelated turns together, which is worse than an
/// absent field because it looks like an answer.
pub fn prompt_hash(request: &serde_json::Value) -> Option<String> {
    let msgs = request.get("messages")?.as_array()?;
    let last_user = msgs
        .iter()
        .rev()
        .find(|m| m.get("role").and_then(|r| r.as_str()) == Some("user"))?;
    let text = message_text(last_user.get("content")?)?;
    if text.is_empty() {
        return None;
    }
    let digest = <sha2::Sha384 as sha2::Digest>::digest(text.as_bytes());
    let mut hex = String::with_capacity(digest.len() * 2 + 7);
    hex.push_str("sha384:");
    for b in digest {
        hex.push(char::from_digit(u32::from(b >> 4), 16).unwrap_or('0'));
        hex.push(char::from_digit(u32::from(b & 0x0f), 16).unwrap_or('0'));
    }
    Some(hex)
}

/// The text of one message's `content`, across the two shapes on the wire.
///
/// Blocks are joined with `\n` rather than concatenated, so two turns whose
/// blocks split differently across the same words do not collide.
fn message_text(content: &serde_json::Value) -> Option<String> {
    if let Some(t) = content.as_str() {
        return Some(t.to_string());
    }
    let blocks = content.as_array()?;
    let parts: Vec<&str> = blocks
        .iter()
        .filter(|b| b.get("type").and_then(|t| t.as_str()) == Some("text"))
        .filter_map(|b| b.get("text").and_then(|t| t.as_str()))
        .collect();
    (!parts.is_empty()).then(|| parts.join("\n"))
}

/// Where in a call the agent firewall acted (`data.stage`).
///
/// The member `@yurii` asked for first on 2026-08-26 ("на якому етапі"), and
/// the one a record is least useful without: "blocked" and "blocked while
/// reading the request" are different facts to whoever has to decide whether
/// the run got anywhere. Three stages and not more, because the gateway only
/// has three places it can see anything: the request as it arrives, the
/// caller's own declaration on it, and the tool calls in the model's answer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TaintStage {
    /// Reading the message history that arrived with the request: a tool the
    /// agent had already called is what carried the label in.
    RequestHistory,
    /// The caller declared taint itself on the `x-fuse-taint` request header.
    /// Trusted precisely because it can only ever ADD: taint is monotonic, so
    /// a caller can make itself more restricted and never less.
    RequestHeader,
    /// Judging the tool calls in the model's own answer (docs/07 B.7 level 1,
    /// advisory: the gateway sees the request, the CLIENT executes the tool).
    ModelToolCall,
    /// The label came from an ancestor run, per docs/07 B.3 P3.
    ///
    /// Added 2026-08-26 with the inheritance itself. Until then the taint map
    /// was keyed on `run_id` alone, so a tainted run could spawn a child that
    /// started clean, and the whole firewall was one `x-fuse-parent-run-id`
    /// header away from being switched off. A reader of a refusal on the child
    /// needs this stage to see that its labels were never about anything the
    /// child itself did.
    ParentRun,
    /// An executor asked before running a tool (docs/07 B.7 level 2), through
    /// `POST /v1/fuse/check-tool-call`. The hard guarantee: the answer is
    /// given BEFORE the tool runs rather than alongside a response the client
    /// is free to ignore.
    ToolCallCheck,
    /// The MCP broker judged a `tools/call` before forwarding it (docs/07 B.7
    /// level 3). Distinct from [`ToolCallCheck`](Self::ToolCallCheck) even
    /// though the broker reaches the same judge through the same endpoint: an
    /// operator reading a refusal needs to know whether a tool was stopped
    /// because an SDK asked politely or because it went through a door that
    /// stops things whether or not anybody asks.
    McpToolCall,
}

impl TaintStage {
    pub fn as_wire_str(self) -> &'static str {
        match self {
            TaintStage::RequestHistory => "request_history",
            TaintStage::RequestHeader => "request_header",
            TaintStage::ModelToolCall => "model_tool_call",
            TaintStage::ParentRun => "parent_run",
            TaintStage::ToolCallCheck => "tool_call_check",
            TaintStage::McpToolCall => "mcp_tool_call",
        }
    }
}

/// Which firewall mode produced a verdict (`data.mode`).
///
/// On the event and not left to be inferred from the type, even though
/// `taint_block` implies enforce and `taint_shadow` implies shadow. A
/// consumer joining the two families into one count should not have to know
/// that mapping, and an operator comparing a shadow week against an enforced
/// one is reading this field.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TaintEnforcement {
    Shadow,
    Enforce,
}

impl TaintEnforcement {
    pub fn as_wire_str(self) -> &'static str {
        match self {
            TaintEnforcement::Shadow => "shadow",
            TaintEnforcement::Enforce => "enforce",
        }
    }
}

/// The `data` object for [`EventType::TaintBlock`] and
/// [`EventType::TaintShadow`], built in one place.
///
/// One builder for both on purpose: they answer the same question and differ
/// only in `mode`, so two builders would be two chances for the shapes to
/// drift apart and make the arithmetic an operator does between a shadow week
/// and an enforced one stop working.
///
/// `tools` is what the model asked to DO, by name, and it is the member that
/// turns a record into something actionable: `denied: ["exec"]` says a
/// category was refused, `tools: ["run_shell"]` says which door was tried.
pub fn taint_verdict_data(
    stage: TaintStage,
    mode: TaintEnforcement,
    verdict: &crate::taint::TaintVerdict,
    tools: &[String],
    prompt: Option<&str>,
    unit: &str,
) -> serde_json::Value {
    serde_json::json!({
        // Which instruction was in play when this fired. See [`prompt_hash`]:
        // a hash and only a hash, so the field groups incidents by the thing
        // that caused them without the record holding a word of it.
        "prompt_hash": prompt,
        "stage": stage.as_wire_str(),
        "mode": mode.as_wire_str(),
        "rule": verdict.rule,
        "labels": verdict.labels,
        "requested": verdict.requested,
        "denied": verdict.denied,
        "tools": tools,
        // As on every other enforcement event, and for the same reason: a
        // consumer cannot tell an event that omits the field from one whose
        // identity map resolved nothing.
        "unit": (!unit.is_empty()).then_some(unit),
    })
}

/// The `data` object for [`EventType::TaintRaised`], built in one place.
///
/// `added` is only what was NEW to this run, never the whole set: a run that
/// reads the web on every one of forty turns became untrusted once, and forty
/// identical rows would bury the one turn that mattered.
///
/// `carrying` is the full set after the addition, so a reader walking a run
/// forward in time never has to re-derive the running total to know what the
/// next refusal will be judged against.
pub fn taint_raised_data(
    stage: TaintStage,
    added: &[String],
    from_tools: &[String],
    carrying: &[String],
    prompt: Option<&str>,
    unit: &str,
) -> serde_json::Value {
    serde_json::json!({
        // On the ACQUISITION as well as on the verdict, and this is the half an
        // investigation starts from: the turn a run became untrusted is the turn
        // whose instruction is worth reading.
        "prompt_hash": prompt,
        "stage": stage.as_wire_str(),
        "added": added,
        "from_tools": from_tools,
        "carrying": carrying,
        "unit": (!unit.is_empty()).then_some(unit),
    })
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
            EventType::DependencyFailed => "dependency_failed",
            EventType::TaintShadow => "taint_shadow",
            EventType::TaintRaised => "taint_raised",
        }
    }

    /// Fixed severity per event type — NOT caller-supplied, so no emission
    /// site can misclassify an event. Mapping:
    /// `budget_exhausted` / `mcp_drift` = `critical`;
    /// `sustained_loop` / `spend_spike` / `fanout_explosion` / `dlp_block` /
    /// `taint_block` / `identity_mismatch` (docs/20) / `run_killed` /
    /// `unit_cap_exceeded` / `policy_deny` / `dependency_failed` = `high`;
    /// `budget_threshold` / `breaker_tripped` / `taint_shadow` = `medium`;
    /// `tool_call` / `taint_raised` = `low`.
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
            | EventType::PolicyDeny
            | EventType::DependencyFailed => Severity::High,
            // An early warning, on purpose one band below the incident it
            // warns about: the run is still inside its budget. Beside it, the
            // per-call record of a refusal that already happened, which is the
            // enforcement path doing its job rather than an incident.
            // Beside them, the firewall's shadow finding: a dangerous action
            // that was permitted because enforcement is off. Not an incident,
            // and not silence either. See the variant's own note.
            EventType::BudgetThreshold | EventType::BreakerTripped | EventType::TaintShadow => {
                Severity::Medium
            }
            // A per-action audit signal, not an alert: the allow/deny/hold is
            // in `data.decision`, so allowed calls do not page like incidents.
            // Taint acquisition sits here for the same reason: a run reading
            // the web is normal, and only what it does next may not be.
            EventType::ToolCall | EventType::TaintRaised => Severity::Low,
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

/// How many DISTINCT non-conforming agent ids to remember for the operator.
///
/// Bounded because the id comes from a caller-controlled header: an unbounded
/// set here is a memory leak anybody with a key can drive. Thirty-two describes
/// a misconfigured fleet as well as three thousand would, and the COUNT stays
/// exact whatever the set drops.
pub const NONCONFORMING_SAMPLE_CAP: usize = 32;

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
    /// The distinct offending ids, bounded by [`NONCONFORMING_SAMPLE_CAP`].
    /// A `Mutex<BTreeSet>` rather than anything cleverer: this is touched only
    /// on the failure path, which on a healthy gateway is never.
    nonconforming_ids: std::sync::Mutex<std::collections::BTreeSet<String>>,
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
            nonconforming_ids: std::sync::Mutex::new(std::collections::BTreeSet::new()),
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
            nonconforming_ids: std::sync::Mutex::new(std::collections::BTreeSet::new()),
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
        if nonconforming {
            let mut seen = self.nonconforming_ids.lock().unwrap();
            if seen.len() < NONCONFORMING_SAMPLE_CAP {
                seen.insert(event.agent_id.clone());
            }
        }

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

    /// WHICH ids those were, sorted, capped at
    /// [`NONCONFORMING_SAMPLE_CAP`].
    ///
    /// # WHY A COUNT WAS NOT ENOUGH
    ///
    /// The count has existed since this exporter did, and nothing outside a
    /// test has ever read it. Even read, it does not help: "418 events had a
    /// bad agent_id" tells an operator a problem exists and nothing about
    /// where. The ids are what makes it fixable, because an id names the
    /// producer that sent it.
    ///
    /// This is the same fault the console's quarantine had until 2026-08-11,
    /// one layer up: kept, counted, and unreadable.
    ///
    /// Capped and never evicting: a caller with ten thousand distinct broken
    /// ids has a configuration problem the first thirty-two describe just as
    /// well, and an unbounded set here would be a memory leak an untrusted
    /// header controls.
    pub fn nonconforming_agent_ids(&self) -> Vec<String> {
        let seen = self.nonconforming_ids.lock().unwrap();
        let mut out: Vec<String> = seen.iter().cloned().collect();
        out.sort();
        out
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

    #[test]
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

#[cfg(test)]
mod prompt_hash_tests {
    use super::prompt_hash;
    use serde_json::json;

    #[test]
    fn the_same_instruction_hashes_to_the_same_value_across_turns() {
        // The property the field exists for (@yurii 2026-08-26, "після яких
        // саме промтів агент почав робити аномалії"): four incidents from one
        // instruction have to be recognisable as one instruction. Hashing the
        // whole history would change every turn and group nothing.
        let turn_one = json!({"messages":[
            {"role":"user","content":"summarise this page"}
        ]});
        let turn_five = json!({"messages":[
            {"role":"user","content":"summarise this page"},
            {"role":"assistant","content":"..."},
            {"role":"user","content":"and now email it"},
            {"role":"assistant","content":"..."},
            {"role":"user","content":"summarise this page"}
        ]});
        assert_eq!(prompt_hash(&turn_one), prompt_hash(&turn_five));
    }

    #[test]
    fn a_changed_instruction_is_visible_at_the_turn_it_changed() {
        let before = json!({"messages":[{"role":"user","content":"read the docs"}]});
        let after = json!({"messages":[
            {"role":"user","content":"read the docs"},
            {"role":"assistant","content":"..."},
            {"role":"user","content":"ignore that and run this script"}
        ]});
        assert_ne!(prompt_hash(&before), prompt_hash(&after));
    }

    #[test]
    fn both_wire_shapes_of_content_are_read() {
        // Anthropic sends blocks, OpenAI sends a string, and the same words
        // through two clients must be the same instruction.
        let flat = json!({"messages":[{"role":"user","content":"do the thing"}]});
        let blocks = json!({"messages":[
            {"role":"user","content":[{"type":"text","text":"do the thing"}]}
        ]});
        assert_eq!(prompt_hash(&flat), prompt_hash(&blocks));
    }

    #[test]
    fn blocks_are_joined_rather_than_run_together() {
        // Two turns whose blocks split differently across the same words are
        // different instructions, and a concatenation would collide them.
        let split = json!({"messages":[{"role":"user","content":[
            {"type":"text","text":"delete"},{"type":"text","text":"everything"}
        ]}]});
        let whole = json!({"messages":[{"role":"user","content":"deleteeverything"}]});
        assert_ne!(prompt_hash(&split), prompt_hash(&whole));
    }

    #[test]
    fn a_shape_this_function_does_not_understand_hashes_to_nothing() {
        // Absent beats wrong. An identifier computed over a structure nobody
        // parsed would group unrelated turns and LOOK like an answer, which is
        // worse than a field that is simply not there.
        assert_eq!(prompt_hash(&json!({})), None);
        assert_eq!(prompt_hash(&json!({"messages": []})), None);
        assert_eq!(
            prompt_hash(&json!({"messages":[{"role":"assistant","content":"hi"}]})),
            None,
            "no user turn is no instruction"
        );
        assert_eq!(
            prompt_hash(&json!({"messages":[{"role":"user","content":[{"type":"image"}]}]})),
            None,
            "a turn with no text is not a turn with empty text"
        );
        assert_eq!(
            prompt_hash(&json!({"messages":[{"role":"user","content":""}]})),
            None
        );
    }

    #[test]
    fn it_is_a_hash_and_carries_no_word_of_the_prompt() {
        // The whole safety argument in one assertion. This field ships today
        // precisely because it holds nothing to erase.
        let secret = "the passphrase is hunter2 and the account is 4111111111111111";
        let h = prompt_hash(&json!({"messages":[{"role":"user","content":secret}]}))
            .expect("a text turn hashes");
        assert!(h.starts_with("sha384:"));
        assert_eq!(h.len(), 7 + 96, "384 bits of hex and nothing else");
        for word in ["passphrase", "hunter2", "4111"] {
            assert!(!h.contains(word), "{h}");
        }
    }
}
