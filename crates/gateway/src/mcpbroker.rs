//! MCP credential-broker: a JSON-RPC proxy an agent points its MCP client at.
//!
//! Jobs at the boundary between the agent and a real MCP server:
//!
//! 1. **Credential brokering** - on `tools/call`, replace `{{secret:NAME}}`
//!    handles in the params with real secrets from the vault *just before*
//!    forwarding. The agent (and the LLM prompt, trace, and memory) only ever
//!    holds handles; the secret appears only on the wire to the MCP server.
//! 2. **Policy gate (the second PEP, docs/23)** - on `tools/call`, put the call
//!    to the same Wardryx PDP the LLM path uses, BEFORE injecting secrets or
//!    forwarding, so a `deny_tool` (or `deny_if_unattested`, or an approval
//!    `hold`) policy enforces at the MCP layer too. Off unless Wardryx is
//!    configured. The broker holds no signer and mutates nothing: a deny/hold
//!    is a JSON-RPC refusal. Each gated call emits one `tool_call` audit event.
//! 3. **Live poisoning + rug-pull scan** - on `tools/list`, run the
//!    tool-description scanner and diff against a pinned lockfile.
//! 4. **DLP** - block raw secrets in outgoing args and **redact** secrets in tool
//!    responses so a result can't leak a credential into the model's context.
//!
//! A request selects one of several **named upstreams** with `X-Fuse-Mcp-Upstream`
//! (`TOKENFUSE_MCP_UPSTREAMS="name=url,…"`); no header uses the default
//! `TOKENFUSE_MCP_UPSTREAM`. An unknown name is refused, never re-routed.
//!
//! Two transports share [`process`]: HTTP (`app`, default `127.0.0.1:4200`) and
//! **stdio** (`run_stdio`, for MCP clients that launch a server as a subprocess).
//! Config: `TOKENFUSE_MCP_UPSTREAM`(S), `_SECRETS` (`name=val,…`), `_SCAN`
//! (`off|warn|block`), `_DLP` (`off|warn|block`), `_DLP_PII` (`off|shadow|
//! mask|block`, a separate opt-in PII extension of `_DLP`, see
//! `tokenfuse_core::dlp`'s module doc), `_LOCK` (rug-pull baseline), `_ADDR`,
//! `_KEYS` (the broker's own client credentials, off unless set), `_STDIO`,
//! `_ALLOW_OPEN_BIND` (opt out of the refusal below, off unless set),
//! `_SECRET_SCOPES` (which agent ids and/or tool names may resolve which
//! secret, off unless set, see [`BrokerState::vault`] and
//! `docs/23-mcp-broker-v2.md` section 4), `_REQUIRE_SECRET_SCOPES` (refuse to
//! start if any configured secret has no scope rule, off unless set), plus
//! the shared `TOKENFUSE_WARDRYX_*` for the policy gate.
//! Run: `tokenfuse mcp-broker` (or `mcp-broker --stdio`).
//!
//! **What is on the door.** Whatever reaches this port can have handles
//! resolved against the whole vault, so two things guard it: the loopback
//! default and optional client credentials ([`BrokerState::keys`], off
//! unless configured). Widening the bind with credentials configured warns
//! (see [`bind_exposure_warning`]); widening it with NOTHING configured
//! REFUSES to start (see [`refuse_open_bind`]), unless the operator opts in
//! with `TOKENFUSE_MCP_ALLOW_OPEN_BIND`.

use std::collections::BTreeMap;
use std::sync::Arc;

use axum::extract::State;
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use serde_json::{json, Value};
use tokenfuse_core::agent_event::{EventType, Exporter as EventExporter};
use tokenfuse_core::mcp::{self, Lock};
use tokenfuse_core::{dlp, inject_secrets, DlpMode, SecretVault};

use crate::clientkeys::{ClientKeys, CLIENT_KEY_HEADER};
use crate::wardryx::{DecideContext, Wardryx, WardryxDecision, WardryxMode};

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum ScanMode {
    Off,
    Warn,
    Block,
}

pub struct BrokerState {
    /// The default upstream MCP server: used when a request names no upstream
    /// (via `X-Fuse-Mcp-Upstream`), and the only upstream on the stdio
    /// transport (which has no per-message header channel). Kept as its own
    /// field, distinct from [`named_upstreams`](Self::named_upstreams), so the
    /// existing single-upstream config (`TOKENFUSE_MCP_UPSTREAM`) keeps working
    /// unchanged.
    pub upstream: String,
    /// Additional named upstreams (`TOKENFUSE_MCP_UPSTREAMS="name=url,..."`).
    /// A request selects one by its `X-Fuse-Mcp-Upstream` header. An unknown
    /// name is refused, never silently sent to the default: forwarding a
    /// request (and its injected secrets) to the wrong server is exactly the
    /// mistake this refusal prevents.
    pub named_upstreams: BTreeMap<String, String>,
    /// Named secrets the broker can inject, and the optional per-secret
    /// [`tokenfuse_core::ScopeRule`]s (`TOKENFUSE_MCP_SECRET_SCOPES`) that
    /// narrow WHICH agent id and/or tool may resolve which. A secret with no
    /// rule resolves for any agent, any tool: the only behaviour before
    /// scoping existed, and still the default for a secret named in no
    /// `TOKENFUSE_MCP_SECRET_SCOPES` entry. See `docs/23-mcp-broker-v2.md`
    /// section 4 and [`process`]'s injection step.
    pub vault: SecretVault,
    pub scan: ScanMode,
    /// Scan outgoing tool-call args for raw secrets the agent pasted directly
    /// (not via a `{{secret:}}` handle). Off｜Shadow(=warn)｜Block.
    pub dlp: DlpMode,
    /// PII masks: a separate, opt-in extension of `dlp` (email/card/phone,
    /// regex-only, see `tokenfuse_core::dlp`'s module doc). Switches
    /// independently of `dlp` - Off by default, so an existing deployment
    /// sees no behavior change until it opts in.
    pub dlp_pii: DlpMode,
    /// Baseline of pinned tool fingerprints; a changed description on
    /// `tools/list` is a rug-pull. `None` disables the check.
    pub lock: Option<Lock>,
    /// The second Policy Enforcement Point (docs/23): every `tools/call` is
    /// put to Wardryx's `decide()`, the same PDP the LLM path uses, so a
    /// `deny_tool` policy now enforces at the MCP layer too. `Wardryx::disabled`
    /// (mode Off) by default, in which case the broker forwards exactly as
    /// before. The broker holds no signer and never mutates a plane: a deny or
    /// hold is a refusal returned to the caller, nothing more.
    pub wardryx: Arc<Wardryx>,
    /// Client credentials for the broker's own door (`TOKENFUSE_MCP_KEYS`), in
    /// the same `secret:key_id,...` form and resolved by the same
    /// [`ClientKeys`] the gateway uses for `TOKENFUSE_CLIENT_KEYS`. Reused
    /// rather than re-invented, including its documented decision to look a
    /// secret up in a plain `HashMap`: moving to a constant-time comparison is
    /// a posture change that belongs across every plane at once, not smuggled
    /// into one of them.
    ///
    /// Empty (the default) means the broker authenticates nobody, exactly as
    /// it always has, so no loopback deployment breaks on upgrade. Set, and
    /// every JSON-RPC call must present a known credential in
    /// [`CLIENT_KEY_HEADER`].
    pub keys: ClientKeys,
    pub client: reqwest::Client,
    /// Agent-event NDJSON exporter (agent-passport SPEC.md §6). Disabled by
    /// default; see `crate::events::from_env`. Emits `mcp_drift` (rug-pull) and
    /// `tool_call` (one per Wardryx-gated `tools/call`) -- see [`process`].
    pub events: Arc<EventExporter>,
}

/// Per-request context the HTTP transport reads off headers and the stdio
/// transport leaves empty. Keeps [`process`] transport-agnostic: everything
/// header-shaped lives here, so stdio simply passes `CallContext::default()`.
#[derive(Default)]
pub struct CallContext {
    /// `X-Fuse-Agent-Id` (agent-passport SPEC.md §3.2). Required for the
    /// Wardryx gate to attribute a `tools/call` to an agent and for any event
    /// to carry a real `agent_id`; absent on stdio.
    pub agent_id: Option<String>,
    /// `X-Fuse-Mcp-Upstream`: selects a [`named_upstreams`](BrokerState::named_upstreams)
    /// entry. Absent -> the default upstream.
    pub upstream: Option<String>,
    /// `x-fuse-on-behalf-of` (comma-separated, root first), forwarded to the
    /// PDP so a delegation-scoped policy can match.
    pub on_behalf_of: Vec<String>,
    /// `x-fuse-attestation-method`, forwarded to the PDP for a
    /// `deny_if_unattested` policy.
    pub attestation_method: Option<String>,
    /// `x-fuse-approval-token`: an operator-granted token that lets a
    /// previously-held `tools/call` through, verified by the PDP exactly as on
    /// the LLM path.
    pub approval_token: Option<String>,
}

pub fn app(state: Arc<BrokerState>) -> Router {
    // Bound the JSON-RPC body a client can force the broker to buffer.
    let max_body = std::env::var("TOKENFUSE_MAX_BODY_BYTES")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(16 * 1024 * 1024);
    Router::new()
        .route("/", post(handle))
        .route("/mcp", post(handle))
        .route("/healthz", get(|| async { "ok" }))
        .layer(axum::extract::DefaultBodyLimit::max(max_body))
        .with_state(state)
}

/// The startup warning for a bind that is not loopback, or `None` when it is.
///
/// The broker's default bind is `127.0.0.1:4200`, and until this existed that
/// default was the ONLY thing protecting it: `TOKENFUSE_MCP_ADDR` widened the
/// bind silently, and anything that reached the port could have
/// `{{secret:NAME}}` handles resolved against the whole vault and forwarded to
/// any configured upstream.
///
/// Deliberately the same shape and voice as the Cloud's own check in
/// `crates/cloud/src/main.rs`, including its loopback set (`127.0.0.1`,
/// `localhost`, `::1`) rather than a cleverer one: a bind to `127.0.0.2` warns
/// although it is also loopback, which costs one false warning, while the two
/// planes disagreeing about what "exposed" means would cost more than that.
/// Unlike the Cloud's, this one is a pure function, so the condition is
/// testable without starting a listener.
///
/// `auth_configured` is what makes the warning worth reading twice: a wide bind
/// is a decision, a wide bind with nothing on the door is a mistake, and an
/// operator who has configured credentials must not be told to configure them.
///
/// This is now only HALF of what guards a non-loopback bind: it still fires,
/// unchanged, whenever the process is allowed to start at all with one (auth
/// configured, or [`refuse_open_bind`] below was opted out of). The harder
/// case, nothing on the door and no opt-out, is [`refuse_open_bind`]'s to
/// decide, and it runs first.
pub fn bind_exposure_warning(addr: &str, auth_configured: bool) -> Option<String> {
    let addr = addr.trim();
    // "host:port" -> host, tolerating "[::1]:4200" and bare "::1:4200".
    let host = addr
        .rsplit_once(':')
        .map(|(h, _)| h)
        .unwrap_or(addr)
        .trim_matches(['[', ']']);
    if matches!(host, "127.0.0.1" | "localhost" | "::1") {
        return None;
    }
    let mut w = format!(
        "binding the MCP credential-broker to a non-loopback address ({addr}): it is now \
         reachable from the network, and anything that reaches it can have {{{{secret:NAME}}}} \
         handles resolved against the whole vault and forwarded to a configured upstream. \
         Ensure a firewall closes this port and remote access goes through a tunnel, not a \
         raw open port."
    );
    if !auth_configured {
        w.push_str(
            " No client credentials are configured either, so this port authenticates \
             nobody: set TOKENFUSE_MCP_KEYS=\"secret:key_id,...\" to require one.",
        );
    }
    Some(w)
}

/// Whether `addr` ("host:port") names a loopback interface, for the startup
/// refusal below.
///
/// Deliberately NOT [`bind_exposure_warning`]'s host set. That set is a
/// pure string match, chosen there to agree with the Cloud plane's own check
/// byte for byte, at the cost of one false warning on `127.0.0.2` (loopback,
/// but not `127.0.0.1`) -- a cost worth paying for a message that only ever
/// says more than it needs to. A REFUSAL is not a message, it is whether the
/// process runs at all, and it is wrong in both directions: undercounting
/// loopback (treating `127.0.0.2` or a bare `::1` as "exposed") breaks a
/// deployment that was never reachable from the network, and overcounting it
/// would start one that is. So this asks the standard library instead:
/// `IpAddr::is_loopback` knows the whole of `127.0.0.0/8` is loopback, not
/// just the one address a string match would name, and knows `::1` without
/// having to spell it out beside "localhost", which is handled separately
/// because it is a name, not something `IpAddr::parse` accepts.
fn is_loopback(addr: &str) -> bool {
    let addr = addr.trim();
    let host = addr
        .rsplit_once(':')
        .map(|(h, _)| h)
        .unwrap_or(addr)
        .trim_matches(['[', ']']);
    if host.eq_ignore_ascii_case("localhost") {
        return true;
    }
    host.parse::<std::net::IpAddr>()
        .map(|ip| ip.is_loopback())
        .unwrap_or(false)
}

/// Whether the broker must refuse to start for this bind, or `None` to
/// proceed exactly as before (which may still print
/// [`bind_exposure_warning`]).
///
/// Decided 2026-08-05 (audit) / 2026-08-06 (the call): a non-loopback bind
/// with no broker authentication configured refuses to start, because that
/// is the one combination with nothing at all guarding the vault, not a
/// wide-bind warning an operator can read and keep going. A wide bind WITH
/// credentials configured is unaffected, a decision this repository already
/// lets an operator make; see [`bind_exposure_warning`]. The explicit
/// opt-out, `TOKENFUSE_MCP_ALLOW_OPEN_BIND`, is for the operator who has
/// made the open-bind decision anyway; it silences the refusal, not the
/// warning, see `opting_out_of_the_refusal_does_not_silence_the_warning`
/// below.
///
/// This is a breaking change for a deployment that was relying on the
/// silent widen, which is exactly why it stayed a warning until the owner
/// made the call: see docs/12's "still open" note, now closed.
pub fn refuse_open_bind(
    addr: &str,
    auth_configured: bool,
    allow_open_bind: bool,
) -> Option<String> {
    if auth_configured || allow_open_bind || is_loopback(addr) {
        return None;
    }
    Some(format!(
        "refusing to start: the MCP credential-broker is bound to {addr}, which is not \
         loopback, and no client credentials are configured (TOKENFUSE_MCP_KEYS is unset). \
         Anything that reaches this address could have {{{{secret:NAME}}}} handles resolved \
         against the whole vault and forwarded to a configured upstream. Set \
         TOKENFUSE_MCP_KEYS=\"secret:key_id,...\" to require a credential, bind to loopback \
         instead (TOKENFUSE_MCP_ADDR=127.0.0.1:4200, the default), or, if you have \
         deliberately decided to run the broker open, set TOKENFUSE_MCP_ALLOW_OPEN_BIND=1."
    ))
}

/// The startup message for how many configured secrets carry no
/// `TOKENFUSE_MCP_SECRET_SCOPES` rule, or `None` when the vault is empty or
/// every configured secret is scoped.
///
/// An unscoped secret is resolvable by ANY agent, ANY tool: the only
/// behaviour before scoping existed, and still the default (invariant 23,
/// CLAUDE.md). That default must never be silent, so this fires whenever it
/// applies rather than only above some threshold. [`refuse_unscoped_secrets`]
/// is the opt-in stricter posture beside this warning; a warning alone is a
/// message, not a control.
pub fn unscoped_secrets_warning(vault: &SecretVault) -> Option<String> {
    let unscoped = vault.unscoped_names();
    if unscoped.is_empty() {
        return None;
    }
    Some(format!(
        "mcp broker: {} of {} configured secret(s) carry no TOKENFUSE_MCP_SECRET_SCOPES rule \
         and are resolvable by any agent, any tool: {}. Set TOKENFUSE_MCP_SECRET_SCOPES to \
         narrow them, or set TOKENFUSE_MCP_REQUIRE_SECRET_SCOPES=1 to refuse to start until \
         every secret is scoped.",
        unscoped.len(),
        vault.len(),
        unscoped.join(", ")
    ))
}

/// Whether the broker must refuse to start because
/// `TOKENFUSE_MCP_REQUIRE_SECRET_SCOPES` is on and at least one configured
/// secret carries no `TOKENFUSE_MCP_SECRET_SCOPES` rule, or `None` to
/// proceed exactly as before (which may still print
/// [`unscoped_secrets_warning`]).
///
/// `require_scopes: false` (the default) never refuses, so an existing
/// `TOKENFUSE_MCP_SECRETS`-only deployment starts exactly as it always has,
/// the same back-compat guarantee [`refuse_open_bind`] gives a deployment
/// with no `TOKENFUSE_MCP_KEYS`. An operator who wants every secret scoped
/// as a hard precondition, not merely a warning read after the fact, opts in.
pub fn refuse_unscoped_secrets(vault: &SecretVault, require_scopes: bool) -> Option<String> {
    if !require_scopes {
        return None;
    }
    let unscoped = vault.unscoped_names();
    if unscoped.is_empty() {
        return None;
    }
    Some(format!(
        "refusing to start: TOKENFUSE_MCP_REQUIRE_SECRET_SCOPES=1 and {} of {} configured \
         secret(s) carry no TOKENFUSE_MCP_SECRET_SCOPES rule: {}. Add a rule for each (or \
         drop it from TOKENFUSE_MCP_SECRETS), or unset TOKENFUSE_MCP_REQUIRE_SECRET_SCOPES to \
         run with unscoped secrets allowed.",
        unscoped.len(),
        vault.len(),
        unscoped.join(", ")
    ))
}

/// JSON-RPC error response with the same id as the request.
fn rpc_error(id: &Value, code: i64, message: &str) -> Value {
    json!({
        "jsonrpc": "2.0",
        "id": id,
        "error": { "code": code, "message": message },
    })
}

/// `" (reason)"` when the PDP gave a reason, else empty -- so a block message
/// reads cleanly whether or not Wardryx explained itself.
fn reason_suffix(reason: &Option<String>) -> String {
    match reason {
        Some(r) if !r.is_empty() => format!(" ({r})"),
        _ => String::new(),
    }
}

/// Emit one `tool_call` audit event for a Wardryx-gated `tools/call`. Skipped
/// when `agent_id` is absent (agent-passport SPEC.md §6.1 forbids a fabricated
/// `agent_id`; [`tokenfuse_core::agent_event::build`] enforces this and the
/// event is counted-and-skipped, never faked). In shadow mode the recorded
/// `decision` is `would-<decision>`, matching the `x-fuse-wardryx` header
/// convention, so a shadow rollout's audit trail never reads as if a call was
/// actually enforced.
fn emit_tool_call(
    st: &BrokerState,
    agent_id: Option<&str>,
    tool: &str,
    upstream: &str,
    decision: WardryxDecision,
    mode: WardryxMode,
) {
    let decision_str = if mode == WardryxMode::Shadow {
        format!("would-{}", decision.as_wire_str())
    } else {
        decision.as_wire_str().to_string()
    };
    let outcome = st.events.emit(
        EventType::ToolCall,
        crate::sink::now_millis(),
        agent_id,
        None,
        None,
        json!({ "tool": tool, "upstream": upstream, "decision": decision_str }),
    );
    crate::events::log_outcome(EventType::ToolCall, outcome);
}

/// The agent id this request can be attributed to, or `None`.
///
/// A header that is present but blank is `None`: an empty string names nobody,
/// and treating it as an identity would put an empty subject in front of the
/// PDP and an empty `agent_id` in an audit event. The LLM path reads it the
/// same way (`proxy::messages` tests `agent_id.is_empty()`).
fn attributed_agent(ctx: &CallContext) -> Option<&str> {
    ctx.agent_id
        .as_deref()
        .map(str::trim)
        .filter(|a| !a.is_empty())
}

/// Whether this request must be refused for want of an identity: the policy
/// gate is ENFORCING, the request is a `tools/call` (the only method the gate
/// covers), and it names no agent.
///
/// One predicate, called by both transports, so the two cannot drift. The HTTP
/// transport answers it with [`crate::proxy::identity_required`], byte for byte
/// the 400 the LLM path returns for the same missing header; stdio answers with
/// the JSON-RPC equivalent ([`IDENTITY_RPC_CODE`]), because a subprocess
/// transport has no status line to carry one.
///
/// Enforce only, mirroring the LLM path exactly: shadow mode blocks nothing by
/// definition, so it keeps observing with whatever attribution it was given,
/// and a broker with no Wardryx configured (the default) is untouched.
fn needs_identity(st: &BrokerState, req: &Value, ctx: &CallContext) -> bool {
    st.wardryx.mode == WardryxMode::Enforce
        && req.get("method").and_then(|m| m.as_str()) == Some("tools/call")
        && attributed_agent(ctx).is_none()
}

/// JSON-RPC code for "this call names no agent, so the policy gate could not
/// judge it". Distinct from `-32004` (the PDP denied or held) on purpose: a
/// refusal because the gate could not RUN is a different fact from a refusal
/// the gate decided, and a client that retries on one should not retry on the
/// other.
const IDENTITY_RPC_CODE: i64 = -32007;

/// The stdio wording of the same refusal. Names the header, like the LLM
/// path's body does, because the caller can only fix what they are told about.
const IDENTITY_RPC_MESSAGE: &str =
    "blocked: policy enforcement is on and this call carries no agent identity; \
     send one in `x-fuse-agent-id`";

/// JSON-RPC code for "a `{{secret:NAME}}` handle names a secret that HAS a
/// `TOKENFUSE_MCP_SECRET_SCOPES` rule, and this call's (agent, tool) does not
/// satisfy it". Distinct from `-32004` (Wardryx denied the TOOL): this is the
/// secret vault's own decision and fires whether or not Wardryx is
/// configured at all. Distinct from `-32007` (no agent id at all): this call
/// DID present an identity, just not one (or a tool) the rule admits.
const SECRET_SCOPE_RPC_CODE: i64 = -32008;

/// HTTP handler - delegates to the transport-agnostic [`process`]. Reads the
/// `x-fuse-*` headers into a [`CallContext`]: `X-Fuse-Agent-Id`
/// (agent-passport SPEC.md §3.2) so an event raised for this request can carry
/// the required `agent_id` (without it, events are skipped, not fabricated),
/// `X-Fuse-Mcp-Upstream` to pick a named upstream, and the delegation /
/// attestation / approval headers the Wardryx gate forwards to the PDP.
async fn handle(
    State(st): State<Arc<BrokerState>>,
    headers: axum::http::HeaderMap,
    Json(req): Json<Value>,
) -> Response {
    let header = |name: &str| {
        headers
            .get(name)
            .and_then(|v| v.to_str().ok())
            .map(str::to_string)
    };
    // The broker's own door, before anything else looks at this request. An
    // unauthenticated caller must reach no vault, no upstream and no scanner.
    //
    // Off unless `TOKENFUSE_MCP_KEYS` is configured, so a loopback deployment
    // is untouched. The body has already been buffered by the time this runs
    // (the extractor consumes it), which is bounded by the same
    // `TOKENFUSE_MAX_BODY_BYTES` limit `app` puts on every route; the check
    // lives here rather than in a `route_layer` so a future route reaching
    // this handler cannot be added without it.
    if st.keys.enabled() {
        let presented = header(CLIENT_KEY_HEADER).unwrap_or_default();
        if st.keys.resolve(presented.trim()).is_none() {
            // Never echo the presented value, not even truncated, and never
            // distinguish "missing" from "wrong": both are the same answer.
            tracing::warn!("mcp broker: refused a call with no usable client credential");
            return crate::proxy::unauthorized_response();
        }
    }
    let ctx = CallContext {
        agent_id: header("x-fuse-agent-id"),
        upstream: header("x-fuse-mcp-upstream"),
        on_behalf_of: header("x-fuse-on-behalf-of")
            .map(|s| {
                s.split(',')
                    .map(str::trim)
                    .filter(|p| !p.is_empty())
                    .map(str::to_string)
                    .collect()
            })
            .unwrap_or_default(),
        attestation_method: header("x-fuse-attestation-method"),
        approval_token: header("x-fuse-approval-token"),
    };
    // Refused here rather than inside `process` so the answer is the LLM
    // path's own 400, produced by the LLM path's own function. `process`
    // refuses too (it is `pub` and stdio calls it directly); this only
    // upgrades the refusal to the shape a caller of the HTTP transport
    // already knows.
    if needs_identity(&st, &req, &ctx) {
        tracing::warn!(
            "mcp broker: refusing a tools/call with no x-fuse-agent-id, the policy gate \
             cannot judge a call it cannot attribute"
        );
        return crate::proxy::identity_required();
    }
    Json(process(&st, req, &ctx).await).into_response()
}

/// Resolve which upstream URL this request forwards to. A named upstream
/// (`X-Fuse-Mcp-Upstream`) must exist in [`BrokerState::named_upstreams`];
/// an unknown name is refused (returned as `Err(rpc_error)`) rather than
/// falling back to the default, so a request and its injected secrets can
/// never be forwarded to a server the operator did not configure. No header
/// -> the default upstream.
fn resolve_upstream<'a>(
    st: &'a BrokerState,
    ctx: &CallContext,
    id: &Value,
) -> Result<&'a str, Value> {
    match ctx.upstream.as_deref() {
        None => Ok(&st.upstream),
        Some(name) => st
            .named_upstreams
            .get(name)
            .map(String::as_str)
            .ok_or_else(|| {
                rpc_error(
                    id,
                    -32005,
                    &format!("unknown mcp upstream {name:?} (X-Fuse-Mcp-Upstream)"),
                )
            }),
    }
}

/// Broker a single JSON-RPC request and return the response - shared by the HTTP
/// and stdio transports. Injects secrets, scans, forwards, and redacts.
///
/// `agent_id`: the caller's `X-Fuse-Agent-Id`, when known - the HTTP
/// transport ([`handle`]) reads it off the request headers; the stdio
/// transport ([`run_stdio`]) has no per-message header channel and always
/// passes `None`, so a stdio-transport rug-pull is detected and logged
/// (`tracing::warn!`, unchanged) but its `mcp_drift` agent-event is skipped
/// (agent-passport SPEC.md §6.1 requires `agent_id`; see
/// `tokenfuse_core::agent_event::build`) and counted - a known, documented
/// gap rather than a fabricated identity.
///
/// With the Wardryx gate ENFORCING, an unattributed `tools/call` is refused
/// here rather than passed through: see [`needs_identity`]. That makes an
/// enforcing broker unusable over stdio, which is the honest consequence of
/// a transport with no identity channel and a policy that keys on identity.
/// Shadow mode and an unconfigured broker are unaffected.
pub async fn process(st: &BrokerState, mut req: Value, ctx: &CallContext) -> Value {
    let id = req.get("id").cloned().unwrap_or(Value::Null);
    let method = req
        .get("method")
        .and_then(|m| m.as_str())
        .unwrap_or("")
        .to_string();
    let agent_id = attributed_agent(ctx);
    // The tool this call names, read once here so both the Wardryx gate
    // below and secret-scope resolution at the injection step (which runs
    // whether or not Wardryx is configured) see the same value. Empty when
    // `params.name` is absent or not a string: a [`tokenfuse_core::ScopeRule`]
    // reads an empty tool as "names no tool", never as "any tool".
    let tool = req
        .get("params")
        .and_then(|p| p.get("name"))
        .and_then(|n| n.as_str())
        .unwrap_or("")
        .to_string();

    // Which real MCP server this request forwards to. Resolved up front so an
    // unknown named upstream is refused before any secret is injected.
    let upstream_url = match resolve_upstream(st, ctx, &id) {
        Ok(u) => u.to_string(),
        Err(e) => return e,
    };

    // In shadow mode the Wardryx gate records what it WOULD have done and lets
    // the call through; this carries that verdict to the response annotation.
    let mut wardryx_shadow: Option<&'static str> = None;

    // 1. Credential brokering + the Wardryx policy gate on tool calls.
    if method == "tools/call" {
        // DLP: catch raw secrets the agent pasted directly into the args (before
        // injection, so vault-injected secrets aren't flagged).
        // Kept for the pii section below (secrets win on overlap); empty
        // when st.dlp is Off, same as if the pii code just never looked.
        let mut secret_findings_in_args: Vec<dlp::Finding> = Vec::new();
        if st.dlp != DlpMode::Off {
            if let Some(params) = req.get("params") {
                let findings = dlp::scan(&params.to_string());
                if !findings.is_empty() {
                    tracing::warn!(secrets = %dlp::summary(&findings), "mcp broker: raw secret in tool args");
                    if st.dlp == DlpMode::Block {
                        return rpc_error(
                            &id,
                            -32002,
                            &format!(
                                "blocked: raw secret in tool arguments ({})",
                                dlp::summary(&findings)
                            ),
                        );
                    }
                }
                secret_findings_in_args = findings;
            }
        }

        // PII masks: a separate, opt-in extension of the same scan, switched
        // independently of st.dlp above (see tokenfuse_core::dlp's module
        // doc for the conservative-by-design limits). Unlike the secret
        // path, Mask here actually redacts the args before forwarding -
        // there is no existing secret-args-masking behavior to stay
        // byte-identical with at this site.
        if st.dlp_pii != DlpMode::Off {
            if let Some(params_text) = req.get("params").map(|p| p.to_string()) {
                let pii_findings = dlp::scan_pii(&params_text);
                if !pii_findings.is_empty() {
                    let pii_summary = dlp::pii_summary(&pii_findings);
                    tracing::warn!(pii = %pii_summary, "mcp broker: pii in tool args");
                    match st.dlp_pii {
                        DlpMode::Block => {
                            return rpc_error(
                                &id,
                                -32006,
                                &format!("blocked: pii in tool arguments ({pii_summary})"),
                            );
                        }
                        DlpMode::Mask => {
                            // Secrets win: never let a pii redaction claim a
                            // span the secret scan already found.
                            let to_redact: Vec<dlp::Finding> = pii_findings
                                .into_iter()
                                .filter(|p| {
                                    !secret_findings_in_args
                                        .iter()
                                        .any(|f| dlp::spans_overlap(f, p))
                                })
                                .collect();
                            if !to_redact.is_empty() {
                                if let Ok(redacted) =
                                    serde_json::from_str(&dlp::redact(&params_text, &to_redact))
                                {
                                    req["params"] = redacted;
                                }
                            }
                        }
                        DlpMode::Shadow | DlpMode::Off => {}
                    }
                }
            }
        }

        // The second PEP: put this tools/call to the same Wardryx PDP the LLM
        // path uses (proxy::messages), so a `deny_tool` (or `deny_if_unattested`,
        // or an approval `hold`) policy enforces at the MCP layer too. Runs
        // BEFORE secret injection and forwarding, so a denied tool never gets a
        // real secret and never reaches the upstream. The broker holds no
        // signer and mutates nothing: a deny/hold is a JSON-RPC refusal, the
        // same shape every other block here uses.
        if st.wardryx.mode != WardryxMode::Off {
            match agent_id {
                Some(aid) => {
                    let dctx = DecideContext {
                        agent_id: aid.to_string(),
                        // The broker has no run/budget/step state; a stable
                        // per-agent id is enough for the tool/attestation rules,
                        // which key on the agent target and tool names, not the
                        // run. Cost/steps/model/domains have no broker-side
                        // equivalent and are sent empty (Wardryx reads empty as
                        // "nothing to restrict", never as a denial).
                        run_id: format!("mcp:{aid}"),
                        on_behalf_of: ctx.on_behalf_of.clone(),
                        tool_names: if tool.is_empty() {
                            Vec::new()
                        } else {
                            vec![tool.clone()]
                        },
                        steps: 0,
                        domains: Vec::new(),
                        model: String::new(),
                        est_cost_usd: 0.0,
                        attestation_method: ctx.attestation_method.clone(),
                        approval_token: ctx.approval_token.clone(),
                    };
                    let outcome = st.wardryx.decide(dctx).await;
                    emit_tool_call(
                        st,
                        agent_id,
                        &tool,
                        &upstream_url,
                        outcome.decision,
                        st.wardryx.mode,
                    );
                    if st.wardryx.mode == WardryxMode::Enforce {
                        match outcome.decision {
                            WardryxDecision::Deny => {
                                tracing::warn!(tool = %tool, "mcp broker: wardryx denied tool call");
                                return rpc_error(
                                    &id,
                                    -32004,
                                    &format!(
                                        "blocked: policy denied tool {tool:?}{}",
                                        reason_suffix(&outcome.reason)
                                    ),
                                );
                            }
                            WardryxDecision::Hold => {
                                // The broker can't run the approval ceremony, so
                                // a hold is a refusal-with-reason here; the
                                // approval row Wardryx created can be granted and
                                // the call retried with x-fuse-approval-token.
                                tracing::warn!(tool = %tool, "mcp broker: wardryx held tool call (approval required)");
                                let appr = outcome
                                    .approval_id
                                    .as_deref()
                                    .map(|a| format!(" (approval {a})"))
                                    .unwrap_or_default();
                                return rpc_error(
                                    &id,
                                    -32004,
                                    &format!("blocked: tool {tool:?} requires approval{appr}"),
                                );
                            }
                            WardryxDecision::Allow => {}
                        }
                    } else {
                        // Shadow: never block; carry the would-decision to the
                        // response so an operator can see what enforce would do.
                        wardryx_shadow = Some(outcome.decision.as_wire_str());
                    }
                }
                None if st.wardryx.mode == WardryxMode::Enforce => {
                    // No agent id, and the gate is enforcing. This used to skip
                    // the PDP call and carry on into secret injection, on the
                    // reasoning that an empty agent id would match no policy
                    // anyway. That is an assumption about another service's
                    // behaviour, and it is false for exactly the policy this
                    // gate was added for: a tool-scoped `deny_tool` (docs/23)
                    // is bypassed by dropping one header the caller writes.
                    //
                    // So refuse, the way the LLM path already does
                    // (`proxy::messages` -> `identity_required`). The HTTP
                    // transport turns this into that same 400 before we get
                    // here; this is the answer for stdio, and for any direct
                    // caller of `process`.
                    tracing::warn!(
                        "mcp broker: refusing a tools/call with no x-fuse-agent-id, the policy \
                         gate cannot judge a call it cannot attribute"
                    );
                    return rpc_error(&id, IDENTITY_RPC_CODE, IDENTITY_RPC_MESSAGE);
                }
                None => {
                    // Shadow: blocks nothing by definition, so an unattributed
                    // call is observed with whatever attribution it has and
                    // forwarded. Same posture as the LLM path's shadow mode,
                    // and the same documented gap as `mcp_drift` on stdio.
                    tracing::warn!(
                        "mcp broker: wardryx shadow gate skipped, no x-fuse-agent-id on this \
                         tools/call"
                    );
                }
            }
        }

        if let Some(params) = req.get_mut("params") {
            let inj = inject_secrets(params, &st.vault, agent_id, &tool);
            if inj.replaced > 0 {
                tracing::info!(count = inj.replaced, "mcp broker: injected secrets");
            }
            if !inj.missing.is_empty() {
                tracing::warn!(missing = ?inj.missing, "mcp broker: unknown secret handles");
            }
            if !inj.refused.is_empty() {
                // A secret exists but its TOKENFUSE_MCP_SECRET_SCOPES rule
                // does not admit this (agent, tool). Refuse the WHOLE call,
                // the same posture as the Wardryx deny above, rather than
                // forwarding it with the handle left as a placeholder: a
                // "leave it unsubstituted but still forward" call still
                // reaches the upstream MCP server and may still trigger
                // whatever side effect that tool has, with a syntactically
                // broken credential standing in for a real one. An agent
                // with no authorization for this secret has no business
                // causing that tool to run at all, so the call never
                // leaves the broker. Never log the secret VALUE: `inj.refused`
                // only ever carries names, never values, same as `missing`.
                tracing::warn!(
                    secrets = ?inj.refused,
                    agent_id = agent_id.unwrap_or(""),
                    tool = %tool,
                    "mcp broker: secret handle scope-denied for this agent/tool"
                );
                return rpc_error(
                    &id,
                    SECRET_SCOPE_RPC_CODE,
                    &format!(
                        "blocked: secret(s) {:?} are not scoped to agent {:?} and tool {:?}",
                        inj.refused,
                        agent_id.unwrap_or("<none>"),
                        tool
                    ),
                );
            }
        }
    }

    // Forward to the real MCP server (serialize by hand - reqwest's json feature
    // isn't enabled in this crate).
    let payload = match serde_json::to_vec(&req) {
        Ok(p) => p,
        Err(e) => return rpc_error(&id, -32000, &format!("encode error: {e}")),
    };
    let upstream = match st
        .client
        .post(&upstream_url)
        .header("content-type", "application/json")
        .body(payload)
        .send()
        .await
        .and_then(|r| r.error_for_status())
    {
        Ok(r) => r,
        Err(e) => return rpc_error(&id, -32000, &format!("upstream error: {e}")),
    };
    let bytes = match upstream.bytes().await {
        Ok(b) => b,
        Err(e) => return rpc_error(&id, -32000, &format!("upstream read: {e}")),
    };
    let mut out: Value = match serde_json::from_slice(&bytes) {
        Ok(v) => v,
        Err(e) => return rpc_error(&id, -32000, &format!("bad upstream json: {e}")),
    };

    // 2. Poisoning + rug-pull checks on tool listings.
    if method == "tools/list" && st.scan != ScanMode::Off {
        let tools = mcp::parse_tools(&out);

        // Rug-pull: a tool's description/schema changed vs. the pinned lock.
        if let Some(lock) = &st.lock {
            let drifts = mcp::diff(&tools, lock);
            // A lock this build cannot compare is not a rug pull, and must not
            // be blocked as one. It IS worth saying out loud: the operator
            // configured TOKENFUSE_MCP_LOCK and is getting no rug-pull
            // detection from it until they re-pin.
            for d in &drifts {
                if let mcp::Drift::LockNotComparable(provenance) = d {
                    tracing::warn!(
                        lock = %provenance,
                        "mcp broker: the pinned lock cannot be compared with this build's \
                         fingerprints, so rug-pull detection is OFF until it is re-pinned \
                         (tokenfuse mcp-scan --lock <file> --write-lock)"
                    );
                }
            }
            let changed: Vec<String> = drifts
                .into_iter()
                .filter_map(|d| match d {
                    mcp::Drift::Changed(name) => Some(name),
                    _ => None,
                })
                .collect();
            if !changed.is_empty() {
                tracing::warn!(tools = ?changed, "mcp broker: rug-pull (tool definition changed)");
                let outcome = st.events.emit(
                    EventType::McpDrift,
                    crate::sink::now_millis(),
                    agent_id,
                    None,
                    None,
                    json!({ "tools_changed": changed }),
                );
                crate::events::log_outcome(EventType::McpDrift, outcome);
                if st.scan == ScanMode::Block {
                    return rpc_error(
                        &id,
                        -32003,
                        &format!(
                            "blocked: tool definition changed (rug-pull): {}",
                            changed.join(", ")
                        ),
                    );
                }
            }
        }

        let findings = mcp::scan_injection(&tools);
        if !findings.is_empty() {
            tracing::warn!(count = findings.len(), findings = ?findings, "mcp broker: tool poisoning");
            if st.scan == ScanMode::Block {
                return rpc_error(
                    &id,
                    -32001,
                    &format!("blocked: {} poisoned tool description(s)", findings.len()),
                );
            }
            // In warn mode, annotate the response without breaking the client.
            if let Some(obj) = out.as_object_mut() {
                obj.insert(
                    "_tokenfuse".into(),
                    json!({ "mcp_findings": findings.len() }),
                );
            }
        }
    }

    // Shadow mode: surface what the Wardryx gate WOULD have done, having let
    // the call through. Never clobbers an existing `_tokenfuse` annotation.
    if let Some(would) = wardryx_shadow {
        if let Some(obj) = out.as_object_mut() {
            let entry = obj.entry("_tokenfuse").or_insert_with(|| json!({}));
            if let Some(t) = entry.as_object_mut() {
                t.insert("wardryx".into(), json!(format!("would-{would}")));
            }
        }
    }

    // 3. Redact secrets (and, if enabled, pii) in the response body so a tool
    //    result can't leak a credential - or now, PII - into the model's
    //    context. Guarded so an unused DLP (both modes Off, the default)
    //    never even serializes `out` to scan it.
    if st.dlp != DlpMode::Off || st.dlp_pii != DlpMode::Off {
        // Shadow annotates first (mirrors the wardryx_shadow annotation
        // above): the redact pass below re-serializes `out` afterward, so
        // the note is naturally preserved through that round trip instead of
        // being overwritten by a redact computed from stale offsets.
        if st.dlp_pii == DlpMode::Shadow {
            let pii_findings = dlp::scan_pii(&out.to_string());
            if !pii_findings.is_empty() {
                let pii_summary = dlp::pii_summary(&pii_findings);
                tracing::warn!(pii = %pii_summary, "mcp broker: pii in tool response");
                if let Some(obj) = out.as_object_mut() {
                    let entry = obj.entry("_tokenfuse").or_insert_with(|| json!({}));
                    if let Some(t) = entry.as_object_mut() {
                        t.insert("dlp_pii".into(), json!(format!("found {pii_summary}")));
                    }
                }
            }
        }

        let text = out.to_string();
        let secret_findings = if st.dlp != DlpMode::Off {
            dlp::scan(&text)
        } else {
            Vec::new()
        };
        if !secret_findings.is_empty() {
            tracing::warn!(secrets = %dlp::summary(&secret_findings), "mcp broker: redacted secrets in tool response");
        }

        let mut to_redact = secret_findings.clone();

        if st.dlp_pii == DlpMode::Block || st.dlp_pii == DlpMode::Mask {
            let pii_findings = dlp::scan_pii(&text);
            if !pii_findings.is_empty() {
                let pii_summary = dlp::pii_summary(&pii_findings);
                tracing::warn!(pii = %pii_summary, "mcp broker: pii in tool response");
                if st.dlp_pii == DlpMode::Block {
                    return rpc_error(
                        &id,
                        -32006,
                        &format!("blocked: pii in tool response ({pii_summary})"),
                    );
                }
                // Mask: secrets win - never let a pii redaction claim a span
                // the secret scan already found.
                to_redact.extend(
                    pii_findings
                        .into_iter()
                        .filter(|p| !secret_findings.iter().any(|f| dlp::spans_overlap(f, p))),
                );
            }
        }

        if !to_redact.is_empty() {
            if let Ok(redacted) = serde_json::from_str(&dlp::redact(&text, &to_redact)) {
                out = redacted;
            }
        }
    }

    out
}

/// Run the broker over **stdio** - newline-delimited JSON-RPC on stdin/stdout,
/// for MCP clients that launch a server as a subprocess. Each request is brokered
/// via [`process`] and forwarded to the configured HTTP upstream. Logs must go to
/// stderr (stdout is the protocol channel).
pub async fn run_stdio(state: Arc<BrokerState>) -> std::io::Result<()> {
    use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
    let mut lines = BufReader::new(tokio::io::stdin()).lines();
    let mut stdout = tokio::io::stdout();
    while let Some(line) = lines.next_line().await? {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        let resp = match serde_json::from_str::<Value>(line) {
            // stdio has no per-message header channel, so the CallContext is
            // empty here: no agent_id (mcp_drift is skipped, and an ENFORCING
            // Wardryx gate refuses the call outright rather than skipping,
            // see `process`) and no named upstream (the default one is always
            // used).
            Ok(req) => process(&state, req, &CallContext::default()).await,
            Err(e) => rpc_error(&Value::Null, -32700, &format!("parse error: {e}")),
        };
        let mut buf = serde_json::to_vec(&resp).unwrap_or_default();
        buf.push(b'\n');
        stdout.write_all(&buf).await?;
        stdout.flush().await?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_loopback_bind_says_nothing() {
        for addr in [
            "127.0.0.1:4200",
            "localhost:4200",
            "[::1]:4200",
            "::1:4200",
            "127.0.0.1:0",
            " 127.0.0.1:4200 ",
        ] {
            assert_eq!(
                bind_exposure_warning(addr, false),
                None,
                "the default bind is the normal case and must be silent: {addr:?}"
            );
        }
    }

    #[test]
    fn a_non_loopback_bind_warns() {
        for addr in [
            "0.0.0.0:4200",
            "[::]:4200",
            "192.168.1.5:4200",
            "10.0.0.4:80",
        ] {
            let w = bind_exposure_warning(addr, true)
                .unwrap_or_else(|| panic!("a non-loopback bind must warn: {addr:?}"));
            assert!(
                w.contains("firewall"),
                "the warning must say what to do about it, in the Cloud's voice: {w:?}"
            );
        }
    }

    /// The dangerous combination is not a wide bind, it is a wide bind with
    /// nothing on the door. The warning has to distinguish them, or an
    /// operator who HAS configured keys learns to ignore it.
    #[test]
    fn the_warning_says_whether_anything_authenticates() {
        let unauthenticated =
            bind_exposure_warning("0.0.0.0:4200", false).expect("non-loopback warns");
        assert!(
            unauthenticated.contains("TOKENFUSE_MCP_KEYS"),
            "with no keys configured the warning must name the variable that fixes it: \
             {unauthenticated:?}"
        );
        let authenticated =
            bind_exposure_warning("0.0.0.0:4200", true).expect("non-loopback still warns");
        assert!(
            !authenticated.contains("TOKENFUSE_MCP_KEYS"),
            "with keys configured, telling the operator to configure keys is noise: \
             {authenticated:?}"
        );
    }

    // --- refuse_open_bind ---------------------------------------------
    //
    // The owner decided (2026-08-05 audit, decided 2026-08-06) that a
    // non-loopback bind with no broker authentication must REFUSE to start,
    // not just warn: the warning above was recommended but deliberately not
    // turned into a refusal, because that breaks a running deployment at
    // boot and is a decision, not a fix. It has now been made.

    /// `is_loopback` answers the harder question `bind_exposure_warning`
    /// deliberately does not: a REFUSAL is consequential in both directions
    /// (undercounting loopback breaks a deployment that was never exposed;
    /// overcounting it starts one that is), so it asks the standard library
    /// rather than matching a fixed set of strings. 127.0.0.1 is not the
    /// whole of 127.0.0.0/8, and ::1 is a literal a string match has to
    /// spell out separately from "localhost".
    #[test]
    fn loopback_is_the_standard_librarys_answer_not_a_string_match() {
        for addr in ["127.0.0.1:4200", "127.0.0.2:4200", "127.255.255.255:4200"] {
            assert!(
                is_loopback(addr),
                "the whole of 127.0.0.0/8 is loopback: {addr:?}"
            );
        }
        for addr in ["[::1]:4200", "::1:4200", "localhost:4200", "LOCALHOST:4200"] {
            assert!(is_loopback(addr), "{addr:?} is loopback");
        }
        for addr in [
            "0.0.0.0:4200",
            "[::]:4200",
            "192.168.1.5:4200",
            "10.0.0.4:80",
        ] {
            assert!(
                !is_loopback(addr),
                "{addr:?} is the unspecified address or a LAN address, not loopback"
            );
        }
    }

    #[test]
    fn a_loopback_bind_is_never_refused() {
        for auth_configured in [false, true] {
            for allow_open_bind in [false, true] {
                assert_eq!(
                    refuse_open_bind("127.0.0.1:4200", auth_configured, allow_open_bind),
                    None,
                    "the default bind must start exactly as it does today regardless of \
                     auth_configured={auth_configured} or allow_open_bind={allow_open_bind}"
                );
            }
        }
    }

    /// The decided behaviour: a wide-open bind with nothing on the door
    /// refuses to start, naming the address, the missing configuration, and
    /// the opt-out, so an operator reading the error can act on it without
    /// reading source code.
    #[test]
    fn an_open_bind_with_no_keys_refuses_to_start() {
        let refusal = refuse_open_bind("0.0.0.0:4200", false, false)
            .expect("a non-loopback bind with no auth and no opt-out must refuse to start");
        assert!(
            refusal.contains("0.0.0.0:4200"),
            "the refusal must name the address that was bound: {refusal:?}"
        );
        assert!(
            refusal.contains("TOKENFUSE_MCP_KEYS"),
            "the refusal must name the missing configuration: {refusal:?}"
        );
        assert!(
            refusal.contains("TOKENFUSE_MCP_ALLOW_OPEN_BIND"),
            "the refusal must name the opt-out: {refusal:?}"
        );
    }

    /// The case the existing warning already covers must stay a warning, not
    /// become a refusal: a wide bind WITH credentials configured is a
    /// decision, not a mistake.
    #[test]
    fn configured_auth_avoids_the_refusal_leaving_only_the_warning() {
        assert_eq!(
            refuse_open_bind("0.0.0.0:4200", true, false),
            None,
            "auth configured must not refuse to start"
        );
    }

    /// The explicit opt-out for an operator who genuinely wants an open
    /// bind: TOKENFUSE_MCP_ALLOW_OPEN_BIND lets the broker start anyway.
    #[test]
    fn the_operator_can_opt_out_of_the_refusal() {
        assert_eq!(
            refuse_open_bind("0.0.0.0:4200", false, true),
            None,
            "TOKENFUSE_MCP_ALLOW_OPEN_BIND must let a deliberately open bind start"
        );
    }

    /// Opting out of the refusal is not the same as opting out of the
    /// warning: an operator who has decided to run the broker open still
    /// needs to be told what that means every time the process starts.
    #[test]
    fn opting_out_of_the_refusal_does_not_silence_the_warning() {
        assert_eq!(refuse_open_bind("0.0.0.0:4200", false, true), None);
        let warning = bind_exposure_warning("0.0.0.0:4200", false)
            .expect("the warning still fires once the refusal is opted out of");
        assert!(warning.contains("TOKENFUSE_MCP_KEYS"));
    }

    // --- unscoped_secrets_warning / refuse_unscoped_secrets ---------------
    //
    // Invariant 23 (CLAUDE.md): an unscoped secret is resolvable by any
    // agent, any tool, which is a real risk that must never be silent.
    // `unscoped_secrets_warning` is the always-on visibility;
    // `refuse_unscoped_secrets` is the opt-in stricter posture beside it,
    // gated on `TOKENFUSE_MCP_REQUIRE_SECRET_SCOPES`.

    fn a_vault_with(secrets: &[(&str, &str)]) -> tokenfuse_core::SecretVault {
        let mut vault = tokenfuse_core::SecretVault::new();
        for (name, value) in secrets {
            vault.insert(*name, *value);
        }
        vault
    }

    #[test]
    fn an_empty_vault_warns_about_nothing() {
        assert_eq!(unscoped_secrets_warning(&a_vault_with(&[])), None);
    }

    #[test]
    fn a_fully_scoped_vault_warns_about_nothing() {
        let mut vault = a_vault_with(&[("gh", "ghp_REAL")]);
        vault.set_scope("gh", tokenfuse_core::ScopeRule::agents(["agent-a"]));
        assert_eq!(unscoped_secrets_warning(&vault), None);
    }

    #[test]
    fn an_unscoped_secret_is_named_in_the_warning() {
        let vault = a_vault_with(&[("gh", "ghp_REAL"), ("stripe", "sk_REAL")]);
        let warning = unscoped_secrets_warning(&vault).expect("an unscoped secret must warn");
        assert!(warning.contains("gh"), "{warning:?}");
        assert!(warning.contains("stripe"), "{warning:?}");
        assert!(
            warning.contains("TOKENFUSE_MCP_SECRET_SCOPES"),
            "the warning must name the variable that fixes it: {warning:?}"
        );
    }

    #[test]
    fn require_scopes_off_never_refuses_even_with_unscoped_secrets() {
        let vault = a_vault_with(&[("gh", "ghp_REAL")]);
        assert_eq!(
            refuse_unscoped_secrets(&vault, false),
            None,
            "the default (off) must behave exactly as before this existed"
        );
    }

    #[test]
    fn require_scopes_with_an_empty_vault_never_refuses() {
        assert_eq!(
            refuse_unscoped_secrets(&a_vault_with(&[]), true),
            None,
            "nothing configured means nothing to refuse"
        );
    }

    /// The decided behaviour: strict mode with an unscoped secret refuses to
    /// start, naming the secret, the switch that caused it, and how to fix
    /// it, so an operator can act without reading source.
    #[test]
    fn require_scopes_refuses_to_start_when_a_secret_is_unscoped() {
        let vault = a_vault_with(&[("gh", "ghp_REAL")]);
        let refusal = refuse_unscoped_secrets(&vault, true)
            .expect("strict mode with an unscoped secret must refuse to start");
        assert!(refusal.contains("gh"), "{refusal:?}");
        assert!(
            refusal.contains("TOKENFUSE_MCP_REQUIRE_SECRET_SCOPES"),
            "the refusal must name the switch that caused it: {refusal:?}"
        );
        assert!(
            refusal.contains("TOKENFUSE_MCP_SECRET_SCOPES"),
            "the refusal must name how to fix it: {refusal:?}"
        );
    }

    /// The mirror image: every secret scoped means strict mode starts
    /// cleanly, same as if it were never turned on.
    #[test]
    fn require_scopes_starts_cleanly_when_every_secret_is_scoped() {
        let mut vault = a_vault_with(&[("gh", "ghp_REAL")]);
        vault.set_scope("gh", tokenfuse_core::ScopeRule::agents(["agent-a"]));
        assert_eq!(
            refuse_unscoped_secrets(&vault, true),
            None,
            "every secret scoped must start cleanly even under strict mode"
        );
    }
}
