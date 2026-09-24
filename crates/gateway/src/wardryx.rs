//! Wardryx enforcement hook: a PEP (Policy Enforcement Point) for the
//! Wardryx service, a PDP (Policy Decision Point).
//!
//! TokenFuse's gateway is already the one hot-path interception point
//! between an agent and the LLM provider (ADR-4: enforcement happens before
//! forwarding). This module lets it enforce decisions Wardryx makes: before
//! a request is forwarded, the gateway asks "should this specific agent
//! action happen right now" and blocks or holds accordingly.
//!
//! This is DEFENSIVE, not offensive. It can only block or hold an
//! operator's own in-flight agent action; it never performs an action on
//! anyone's behalf.
//!
//! Wired into `proxy::messages` immediately after the custom WASM policy
//! block and before the budget `reserve()` gate (see that function for the
//! exact insertion point). `Off` (the default, and whatever
//! `TOKENFUSE_WARDRYX_URL` unset forces) is a true no-op: no allocation, no
//! network call.
//!
//! Modes:
//! - `off` (default): the hook never runs.
//! - `shadow`: always consults the PDP (subject to the cache) and reports
//!   the decision via the `x-fuse-wardryx` response header, but never blocks.
//! - `enforce`: a `deny`/`hold` decision short-circuits the request with an
//!   HTTP 403.
//!
//! `FailMode` governs what happens when the PDP can't be reached in time, or
//! answers without a verdict (a status outside 2xx): `open` treats an outage
//! as `allow`, `closed` as `deny`. It only changes which decision is
//! synthesized; the mode above still decides whether that decision can
//! actually block.
//!
//! A short-TTL in-memory cache keyed by `(agent_id, sorted tool-set hash,
//! attestation_method)` skips the network round trip on repeat calls in a hot
//! loop. It is a
//! simple time-based cache, not a policy_version-aware invalidation scheme;
//! a poller that proactively drops cache entries on a policy_version change
//! is a documented future enhancement, not required for this wave. `hold`
//! decisions are never cached, since a cached one would let a caller replay
//! a stale `approval_id`.
//!
//! The cache key is coarser than the full `DecideContext`: it never varies
//! by `est_cost_usd`, `steps`, or `domains`. That used to be a real gap -- a
//! cache hit inside the TTL window could reuse a decision made against an
//! earlier value of all three, so a burst of calls faster than the TTL
//! (default 3s) could reuse an `allow` cached before a step count crossed a
//! policy's `max_steps`, before a domain left `allow_domains`, or before a
//! cost crossed `require_human_above_usd`, quietly bypassing all three caps
//! for the rest of the window. This is now resolved: every `/v1/decide`
//! response carries a `cacheable` flag (see `DecideWireResponse`), computed
//! by Wardryx from the matched policy set, not guessed at here. `cacheable`
//! is `true` only when the decision is a pure function of `(agent_id,
//! tool_names)` -- no matched policy sets `max_steps`, `allow_domains`, or
//! `require_human_above_usd` -- and `false` whenever a matched policy
//! depends on per-request state that can differ on the very next call, even
//! if the specific rule that produced this decision was something else
//! entirely (a `deny_tool` hit, say). `Cache::put` only ever stores a
//! `cacheable: true` decision; a `false` one is always re-decided against
//! Wardryx, so a request-specific rule can no longer be bypassed by a stale
//! hit within the TTL. A response that omits `cacheable` (an older Wardryx
//! that predates this field) defaults to `false`, the fail-safe reading:
//! never assume a decision is reusable unless the PDP says so. What remains
//! coarse is the *cacheable* case: a `deny_tool`/`deny_if_unattested`-only
//! decision is keyed on `(agent_id, tool-set hash, attestation_method)` --
//! attestation is in the key so a `deny_if_unattested` verdict never leaks
//! across attestation states -- so a policy
//! edit that changes one of those can take up to the TTL to be reflected,
//! same as the policy_version note above; lower
//! `TOKENFUSE_WARDRYX_CACHE_TTL_MS` (0 disables reuse entirely) if that
//! window matters more than the round-trip savings.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::hash::{Hash, Hasher};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Mutex;
use std::time::{Duration, Instant};

/// Default per-call timeout when `TOKENFUSE_WARDRYX_TIMEOUT_MS` is unset.
const DEFAULT_TIMEOUT_MS: u64 = 50;

/// Wall clock in epoch millis, for stamping verdicts. The cache above uses
/// `Instant` because it only measures elapsed time; a verdict has to be
/// comparable against a window an operator asks about from outside.
fn now_millis() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as i64)
        .unwrap_or(0)
}

/// Default decision-cache TTL when `TOKENFUSE_WARDRYX_CACHE_TTL_MS` is unset.
const DEFAULT_CACHE_TTL_MS: u64 = 3_000;

/// Operating mode, mirroring the off/shadow/enforce convention already used
/// by `TOKENFUSE_FIREWALL`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum WardryxMode {
    #[default]
    Off,
    Shadow,
    Enforce,
}

/// What to do when no verdict comes back before this call's deadline: the
/// PDP can't be reached (timeout or transport error), or it answers with a
/// status outside 2xx (`WardryxError::Refused`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum FailMode {
    /// Treat an unreachable PDP as `allow`: the request proceeds.
    #[default]
    Open,
    /// Treat an unreachable PDP as `deny`: the request is blocked.
    Closed,
}

/// One decision from the PDP.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WardryxDecision {
    Allow,
    Deny,
    Hold,
}

impl WardryxDecision {
    fn parse(s: &str) -> Option<Self> {
        match s.to_ascii_lowercase().as_str() {
            "allow" => Some(WardryxDecision::Allow),
            "deny" => Some(WardryxDecision::Deny),
            "hold" => Some(WardryxDecision::Hold),
            _ => None,
        }
    }

    /// The `x-fuse-wardryx` response header value for this decision (used
    /// both bare, in enforce mode, and as the `would-<decision>` suffix in
    /// shadow mode).
    pub fn as_wire_str(&self) -> &'static str {
        match self {
            WardryxDecision::Allow => "allow",
            WardryxDecision::Deny => "deny",
            WardryxDecision::Hold => "hold",
        }
    }
}

/// What the PDP has actually ANSWERED, since this process started.
///
/// Configuration says a policy plane should be consulted. This says one was,
/// and what it said. The 2026-08-04 cloud range found the gap between those two
/// sentences to be the critical one: the deployment check for "the policy plane
/// is on the data path" read environment variables, so a deployment whose PDP
/// answered nothing at all passed it, and the same run showed that happening by
/// accident rather than by malice.
///
/// Three things about the shape are load-bearing.
///
/// **`unreachable` is not a verdict.** Under `failmode=open` an unreachable PDP
/// yields a synthesized `allow`, which is exactly the state this report exists
/// to distinguish from a governed one. Counting it as an allow would rebuild
/// the fault inside the check meant to catch it.
///
/// **A cache hit is not counted either.** It is a real verdict, but it was
/// counted when it came off the wire, and the cache TTL is measured in seconds.
/// Counting hits would let one wire call answer for a window of any length.
///
/// **Totals are since startup and the timestamps carry the window.** A count
/// with no clock cannot answer "in the last period", and a restarted gateway
/// honestly reports that it has seen nothing yet rather than inheriting a
/// predecessor's evidence.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize)]
pub struct Verdicts {
    pub allow: u64,
    pub deny: u64,
    pub hold: u64,
    /// Outcomes this gateway synthesized because no verdict came back: the
    /// PDP could not be reached, or it answered with a status outside 2xx
    /// (`WardryxError::Refused`, a wrong key or a question it refused). The
    /// name predates the second case and is on the wire of
    /// `/v1/policy-plane`, so it stays. Not verdicts, deliberately kept beside
    /// them: a plane that is failing open looks identical to a healthy one
    /// from every other angle.
    pub unreachable_fallbacks: u64,
    /// Epoch millis of the last of each, `0` for never.
    pub last_allow_millis: i64,
    pub last_deny_millis: i64,
    pub last_hold_millis: i64,
    pub last_unreachable_millis: i64,
}

/// The full result of a `decide` call: what to do, plus everything a block
/// response needs in order to explain itself to the caller.
#[derive(Debug, Clone)]
pub struct WardryxOutcome {
    pub decision: WardryxDecision,
    pub policy_version: Option<String>,
    pub reason: Option<String>,
    /// Set only on `hold`: the id the caller references, via
    /// `x-fuse-approval-token` once approved, to resubmit the request.
    pub approval_id: Option<String>,
    /// This outcome was SYNTHESIZED because no verdict came back, and no
    /// policy engine produced it: the PDP could not be reached, its answer
    /// could not be read, or it answered with a status outside 2xx
    /// (`WardryxError::Refused`). The name predates the last case and is kept,
    /// because what `proxy` and `mcpbroker` key on is "no policy decided
    /// this", which is true of all three; `reason` says which.
    ///
    /// A field rather than a caller parsing `reason` for the word
    /// "unreachable": the reason is an operator-facing string that exists to
    /// be read, and a control-flow decision keyed on its wording breaks
    /// silently the first time somebody improves the sentence.
    ///
    /// It is here because the fallback is invisible from every other angle.
    /// `Verdicts` already counts it (`unreachable_fallbacks`), and that
    /// counter is what `/v1/policy-plane` reports, but a count is a number in
    /// a process that restarts; nothing on the shared bus said the plane had
    /// been down at all, so a call that nobody governed was recorded as a
    /// call that policy allowed.
    pub unreachable: bool,
    /// Whether resubmission requires `x-fuse-approval-token`. Defaults to
    /// `true` (the safer assumption) when the PDP response omits it.
    pub approval_token_required: bool,
}

/// Everything `Wardryx::decide` needs: the caller (`proxy::messages`)
/// gathers this up front from request context already in scope at the
/// insertion point, so `decide` itself stays a single, easy-to-read call.
pub struct DecideContext {
    pub agent_id: String,
    pub run_id: String,
    pub on_behalf_of: Vec<String>,
    pub tool_names: Vec<String>,
    /// The run's accumulated step count *before* this action, i.e.
    /// `snapshot.steps` at the insertion point: how many prior actions on
    /// this run have already been reserved. Checked by Wardryx against a
    /// matched policy's `max_steps`; once this reaches or exceeds that cap,
    /// Wardryx denies. Zero for a run's first action.
    pub steps: u32,
    /// Best-effort domains this action's declared tools reference (see
    /// `proxy::referenced_domains`). Empty for a plain LLM call with no
    /// URL-bearing tools, which Wardryx treats as "nothing declared to
    /// restrict," never as a denial.
    pub domains: Vec<String>,
    pub model: String,
    pub est_cost_usd: f64,
    pub attestation_method: Option<String>,
    /// Whether THIS gateway verified a delegation token for this request, per
    /// agent-passport SPEC 5.2, and took `on_behalf_of` from it.
    ///
    /// False is the honest default and says "nobody proved this", which is a
    /// different statement from saying nothing. It is set by
    /// [`crate::chainproof::resolve`] and by nothing else: no header sets it,
    /// because a caller that could assert it would be asserting the very thing
    /// the field exists to establish.
    pub chain_proven: bool,
    pub approval_token: Option<String>,
}

#[derive(Debug, Serialize)]
struct DecideWireRequest<'a> {
    agent_id: &'a str,
    run_id: &'a str,
    on_behalf_of: &'a [String],
    tool_names: &'a [String],
    domains: &'a [String],
    steps: u32,
    model: &'a str,
    est_cost_usd: f64,
    attestation_method: Option<&'a str>,
    approval_token: Option<&'a str>,
    chain_proven: bool,
}

#[derive(Debug, Deserialize)]
struct DecideWireResponse {
    decision: String,
    #[serde(default)]
    policy_version: Option<String>,
    #[serde(default)]
    reason: Option<String>,
    #[serde(default)]
    approval_id: Option<String>,
    #[serde(default)]
    approval_token_required: Option<bool>,
    /// Whether this decision is safe to store and later serve again for
    /// another request against the same `(agent_id, tool_names)`, per
    /// Wardryx's `/v1/decide` contract. Defaults to `false` -- the
    /// fail-safe reading -- when the response omits it, so an older PDP
    /// that predates this field is never assumed cacheable by silence.
    #[serde(default)]
    cacheable: bool,
}

#[derive(Debug, thiserror::Error)]
enum WardryxError {
    #[error("wardryx request failed: {0}")]
    Transport(String),
    #[error("wardryx response was not valid JSON: {0}")]
    Decode(String),
    #[error("wardryx returned an unrecognized decision: {0}")]
    UnknownDecision(String),
    /// A 404 on `/v1/filter-tools`, its own error kind, distinct from every
    /// other failure: it means this wardryx predates the route rather than
    /// that the route is temporarily broken, and shadow tool pruning has no
    /// use for retrying it.
    #[error(
        "this wardryx has no /v1/filter-tools route (it predates it); shadow pruning measures nothing"
    )]
    FilterRouteNotFound,
    /// The PDP ANSWERED, with a status outside 2xx: wardryx refusing the call
    /// (400 for a question with no subject, 401 for a wrong key) or failing
    /// to decide it (5xx), or something in front of it answering instead.
    /// Checked before the body is decoded, because a refusal's body is an
    /// error message and reading it as a decision reports the refusal as bad
    /// JSON, which sends an operator to look at a parser when the PDP told
    /// them what was wrong. `detail` is wardryx's own `{"error": ...}` message
    /// when the body carries one, else the status's standard reason phrase;
    /// either way one line, cleaned by [`quoted`] and capped.
    #[error("wardryx answered {status} on {route}: {detail}")]
    Refused {
        route: &'static str,
        status: u16,
        detail: String,
    },
}

impl WardryxError {
    /// What a failmode fallback's reason says happened. A PDP that answered
    /// was not unreachable, so a refusal says what it answered; every other
    /// kind keeps the sentence it has always had.
    fn as_reason(&self) -> String {
        match self {
            WardryxError::Refused { .. } => self.to_string(),
            other => format!("wardryx unreachable ({other})"),
        }
    }
}

/// How much of a refusal's body is read to find wardryx's message. Its
/// `{"error": ...}` is one short sentence, and a body in any other shape is
/// not quoted at all, so nothing past this can change what is reported.
const REFUSAL_BODY_MAX_BYTES: usize = 4 * 1024;

/// The longest message a refusal quotes. Chosen so the whole fallback reason
/// for `/v1/decide` (61 characters around the message at the longest status
/// and failmode, plus the cut marker) stays inside the 200 characters
/// `dependency_failed` keeps of it, so the event never cuts the sentence
/// that names the status.
const REFUSAL_DETAIL_MAX_CHARS: usize = 120;

/// `text` as one line safe to log, record and hand back to a caller: control
/// and invisible characters made harmless by the same function the injection
/// detector's excerpts use, runs of whitespace collapsed, and at most
/// [`REFUSAL_DETAIL_MAX_CHARS`] characters, cut with `…`.
fn quoted(text: &str) -> String {
    let flat = tokenfuse_core::injection::sanitise(text);
    let one_line = flat.split_whitespace().collect::<Vec<_>>().join(" ");
    if one_line.chars().count() <= REFUSAL_DETAIL_MAX_CHARS {
        return one_line;
    }
    let mut cut: String = one_line.chars().take(REFUSAL_DETAIL_MAX_CHARS).collect();
    cut.push('…');
    cut
}

/// Turn an answer outside 2xx into [`WardryxError::Refused`]. Reads at most
/// [`REFUSAL_BODY_MAX_BYTES`] of the body, and a body that breaks mid-read is
/// still a refusal: the status line arrived, and that is the fact reported.
async fn refusal(route: &'static str, mut resp: reqwest::Response) -> WardryxError {
    let status = resp.status();
    let mut body = Vec::new();
    while body.len() < REFUSAL_BODY_MAX_BYTES {
        match resp.chunk().await {
            Ok(Some(chunk)) => body.extend_from_slice(&chunk),
            Ok(None) | Err(_) => break,
        }
    }
    body.truncate(REFUSAL_BODY_MAX_BYTES);
    let said = serde_json::from_slice::<serde_json::Value>(&body)
        .ok()
        .and_then(|v| v.get("error")?.as_str().map(quoted))
        .filter(|s| !s.is_empty());
    WardryxError::Refused {
        route,
        status: status.as_u16(),
        detail: said.unwrap_or_else(|| {
            status
                .canonical_reason()
                .unwrap_or("no reason given")
                .to_string()
        }),
    }
}

/// Talks to the Wardryx `POST {base_url}/v1/decide` endpoint. Kept separate
/// from [`Wardryx`] (the mode/failmode/cache bundle) so the HTTP concern and
/// the policy concern stay independently readable and testable.
struct WardryxClient {
    http: reqwest::Client,
    base_url: String,
    key: Option<String>,
    timeout: Duration,
}

impl WardryxClient {
    fn new(base_url: impl Into<String>, key: Option<String>, timeout: Duration) -> Self {
        WardryxClient {
            http: reqwest::Client::new(),
            base_url: base_url.into(),
            key,
            timeout,
        }
    }

    /// Returns the decision alongside whether Wardryx marked it safe to
    /// cache. `cacheable` is kept out of [`WardryxOutcome`] itself: it is a
    /// caching concern for [`Cache::put`] to gate on, not part of what a
    /// block response needs to explain itself to the caller (see
    /// `WardryxOutcome`'s doc comment).
    async fn decide(
        &self,
        req: &DecideWireRequest<'_>,
    ) -> Result<(WardryxOutcome, bool), WardryxError> {
        let endpoint = format!("{}/v1/decide", self.base_url.trim_end_matches('/'));
        let payload = serde_json::to_vec(req).map_err(|e| WardryxError::Decode(e.to_string()))?;
        let mut builder = self
            .http
            .post(&endpoint)
            .timeout(self.timeout)
            .header("content-type", "application/json")
            .body(payload);
        if let Some(key) = &self.key {
            if !key.is_empty() {
                builder = builder.bearer_auth(key);
            }
        }
        let resp = builder
            .send()
            .await
            .map_err(|e| WardryxError::Transport(e.to_string()))?;
        if !resp.status().is_success() {
            return Err(refusal("/v1/decide", resp).await);
        }
        let bytes = resp
            .bytes()
            .await
            .map_err(|e| WardryxError::Transport(e.to_string()))?;
        let wire: DecideWireResponse =
            serde_json::from_slice(&bytes).map_err(|e| WardryxError::Decode(e.to_string()))?;
        let decision = WardryxDecision::parse(&wire.decision)
            .ok_or(WardryxError::UnknownDecision(wire.decision))?;
        let outcome = WardryxOutcome {
            decision,
            policy_version: wire.policy_version,
            reason: wire.reason,
            approval_id: wire.approval_id,
            approval_token_required: wire.approval_token_required.unwrap_or(true),
            // A plane that answered. This is the value that makes the flag
            // worth having: without a decode path that sets it false, an
            // "unreachable" flag is a constant.
            unreachable: false,
        };
        Ok((outcome, wire.cacheable))
    }

    /// `POST {base_url}/v1/filter-tools`, same key and timeout as `decide`
    /// (see this struct's doc). Applies wardryx's `deny_tool` rule to each
    /// name in `tool_names` alone, in shadow, W2a: measurement only, never
    /// enforcement. A 404 is reported as its own error kind rather than a
    /// generic transport/decode failure, since it means this wardryx
    /// predates the route; any other status outside 2xx is
    /// [`WardryxError::Refused`], the same kind `decide` reports.
    async fn filter_tools(
        &self,
        req: &FilterToolsWireRequest<'_>,
    ) -> Result<FilterOutcome, WardryxError> {
        let endpoint = format!("{}/v1/filter-tools", self.base_url.trim_end_matches('/'));
        let payload = serde_json::to_vec(req).map_err(|e| WardryxError::Decode(e.to_string()))?;
        let mut builder = self
            .http
            .post(&endpoint)
            .timeout(self.timeout)
            .header("content-type", "application/json")
            .body(payload);
        if let Some(key) = &self.key {
            if !key.is_empty() {
                builder = builder.bearer_auth(key);
            }
        }
        let resp = builder
            .send()
            .await
            .map_err(|e| WardryxError::Transport(e.to_string()))?;
        if resp.status().as_u16() == 404 {
            return Err(WardryxError::FilterRouteNotFound);
        }
        if !resp.status().is_success() {
            return Err(refusal("/v1/filter-tools", resp).await);
        }
        let bytes = resp
            .bytes()
            .await
            .map_err(|e| WardryxError::Transport(e.to_string()))?;
        let wire: FilterToolsWireResponse =
            serde_json::from_slice(&bytes).map_err(|e| WardryxError::Decode(e.to_string()))?;
        Ok(FilterOutcome {
            allowed: wire.allowed,
            denied: wire
                .denied
                .into_iter()
                .map(|d| DeniedTool {
                    name: d.name,
                    policy: d.policy,
                    rule: d.rule,
                })
                .collect(),
            policy_version: wire.policy_version,
        })
    }
}

/// One tool wardryx's policy would deny, from `/v1/filter-tools`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeniedTool {
    pub name: String,
    pub policy: Option<String>,
    pub rule: Option<String>,
}

/// The result of a `filter_tools` call: which of the requested tool names
/// wardryx's `deny_tool` rule would remove, and which it would keep. This is
/// a measurement of what the POLICY says, never an instruction this gateway
/// acts on in W2a: nothing here changes the forwarded request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FilterOutcome {
    pub allowed: Vec<String>,
    pub denied: Vec<DeniedTool>,
    pub policy_version: Option<String>,
}

#[derive(Debug, Serialize)]
struct FilterToolsWireRequest<'a> {
    agent_id: &'a str,
    run_id: &'a str,
    tool_names: &'a [String],
}

#[derive(Debug, Deserialize)]
struct DeniedToolWire {
    name: String,
    #[serde(default)]
    policy: Option<String>,
    #[serde(default)]
    rule: Option<String>,
}

#[derive(Debug, Deserialize)]
struct FilterToolsWireResponse {
    #[serde(default)]
    allowed: Vec<String>,
    #[serde(default)]
    denied: Vec<DeniedToolWire>,
    #[serde(default)]
    policy_version: Option<String>,
}

/// What shadow tool pruning measured for one request: how many tools were
/// declared, how many wardryx's policy would remove, and the estimated input
/// tokens their schemas cost. Every field is `None` together whenever nothing
/// was measured (the setting is off, the hook is off, no tool was declared,
/// or the filter-tools call failed) - never zero, because zero is a real
/// measured answer and `None` is the honest "we do not know" (invariant 61).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct ShadowPruneMeasurement {
    pub tools_offered: Option<u32>,
    pub tools_would_prune: Option<u32>,
    pub pruned_schema_tokens_est: Option<u64>,
}

/// One cached `filter_tools` answer, same TTL treatment as [`CacheEntry`]
/// above: this reuses wardryx's own decision that `deny_tool` alone, unlike
/// the request-shaped rules `Decide` also applies, is a pure function of
/// `(agent_id, tool_names)`, so every successful answer is cacheable.
#[derive(Debug, Clone)]
struct FilterCacheEntry {
    outcome: FilterOutcome,
    cached_at: Instant,
}

/// Short-TTL in-memory cache for `filter_tools`, keyed the same way
/// [`Cache::key`] keys `decide` (agent id plus a hash of the sorted tool
/// set), minus the attestation/chain fields `Filter` never consults.
struct FilterCache {
    ttl: Duration,
    entries: Mutex<HashMap<(String, u64), FilterCacheEntry>>,
}

impl FilterCache {
    fn new(ttl: Duration) -> Self {
        FilterCache {
            ttl,
            entries: Mutex::new(HashMap::new()),
        }
    }

    fn key(agent_id: &str, tool_names: &[String]) -> (String, u64) {
        let mut sorted: Vec<&str> = tool_names.iter().map(String::as_str).collect();
        sorted.sort_unstable();
        let mut hasher = std::collections::hash_map::DefaultHasher::new();
        sorted.hash(&mut hasher);
        (agent_id.to_string(), hasher.finish())
    }

    fn get(&self, agent_id: &str, tool_names: &[String]) -> Option<FilterOutcome> {
        let key = Self::key(agent_id, tool_names);
        let entries = self.entries.lock().unwrap();
        let entry = entries.get(&key)?;
        if entry.cached_at.elapsed() >= self.ttl {
            return None;
        }
        Some(entry.outcome.clone())
    }

    fn put(&self, agent_id: &str, tool_names: &[String], outcome: FilterOutcome) {
        let key = Self::key(agent_id, tool_names);
        self.entries.lock().unwrap().insert(
            key,
            FilterCacheEntry {
                outcome,
                cached_at: Instant::now(),
            },
        );
    }
}

/// One cached decision.
#[derive(Debug, Clone)]
struct CacheEntry {
    decision: WardryxDecision,
    policy_version: Option<String>,
    reason: Option<String>,
    cached_at: Instant,
}

/// Short-TTL in-memory decision cache keyed by `(agent_id, sorted tool-set
/// hash)`. See the module doc for why `hold` is never cached.
struct Cache {
    ttl: Duration,
    entries: Mutex<HashMap<(String, u64), CacheEntry>>,
}

impl Cache {
    fn new(ttl: Duration) -> Self {
        Cache {
            ttl,
            entries: Mutex::new(HashMap::new()),
        }
    }

    fn key(
        agent_id: &str,
        tool_names: &[String],
        attestation_method: Option<&str>,
        chain_proven: bool,
    ) -> (String, u64) {
        let mut sorted: Vec<&str> = tool_names.iter().map(String::as_str).collect();
        sorted.sort_unstable();
        let mut hasher = std::collections::hash_map::DefaultHasher::new();
        sorted.hash(&mut hasher);
        // Attestation is a per-request input that a `deny_if_unattested` policy
        // decides on, so it must be part of the key. Without it, an attested and
        // an unattested request for the same (agent, tool-set) collide, and
        // whichever is cached first wins for the other — letting an unattested
        // agent inherit an attested "allow" (or vice-versa) inside the TTL.
        attestation_method.hash(&mut hasher);
        // And `chain_proven` for exactly the reason above, one field over: a
        // `deny_if_chain_unproven` policy decides on it, so a proven and an
        // unproven request for the same (agent, tool-set) must not share an
        // entry. Whichever landed first would answer for the other, which on
        // this field means an unproven caller inheriting a proven "allow".
        chain_proven.hash(&mut hasher);
        (agent_id.to_string(), hasher.finish())
    }

    fn get(
        &self,
        agent_id: &str,
        tool_names: &[String],
        attestation_method: Option<&str>,
        chain_proven: bool,
    ) -> Option<WardryxOutcome> {
        let key = Self::key(agent_id, tool_names, attestation_method, chain_proven);
        let entries = self.entries.lock().unwrap();
        let entry = entries.get(&key)?;
        if entry.cached_at.elapsed() >= self.ttl {
            return None;
        }
        Some(WardryxOutcome {
            decision: entry.decision,
            policy_version: entry.policy_version.clone(),
            reason: entry.reason.clone(),
            // Only `allow`/`deny` are ever stored (see `put`), and neither
            // carries an approval id, so this is always correct for a hit.
            approval_id: None,
            // A cache hit is a real verdict the PDP gave, replayed. `fallback`
            // is never cached (its own doc says why: a transient outage must
            // not outlive itself by a TTL), so nothing unreachable can arrive
            // here to be reported twice.
            unreachable: false,
            approval_token_required: true,
        })
    }

    /// Stores `outcome`, unless either guard below says not to. `cacheable`
    /// comes straight from the PDP's `/v1/decide` response (see
    /// `DecideWireResponse::cacheable`): Wardryx, not this cache, is the
    /// source of truth for whether a decision generalizes beyond the one
    /// request that produced it.
    fn put(
        &self,
        agent_id: &str,
        tool_names: &[String],
        attestation_method: Option<&str>,
        chain_proven: bool,
        outcome: &WardryxOutcome,
        cacheable: bool,
    ) {
        // Never cache `hold`: a replayed hit would hand out a stale
        // `approval_id` for what looks like a fresh hold.
        if outcome.decision == WardryxDecision::Hold {
            return;
        }
        // Only store a decision the PDP marked safe to reuse. `cacheable`
        // is false whenever a matched policy depends on per-request state
        // (max_steps, allow_domains, require_human_above_usd) that can
        // differ on the very next call even for this same agent/tool set;
        // storing it anyway would resurrect the exact stale-cache gap this
        // flag exists to close.
        if !cacheable {
            return;
        }
        let key = Self::key(agent_id, tool_names, attestation_method, chain_proven);
        let entry = CacheEntry {
            decision: outcome.decision,
            policy_version: outcome.policy_version.clone(),
            reason: outcome.reason.clone(),
            cached_at: Instant::now(),
        };
        self.entries.lock().unwrap().insert(key, entry);
    }
}

/// The Wardryx hook: mode, fail-open/closed behavior, the HTTP client
/// (absent when disabled), and the decision cache. Bundled the same way
/// [`crate::router::Router`] bundles the model router's mode/rules/index.
pub struct Wardryx {
    pub mode: WardryxMode,
    failmode: FailMode,
    client: Option<WardryxClient>,
    cache: Cache,
    /// What the PDP has answered (see [`Verdicts`]). One mutex acquisition per
    /// wire decision, next to the one `Cache` already takes on the same path.
    verdicts: Mutex<Verdicts>,
    /// Shadow tool pruning (W2a): the `filter_tools` decision cache.
    filter_cache: FilterCache,
    /// Whether this process has already warned that this wardryx has no
    /// `/v1/filter-tools` route. One line for the process lifetime
    /// (invariant 61), not one per call.
    warned_filter_not_found: AtomicBool,
    /// Whether this process has already warned about every OTHER
    /// `filter_tools` failure kind (transport, decode, a status outside 2xx
    /// other than 404). One line for the process lifetime, distinct from the
    /// 404 warning above.
    warned_filter_other: AtomicBool,
}

impl Wardryx {
    /// Off, no client configured. `AppState`'s starting point before
    /// `serve()` calls `from_env`.
    pub fn disabled() -> Self {
        Wardryx {
            mode: WardryxMode::Off,
            failmode: FailMode::Open,
            client: None,
            cache: Cache::new(Duration::from_millis(DEFAULT_CACHE_TTL_MS)),
            verdicts: Mutex::new(Verdicts::default()),
            filter_cache: FilterCache::new(Duration::from_millis(DEFAULT_CACHE_TTL_MS)),
            warned_filter_not_found: AtomicBool::new(false),
            warned_filter_other: AtomicBool::new(false),
        }
    }

    /// Build directly from explicit settings (used by `from_env` and by
    /// tests that point the client at a stub server rather than going
    /// through environment variables).
    pub fn new(
        mode: WardryxMode,
        failmode: FailMode,
        base_url: impl Into<String>,
        key: Option<String>,
        timeout: Duration,
        cache_ttl: Duration,
    ) -> Self {
        Wardryx {
            mode,
            failmode,
            client: Some(WardryxClient::new(base_url, key, timeout)),
            cache: Cache::new(cache_ttl),
            verdicts: Mutex::new(Verdicts::default()),
            filter_cache: FilterCache::new(cache_ttl),
            warned_filter_not_found: AtomicBool::new(false),
            warned_filter_other: AtomicBool::new(false),
        }
    }

    /// Build from `TOKENFUSE_WARDRYX_*` env (see the module doc for the
    /// full list). A missing/empty `TOKENFUSE_WARDRYX_URL` forces `Off`
    /// regardless of `TOKENFUSE_WARDRYX_MODE`: with nothing to call there is
    /// nothing to enforce or shadow.
    pub fn from_env() -> Self {
        let requested_mode = match std::env::var("TOKENFUSE_WARDRYX_MODE").as_deref() {
            Ok("shadow") => WardryxMode::Shadow,
            Ok("enforce") => WardryxMode::Enforce,
            _ => WardryxMode::Off,
        };
        let url = std::env::var("TOKENFUSE_WARDRYX_URL")
            .ok()
            .filter(|s| !s.is_empty());
        let Some(url) = url else {
            if requested_mode != WardryxMode::Off {
                tracing::warn!(
                    "TOKENFUSE_WARDRYX_MODE is set but TOKENFUSE_WARDRYX_URL is not; \
                     the wardryx hook stays off"
                );
            }
            return Wardryx::disabled();
        };

        let failmode = match std::env::var("TOKENFUSE_WARDRYX_FAILMODE").as_deref() {
            Ok("closed") => FailMode::Closed,
            _ => FailMode::Open,
        };
        let key = std::env::var("TOKENFUSE_WARDRYX_KEY")
            .ok()
            .filter(|s| !s.is_empty());
        let timeout_ms: u64 = std::env::var("TOKENFUSE_WARDRYX_TIMEOUT_MS")
            .ok()
            .and_then(|s| s.parse().ok())
            .unwrap_or(DEFAULT_TIMEOUT_MS);
        let cache_ttl_ms: u64 = std::env::var("TOKENFUSE_WARDRYX_CACHE_TTL_MS")
            .ok()
            .and_then(|s| s.parse().ok())
            .unwrap_or(DEFAULT_CACHE_TTL_MS);

        Wardryx::new(
            requested_mode,
            failmode,
            url,
            key,
            Duration::from_millis(timeout_ms),
            Duration::from_millis(cache_ttl_ms),
        )
    }

    /// Ask the PDP (or the cache) what to do about this call. Always
    /// returns an outcome: transport/timeout/decode failures and an answer
    /// outside 2xx are absorbed here via `failmode`, never surfaced as a
    /// `Result` to the caller.
    /// Only meant to be called when `mode != Off` (see `proxy::messages`);
    /// `client` is guaranteed `Some` whenever that holds (see `from_env`),
    /// but a missing client still fails safe via `failmode` rather than
    /// panicking, in case a future caller changes that invariant.
    pub async fn decide(&self, ctx: DecideContext) -> WardryxOutcome {
        if let Some(cached) = self.cache.get(
            &ctx.agent_id,
            &ctx.tool_names,
            ctx.attestation_method.as_deref(),
            ctx.chain_proven,
        ) {
            return cached;
        }
        let Some(client) = &self.client else {
            return self.fallback("wardryx unreachable (wardryx hook has no client configured)");
        };

        let wire = DecideWireRequest {
            agent_id: &ctx.agent_id,
            run_id: &ctx.run_id,
            on_behalf_of: &ctx.on_behalf_of,
            tool_names: &ctx.tool_names,
            domains: &ctx.domains,
            steps: ctx.steps,
            model: &ctx.model,
            est_cost_usd: ctx.est_cost_usd,
            attestation_method: ctx.attestation_method.as_deref(),
            approval_token: ctx.approval_token.as_deref(),
            chain_proven: ctx.chain_proven,
        };
        match client.decide(&wire).await {
            Ok((outcome, cacheable)) => {
                self.record_verdict_at(outcome.decision, now_millis());
                self.cache.put(
                    &ctx.agent_id,
                    &ctx.tool_names,
                    ctx.attestation_method.as_deref(),
                    ctx.chain_proven,
                    &outcome,
                    cacheable,
                );
                outcome
            }
            Err(e) => {
                tracing::warn!(
                    error = %e,
                    failmode = ?self.failmode,
                    "wardryx decide call failed; applying failmode"
                );
                // Every kind, a refusal included, is a fallback and never a
                // verdict (invariant 19): an answer with no decision in it
                // governed nothing, whatever its status says about the PDP.
                self.record_unreachable_at(now_millis());
                self.fallback(&e.as_reason())
            }
        }
    }

    /// Record a verdict the PDP itself returned, stamped by the caller.
    ///
    /// Public so `tests/policy_plane.rs` can place a verdict at a chosen
    /// instant without a stub PDP and a sleep; `decide` is the only caller in
    /// production and passes `now_millis()`. Deliberately NOT called for a
    /// cache hit or for a failmode fallback, for the reasons in [`Verdicts`].
    pub fn record_verdict_at(&self, decision: WardryxDecision, at_millis: i64) {
        let mut v = self.verdicts.lock().unwrap_or_else(|e| e.into_inner());
        match decision {
            WardryxDecision::Allow => {
                v.allow += 1;
                v.last_allow_millis = v.last_allow_millis.max(at_millis);
            }
            WardryxDecision::Deny => {
                v.deny += 1;
                v.last_deny_millis = v.last_deny_millis.max(at_millis);
            }
            WardryxDecision::Hold => {
                v.hold += 1;
                v.last_hold_millis = v.last_hold_millis.max(at_millis);
            }
        }
    }

    /// Record that this gateway had to synthesize an outcome because the PDP
    /// did not answer. See [`Verdicts::unreachable_fallbacks`].
    pub fn record_unreachable_at(&self, at_millis: i64) {
        let mut v = self.verdicts.lock().unwrap_or_else(|e| e.into_inner());
        v.unreachable_fallbacks += 1;
        v.last_unreachable_millis = v.last_unreachable_millis.max(at_millis);
    }

    /// What the PDP has answered since this process started.
    pub fn verdicts(&self) -> Verdicts {
        *self.verdicts.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// Shadow tool pruning (W2a): ask wardryx which of `tool_defs` its
    /// `deny_tool` rule would remove, and price their schemas in estimated
    /// input tokens. Never changes anything about the call this request
    /// forwards; it only measures. The caller (`proxy::messages`) is
    /// responsible for gating this on `TOKENFUSE_TOOLS_PRUNE=shadow`, the
    /// hook being on, and the request declaring at least one tool - this
    /// method assumes all three already hold and does not re-check them.
    ///
    /// Every field of the result is `None` together on any error: a missing
    /// client, a transport failure, a body that will not decode, a 404
    /// (this wardryx predates `/v1/filter-tools`), or any other status
    /// outside 2xx. Never zero, because zero tools_would_prune is a real
    /// measured answer this method also returns on a clean success with
    /// nothing denied.
    pub async fn measure_shadow_prune(
        &self,
        agent_id: &str,
        run_id: &str,
        tool_defs: &[(String, usize)],
    ) -> ShadowPruneMeasurement {
        let none = ShadowPruneMeasurement::default();
        let tool_names: Vec<String> = tool_defs.iter().map(|(n, _)| n.clone()).collect();

        let outcome = if let Some(cached) = self.filter_cache.get(agent_id, &tool_names) {
            cached
        } else {
            let Some(client) = &self.client else {
                return none;
            };
            let wire = FilterToolsWireRequest {
                agent_id,
                run_id,
                tool_names: &tool_names,
            };
            match client.filter_tools(&wire).await {
                Ok(outcome) => {
                    self.filter_cache
                        .put(agent_id, &tool_names, outcome.clone());
                    outcome
                }
                Err(WardryxError::FilterRouteNotFound) => {
                    if !self.warned_filter_not_found.swap(true, Ordering::SeqCst) {
                        tracing::warn!(
                            "wardryx has no /v1/filter-tools route (this wardryx predates it); \
                             shadow tool pruning measures nothing"
                        );
                    }
                    return none;
                }
                Err(e) => {
                    if !self.warned_filter_other.swap(true, Ordering::SeqCst) {
                        tracing::warn!(
                            error = %e,
                            "wardryx filter-tools call failed; shadow tool pruning measures \
                             nothing for this failure kind"
                        );
                    }
                    return none;
                }
            }
        };

        let denied: std::collections::HashSet<&str> =
            outcome.denied.iter().map(|d| d.name.as_str()).collect();
        let mut would_prune: u32 = 0;
        let mut pruned_bytes: u64 = 0;
        for (name, len) in tool_defs {
            if denied.contains(name.as_str()) {
                would_prune += 1;
                pruned_bytes += *len as u64;
            }
        }
        ShadowPruneMeasurement {
            tools_offered: Some(tool_defs.len() as u32),
            tools_would_prune: Some(would_prune),
            // Bytes are the finest unit this measurement has: they are summed
            // and divided ONCE, the way `estimate_cost` divides a whole body,
            // so N denied tools do not each lose up to three bytes before the
            // sum (invariant 61, the money path's round-once rule).
            pruned_schema_tokens_est: Some(pruned_bytes / crate::estimate::CHARS_PER_TOKEN),
        }
    }

    /// Synthesize an outcome for "no verdict came back", per `failmode`:
    /// the PDP could not be reached, or it answered with an error status.
    /// `what_happened` is the first half of the reason, from
    /// [`WardryxError::as_reason`]. Never cached: a transient outage should
    /// not stick around for the cache TTL once the PDP recovers, and a
    /// refusal (a wrong key fixed, an identity header added) no more than an
    /// outage.
    fn fallback(&self, what_happened: &str) -> WardryxOutcome {
        let decision = match self.failmode {
            FailMode::Open => WardryxDecision::Allow,
            FailMode::Closed => WardryxDecision::Deny,
        };
        WardryxOutcome {
            decision,
            policy_version: None,
            reason: Some(format!(
                "{what_happened}; failmode={:?} applied",
                self.failmode
            )),
            approval_id: None,
            approval_token_required: true,
            unreachable: true,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decision_parses_case_insensitively() {
        assert_eq!(
            WardryxDecision::parse("Allow"),
            Some(WardryxDecision::Allow)
        );
        assert_eq!(WardryxDecision::parse("DENY"), Some(WardryxDecision::Deny));
        assert_eq!(WardryxDecision::parse("hold"), Some(WardryxDecision::Hold));
        assert_eq!(WardryxDecision::parse("bogus"), None);
    }

    #[test]
    fn cache_key_is_order_independent() {
        let a = Cache::key("agent-1", &["b".to_string(), "a".to_string()], None, false);
        let b = Cache::key("agent-1", &["a".to_string(), "b".to_string()], None, false);
        assert_eq!(a, b, "tool order must not change the cache key");
    }

    #[test]
    fn cache_key_differs_by_agent() {
        let a = Cache::key("agent-1", &["a".to_string()], None, false);
        let b = Cache::key("agent-2", &["a".to_string()], None, false);
        assert_ne!(a, b);
    }

    #[test]
    fn cache_key_differs_by_attestation() {
        // Regression: a `deny_if_unattested` decision must not leak across
        // attestation states. An attested and an unattested request for the
        // same agent + tool-set must land on different cache keys, so one can
        // never inherit the other's cached decision inside the TTL.
        let unattested = Cache::key("agent-1", &["a".to_string()], None, false);
        let attested = Cache::key("agent-1", &["a".to_string()], Some("spiffe"), false);
        assert_ne!(
            unattested, attested,
            "attestation must be part of the decision-cache key"
        );
    }

    #[test]
    fn cache_round_trips_allow_and_deny() {
        let cache = Cache::new(Duration::from_secs(60));
        let outcome = WardryxOutcome {
            decision: WardryxDecision::Deny,
            policy_version: Some("v1".to_string()),
            reason: Some("no".to_string()),
            approval_id: None,
            approval_token_required: true,
            unreachable: false,
        };
        cache.put(
            "agent-1",
            &["grep".to_string()],
            None,
            false,
            &outcome,
            true,
        );
        let hit = cache
            .get("agent-1", &["grep".to_string()], None, false)
            .unwrap();
        assert_eq!(hit.decision, WardryxDecision::Deny);
        assert_eq!(hit.policy_version.as_deref(), Some("v1"));
    }

    #[test]
    fn cache_never_stores_hold() {
        let cache = Cache::new(Duration::from_secs(60));
        let outcome = WardryxOutcome {
            decision: WardryxDecision::Hold,
            policy_version: None,
            reason: None,
            approval_id: Some("appr-1".to_string()),
            approval_token_required: true,
            unreachable: false,
        };
        // cacheable: true here on purpose -- proves the hold guard fires on
        // its own, independent of the cacheable guard below it.
        cache.put(
            "agent-1",
            &["grep".to_string()],
            None,
            false,
            &outcome,
            true,
        );
        assert!(cache
            .get("agent-1", &["grep".to_string()], None, false)
            .is_none());
    }

    #[test]
    fn cache_never_stores_when_not_cacheable() {
        // An allow that would otherwise be stored (see
        // cache_round_trips_allow_and_deny), but arrives with cacheable:
        // false -- e.g. a matched policy sets max_steps/allow_domains/
        // require_human_above_usd -- must never be reused for a later call.
        let cache = Cache::new(Duration::from_secs(60));
        let outcome = WardryxOutcome {
            decision: WardryxDecision::Allow,
            policy_version: Some("v1".to_string()),
            reason: Some("allowed for now".to_string()),
            approval_id: None,
            approval_token_required: true,
            unreachable: false,
        };
        cache.put(
            "agent-1",
            &["grep".to_string()],
            None,
            false,
            &outcome,
            false,
        );
        assert!(cache
            .get("agent-1", &["grep".to_string()], None, false)
            .is_none());
    }

    #[test]
    fn cache_expires_after_ttl() {
        let cache = Cache::new(Duration::from_millis(1));
        let outcome = WardryxOutcome {
            decision: WardryxDecision::Allow,
            policy_version: None,
            reason: None,
            approval_id: None,
            approval_token_required: true,
            unreachable: false,
        };
        cache.put(
            "agent-1",
            &["grep".to_string()],
            None,
            false,
            &outcome,
            true,
        );
        std::thread::sleep(Duration::from_millis(20));
        assert!(cache
            .get("agent-1", &["grep".to_string()], None, false)
            .is_none());
    }

    #[tokio::test]
    async fn from_env_stays_off_without_a_url() {
        std::env::remove_var("TOKENFUSE_WARDRYX_URL");
        std::env::set_var("TOKENFUSE_WARDRYX_MODE", "enforce");
        let w = Wardryx::from_env();
        assert_eq!(w.mode, WardryxMode::Off);
        std::env::remove_var("TOKENFUSE_WARDRYX_MODE");
    }

    #[tokio::test]
    async fn decide_fails_open_with_no_client_configured() {
        let w = Wardryx::disabled();
        let outcome = w
            .decide(DecideContext {
                chain_proven: false,
                agent_id: "a".into(),
                run_id: "r".into(),
                on_behalf_of: vec![],
                tool_names: vec![],
                domains: vec![],
                steps: 0,
                model: "m".into(),
                est_cost_usd: 0.0,
                attestation_method: None,
                approval_token: None,
            })
            .await;
        assert_eq!(outcome.decision, WardryxDecision::Allow);
    }

    #[tokio::test]
    async fn decide_fails_closed_with_no_client_configured_when_requested() {
        let mut w = Wardryx::disabled();
        w.failmode = FailMode::Closed;
        let outcome = w
            .decide(DecideContext {
                chain_proven: false,
                agent_id: "a".into(),
                run_id: "r".into(),
                on_behalf_of: vec![],
                tool_names: vec![],
                domains: vec![],
                steps: 0,
                model: "m".into(),
                est_cost_usd: 0.0,
                attestation_method: None,
                approval_token: None,
            })
            .await;
        assert_eq!(outcome.decision, WardryxDecision::Deny);
    }

    // -- a PDP that ANSWERS with a non-2xx status is a refusal, not bad JSON --
    //
    // Measured 2026-09-24 on a live gateway in shadow mode with no
    // x-fuse-agent-id: wardryx answered 400 ("agent_id and run_id are
    // required") and this hook logged "wardryx response was not valid JSON:
    // missing field `decision`", sending an operator to look at JSON when the
    // PDP had refused the call. A wrong key (401) and a 5xx read the same way.

    fn ctx_for(agent: &str) -> DecideContext {
        DecideContext {
            chain_proven: false,
            agent_id: agent.into(),
            run_id: "r".into(),
            on_behalf_of: vec![],
            tool_names: vec![],
            domains: vec![],
            steps: 0,
            model: "m".into(),
            est_cost_usd: 0.0,
            attestation_method: None,
            approval_token: None,
        }
    }

    /// A stub PDP answering every `POST /v1/decide` with `status` and `body`,
    /// counting the calls it received.
    async fn answering_pdp(
        status: u16,
        body: String,
    ) -> (String, std::sync::Arc<std::sync::atomic::AtomicUsize>) {
        answering("/v1/decide", status, body).await
    }

    /// The same stub on any route.
    async fn answering(
        route: &'static str,
        status: u16,
        body: String,
    ) -> (String, std::sync::Arc<std::sync::atomic::AtomicUsize>) {
        use axum::response::IntoResponse;
        let calls = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let seen = std::sync::Arc::clone(&calls);
        let app = axum::Router::new().route(
            route,
            axum::routing::post(move || {
                let seen = std::sync::Arc::clone(&seen);
                let body = body.clone();
                async move {
                    seen.fetch_add(1, Ordering::SeqCst);
                    (
                        axum::http::StatusCode::from_u16(status).unwrap(),
                        [("content-type", "application/json")],
                        body,
                    )
                        .into_response()
                }
            }),
        );
        let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = l.local_addr().unwrap();
        tokio::spawn(async move {
            let _ = axum::serve(l, app).await;
        });
        (format!("http://{addr}"), calls)
    }

    fn hook(url: String, failmode: FailMode, cache_ttl: Duration) -> Wardryx {
        Wardryx::new(
            WardryxMode::Shadow,
            failmode,
            url,
            None,
            Duration::from_secs(2),
            cache_ttl,
        )
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    // The guard only serialises the tests that read the process-wide log
    // buffer, and nothing this test spawns ever takes it, so holding it
    // across the awaits below cannot deadlock, whatever thread they resume on.
    #[allow(clippy::await_holding_lock)]
    async fn a_refusal_is_logged_and_reasoned_by_its_status_not_as_bad_json() {
        let _serial = crate::testlog::log_lock();
        crate::testlog::captured_log().lock().unwrap().clear();
        let (url, _) = answering_pdp(
            400,
            r#"{"error":"agent_id and run_id are required"}"#.to_string(),
        )
        .await;
        let w = hook(url, FailMode::Open, Duration::from_secs(0));

        let outcome = w.decide(ctx_for("")).await;

        assert_eq!(
            outcome.decision,
            WardryxDecision::Allow,
            "failmode open, unchanged"
        );
        assert!(
            outcome.unreachable,
            "a refusal is still a fallback, not a verdict"
        );
        let reason = outcome.reason.expect("a fallback always carries a reason");
        assert!(
            reason.contains("400"),
            "the reason names the status: {reason}"
        );
        assert!(
            reason.contains("agent_id and run_id are required"),
            "the reason carries what the PDP said: {reason}"
        );
        assert!(!reason.contains("not valid JSON"), "{reason}");
        assert!(
            !reason.contains("unreachable"),
            "a PDP that answered was not unreachable: {reason}"
        );
        // Found by what this PDP said rather than by the message alone: the
        // buffer is process-wide and other tests here log the same message
        // concurrently without the lock.
        let log =
            String::from_utf8_lossy(&crate::testlog::captured_log().lock().unwrap()).to_string();
        let line = log
            .lines()
            .find(|l| {
                l.contains("wardryx decide call failed")
                    && l.contains("agent_id and run_id are required")
            })
            .unwrap_or_else(|| panic!("one warn line quoting the refusal, got:\n{log}"));
        assert!(
            line.contains("400"),
            "the logged error names the status: {line}"
        );
        assert!(!line.contains("not valid JSON"), "{line}");
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    // The guard only serialises the tests that read the process-wide log
    // buffer, and nothing this test spawns ever takes it, so holding it
    // across the awaits below cannot deadlock, whatever thread they resume on.
    #[allow(clippy::await_holding_lock)]
    async fn a_filter_tools_refusal_names_its_status_and_what_wardryx_said() {
        let _serial = crate::testlog::log_lock();
        crate::testlog::captured_log().lock().unwrap().clear();
        let (url, _) = answering(
            "/v1/filter-tools",
            401,
            r#"{"error":"missing or invalid bearer token"}"#.to_string(),
        )
        .await;
        let w = hook(url, FailMode::Open, Duration::from_secs(0));

        let m = w
            .measure_shadow_prune("agent://t/a", "r", &[("gh_api".to_string(), 40)])
            .await;

        assert_eq!(
            m,
            ShadowPruneMeasurement::default(),
            "a refusal measures nothing"
        );
        let log =
            String::from_utf8_lossy(&crate::testlog::captured_log().lock().unwrap()).to_string();
        let line = log
            .lines()
            .find(|l| {
                l.contains("wardryx filter-tools call failed")
                    && l.contains("missing or invalid bearer token")
            })
            .unwrap_or_else(|| panic!("one warn line quoting the refusal, got:\n{log}"));
        assert!(line.contains("401"), "{line}");
        assert!(
            !line.contains("request failed"),
            "the request did not fail, the PDP answered: {line}"
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn every_non_2xx_names_its_status_and_the_failmode_is_unchanged() {
        for (status, body, failmode, detail) in [
            (
                401,
                r#"{"error":"unauthorized"}"#,
                FailMode::Closed,
                "unauthorized",
            ),
            (403, r#"{"error":"forbidden"}"#, FailMode::Open, "forbidden"),
            (
                500,
                "internal oops, not json",
                FailMode::Closed,
                "Internal Server Error",
            ),
            (503, "", FailMode::Open, "Service Unavailable"),
            // wardryx's shape with nothing in it says nothing: the standard
            // phrase stands in, never an empty quote.
            (400, r#"{"error":"  "}"#, FailMode::Open, "Bad Request"),
            // A status with no standard phrase still names itself.
            (599, "", FailMode::Closed, "no reason given"),
        ] {
            let (url, _) = answering_pdp(status, body.to_string()).await;
            let w = hook(url, failmode, Duration::from_secs(0));
            let outcome = w.decide(ctx_for("agent://t/a")).await;
            let expected = match failmode {
                FailMode::Open => WardryxDecision::Allow,
                FailMode::Closed => WardryxDecision::Deny,
            };
            assert_eq!(outcome.decision, expected, "status {status}");
            assert!(outcome.unreachable, "status {status}");
            let reason = outcome.reason.unwrap();
            assert!(reason.contains(&status.to_string()), "{status}: {reason}");
            assert!(reason.contains(detail), "{status}: {reason}");
            assert!(!reason.contains("not valid JSON"), "{status}: {reason}");
        }
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_refusal_is_counted_as_a_fallback_and_never_cached() {
        let (url, calls) = answering_pdp(401, r#"{"error":"unauthorized"}"#.to_string()).await;
        // A cache that WOULD reuse an answer, so reuse is observable.
        let w = hook(url, FailMode::Open, Duration::from_secs(60));

        w.decide(ctx_for("agent://t/a")).await;
        w.decide(ctx_for("agent://t/a")).await;

        assert_eq!(calls.load(Ordering::SeqCst), 2, "a refusal is never cached");
        let v = w.verdicts();
        assert_eq!(
            v.unreachable_fallbacks, 2,
            "counted as a fallback each time"
        );
        assert_eq!(
            (v.allow, v.deny, v.hold),
            (0, 0, 0),
            "and never as a verdict"
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_2xx_that_does_not_decode_stays_a_decode_error() {
        let (url, _) = answering_pdp(200, r#"{"not":"a decision"}"#.to_string()).await;
        let w = hook(url, FailMode::Open, Duration::from_secs(0));
        let reason = w.decide(ctx_for("agent://t/a")).await.reason.unwrap();
        assert!(reason.contains("not valid JSON"), "{reason}");
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_pdp_nobody_can_reach_is_still_called_unreachable() {
        let w = hook(
            "http://127.0.0.1:1".into(),
            FailMode::Open,
            Duration::from_secs(0),
        );
        let reason = w.decide(ctx_for("agent://t/a")).await.reason.unwrap();
        assert!(reason.contains("unreachable"), "{reason}");
    }

    /// A PDP whose refusal never ends: a status line, then a chunked body
    /// written until the reader goes away. Raw TCP, because a handler here
    /// cannot stream an endless body without a dependency this crate lacks.
    async fn endless_refusal() -> String {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = l.local_addr().unwrap();
        tokio::spawn(async move {
            while let Ok((mut sock, _)) = l.accept().await {
                tokio::spawn(async move {
                    let mut request = vec![0u8; 64 * 1024];
                    let _ = sock.read(&mut request).await;
                    let head = "HTTP/1.1 400 Bad Request\r\ncontent-type: application/json\r\n\
                                transfer-encoding: chunked\r\n\r\n";
                    if sock.write_all(head.as_bytes()).await.is_err() {
                        return;
                    }
                    let piece = "x".repeat(16 * 1024);
                    let chunk = format!("{:x}\r\n{piece}\r\n", piece.len());
                    while sock.write_all(chunk.as_bytes()).await.is_ok() {}
                });
            }
        });
        format!("http://{addr}")
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_refusal_whose_body_never_ends_is_reported_without_waiting_for_it() {
        let url = endless_refusal().await;
        let w = Wardryx::new(
            WardryxMode::Shadow,
            FailMode::Closed,
            url,
            None,
            Duration::from_secs(10),
            Duration::from_secs(0),
        );

        let started = Instant::now();
        let outcome = w.decide(ctx_for("agent://t/a")).await;
        let took = started.elapsed();

        assert!(
            took < Duration::from_secs(3),
            "the body is read to its cap and dropped, not to the 10 s timeout: {took:?}"
        );
        assert_eq!(
            outcome.decision,
            WardryxDecision::Deny,
            "failmode closed, unchanged"
        );
        let reason = outcome.reason.unwrap();
        assert!(reason.contains("400"), "{reason}");
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_hostile_refusal_body_becomes_one_short_line() {
        let mut seed: u64 = 0x5eed_0924;
        let mut next = move || {
            seed ^= seed << 13;
            seed ^= seed >> 7;
            seed ^= seed << 17;
            seed
        };
        let pieces = [
            "\n",
            "\r",
            "\u{0}",
            "\u{1b}[31m",
            "\t",
            "é",
            "{",
            "\"",
            "x",
            "\u{202e}",
            "\u{200b}",
            "\u{2028}",
            "\u{85}",
        ];
        for round in 0..40 {
            let mut msg = String::new();
            for _ in 0..(next() % 3000) {
                msg.push_str(pieces[(next() % pieces.len() as u64) as usize]);
            }
            let body = if round % 2 == 0 {
                serde_json::json!({ "error": msg }).to_string()
            } else {
                msg.clone()
            };
            let (url, _) = answering_pdp(400, body).await;
            let w = hook(url, FailMode::Open, Duration::from_secs(0));
            let reason = w.decide(ctx_for("agent://t/a")).await.reason.unwrap();
            assert!(
                !reason
                    .chars()
                    .any(|c| c.is_control() || matches!(c, '\u{202e}' | '\u{200b}' | '\u{2028}')),
                "round {round}: a control or invisible character reached the reason: {reason:?}"
            );
            assert!(
                reason.chars().count() <= 300,
                "round {round}: {} characters",
                reason.chars().count()
            );
            assert!(reason.contains("400"), "round {round}: {reason:?}");
        }
    }
}
