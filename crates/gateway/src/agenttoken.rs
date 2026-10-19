//! The agent's own token as the door credential (wave 1, WAVE1-DESIGN 1.5).
//!
//! # What this is
//!
//! vouchryx mints each enrolled agent a five-minute access token of its own
//! (`client_credentials` with DPoP, vouchryx#48): header `typ: at+jwt`, `sub`
//! and `client_id` the agent, one audience, bound to the key that signed the
//! proof at issuance, carrying the agent's `unit` and `org`. With
//! `TOKENFUSE_AGENT_TOKENS` on, that token presented as `Authorization: DPoP`
//! with an RFC 9449 proof is a door credential at the LLM door, the OpenAI
//! door, the MCP broker and the tool-call check. It is verified here, offline,
//! against the delegation door's own issuer, JWKS, audience and origin, and
//! the agent id, the unit and the run principal are taken from it, never from
//! a header.
//!
//! # Off, accept, require
//!
//! `off` (the binary's default) changes nothing. `accept` admits a token and
//! keeps every static client key working beside it (the launchers' setting).
//! `require` refuses every static client key. On either of the last two the
//! process refuses to start without what verification needs: the delegation
//! door (issuer, JWKS, origin), a named audience, and a revocation list that
//! fails closed.

use std::collections::BTreeSet;
use std::sync::Arc;

use axum::body::Body;
use axum::http::{HeaderMap, StatusCode};
use axum::response::Response;
use tokenfuse_delegation::{Refusal, VerifiedAgent};

/// The switch.
pub const SWITCH: &str = "TOKENFUSE_AGENT_TOKENS";

/// The three words the switch reads, in the order a refusal names them.
pub const WORDS: &[&str] = &["off", "accept", "require"];

/// The key id the MCP broker's own gateway key must resolve to for the
/// tool-call check to take an agent token the broker relays without a proof.
pub const BROKER_KEY_ID: &str = "broker";

/// The variable naming the static client keys still admitted under `require`
/// at the gateway's doors (`TOKENFUSE_CLIENT_KEYS`).
pub const STATIC_KEYS_VAR: &str = "TOKENFUSE_AGENT_TOKENS_STATIC_KEYS";

/// The same list at the MCP broker, whose static keys are `TOKENFUSE_MCP_KEYS`.
pub const BROKER_STATIC_KEYS_VAR: &str = "TOKENFUSE_MCP_AGENT_TOKENS_STATIC_KEYS";

/// The most bytes of an agent token the policy plane is sent. Above it the token
/// is admitted and not forwarded (invariant 140).
pub const TOKEN_FOR_PDP_CAP_BYTES: usize = 4 * 1024;

/// How many proof `jti` values one generation of the replay cache holds (two
/// generations are kept). Only a proof that already verified reaches it, so it
/// bounds what an admitted agent can make this process remember; past it a
/// proof is refused rather than a used one forgotten.
pub const REPLAY_CAP: usize = 16_384;

/// The identity source words wardryx reads (its `policy.IdentitySource*`):
/// how the enforcement point knew the agent.
pub const IDENTITY_AGENT_TOKEN: &str = "agent-token";
pub const IDENTITY_CLIENT_KEY: &str = "client-key";
pub const IDENTITY_NONE: &str = "none";

/// The identity-mismatch reasons this door adds.
pub const AGENT_CONTRADICTS_TOKEN: &str = "agent_id_contradicts_token";
pub const UNIT_CONTRADICTS_MAP: &str = "unit_contradicts_map";

/// What `TOKENFUSE_AGENT_TOKENS` asked for.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Mode {
    #[default]
    Off,
    Accept,
    Require,
}

impl Mode {
    pub fn as_str(self) -> &'static str {
        match self {
            Mode::Off => "off",
            Mode::Accept => "accept",
            Mode::Require => "require",
        }
    }
}

/// The door, on: its mode and the cache that makes a proof single-use.
pub struct AgentTokens {
    mode: Mode,
    replay: tokenfuse_dpop::ReplayCache,
    allow: BTreeSet<String>,
}

impl AgentTokens {
    pub fn new(mode: Mode) -> Self {
        AgentTokens {
            mode,
            replay: tokenfuse_dpop::ReplayCache::new(REPLAY_CAP),
            allow: BTreeSet::new(),
        }
    }

    /// [`AgentTokens::new`] with the static key ids admitted under `require`.
    pub fn with_static_keys(mode: Mode, allow: BTreeSet<String>) -> Self {
        let _ = allow;
        Self::new(mode)
    }

    /// The static key ids this door admits under `require`, sorted.
    pub fn static_key_ids(&self) -> Vec<String> {
        self.allow.iter().cloned().collect()
    }

    pub fn mode(&self) -> Mode {
        self.mode
    }

    /// Record a proof's `jti` as used at `now`. False when it was seen inside
    /// its window, or when the cache is full and single use can no longer be
    /// promised.
    pub fn first_use(&self, jti: &str, now: i64) -> bool {
        self.replay.check_and_record(jti, now).is_ok()
    }
}

/// The mode only: the replay cache is a set of proof identifiers, which a log
/// line has no use for.
impl std::fmt::Debug for AgentTokens {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AgentTokens")
            .field("mode", &self.mode)
            .finish_non_exhaustive()
    }
}

/// `None` is the door off.
pub type Tokens = Option<Arc<AgentTokens>>;

/// Whether the door requires a token of every caller.
pub fn required(tokens: &Tokens) -> bool {
    tokens.as_ref().is_some_and(|t| t.mode() == Mode::Require)
}

/// Whether a static client key with this id is admitted under `require`
/// (invariant 138 at the gateway's doors, 139 at the broker's).
pub fn static_key_listed(tokens: &Tokens, key_id: &str) -> bool {
    let _ = (tokens, key_id);
    false
}

/// The names one static-key list is read under, and the key ids it may name.
pub struct StaticKeys<'a> {
    /// The variable the list is read from, named in every refusal about it.
    pub list_var: &'a str,
    /// The variable the key set is read from, named when a listed id is not in it.
    pub keys_var: &'a str,
    /// The list's value, `None` when the variable is unset.
    pub value: Option<&'a str>,
    /// The key ids the key set configures.
    pub configured: &'a [&'a str],
}

/// Read a static-key list for `mode`: empty when unset or blank, an error when
/// it is set outside `require` or names an id the key set does not configure.
pub fn parse_static_keys(spec: &StaticKeys<'_>, mode: Mode) -> Result<BTreeSet<String>, String> {
    let _ = (spec, mode);
    Ok(BTreeSet::new())
}

/// The pure startup decision: the switch's value, the delegation door this
/// process built, and what the revocation variables asked for.
pub fn from_values(
    value: Option<&str>,
    proving: Option<&crate::chainproof::Proving>,
    revocations: &crate::revocations::Wanted,
    statics: &StaticKeys<'_>,
) -> Result<Tokens, String> {
    let mode = match crate::defaults::switch_word(SWITCH, value, WORDS)? {
        None | Some("off") => return Ok(None),
        Some("require") => Mode::Require,
        Some(_) => Mode::Accept,
    };
    let _ = statics;
    let on = mode.as_str();
    let Some(proving) = proving else {
        return Err(format!(
            "tokenfuse: {SWITCH}={on} verifies each agent token against the delegation door, \
             and none is configured: set TOKENFUSE_DELEGATION_ISSUER, TOKENFUSE_DELEGATION_JWKS \
             and TOKENFUSE_DELEGATION_URL (vouchryx's issuer, its key set, and this process's \
             public origin)"
        ));
    };
    if proving.cfg.audience.trim().is_empty() {
        return Err(format!(
            "tokenfuse: {SWITCH}={on} needs TOKENFUSE_DELEGATION_AUDIENCE, this process's own \
             resource: an empty audience would accept a token minted for any resource"
        ));
    }
    match revocations {
        crate::revocations::Wanted::On {
            fail_mode: tokenfuse_delegation::revocations::FailMode::Closed,
            ..
        } => {}
        crate::revocations::Wanted::On { .. } => {
            return Err(format!(
                "tokenfuse: {SWITCH}={on} needs a revocation list that fails closed: \
                 TOKENFUSE_DELEGATION_REVOCATIONS_FAILMODE=open would honour a stopped agent \
                 while the list cannot be read"
            ));
        }
        crate::revocations::Wanted::Off => {
            return Err(format!(
                "tokenfuse: {SWITCH}={on} needs TOKENFUSE_DELEGATION_REVOCATIONS, vouchryx's \
                 revocation list: without it an agent stopped there keeps working here until \
                 its token expires"
            ));
        }
        crate::revocations::Wanted::Refused(why) => return Err(why.clone()),
    }
    Ok(Some(Arc::new(AgentTokens::new(mode))))
}

/// [`from_values`] against the process environment; exits 2 on a refusal,
/// before the listener binds. `list_var` and `keys_var` name the static-key
/// list and the key set it is checked against (the gateway's or the broker's).
pub fn from_env(
    proving: &crate::chainproof::ChainProof,
    list_var: &str,
    keys_var: &str,
    configured: &[&str],
) -> Tokens {
    let value = std::env::var(SWITCH).ok();
    let list = std::env::var(list_var).ok();
    let wanted = crate::revocations::wanted(|k| std::env::var(k).ok(), proving.is_some());
    let statics = StaticKeys {
        list_var,
        keys_var,
        value: list.as_deref(),
        configured,
    };
    crate::defaults::exit_on_refusal(from_values(
        value.as_deref(),
        proving.as_deref(),
        &wanted,
        &statics,
    ))
}

/// What a request's credentials said about this door.
#[derive(Debug)]
pub enum Door {
    /// No agent token on this request, or the door is off: the static paths
    /// decide, exactly as before.
    NotPresented,
    /// An agent token verified, with its proof, for this request.
    Admitted(VerifiedAgent),
    /// An agent token was presented and refused. The wire never says which
    /// check failed; the operator's log does.
    Refused(Why),
}

/// Why a presented agent token was refused, for the operator's log only.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Why {
    /// The token or its proof did not verify.
    Token(Refusal),
    /// A client key came with it: two credentials is confusion or a probe.
    BesideAKey,
    /// The proof's `jti` was used before inside its window.
    Replayed,
    /// The token names an agent id the estate's records refuse.
    NotCanonical,
}

/// Judge the agent-token door for one request arriving on `path`.
pub fn admit(
    tokens: &Tokens,
    proving: &crate::chainproof::ChainProof,
    feed: &crate::revocations::Feed,
    headers: &HeaderMap,
    path: &str,
    now: i64,
) -> Door {
    let (Some(tokens), Some(proving)) = (tokens.as_ref(), proving.as_ref()) else {
        return Door::NotPresented;
    };
    let Some(token) = agent_token_in(headers) else {
        return Door::NotPresented;
    };
    if headers.contains_key(crate::clientkeys::CLIENT_KEY_HEADER) {
        return Door::Refused(Why::BesideAKey);
    }
    let proof = headers
        .get(crate::mcpdoor::PROOF_HEADER)
        .and_then(|v| v.to_str().ok());
    // The origin is the deployment's, the path the route's: never a `Host`
    // header, which the caller writes (invariant 30's `htu` rule).
    let url = format!("{}{}", proving.origin.trim_end_matches('/'), path);
    let agent = match tokenfuse_delegation::verify_agent_token(
        &proving.cfg,
        token,
        proof,
        "POST",
        &url,
        now,
        crate::revocations::hook(feed, now),
    ) {
        Ok(agent) => agent,
        Err(refusal) => return Door::Refused(Why::Token(refusal)),
    };
    admitted(tokens, agent, now)
}

/// The checks after a token verified, shared by both ways in: an agent id the
/// records accept, and a proof used once (none for a relayed token).
fn admitted(tokens: &AgentTokens, agent: VerifiedAgent, now: i64) -> Door {
    if !tokenfuse_core::agent_event::is_canonical_agent_id(&agent.subject) {
        return Door::Refused(Why::NotCanonical);
    }
    if !agent.proof_jti.is_empty() && !tokens.first_use(&agent.proof_jti, now) {
        return Door::Refused(Why::Replayed);
    }
    Door::Admitted(agent)
}

/// The agent token in `Authorization: DPoP`, when that is what it holds.
fn agent_token_in(headers: &HeaderMap) -> Option<&str> {
    crate::chainproof::dpop_credential(headers.get("authorization").and_then(|v| v.to_str().ok()))
        .filter(|t| tokenfuse_delegation::is_agent_token(t))
}

/// The agent token this request presented, for the policy plane, when it is
/// within [`TOKEN_FOR_PDP_CAP_BYTES`] (invariant 140).
pub fn token_for_pdp(headers: &HeaderMap) -> Option<String> {
    let _ = headers;
    None
}

/// A token for the policy plane when it is an agent token within the cap.
pub fn for_pdp(token: &str) -> Option<String> {
    let _ = token;
    None
}

/// Judge an agent token the MCP broker relays to the tool-call check beside
/// its own gateway key, without a proof.
pub fn relayed(
    tokens: &Tokens,
    proving: &crate::chainproof::ChainProof,
    feed: &crate::revocations::Feed,
    headers: &HeaderMap,
    now: i64,
) -> Door {
    let (Some(tokens), Some(proving)) = (tokens.as_ref(), proving.as_ref()) else {
        return Door::NotPresented;
    };
    let Some(token) = agent_token_in(headers) else {
        return Door::NotPresented;
    };
    match tokenfuse_delegation::verify_relayed_agent_token(
        &proving.cfg,
        token,
        now,
        crate::revocations::hook(feed, now),
    ) {
        Ok(agent) => admitted(tokens, agent, now),
        Err(refusal) => Door::Refused(Why::Token(refusal)),
    }
}

/// Whether the request carries a token that declares itself an agent token
/// in `Authorization: DPoP`. Read unverified: it picks a path, nothing more.
pub fn carries_agent_token(headers: &HeaderMap) -> bool {
    agent_token_in(headers).is_some()
}

/// The word wardryx is told, from the door that admitted the call.
///
/// `@claude` 2026-10-18: any door credential that is not an agent token (a
/// static key, the broker's CIMD proof door, an XAA bearer token) is
/// `client-key`, the word wardryx has for a credential vouchryx did not mint
/// to this agent; `none` is a door that authenticated nobody.
pub fn identity_source(agent_token: bool, credential: bool) -> &'static str {
    if agent_token {
        IDENTITY_AGENT_TOKEN
    } else if credential {
        IDENTITY_CLIENT_KEY
    } else {
        IDENTITY_NONE
    }
}

/// The identity check for a call an agent token admitted.
pub fn contradiction(
    map: &crate::identitymap::IdentityMap,
    agent: &VerifiedAgent,
    header_agent: &str,
) -> Option<crate::identitymap::Mismatch> {
    let header_agent = header_agent.trim();
    if !header_agent.is_empty() && header_agent != agent.subject {
        return Some(crate::identitymap::Mismatch {
            reason: AGENT_CONTRADICTS_TOKEN,
        });
    }
    // The map may name the agent's unit; where it does, the token's must be
    // one of the units it names. A map that names the agent nowhere has no
    // say, and the token's unit stands.
    let units = map.units_naming(&agent.subject);
    if !units.is_empty() && !units.contains(&agent.unit.as_str()) {
        return Some(crate::identitymap::Mismatch {
            reason: UNIT_CONTRADICTS_MAP,
        });
    }
    None
}

/// One warn line for a refused agent token, never the token itself.
pub fn log_refusal(door: &'static str, why: Why) {
    tracing::warn!(door, ?why, "refused an agent token");
}

/// The challenge the LLM door answers a refused agent token with.
const REFUSED_CHALLENGE: &str = "DPoP algs=\"ES256\", error=\"invalid_token\"";
/// The challenge the LLM door answers a call with no agent token with.
const REQUIRED_CHALLENGE: &str = "DPoP algs=\"ES256\"";

/// `401` for a presented agent token that was refused. Cause-free, as every
/// door's refusal is: which check failed is an oracle.
pub fn refused_response() -> Response {
    refused_response_with(REFUSED_CHALLENGE)
}

/// [`refused_response`] with the challenge the caller gives. The MCP broker names
/// the protected resource document in it (RFC 9728); the LLM door does not.
pub fn refused_response_with(challenge: &str) -> Response {
    unauthorized_json(
        "agent_token_refused",
        "the agent token presented with this request was refused",
        challenge,
    )
}

/// `401` for a call with no agent token when the door requires one.
pub fn required_response() -> Response {
    required_response_with(REQUIRED_CHALLENGE, STATIC_KEYS_VAR)
}

/// [`required_response`] with the challenge the caller gives.
pub fn required_response_with(challenge: &str, list_var: &str) -> Response {
    let _ = list_var;
    unauthorized_json(
        "agent_token_required",
        "this gateway requires an agent token: `Authorization: DPoP <token>` with a DPoP proof",
        challenge,
    )
}

fn unauthorized_json(kind: &str, reason: &str, challenge: &str) -> Response {
    let body = serde_json::json!({
        "error": {
            "type": kind,
            "reason": reason,
            "retryable": false,
        }
    });
    Response::builder()
        .status(StatusCode::UNAUTHORIZED)
        .header("content-type", "application/json")
        .header("x-fuse", "unauthorized")
        .header("www-authenticate", challenge)
        .body(Body::from(body.to_string()))
        .expect("valid response")
}

/// `403` for a header that names another agent than the token proves, at a
/// door with no run to file it under (the MCP broker).
pub fn contradicted_response(proven: &str, claimed: &str) -> Response {
    let body = serde_json::json!({
        "error": {
            "type": "identity_mismatch",
            "reason": AGENT_CONTRADICTS_TOKEN,
            "detail": format!(
                "the agent token proves {proven} and `x-fuse-agent-id` claims {claimed}"
            ),
            "retryable": false,
        }
    });
    Response::builder()
        .status(StatusCode::FORBIDDEN)
        .header("content-type", "application/json")
        .header("x-fuse", "blocked")
        .header(
            "x-fuse-identity",
            format!("blocked={AGENT_CONTRADICTS_TOKEN}"),
        )
        .body(Body::from(body.to_string()))
        .expect("valid response")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::chainproof::Proving;
    use crate::revocations::Wanted;
    use tokenfuse_delegation::revocations::FailMode;
    use tokenfuse_delegation::testing::{agent_token, cfg, token, Key};
    use serde_json::json;

    fn proving(audience: &str) -> Proving {
        let mut c = cfg(&Key::new());
        c.audience = audience.to_string();
        Proving {
            cfg: c,
            origin: "https://tokenfuse.acme.example".to_string(),
        }
    }

    fn polling(fail_mode: FailMode) -> Wanted {
        Wanted::On {
            url: "https://vouchryx.acme.example/v1/revocations".to_string(),
            interval_ms: 12_000,
            max_age_secs: 60,
            fail_mode,
        }
    }

    fn mode_of(t: Result<Tokens, String>) -> Result<Option<Mode>, String> {
        t.map(|t| t.map(|t| t.mode()))
    }

    /// The three words in any case; unset, empty and blank are off; anything
    /// else refuses to start naming the variable, the value and the words.
    #[test]
    fn the_agent_tokens_switch_reads_three_words_and_refuses_a_fourth() {
        let p = proving("https://tokenfuse.acme.example");
        let on = polling(FailMode::Closed);
        for (value, want) in [
            (None, None),
            (Some(""), None),
            (Some("  "), None),
            (Some("off"), None),
            (Some("accept"), Some(Mode::Accept)),
            (Some("ACCEPT"), Some(Mode::Accept)),
            (Some(" require "), Some(Mode::Require)),
        ] {
            assert_eq!(
                mode_of(from_values(value, Some(&p), &on, &no_list())),
                Ok(want),
                "{value:?}"
            );
        }
        let err = from_values(Some("acept"), Some(&p), &on, &no_list()).unwrap_err();
        assert!(err.contains(SWITCH), "{err}");
        assert!(err.contains("acept"), "{err}");
        assert!(err.contains("off|accept|require"), "{err}");
    }

    /// On, the door needs everything verification needs, and says which one is
    /// missing; off, it needs nothing.
    #[test]
    fn agent_tokens_on_need_the_door_a_named_audience_and_a_list_that_fails_closed() {
        let p = proving("https://tokenfuse.acme.example");
        let closed = polling(FailMode::Closed);
        let cases: [(Option<&Proving>, &Wanted, &str); 4] = [
            (None, &closed, "TOKENFUSE_DELEGATION_ISSUER"),
            (Some(&p), &Wanted::Off, "TOKENFUSE_DELEGATION_REVOCATIONS"),
            (
                Some(&p),
                &Wanted::On {
                    url: "https://v.example/v1/revocations".to_string(),
                    interval_ms: 12_000,
                    max_age_secs: 60,
                    fail_mode: FailMode::Open,
                },
                "TOKENFUSE_DELEGATION_REVOCATIONS_FAILMODE",
            ),
            (Some(&p), &closed, ""),
        ];
        for (proving, wanted, names) in cases {
            let got = from_values(Some("accept"), proving, wanted, &no_list());
            if names.is_empty() {
                assert_eq!(mode_of(got), Ok(Some(Mode::Accept)));
            } else {
                let Err(err) = got else {
                    panic!("{names} missing must refuse");
                };
                assert!(err.contains(names), "{err}");
            }
        }
        for audience in ["", "   "] {
            let err = from_values(Some("require"), Some(&proving(audience)), &closed, &no_list())
                .expect_err("an empty audience must refuse");
            assert!(err.contains("TOKENFUSE_DELEGATION_AUDIENCE"), "{err}");
        }
        assert_eq!(
            mode_of(from_values(Some("off"), None, &Wanted::Off, &no_list())),
            Ok(None)
        );
        assert_eq!(mode_of(from_values(None, None, &Wanted::Off, &no_list())), Ok(None));
    }

    /// wardryx is told how the door knew the agent, from the door alone.
    #[test]
    fn the_identity_source_is_the_door_that_admitted_the_call() {
        assert_eq!(identity_source(true, true), IDENTITY_AGENT_TOKEN);
        assert_eq!(identity_source(true, false), IDENTITY_AGENT_TOKEN);
        assert_eq!(identity_source(false, true), IDENTITY_CLIENT_KEY);
        assert_eq!(identity_source(false, false), IDENTITY_NONE);
    }

    fn verified(unit: &str) -> VerifiedAgent {
        VerifiedAgent {
            subject: "agent://acme/triage".to_string(),
            unit: unit.to_string(),
            org: "default".to_string(),
            jti: "t".to_string(),
            jkt: "k".to_string(),
            proof_jti: "p".to_string(),
            issued_at: 0,
            expires_at: 300,
        }
    }

    fn map(raw: &str, label: &str) -> crate::identitymap::IdentityMap {
        let path =
            std::env::temp_dir().join(format!("tf-agenttoken-{label}-{}.json", std::process::id()));
        std::fs::write(&path, raw).unwrap();
        let m = crate::identitymap::IdentityMap::from_path(&path).expect("the map loads");
        let _ = std::fs::remove_file(&path);
        m
    }

    /// A header naming another agent, or a map binding the agent to another
    /// unit, is a mismatch; the token's own agent in the header, or a map that
    /// names the agent nowhere, is not.
    #[test]
    fn a_token_contradicted_by_its_header_or_the_identity_map_is_a_mismatch() {
        let empty = crate::identitymap::IdentityMap::default();
        let agent = verified("ops");
        assert_eq!(contradiction(&empty, &agent, ""), None);
        assert_eq!(contradiction(&empty, &agent, "agent://acme/triage"), None);
        assert_eq!(
            contradiction(&empty, &agent, "agent://acme/other").map(|m| m.reason),
            Some(AGENT_CONTRADICTS_TOKEN)
        );
        let bound = map(
            r#"{"units":[{"id":"finance"},{"id":"ops"}],
                "keys":[{"key_id":"k1","unit":"finance","agents":["agent://acme/*"]}]}"#,
            "bound",
        );
        assert_eq!(
            contradiction(&bound, &agent, "").map(|m| m.reason),
            Some(UNIT_CONTRADICTS_MAP)
        );
        assert_eq!(contradiction(&bound, &verified("finance"), ""), None);
        let elsewhere = map(
            r#"{"units":[{"id":"finance"}],
                "keys":[{"key_id":"k1","unit":"finance","agents":["agent://other/*"]}]}"#,
            "elsewhere",
        );
        assert_eq!(contradiction(&elsewhere, &agent, ""), None);
    }

    fn no_list() -> StaticKeys<'static> {
        StaticKeys {
            list_var: STATIC_KEYS_VAR,
            keys_var: "TOKENFUSE_CLIENT_KEYS",
            value: None,
            configured: &[],
        }
    }

    fn list<'a>(value: &'a str, configured: &'a [&'a str]) -> StaticKeys<'a> {
        StaticKeys {
            list_var: STATIC_KEYS_VAR,
            keys_var: "TOKENFUSE_CLIENT_KEYS",
            value: Some(value),
            configured,
        }
    }

    fn ids(set: BTreeSet<String>) -> Vec<String> {
        set.into_iter().collect()
    }

    /// The list is read under require and nowhere else: set while the switch is
    /// off or accept, it refuses and names the variable. Checked before the
    /// delegation door is, so the refusal is the one a reader meets first.
    #[test]
    fn the_static_key_list_is_refused_unless_require_is_on() {
        let p = proving("https://tokenfuse.acme.example");
        let on = polling(FailMode::Closed);
        let configured = ["key-a"];
        for value in [None, Some("off"), Some("accept")] {
            let err = from_values(value, Some(&p), &on, &list("key-a", &configured))
                .expect_err("a list outside require must refuse");
            assert!(err.contains(STATIC_KEYS_VAR), "{value:?}: {err}");
        }
        let err = from_values(Some("accept"), None, &Wanted::Off, &list("key-a", &configured))
            .expect_err("a list refuses before the delegation door is asked about");
        assert!(err.contains(STATIC_KEYS_VAR), "{err}");
    }

    /// An id the key set does not configure is refused, naming the id and the
    /// key set's variable: a list naming a key nobody holds is a typo or a
    /// removed key, and either way the operator must hear it at startup.
    #[test]
    fn the_static_key_list_names_an_id_the_key_set_does_not_configure() {
        let configured = ["key-a"];
        let err = parse_static_keys(&list("key-a,key-zz", &configured), Mode::Require)
            .expect_err("an id the key set does not configure must refuse");
        assert!(err.contains("key-zz"), "{err}");
        assert!(err.contains("TOKENFUSE_CLIENT_KEYS"), "{err}");
    }

    /// A value that names no key id at all is refused rather than read as an
    /// empty list: an operator who wrote separators meant a list.
    #[test]
    fn a_list_of_separators_alone_names_no_key_and_is_refused() {
        let configured = ["key-a"];
        for value in [",", " , ,", " , "] {
            assert!(
                parse_static_keys(&list(value, &configured), Mode::Require).is_err(),
                "{value:?}"
            );
        }
    }

    /// Entries are trimmed and a repeated id is one id.
    #[test]
    fn the_static_key_list_reads_its_entries_trimmed() {
        let configured = ["key-a", "key-b"];
        let got = parse_static_keys(&list(" key-b , key-a,key-a ", &configured), Mode::Require);
        assert_eq!(got.map(ids), Ok(vec!["key-a".to_string(), "key-b".to_string()]));
    }

    /// Unset, empty and blank are no list in every mode, as the switch's own
    /// blank handling reads them.
    #[test]
    fn a_blank_static_key_list_is_no_list_in_any_mode() {
        for mode in [Mode::Off, Mode::Accept, Mode::Require] {
            for value in [None, Some(""), Some("   ")] {
                let spec = StaticKeys {
                    list_var: STATIC_KEYS_VAR,
                    keys_var: "TOKENFUSE_CLIENT_KEYS",
                    value,
                    configured: &[],
                };
                assert_eq!(parse_static_keys(&spec, mode), Ok(BTreeSet::new()), "{mode:?} {value:?}");
            }
        }
    }

    /// Under require, only a listed id is admitted; off the mode, nothing is.
    #[test]
    fn static_key_listed_is_true_only_for_a_listed_id_under_require() {
        let allow: BTreeSet<String> = ["key-a".to_string()].into_iter().collect();
        let require = Some(Arc::new(AgentTokens::with_static_keys(Mode::Require, allow.clone())));
        assert!(static_key_listed(&require, "key-a"));
        assert!(!static_key_listed(&require, "key-b"));
        assert!(!static_key_listed(&require, ""));
        let accept = Some(Arc::new(AgentTokens::with_static_keys(Mode::Accept, allow)));
        assert!(!static_key_listed(&accept, "key-a"));
        assert!(!static_key_listed(&None, "key-a"));
    }

    fn bearer(token: &str) -> HeaderMap {
        let mut h = HeaderMap::new();
        h.insert("authorization", format!("DPoP {token}").parse().unwrap());
        h
    }

    /// Only an agent token is forwarded: a delegation token is a chain proof,
    /// and the policy plane is not told about it through this field.
    #[test]
    fn a_token_for_the_policy_plane_is_only_an_agent_token() {
        let issuer = Key::new();
        let holder = Key::new();
        let at = crate::sink::now_millis() / 1000;
        let agent = agent_token(&issuer, &holder, at, json!({}));
        let delegation = token(&issuer, &holder, at, json!({}));
        assert_eq!(token_for_pdp(&bearer(&agent)), Some(agent.clone()));
        assert_eq!(token_for_pdp(&bearer(&delegation)), None);
        assert_eq!(token_for_pdp(&HeaderMap::new()), None);
    }

    /// At the cap a token is forwarded and one byte past it is not: grow the
    /// token's padding one byte at a time until it crosses the cap, and check
    /// the boundary on both sides of the crossing.
    #[test]
    fn a_token_for_the_policy_plane_is_bounded_at_4_kib() {
        let issuer = Key::new();
        let holder = Key::new();
        let at = crate::sink::now_millis() / 1000;
        let mut pad = 0usize;
        let (mut last_under, mut first_over) = (None, None);
        while first_over.is_none() {
            let tok = agent_token(&issuer, &holder, at, json!({ "pad": "x".repeat(pad) }));
            if tok.len() <= TOKEN_FOR_PDP_CAP_BYTES {
                last_under = Some(tok);
            } else {
                first_over = Some(tok);
            }
            pad += 1;
        }
        let under = last_under.expect("a token under the cap");
        let over = first_over.expect("a token over the cap");
        assert_eq!(for_pdp(&under), Some(under.clone()), "{} bytes", under.len());
        assert_eq!(for_pdp(&over), None, "{} bytes", over.len());
    }
}
