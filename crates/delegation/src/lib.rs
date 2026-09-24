//! Verifying a `vouchryx` delegation token, offline (block A2).
//!
//! # What this is for
//!
//! `vouchryx` mints RFC 8693 delegation tokens, sender-constrained by RFC 9449
//! DPoP. Every enforcement point in the estate has to check one. The Go half of
//! this lives in `agent-stack-go/delegation`, which `wardryx`, `idryx`,
//! `scopyx`, `heraldyx` and `mockryx` import; this is the same check for the
//! Rust side, and the two must not disagree.
//!
//! # Offline, and that is the design
//!
//! Nothing here reaches out. The key set is held locally, the clock is passed
//! in, and revocation is a closure the caller owns. wardryx decides at a 3.2 ms
//! p50 and audits every decision: putting signature verification behind a round
//! trip taxes every decision in the estate and makes the token service a hard
//! dependency of every enforcement point at once, which is the shape
//! `dependency_failed` was cut to record.
//!
//! # The one defence that is shared rather than repeated
//!
//! Which algorithms a key may be used with, how a proof is checked, and how a key
//! is named all come from [`tokenfuse_dpop`], the single copy in this
//! repository. Two verifiers with two copies of those rules is how they end up
//! disagreeing about which signatures are valid, and there are now three: this
//! one, the Cloud's OIDC bearer path, and the MCP credential-broker's door in
//! the gateway crate. The rule sits in a crate rather than in either plane,
//! because the gateway must not depend on the Cloud.
//!
//! # What it refuses, and why each is not paranoia
//!
//! - **A token with `cnf.jkt` and no proof.** Refused, never accepted with the
//!   binding skipped: an enforcement point that simply forgot to pass a proof
//!   would otherwise report success while honouring a stolen token, and that
//!   failure looks exactly like it is working.
//! - **A token with no `cnf.jkt` at all.** `vouchryx` binds everything it mints,
//!   so an unbound one is from somewhere else or from a version that stopped
//!   binding. Both are worth refusing loudly.
//! - **A proof signed by a key other than the one it carries.** Otherwise
//!   anybody staples a victim's public key to their own proof.
//! - **A proof for another request or another moment.** A proof is for ONE
//!   request; without that, one captured from a harmless call is replayed here.
//!
//! # Revocation is the caller's, and [`revocations`] is what the caller fills it from
//!
//! `revoked` is a closure on purpose: this crate does not fetch. What it lacked
//! until 2026-08-26 was anything to put in that closure, so every caller in the
//! estate passed one that answers false and `vouchryx`'s list was served to
//! nobody. [`revocations::Revocations`] is the local cache and the staleness
//! policy that fills it, still with no client in this crate.

use jsonwebtoken::jwk::JwkSet;
use jsonwebtoken::{decode, decode_header, DecodingKey, Validation};
use serde::de::DeserializeOwned;
use serde::Deserialize;

/// Re-exported so this module's public surface is unchanged by the move. The
/// window, the thumbprint and the proof verifier all live in
/// [`tokenfuse_dpop`] now, one crate two planes can both depend on.
pub use tokenfuse_dpop::{algorithms_for_key, thumbprint, PROOF_WINDOW_SECS};

/// Parse an issuer's JWKS.
///
/// Here rather than at the caller so a caller does not have to name
/// `jsonwebtoken` to configure this crate. The gateway depends on this crate
/// and not on that one, and keeping it that way means the JWS library stays a
/// detail of verification rather than something two crates now know about.
pub fn parse_jwks(raw: &str) -> Result<JwkSet, serde_json::Error> {
    serde_json::from_str(raw)
}

/// Why a delegation was refused.
///
/// Distinct because each sends an operator somewhere different: a signature
/// failure is a security event, an expiry is a client that needs to refresh, a
/// revocation is somebody's deliberate act. This is the INTERNAL vocabulary;
/// what reaches a caller over the wire must not distinguish them, for the reason
/// `vouchryx`'s own API documents: a verifier that narrates which of eight
/// checks failed is an oracle.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Refusal {
    Malformed,
    BadSignature,
    Issuer,
    Audience,
    Expired,
    /// The token carries no `cnf.jkt`, so it is a bearer token.
    NotBound,
    /// The token is bound and the caller presented no proof.
    NoProof,
    /// The presenter does not hold the key the token is bound to.
    WrongKey,
    Revoked,
}

/// What an enforcement point may rely on after a successful check.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedDelegation {
    /// `sub`: who the token is FOR.
    pub subject: String,
    /// The delegation chain: `subject` followed by the actors from `act`.
    ///
    /// **Read, not verified.** agent-stack-go's invariant 5 applies here too:
    /// root-first ordering is a property of how a chain was BUILT and cannot be
    /// checked from the finished list. The signature guarantees the issuer put
    /// these names in this nesting; that the nesting means what the issuer
    /// intended is the issuer's to get right.
    pub chain: Vec<String>,
    /// The thumbprint the token is bound to, which MATCHED the proof.
    pub jkt: String,
    pub jti: String,
    pub issued_at: i64,
    pub expires_at: i64,
}

/// Everything the process already holds. No client, no URL, no timeout.
#[derive(Debug)]
pub struct DelegationConfig {
    pub jwks: JwkSet,
    /// The exact `iss` required. Not a prefix: a prefix is how a service ends
    /// up trusting `vouchryx.acme.example.evil.test`.
    pub issuer: String,
    /// The `aud` required, or empty to accept any. Empty is a real choice for a
    /// single-tenant deployment and a mistake in a shared one, so it is
    /// explicit rather than defaulted.
    pub audience: String,
}

#[derive(Deserialize)]
struct DelegationClaims {
    #[serde(default)]
    sub: String,
    #[serde(default)]
    jti: String,
    #[serde(default)]
    iat: i64,
    exp: i64,
    #[serde(default)]
    cnf: Option<Confirmation>,
    #[serde(default)]
    act: Option<Act>,
}

#[derive(Deserialize)]
struct Confirmation {
    #[serde(default)]
    jkt: String,
}

/// RFC 8693 section 4.1's nested actor claim.
#[derive(Deserialize)]
struct Act {
    #[serde(default)]
    sub: String,
    #[serde(default)]
    act: Option<Box<Act>>,
}

/// The chain cap agent-passport SPEC 5.1 sets, in the unit SPEC 5.1 uses:
/// ENTRIES of `on_behalf_of`.
///
/// "Maximum chain depth is 32 entries", and SPEC section 5 calls the members of
/// `on_behalf_of` entries. The root, usually a human, is the first of them.
///
/// Public because it is the cap on the CHAIN, not on the token: the gateway
/// applies the same number to a chain a caller merely declares in
/// `x-fuse-on-behalf-of`, with or without an issuer configured
/// (`tokenfuse_gateway::chainproof::declared_chain`, tokenfuse#297), and reads
/// it from here so the two doors cannot hold two numbers.
pub const MAX_CHAIN_ENTRIES: usize = 32;

/// The same cap counted in RFC 8693 actors, and the thing that stops a
/// self-referential `act` being walked for ever.
///
/// Derived rather than retyped, because the two numbers are one rule.
/// `verify_delegation` refuses a token with an empty `sub`, so every chain this
/// crate builds carries the subject as its first ENTRY and the actors get one
/// fewer. Measured 2026-08-27: this bound was 32 actors, so a full token
/// verified here and produced a 33-entry chain that every validating consumer
/// in the estate quarantined with `maxItems: got 33, want 32`.
const MAX_ACTORS_WITH_SUBJECT: usize = MAX_CHAIN_ENTRIES - 1;

/// Verify a delegation token and everything that makes it more than a bearer
/// token.
///
/// The order is deliberate and each step is cheaper than the next thing it
/// protects: shape, signature, issuer, audience, expiry, binding, chain,
/// revocation. A
/// revocation lookup on a forged token is work an attacker chose, which on a
/// busy enforcement point is a cheap denial of service.
///
/// `proof`, `method` and `url` are the RFC 9449 header and what THIS server
/// received. `now` is a Unix second, injected so an expiry is testable without
/// sleeping. `revoked` is consulted last, once per chain entry (the subject,
/// then every actor, root first), and may be a closure that always answers
/// false, which is a caller deciding that a valid signature is enough.
/// [`revocations::Revocations::hook`] is the closure for a caller that has not
/// decided that.
/// The decode path every verifier in this file shares: header, `kid`, key,
/// algorithm, signature, `iss`, `aud`, deserialize. Factored out of
/// `verify_delegation`'s original body (invariant 29's own rule applied one
/// level down: verbatim is two things that agree today, a shared function is
/// two things that cannot disagree tomorrow).
///
/// `require_audience` is the one axis the two callers disagree on.
/// `verify_delegation` accepts an empty `cfg.audience` as "any audience", a
/// real choice for a single-tenant deployment. `verify_access_token` must
/// not: an operator who has not configured `TOKENFUSE_MCP_RESOURCE` must not
/// have every resource accepted, so an empty audience there is refused
/// outright rather than read as permissive.
///
/// `T` carries no `iss`/`aud` field, on purpose: `Validation` checks both
/// against the raw claims independent of what the target struct names, which
/// is provable rather than assumed, since `DelegationClaims` has never
/// carried either and `a_token_from_another_issuer_or_for_another_audience_is_refused`
/// has passed since this file was written.
fn decode_claims<T: DeserializeOwned>(
    cfg: &DelegationConfig,
    token: &str,
    require_audience: bool,
) -> Result<T, Refusal> {
    let header = decode_header(token).map_err(|_| Refusal::Malformed)?;
    let kid = header.kid.ok_or(Refusal::Malformed)?;
    let jwk = cfg.jwks.find(&kid).ok_or(Refusal::BadSignature)?;

    // The single copy of the alg rule. See `oidc::algorithms_for_key`.
    let algorithms = tokenfuse_dpop::algorithms_for_key(jwk).ok_or(Refusal::BadSignature)?;
    let key = DecodingKey::from_jwk(jwk).map_err(|_| Refusal::BadSignature)?;

    let mut validation = Validation::new(algorithms[0]);
    validation.algorithms = algorithms;
    validation.validate_exp = false; // checked by the caller against the injected clock
    validation.set_required_spec_claims(&["exp", "iss"]);
    validation.set_issuer(&[&cfg.issuer]);
    if cfg.audience.is_empty() {
        if require_audience {
            return Err(Refusal::Audience);
        }
        validation.validate_aud = false;
    } else {
        validation.set_audience(&[&cfg.audience]);
    }
    decode::<T>(token, &key, &validation)
        .map(|d| d.claims)
        .map_err(|e| {
            use jsonwebtoken::errors::ErrorKind;
            match e.kind() {
                ErrorKind::InvalidIssuer => Refusal::Issuer,
                ErrorKind::InvalidAudience => Refusal::Audience,
                _ => Refusal::BadSignature,
            }
        })
}

pub fn verify_delegation(
    cfg: &DelegationConfig,
    token: &str,
    proof: Option<&str>,
    method: &str,
    url: &str,
    now: i64,
    revoked: impl Fn(&str, &str, i64) -> bool,
) -> Result<VerifiedDelegation, Refusal> {
    let claims: DelegationClaims = decode_claims(cfg, token, false)?;

    if now >= claims.exp {
        return Err(Refusal::Expired);
    }
    if claims.sub.is_empty() || claims.jti.is_empty() {
        return Err(Refusal::Malformed);
    }

    // THE STEP THAT MAKES THIS NOT A BEARER TOKEN.
    let jkt = claims
        .cnf
        .as_ref()
        .map(|c| c.jkt.clone())
        .filter(|j| !j.is_empty())
        .ok_or(Refusal::NotBound)?;
    let presented = match proof {
        None => return Err(Refusal::NoProof),
        // Every way a proof can fail is one refusal on the wire. `tokenfuse_dpop`
        // keeps a finer vocabulary for an operator's log; narrating which of six
        // checks failed to the CALLER tells an attacker whether their captured
        // proof was still fresh and which server it was made for.
        Some(p) => {
            tokenfuse_dpop::verify_proof(p, method, url, now).map_err(|_| Refusal::WrongKey)?
        }
    };
    if presented.jkt != jkt {
        return Err(Refusal::WrongKey);
    }

    // The chain is read BEFORE the list is asked, because the list is asked
    // about every entry of it: a subject revocation names a PARTY, and the
    // party an operator revokes when an agent is compromised usually sits in
    // `act`, with a human at the root in `sub`. Root first, first hit refuses.
    // Until 2026-09-17 the list was asked about `sub` alone, so an entry
    // naming an agent in `act` matched nothing and revoked nobody, and every
    // test of this path had planted the agent as the argument directly. At
    // most `MAX_CHAIN_ENTRIES` calls, none for a token that failed an earlier
    // step and none for a chain that does not parse.
    let chain = chain_of(&claims.sub, claims.act.as_ref())?;
    for party in &chain {
        if revoked(&claims.jti, party, claims.iat) {
            return Err(Refusal::Revoked);
        }
    }

    Ok(VerifiedDelegation {
        chain,
        subject: claims.sub,
        jkt,
        jti: claims.jti,
        issued_at: claims.iat,
        expires_at: claims.exp,
    })
}

/// What an enforcement point may rely on after a successful check of a
/// vouchryx Cross App Access (XAA) bearer access token (block A6, W3-tokenfuse).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedAccess {
    /// `sub`: the user this token is for (vouchryx mints
    /// `user://<lowercase IdP host>/<IdP sub>`).
    pub subject: String,
    /// The chain's last entry: the one actor an XAA access token names, always
    /// `agent://...`. Kept alongside `chain` rather than making a caller find
    /// it, the same reason `chainproof::proven_actor` exists one plane over.
    pub agent: String,
    /// `[subject] + reverse(act)`, the same assembly `VerifiedDelegation::chain`
    /// documents.
    pub chain: Vec<String>,
    /// Non-empty by construction: this is what an exchange (delegation) token
    /// never carries, so a delegation token can never be replayed as one.
    pub client_id: String,
    pub jti: String,
    pub issued_at: i64,
    pub expires_at: i64,
    pub scope: Option<String>,
}

#[derive(Deserialize)]
struct AccessTokenClaims {
    #[serde(default)]
    sub: String,
    #[serde(default)]
    jti: String,
    #[serde(default)]
    iat: i64,
    exp: i64,
    #[serde(default)]
    cnf: Option<Confirmation>,
    #[serde(default)]
    act: Option<Act>,
    #[serde(default)]
    client_id: String,
    #[serde(default)]
    scope: Option<String>,
}

/// Verify a vouchryx Cross App Access (XAA) bearer access token.
///
/// Shares [`verify_delegation`]'s decode path ([`decode_claims`]) and its
/// chain assembly ([`chain_of`]), and differs in shape rather than in
/// mechanism: an access token carries `client_id` (an exchange token never
/// does) and must never carry `cnf.jkt` (a bound token presented here has
/// been downgraded to bearer, invariant 29's rule applied to a token this
/// door never receives a proof for at all).
///
/// There is deliberately no `proof`/`method`/`url` parameter, unlike
/// `verify_delegation`. The MCP broker's XAA door is bearer-only by
/// construction: a request carrying a `dpop` header alongside
/// `Authorization: Bearer` is refused before this function is ever called
/// (two credentials), so a proof never reaches this path and a token
/// claiming to need one (`cnf.jkt` present) is always a downgrade.
///
/// Order, cheapest first: `kid`/key/algorithm/signature (inside
/// `decode_claims`), `iss` and `aud` (also inside `decode_claims`, `aud`
/// REQUIRED, an empty configured resource is a refusal rather than "accept
/// any"), `exp` against the injected clock, `sub` and `jti` non-empty,
/// `client_id` non-empty, `cnf.jkt` absent, `act` present and its chain
/// (`[sub] + reverse(act)`) at least two entries long and ending in an
/// `agent://` entry (a token with no actor names a person, and a person is
/// not an agent), then `revoked` for every chain entry, root first
/// (invariant 48).
pub fn verify_access_token(
    cfg: &DelegationConfig,
    token: &str,
    now: i64,
    revoked: impl Fn(&str, &str, i64) -> bool,
) -> Result<VerifiedAccess, Refusal> {
    let claims: AccessTokenClaims = decode_claims(cfg, token, true)?;

    if now >= claims.exp {
        return Err(Refusal::Expired);
    }
    if claims.sub.is_empty() || claims.jti.is_empty() {
        return Err(Refusal::Malformed);
    }
    // THE STEP THAT MAKES THIS AN ACCESS TOKEN AND NOT AN EXCHANGE TOKEN.
    // vouchryx's RFC 8693 exchange (delegation) tokens never carry `client_id`;
    // its XAA access tokens always do. Without this check, a delegation token
    // minted for the LLM proxy's chain-proof door could be replayed here as a
    // bearer credential.
    if claims.client_id.is_empty() {
        return Err(Refusal::Malformed);
    }
    // A bound token presented with no proof is a downgrade, and this door
    // never has a proof to offer: unlike `verify_delegation`, there is no
    // `proof` parameter at all, so `cnf.jkt` being present is unconditionally
    // a refusal rather than something checked against a presented key.
    if claims.cnf.as_ref().is_some_and(|c| !c.jkt.is_empty()) {
        return Err(Refusal::NoProof);
    }
    if claims.act.is_none() {
        return Err(Refusal::Malformed);
    }
    let chain = chain_of(&claims.sub, claims.act.as_ref())?;
    let is_agent = |leaf: &str| {
        leaf.strip_prefix("agent://")
            .is_some_and(|rest| !rest.is_empty())
    };
    if chain.len() < 2 || !chain.last().is_some_and(|leaf| is_agent(leaf)) {
        return Err(Refusal::Malformed);
    }

    // The chain is read BEFORE the list is asked, same reason and same order
    // as `verify_delegation`: a subject revocation names a PARTY, and asking
    // about every entry, root first, is invariant 48's rule.
    for party in &chain {
        if revoked(&claims.jti, party, claims.iat) {
            return Err(Refusal::Revoked);
        }
    }

    let agent = chain
        .last()
        .expect("checked above: at least two entries")
        .clone();
    Ok(VerifiedAccess {
        subject: claims.sub,
        agent,
        chain,
        client_id: claims.client_id,
        jti: claims.jti,
        issued_at: claims.iat,
        expires_at: claims.exp,
        scope: claims.scope,
    })
}

/// The delegation chain: the subject, then the actors, root first.
///
/// RFC 8693 keeps them apart. `sub` is who the token is FOR, and `act` is the
/// chain of who is acting; the subject is deliberately not in `act`, because it
/// is not an actor. agent-passport SPEC section 5 does the opposite: its
/// `on_behalf_of` is one ordered list, root first, and the root is the person.
///
/// So the two are not the same list in a different order. They are a list and a
/// list-plus-its-head, and a verifier that handed the actors straight to a
/// record would write a delegation chain with the human missing from it. Every
/// token would still verify.
///
/// The head is also why the cap here is [`MAX_ACTORS_WITH_SUBJECT`] and not
/// [`MAX_CHAIN_ENTRIES`]: the subject about to be pushed is an entry, and SPEC
/// 5.1 counts entries.
fn chain_of(sub: &str, act: Option<&Act>) -> Result<Vec<String>, Refusal> {
    // `act` nests current-first (RFC 8693 4.1: "The outermost `act` claim
    // represents the current actor"), and this estate records root-first, so
    // collecting then reversing is the mapping rather than a tidy-up.
    // How many ACTORS fit depends on whether a subject is about to take one of
    // the entries. SPEC 5.1 counts entries, so a chain with no human at the
    // root has the whole budget for actors.
    //
    // This bounded at `MAX_ACTORS_WITH_SUBJECT` unconditionally, so a
    // machine-to-machine chain of exactly the cap was refused. Found by the
    // cross-language verdict table on its first run, the second disagreement it
    // turned up between this door and agent-stack-go's, which had the
    // conditional and this one did not.
    let actor_budget = if sub.is_empty() {
        MAX_CHAIN_ENTRIES
    } else {
        MAX_ACTORS_WITH_SUBJECT
    };
    let mut current_first = Vec::new();
    let mut cursor = act;
    while let Some(a) = cursor {
        if current_first.len() >= actor_budget {
            return Err(Refusal::Malformed);
        }
        if a.sub.is_empty() {
            return Err(Refusal::Malformed);
        }
        current_first.push(a.sub.clone());
        cursor = a.act.as_deref();
    }
    let mut chain = Vec::with_capacity(current_first.len() + 1);
    // An ABSENT subject is not an empty entry. A machine-to-machine chain has
    // no human at the root, and the whole entry budget belongs to the actors.
    //
    // Pushing it unconditionally put `""` at the head, which the entry-scheme
    // rule below then refused. Found by the cross-language verdict table on its
    // first run: agent-stack-go's door accepted the same shape and this one did
    // not. Unreachable through THIS door, which refuses a token carrying no
    // `sub` earlier and for a different reason, so the disagreement was in the
    // assembler alone. It is fixed rather than excused, because a table whose
    // cases are allowed to mean different things per door holds nothing.
    if !sub.is_empty() {
        chain.push(sub.to_string());
    }
    chain.extend(current_first.into_iter().rev());

    // The two rules the RECORD applies to a chain, applied here as well.
    //
    // `agent-conform` runs `chain.Validate` on every `on_behalf_of` it reads
    // and the v0.2 envelope pins `pattern: ^(agent|user)://` on every item. So
    // a chain this door hands out and the record refuses is a token that
    // verified and whose trail cannot be written, which is the quarantine the
    // entry cap produced one commit ago, two rules over.
    //
    // Duplicated rather than shared, and the duplication is structural: the
    // rules live in Go, this is Rust, and there is no seam between them. What
    // stops the two drifting is a gate, the same answer agent-stack-go reached
    // for its own pair in `scripts/door-and-record-agree.sh`.
    //
    // The SCHEME only, deliberately: a stricter pattern here would refuse
    // chains the record accepts, which is this rule failing in the other
    // direction.
    let mut seen = std::collections::HashSet::with_capacity(chain.len());
    for entry in &chain {
        // SPEC 5.1: the chain MUST be acyclic.
        if !seen.insert(entry.as_str()) {
            return Err(Refusal::Malformed);
        }
        // SPEC 5: entries are `agent://` or `user://` URIs.
        if !entry.starts_with("agent://") && !entry.starts_with("user://") {
            return Err(Refusal::Malformed);
        }
    }
    Ok(chain)
}

/// Deliberately reached by module path rather than re-exported at the crate
/// root: `FailMode` is a name the gateway already has from `wardryx`, and two
/// of them in one `use` line is how a caller ends up configuring the wrong one.
pub mod revocations;

#[cfg(any(test, feature = "testing"))]
pub mod testing;

#[cfg(test)]
mod tests {
    use super::*;
    // The fixture that mints what vouchryx mints now lives in `testing`, behind
    // a feature, because a third party needs it: an enforcement point testing
    // what it does with a real token. Copying it there would have been a
    // fixture drifting from the thing it is a fixture for.

    use crate::testing::*;

    #[test]
    fn a_delegation_verifies_and_the_chain_keeps_its_root() {
        let (issuer, holder, now) = (Key::new(), Key::new(), 1_800_000_000);
        let v = verify_delegation(
            &cfg(&issuer),
            &token(&issuer, &holder, now, serde_json::json!({})),
            Some(&proof(&holder, now)),
            "POST",
            URL,
            now,
            never,
        )
        .expect("a good delegation");
        assert_eq!(v.subject, "user://acme/alice");
        assert_eq!(
            v.chain,
            vec![
                "user://acme/alice",
                "agent://acme/triage",
                "agent://acme/runbook"
            ],
            "the RFC nests current-first and this estate records root-first, and \
             the subject is in the chain but not in `act`"
        );
        assert_eq!(v.jti, "tok-1");
    }

    /// THE ONE THAT MAKES THIS WORTH HAVING. Without it every enforcement point
    /// in the estate honours a stolen token.
    #[test]
    fn a_token_presented_by_the_wrong_holder_is_refused() {
        let (issuer, holder, thief, now) = (Key::new(), Key::new(), Key::new(), 1_800_000_000);
        let err = verify_delegation(
            &cfg(&issuer),
            &token(&issuer, &holder, now, serde_json::json!({})),
            Some(&proof(&thief, now)),
            "POST",
            URL,
            now,
            never,
        )
        .unwrap_err();
        assert_eq!(err, Refusal::WrongKey);
    }

    /// The failure that looks like it is working: an enforcement point that
    /// simply forgot to pass a proof.
    #[test]
    fn a_bound_token_checked_with_no_proof_is_refused_rather_than_downgraded() {
        let (issuer, holder, now) = (Key::new(), Key::new(), 1_800_000_000);
        let err = verify_delegation(
            &cfg(&issuer),
            &token(&issuer, &holder, now, serde_json::json!({})),
            None,
            "POST",
            URL,
            now,
            never,
        )
        .unwrap_err();
        assert_eq!(err, Refusal::NoProof);
    }

    #[test]
    fn an_unbound_token_is_refused_rather_than_treated_as_something_else() {
        let (issuer, holder, now) = (Key::new(), Key::new(), 1_800_000_000);
        let err = verify_delegation(
            &cfg(&issuer),
            &token(&issuer, &holder, now, serde_json::json!({"cnf": null})),
            Some(&proof(&holder, now)),
            "POST",
            URL,
            now,
            never,
        )
        .unwrap_err();
        assert_eq!(err, Refusal::NotBound);
    }

    #[test]
    fn an_expired_delegation_is_refused_against_the_injected_clock() {
        let (issuer, holder, now) = (Key::new(), Key::new(), 1_800_000_000);
        let err = verify_delegation(
            &cfg(&issuer),
            &token(&issuer, &holder, now, serde_json::json!({"exp": now - 1})),
            Some(&proof(&holder, now)),
            "POST",
            URL,
            now,
            never,
        )
        .unwrap_err();
        assert_eq!(err, Refusal::Expired);
    }

    #[test]
    fn a_revoked_delegation_is_refused_though_its_signature_is_perfect() {
        let (issuer, holder, now) = (Key::new(), Key::new(), 1_800_000_000);
        let err = verify_delegation(
            &cfg(&issuer),
            &token(&issuer, &holder, now, serde_json::json!({})),
            Some(&proof(&holder, now)),
            "POST",
            URL,
            now,
            |jti, sub, _| {
                assert_eq!(jti, "tok-1");
                assert_eq!(sub, "user://acme/alice");
                true
            },
        )
        .unwrap_err();
        assert_eq!(err, Refusal::Revoked);
    }

    /// The nested `act` for a root-first list of actors: the outermost `act`
    /// is the current actor (RFC 8693 4.1), so the list is wrapped from the
    /// first actor outwards.
    fn nest_actors(actors: &[String]) -> serde_json::Value {
        let mut act = serde_json::json!({"sub": actors[0]});
        for a in &actors[1..] {
            act = serde_json::json!({"sub": a, "act": act});
        }
        act
    }

    /// A subject revocation names a PARTY. A compromised agent sits in `act`,
    /// never in `sub`, so a list matched against `sub` alone revokes the human
    /// at the root and spares the very agent the entry was written for. Every
    /// earlier test of this path planted the agent as the `subject` argument
    /// directly, which is why the gap lived this long. Seeded sweep: 200
    /// chains of every depth up to the cap, one random member named each.
    #[test]
    fn a_revocation_naming_any_party_in_the_chain_refuses_the_token() {
        let (issuer, holder, now) = (Key::new(), Key::new(), 1_800_000_000_i64);
        let mut seed: u64 = 20260917;
        let mut next = move || {
            // xorshift64: deterministic, dependency-free.
            seed ^= seed << 13;
            seed ^= seed >> 7;
            seed ^= seed << 17;
            seed
        };
        for i in 0..200 {
            let depth = 1 + (next() % MAX_ACTORS_WITH_SUBJECT as u64) as usize;
            let actors: Vec<String> = (0..depth)
                .map(|j| format!("agent://acme/a{i}-{j}"))
                .collect();
            // Issued seven seconds ago, so a verifier that forwarded `now` in
            // place of the token's own `iat` is told apart by the fourth case.
            let issued = now - 7;
            let tok = token(
                &issuer,
                &holder,
                now,
                serde_json::json!({"act": nest_actors(&actors), "jti": format!("tok-{i}"), "iat": issued}),
            );
            let mut chain = vec!["user://acme/alice".to_string()];
            chain.extend(actors.iter().cloned());
            let named = chain[(next() % chain.len() as u64) as usize].clone();
            let position = chain.iter().position(|p| *p == named).unwrap();
            let verify = |revoked: &dyn Fn(&str, &str, i64) -> bool| {
                verify_delegation(
                    &cfg(&issuer),
                    &tok,
                    Some(&proof(&holder, now)),
                    "POST",
                    URL,
                    now,
                    revoked,
                )
            };
            // Naming any member, dated at or after the token's issue: refused.
            assert_eq!(
                verify(&|_, sub, iat| sub == named && iat <= now).map(|_| ()),
                Err(Refusal::Revoked),
                "seed 20260917 case {i}: a revocation naming {named:?} (position {position} of {}) was not honoured",
                chain.len()
            );
            // Naming nobody in the chain: honoured.
            assert!(
                verify(&|_, sub, _| sub == "agent://acme/stranger").is_ok(),
                "case {i}: a revocation naming a stranger refused the token"
            );
            // Naming a member but dated before the token's issue: revoking is
            // not banning (vouchryx's invariant 7), so the token stands.
            assert!(
                verify(&|_, sub, iat| sub == named && iat < issued).is_ok(),
                "case {i}: a revocation older than the token refused it"
            );
            // Naming a member, dated after the issue but before now: refused,
            // and only a verifier forwarding the token's own `iat` gets this
            // right.
            assert_eq!(
                verify(&|_, sub, iat| sub == named && iat <= now - 3).map(|_| ()),
                Err(Refusal::Revoked),
                "case {i}: a revocation between the token's issue and now was not honoured"
            );
        }
    }

    /// The list is asked about every chain entry, so the chain has to be read
    /// before the list is asked about anything: a cyclic `act` is refused as
    /// malformed with zero calls, rather than costing a lookup per entry
    /// first. Pins the order, which nothing else did.
    #[test]
    fn revocation_is_not_consulted_for_a_token_whose_chain_is_malformed() {
        let (issuer, holder, now) = (Key::new(), Key::new(), 1_800_000_000_i64);
        let cyclic = serde_json::json!({"sub": "agent://acme/triage", "act": {"sub": "agent://acme/triage"}});
        let calls = std::cell::Cell::new(0usize);
        let err = verify_delegation(
            &cfg(&issuer),
            &token(&issuer, &holder, now, serde_json::json!({"act": cyclic})),
            Some(&proof(&holder, now)),
            "POST",
            URL,
            now,
            |_, _, _| {
                calls.set(calls.get() + 1);
                true
            },
        )
        .unwrap_err();
        assert_eq!(
            err,
            Refusal::Malformed,
            "a cyclic chain was not refused as malformed"
        );
        assert_eq!(
            calls.get(),
            0,
            "the revocation list was consulted for a token whose chain never parsed"
        );
    }

    #[test]
    fn a_proof_for_another_request_or_another_moment_is_refused() {
        let (issuer, holder, now) = (Key::new(), Key::new(), 1_800_000_000);
        let tok = token(&issuer, &holder, now, serde_json::json!({}));
        for (method, url, clock) in [
            ("GET", URL, now),
            ("POST", "https://tokenfuse.acme.example/v1/kill", now),
            ("POST", URL, now + PROOF_WINDOW_SECS + 1),
            ("POST", URL, now - PROOF_WINDOW_SECS - 1),
        ] {
            let err = verify_delegation(
                &cfg(&issuer),
                &tok,
                Some(&proof(&holder, now)),
                method,
                url,
                clock,
                never,
            )
            .unwrap_err();
            assert_eq!(err, Refusal::WrongKey, "{method} {url} at {clock}");
        }
    }

    #[test]
    fn a_query_string_does_not_break_an_honest_client() {
        // RFC 9449 4.3. A server comparing them whole refuses every proof for a
        // URL carrying a cache-buster, which reads as a broken feature.
        let (issuer, holder, now) = (Key::new(), Key::new(), 1_800_000_000);
        verify_delegation(
            &cfg(&issuer),
            &token(&issuer, &holder, now, serde_json::json!({})),
            Some(&proof(&holder, now)),
            "POST",
            &format!("{URL}?trace=1"),
            now,
            never,
        )
        .expect("a query string is not a different request");
    }

    #[test]
    fn an_access_token_is_not_a_proof() {
        // The `typ` is what stops one being the other.
        let (issuer, holder, now) = (Key::new(), Key::new(), 1_800_000_000);
        let not_a_proof = holder.sign(
            serde_json::json!({"typ": "JWT", "alg": "ES256", "jwk": holder.jwk_value(None)}),
            serde_json::json!({"htm": "POST", "htu": URL, "iat": now}),
        );
        let err = verify_delegation(
            &cfg(&issuer),
            &token(&issuer, &holder, now, serde_json::json!({})),
            Some(&not_a_proof),
            "POST",
            URL,
            now,
            never,
        )
        .unwrap_err();
        assert_eq!(err, Refusal::WrongKey);
    }

    #[test]
    fn a_client_leaking_its_private_key_is_refused_rather_than_helped() {
        // Checked on the RAW header, because `Jwk` has no field for `d` and
        // would drop it in silence.
        let (issuer, holder, now) = (Key::new(), Key::new(), 1_800_000_000);
        let mut jwk = holder.jwk_value(None);
        jwk["d"] = serde_json::json!("bm90LWEtcmVhbC1rZXk");
        let leaky = holder.sign(
            serde_json::json!({"typ": "dpop+jwt", "alg": "ES256", "jwk": jwk}),
            serde_json::json!({"htm": "POST", "htu": URL, "iat": now, "jti": "p"}),
        );
        let err = verify_delegation(
            &cfg(&issuer),
            &token(&issuer, &holder, now, serde_json::json!({})),
            Some(&leaky),
            "POST",
            URL,
            now,
            never,
        )
        .unwrap_err();
        assert_eq!(err, Refusal::WrongKey);
    }

    #[test]
    fn a_token_from_another_issuer_or_for_another_audience_is_refused() {
        let (issuer, holder, now) = (Key::new(), Key::new(), 1_800_000_000);
        for (over, want) in [
            (
                serde_json::json!({"iss": "https://evil.example"}),
                Refusal::Issuer,
            ),
            (
                serde_json::json!({"aud": "https://elsewhere.example"}),
                Refusal::Audience,
            ),
        ] {
            let err = verify_delegation(
                &cfg(&issuer),
                &token(&issuer, &holder, now, over),
                Some(&proof(&holder, now)),
                "POST",
                URL,
                now,
                never,
            )
            .unwrap_err();
            assert_eq!(err, want);
        }
    }

    #[test]
    fn a_token_signed_by_a_key_that_is_not_the_issuers_is_refused() {
        let (issuer, impostor, holder, now) = (Key::new(), Key::new(), Key::new(), 1_800_000_000);
        let forged = token(&impostor, &holder, now, serde_json::json!({}));
        let err = verify_delegation(
            &cfg(&issuer),
            &forged,
            Some(&proof(&holder, now)),
            "POST",
            URL,
            now,
            never,
        )
        .unwrap_err();
        assert_eq!(err, Refusal::BadSignature);
    }

    /// The single copy of the alg rule, held from this side too. `oidc.rs` has
    /// its own tests for it; this one exists because a second verifier is
    /// exactly how a shared rule stops being shared.
    #[test]
    fn the_algorithm_still_comes_from_the_key_on_this_path() {
        let key = Key::new();
        let ec: jsonwebtoken::jwk::Jwk =
            serde_json::from_value(key.jwk_value(Some("k"))).expect("a jwk");
        let algs = tokenfuse_dpop::algorithms_for_key(&ec).expect("an EC key is usable");
        assert!(
            algs.iter().all(|a| matches!(
                a,
                jsonwebtoken::Algorithm::ES256 | jsonwebtoken::Algorithm::ES384
            )),
            "an EC key must never be offered a symmetric algorithm: {algs:?}"
        );

        let oct: jsonwebtoken::jwk::Jwk =
            serde_json::from_value(serde_json::json!({"kty": "oct", "k": "c2VjcmV0", "kid": "s"}))
                .expect("a jwk");
        assert!(
            tokenfuse_dpop::algorithms_for_key(&oct).is_none(),
            "a symmetric key is refused outright, which is what closes `none` too"
        );
    }

    #[test]
    fn a_self_referential_act_does_not_spin() {
        // The claim comes off the wire, so its shape is the caller's to choose.
        // A reader that walked a cycle would hang inside the request path.
        let mut nested = serde_json::json!({"sub": "agent://acme/a"});
        for _ in 0..40 {
            nested = serde_json::json!({"sub": "agent://acme/a", "act": nested});
        }
        let (issuer, holder, now) = (Key::new(), Key::new(), 1_800_000_000);
        let err = verify_delegation(
            &cfg(&issuer),
            &token(&issuer, &holder, now, serde_json::json!({"act": nested})),
            Some(&proof(&holder, now)),
            "POST",
            URL,
            now,
            never,
        )
        .unwrap_err();
        assert_eq!(err, Refusal::Malformed);
    }
    /// The one behaviour this path GAINED when the proof verifier moved into
    /// `tokenfuse_dpop` on 2026-08-26: RFC 9449 4.2 makes `jti` REQUIRED, and a
    /// proof without one cannot be made single-use by any cache. This verifier
    /// has no replay cache of its own yet, so the refusal is the whole of the
    /// defence here rather than half of it.
    ///
    /// Safe to tighten because nothing in this repository calls
    /// `verify_delegation` yet; there is no deployed client to break.
    #[test]
    fn a_proof_with_no_jti_is_refused_on_this_path_too() {
        let (issuer, holder, now) = (Key::new(), Key::new(), 1_800_000_000);
        let jtiless = holder.sign(
            serde_json::json!({
                "typ": "dpop+jwt", "alg": "ES256", "jwk": holder.jwk_value(None)
            }),
            serde_json::json!({"htm": "POST", "htu": URL, "iat": now}),
        );
        let err = verify_delegation(
            &cfg(&issuer),
            &token(&issuer, &holder, now, serde_json::json!({})),
            Some(&jtiless),
            "POST",
            URL,
            now,
            never,
        )
        .unwrap_err();
        assert_eq!(err, Refusal::WrongKey);
    }

    /// agent-passport SPEC 5.1: "Maximum chain depth is 32 entries".
    ///
    /// Written out here rather than read from this crate's own constant on
    /// purpose. The question is whether this crate agrees with the SPEC, and a
    /// test that takes the number from the code under test can only ever prove
    /// that the code agrees with itself.
    const SPEC_5_1_MAX_ENTRIES: usize = 32;

    /// An `act` claim `n` actors deep, nested the way RFC 8693 4.1 nests it:
    /// the OUTERMOST is the current actor and nesting goes back in time.
    fn nested_act(n: usize) -> serde_json::Value {
        let mut act = serde_json::json!({"sub": "agent://acme/a0"});
        for i in 1..n {
            act = serde_json::json!({"sub": format!("agent://acme/a{i}"), "act": act});
        }
        act
    }

    /// THE SEAM. This door decides what verifies; a different repository holds
    /// what verified. Nothing inside this crate can see the second half, so
    /// nothing inside this crate could see that a token it accepted produced a
    /// record every consumer refuses.
    ///
    /// Swept rather than sampled. The whole defect is one entry wide, and a
    /// test that picks a depth picks one side of it.
    #[test]
    fn no_chain_this_door_builds_is_longer_than_the_record_accepts() {
        let (issuer, holder, now) = (Key::new(), Key::new(), 1_800_000_000);
        for actors in 1..=SPEC_5_1_MAX_ENTRIES + 2 {
            let tok = token(
                &issuer,
                &holder,
                now,
                serde_json::json!({"act": nested_act(actors)}),
            );
            let verified = verify_delegation(
                &cfg(&issuer),
                &tok,
                Some(&proof(&holder, now)),
                "POST",
                URL,
                now,
                never,
            );
            let Ok(v) = verified else {
                continue; // refused, which is the honest answer at the boundary
            };
            assert!(
                v.chain.len() <= SPEC_5_1_MAX_ENTRIES,
                "a token carrying {actors} actors verified and produced a {} entry \
                 chain. agent-conform, the v0.2 and v0.3 envelope schemas and \
                 agent-stack-go's chain.Validate all refuse it: \
                 `maxItems: got {}, want {SPEC_5_1_MAX_ENTRIES}`",
                v.chain.len(),
                v.chain.len(),
            );
        }
    }

    /// The subject is the chain's first ENTRY, so a token that names one has
    /// room for one actor fewer. `verify_delegation` refuses a token with no
    /// `sub`, so in this crate that is every token.
    #[test]
    fn the_subject_counts_towards_the_cap_because_the_spec_counts_entries() {
        let (issuer, holder, now) = (Key::new(), Key::new(), 1_800_000_000);
        let verify = |actors: usize| {
            verify_delegation(
                &cfg(&issuer),
                &token(
                    &issuer,
                    &holder,
                    now,
                    serde_json::json!({"act": nested_act(actors)}),
                ),
                Some(&proof(&holder, now)),
                "POST",
                URL,
                now,
                never,
            )
        };

        let full =
            verify(SPEC_5_1_MAX_ENTRIES - 1).expect("a subject plus 31 actors is 32 entries");
        assert_eq!(full.chain.len(), SPEC_5_1_MAX_ENTRIES);
        assert_eq!(
            full.chain[0], "user://acme/alice",
            "the root is still first"
        );

        assert_eq!(
            verify(SPEC_5_1_MAX_ENTRIES).unwrap_err(),
            Refusal::Malformed,
            "a subject plus {SPEC_5_1_MAX_ENTRIES} actors is one entry too many"
        );
    }

    /// The record refuses a chain naming one principal twice: SPEC 5.1 says
    /// `on_behalf_of` MUST be acyclic, `chain.Validate` has enforced it since
    /// it was written, and `agent-conform` calls it on every line.
    ///
    /// This door did not. So a token whose `sub` also appears in its `act`
    /// verified here and every event it produced was quarantined, which is the
    /// same sentence as the depth cap one commit earlier. agent-stack-go closed
    /// its half in TAIPANBOX/agent-stack-go#40; this is the language actually on
    /// the request path.
    #[test]
    fn a_chain_naming_one_principal_twice_is_refused() {
        let root = "user://acme/alice";
        let act = Act {
            sub: root.to_string(),
            act: None,
        };
        assert_eq!(
            chain_of(root, Some(&act)),
            Err(Refusal::Malformed),
            "the door handed out a chain the record refuses as a cycle"
        );
    }

    /// A repeat among the ACTORS alone, so the rule is about the whole
    /// assembled chain and not only about the subject.
    #[test]
    fn a_chain_naming_one_actor_twice_is_refused() {
        let inner = Act {
            sub: "agent://acme/triage".to_string(),
            act: None,
        };
        let outer = Act {
            sub: "agent://acme/triage".to_string(),
            act: Some(Box::new(inner)),
        };
        assert_eq!(
            chain_of("user://acme/alice", Some(&outer)),
            Err(Refusal::Malformed)
        );
    }

    /// The record accepts only `agent://` and `user://` entries: the v0.2
    /// envelope pins `pattern: ^(agent|user)://` on every item of
    /// `on_behalf_of`. This door accepted anything non-empty.
    #[test]
    fn a_principal_that_is_not_an_agent_or_user_uri_is_refused() {
        for bad in [
            "mailto:alice@acme.example",
            "acme.example/alice",
            "https://acme.example/alice",
            "agent:/acme/triage",
        ] {
            let act = Act {
                sub: bad.to_string(),
                act: None,
            };
            assert_eq!(
                chain_of("user://acme/alice", Some(&act)),
                Err(Refusal::Malformed),
                "{bad} was handed out as a principal"
            );
        }
    }

    /// The guard against overshooting, and it must pass before AND after: the
    /// shape every real token has, in both schemes the spec names, at either
    /// end of the chain.
    #[test]
    fn the_shape_every_real_token_has_is_still_accepted() {
        let inner = Act {
            sub: "user://acme/carol".to_string(),
            act: None,
        };
        let outer = Act {
            sub: "agent://acme/triage".to_string(),
            act: Some(Box::new(inner)),
        };
        assert_eq!(
            chain_of("user://acme/alice", Some(&outer)),
            Ok(vec![
                "user://acme/alice".to_string(),
                "user://acme/carol".to_string(),
                "agent://acme/triage".to_string(),
            ])
        );
    }

    /// The cross-language verdict table, vendored byte for byte from
    /// `agent-stack-go/chain/testdata/chain-verdict-vectors.json`.
    ///
    /// The record's rules live in Go. This door is Rust. There is no seam
    /// between them and there cannot be one, so the rules exist twice and a
    /// third time in agent-stack-go's own door. Three of them were found
    /// disagreeing across those copies on 2026-08-27, all in one afternoon.
    ///
    /// A gate reading source text cannot hold this: a regex over two languages
    /// tells you a rule is MENTIONED, never that it ANSWERS. A table each door
    /// RUNS is the only form of the check a comment cannot satisfy.
    #[test]
    fn the_door_answers_the_cross_language_table() {
        let raw = include_str!("../testdata/chain-verdict-vectors.json");
        let doc: serde_json::Value = serde_json::from_str(raw).expect("the table is JSON");
        let vectors = doc["vectors"].as_array().expect("the table has vectors");
        assert!(!vectors.is_empty(), "an empty table would prove nothing");

        for v in vectors {
            let name = v["name"].as_str().unwrap_or("?");
            let why = v["why"].as_str().unwrap_or("");
            let sub = v["sub"].as_str().unwrap_or("");

            // `act`, outermost first, with a generated case expanded the same
            // way every language expands it.
            let actors: Vec<String> = if let Some(g) = v.get("act_generated") {
                let template = g["template"].as_str().expect("a template");
                let count = g["count"].as_u64().expect("a count");
                (1..=count)
                    .map(|i| template.replace("%d", &i.to_string()))
                    .collect()
            } else {
                v["act"]
                    .as_array()
                    .expect("an act list")
                    .iter()
                    .map(|a| a.as_str().unwrap_or("").to_string())
                    .collect()
            };

            // Nest them the way RFC 8693 does: outermost is the current actor.
            let mut act: Option<Box<Act>> = None;
            for a in actors.iter().rev() {
                act = Some(Box::new(Act {
                    sub: a.clone(),
                    act: act.take(),
                }));
            }

            let got = chain_of(sub, act.as_deref());
            match v["verdict"].as_str().expect("a verdict") {
                "accept" => {
                    let chain = got.unwrap_or_else(|e| {
                        panic!("{name}: refused a chain the table accepts: {e:?}\nwhy: {why}")
                    });
                    if let Some(want) = v["chain"].as_array() {
                        let want: Vec<String> = want
                            .iter()
                            .map(|c| c.as_str().unwrap_or("").to_string())
                            .collect();
                        assert_eq!(chain, want, "{name}: the table says {want:?}\nwhy: {why}");
                    }
                }
                // Every refusal is `Malformed` here: this crate deliberately
                // does not tell a caller WHICH check failed, because that is an
                // oracle. The table names the RULE, and what has to agree
                // across the three implementations is accept-versus-refuse plus
                // the assembled chain, not the spelling of the error.
                "cycle" | "too_deep" | "invalid_entry" => {
                    assert_eq!(
                        got,
                        Err(Refusal::Malformed),
                        "{name}: the table refuses this\nwhy: {why}"
                    );
                }
                other => {
                    panic!("{name}: the table names a verdict this test does not know: {other}")
                }
            }
        }
    }

    // -------------------------------------------------------------------
    // verify_access_token (W3-tokenfuse: the MCP broker's XAA bearer door)
    // -------------------------------------------------------------------

    #[test]
    fn an_access_token_verifies_and_names_its_agent() {
        let (issuer, now) = (Key::new(), 1_800_000_000);
        let v = verify_access_token(
            &cfg(&issuer),
            &access_token(&issuer, now, serde_json::json!({})),
            now,
            never,
        )
        .expect("a good access token");
        assert_eq!(v.subject, "user://acme/alice");
        assert_eq!(v.agent, "agent://acme/triage");
        assert_eq!(v.chain, vec!["user://acme/alice", "agent://acme/triage"]);
        assert_eq!(v.client_id, XAA_CLIENT_ID);
        assert_eq!(v.jti, "at-1");
        assert_eq!(v.issued_at, now);
        assert_eq!(v.expires_at, now + 300);
        assert_eq!(v.scope, None);
    }

    #[test]
    fn an_access_tokens_scope_is_carried_into_verified_access() {
        let (issuer, now) = (Key::new(), 1_800_000_000);
        let v = verify_access_token(
            &cfg(&issuer),
            &access_token(&issuer, now, serde_json::json!({"scope": "read"})),
            now,
            never,
        )
        .expect("a good access token");
        assert_eq!(v.scope, Some("read".to_string()));
    }

    /// `require_audience: true` for this function: an empty configured
    /// resource must never read as "accept any", the opposite of
    /// `verify_delegation`'s own choice for an empty `TOKENFUSE_DELEGATION_AUDIENCE`.
    #[test]
    fn an_empty_configured_resource_refuses_every_access_token() {
        let (issuer, now) = (Key::new(), 1_800_000_000);
        let mut c = cfg(&issuer);
        c.audience = String::new();
        let err = verify_access_token(
            &c,
            &access_token(&issuer, now, serde_json::json!({})),
            now,
            never,
        )
        .unwrap_err();
        assert_eq!(err, Refusal::Audience);
    }

    /// Mutant #2 from the W3-tokenfuse brief: `aud` compared by prefix rather
    /// than exactly. The token's `aud` (`AUD`) is a strict PREFIX of the
    /// configured resource, never equal to it.
    #[test]
    fn an_audience_that_is_only_a_prefix_match_is_refused() {
        let (issuer, now) = (Key::new(), 1_800_000_000);
        let mut c = cfg(&issuer);
        c.audience = format!("{AUD}/mcp");
        let err = verify_access_token(
            &c,
            &access_token(&issuer, now, serde_json::json!({})),
            now,
            never,
        )
        .unwrap_err();
        assert_eq!(err, Refusal::Audience);
    }

    #[test]
    fn an_expired_access_token_is_refused() {
        let (issuer, now) = (Key::new(), 1_800_000_000);
        let err = verify_access_token(
            &cfg(&issuer),
            &access_token(&issuer, now, serde_json::json!({"exp": now - 1})),
            now,
            never,
        )
        .unwrap_err();
        assert_eq!(err, Refusal::Expired);
    }

    #[test]
    fn an_access_token_from_another_issuer_is_refused() {
        let (issuer, now) = (Key::new(), 1_800_000_000);
        let err = verify_access_token(
            &cfg(&issuer),
            &access_token(
                &issuer,
                now,
                serde_json::json!({"iss": "https://evil.example"}),
            ),
            now,
            never,
        )
        .unwrap_err();
        assert_eq!(err, Refusal::Issuer);
    }

    /// Mutant #4: `client_id` requirement dropped. This is what makes the
    /// token an access token rather than an exchange (delegation) token: a
    /// token minted by `verify_delegation`'s own fixture has no `client_id`
    /// at all and must be refused here too (see also
    /// `an_exchange_token_shaped_delegation_token_is_refused_as_an_access_token`
    /// below, the HTTP-level twin of this same rule).
    #[test]
    fn an_access_token_with_no_client_id_is_refused() {
        let (issuer, now) = (Key::new(), 1_800_000_000);
        let err = verify_access_token(
            &cfg(&issuer),
            &access_token(&issuer, now, serde_json::json!({"client_id": null})),
            now,
            never,
        )
        .unwrap_err();
        assert_eq!(err, Refusal::Malformed);
    }

    /// A real vouchryx delegation (exchange) token, minted by
    /// `verify_delegation`'s own fixture, presented at the access-token door:
    /// it carries no `client_id` (checked first, per the order the brief
    /// fixes) and also `cnf.jkt` (vouchryx binds every exchange token, which
    /// would refuse it on its own too, see
    /// `a_bound_access_token_with_no_proof_is_refused`), so this is refused
    /// as `Malformed` before the `cnf` check is even reached.
    #[test]
    fn an_exchange_token_is_refused_as_an_access_token() {
        let (issuer, holder, now) = (Key::new(), Key::new(), 1_800_000_000);
        let exchange_tok = token(&issuer, &holder, now, serde_json::json!({}));
        let err = verify_access_token(&cfg(&issuer), &exchange_tok, now, never).unwrap_err();
        assert_eq!(err, Refusal::Malformed);
    }

    /// Mutant #3: `cnf` bound token accepted. There is no `proof` parameter on
    /// this function at all (unlike `verify_delegation`), so a `cnf.jkt`
    /// present on the token is unconditionally a downgrade.
    #[test]
    fn a_bound_access_token_with_no_proof_is_refused() {
        let (issuer, holder, now) = (Key::new(), Key::new(), 1_800_000_000);
        let jkt = tokenfuse_dpop::thumbprint(
            &serde_json::from_value(holder.jwk_value(None)).expect("a jwk"),
        )
        .expect("a thumbprint");
        let err = verify_access_token(
            &cfg(&issuer),
            &access_token(&issuer, now, serde_json::json!({"cnf": {"jkt": jkt}})),
            now,
            never,
        )
        .unwrap_err();
        assert_eq!(err, Refusal::NoProof);
    }

    #[test]
    fn an_access_token_with_no_actor_is_refused() {
        let (issuer, now) = (Key::new(), 1_800_000_000);
        let err = verify_access_token(
            &cfg(&issuer),
            &access_token(&issuer, now, serde_json::json!({"act": null})),
            now,
            never,
        )
        .unwrap_err();
        assert_eq!(err, Refusal::Malformed);
    }

    /// A token with no `act` names a person, and a person is not an agent:
    /// this is the same fact `chainproof::proven_actor` states one plane
    /// over, checked here at the point the chain is assembled rather than
    /// afterward.
    #[test]
    fn an_access_tokens_actor_that_is_a_person_is_refused() {
        let (issuer, now) = (Key::new(), 1_800_000_000);
        let err = verify_access_token(
            &cfg(&issuer),
            &access_token(
                &issuer,
                now,
                serde_json::json!({"act": {"sub": "user://acme/eve"}}),
            ),
            now,
            never,
        )
        .unwrap_err();
        assert_eq!(err, Refusal::Malformed);
    }

    /// Mutant #5: revocation asked about the root only. Naming the AGENT
    /// (chain[1], never the subject at chain[0]) must still refuse: an
    /// implementation that only asks about `chain[0]` would miss every case
    /// here. Seeded sweep, the same shape as `verify_delegation`'s own
    /// `a_revocation_naming_any_party_in_the_chain_refuses_the_token`.
    #[test]
    fn a_revocation_naming_the_agent_in_an_access_tokens_chain_refuses_it() {
        let (issuer, now) = (Key::new(), 1_800_000_000_i64);
        for i in 0..200 {
            let agent = format!("agent://acme/a{i}");
            let tok = access_token(
                &issuer,
                now,
                serde_json::json!({"act": {"sub": agent}, "jti": format!("at-{i}")}),
            );
            // Naming the agent: refused, regardless of which of the two
            // chain entries the caller of `revoked` is asked about, so long
            // as the loop does not stop at the subject alone.
            let revoked_agent = |_: &str, sub: &str, _: i64| sub == agent;
            assert_eq!(
                verify_access_token(&cfg(&issuer), &tok, now, revoked_agent).map(|_| ()),
                Err(Refusal::Revoked),
                "case {i}: revoking the agent {agent:?} was not honoured"
            );
            // Naming a stranger: honoured.
            assert!(
                verify_access_token(&cfg(&issuer), &tok, now, |_, sub: &str, _| sub
                    == "agent://acme/stranger")
                .is_ok(),
                "case {i}: a revocation naming a stranger refused the token"
            );
        }
    }

    #[test]
    fn an_access_token_with_alg_none_is_refused() {
        let (issuer, now) = (Key::new(), 1_800_000_000);
        let header = b64(br#"{"alg":"none","typ":"JWT","kid":"v-1"}"#);
        let claims = b64(serde_json::json!({
            "iss": ISS, "sub": "user://acme/alice", "aud": AUD,
            "iat": now, "exp": now + 300, "jti": "at-none",
            "client_id": XAA_CLIENT_ID, "act": {"sub": "agent://acme/triage"},
        })
        .to_string()
        .as_bytes());
        let forged = format!("{header}.{claims}.");
        let err = verify_access_token(&cfg(&issuer), &forged, now, never).unwrap_err();
        assert_eq!(
            err,
            Refusal::Malformed,
            "an alg:none header must never reach key selection at all"
        );
    }

    /// Mutant territory for invariant 29's rule applied to this path: the
    /// algorithm comes from the KEY (an EC key here, so ES256/ES384 only),
    /// never from the header, so a header claiming HS256 and "signed" with
    /// the issuer's own PUBLIC key bytes as an HMAC secret must be refused
    /// before that secret is ever used.
    #[test]
    fn an_access_token_signed_hs256_with_the_public_key_as_secret_is_refused() {
        let (issuer, now) = (Key::new(), 1_800_000_000);
        let mut header = jsonwebtoken::Header::new(jsonwebtoken::Algorithm::HS256);
        header.kid = Some("v-1".to_string());
        let claims = serde_json::json!({
            "iss": ISS, "sub": "user://acme/alice", "aud": AUD,
            "iat": now, "exp": now + 300, "jti": "at-hs256",
            "client_id": XAA_CLIENT_ID, "act": {"sub": "agent://acme/triage"},
        });
        let secret = issuer.jwk_value(None).to_string();
        let forged = jsonwebtoken::encode(
            &header,
            &claims,
            &jsonwebtoken::EncodingKey::from_secret(secret.as_bytes()),
        )
        .expect("jsonwebtoken can encode HS256 with an arbitrary secret");
        let err = verify_access_token(&cfg(&issuer), &forged, now, never).unwrap_err();
        assert_eq!(err, Refusal::BadSignature);
    }

    /// T3's hostile-input layer: neither pure noise nor a plausible
    /// three-part shape may ever panic this function. A panic here IS the
    /// test failing; there is no separate assertion to write.
    #[test]
    fn two_hundred_hostile_bearer_strings_never_panic_verify_access_token() {
        let (issuer, now) = (Key::new(), 1_800_000_000_i64);
        let mut seed: u64 = 20260924;
        let mut next = move || {
            seed ^= seed << 13;
            seed ^= seed >> 7;
            seed ^= seed << 17;
            seed
        };
        for i in 0..200 {
            let len = 1 + (next() % 512) as usize;
            let bytes: Vec<u8> = (0..len).map(|_| (next() % 256) as u8).collect();
            let candidate = if i % 2 == 0 {
                String::from_utf8_lossy(&bytes).into_owned()
            } else {
                let a = len / 3;
                let b = 2 * len / 3;
                format!(
                    "{}.{}.{}",
                    b64(&bytes[..a]),
                    b64(&bytes[a..b]),
                    b64(&bytes[b..])
                )
            };
            let _ = verify_access_token(&cfg(&issuer), &candidate, now, never);
        }
    }
}
