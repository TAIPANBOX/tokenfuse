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
const MAX_CHAIN_ENTRIES: usize = 32;

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
/// protects: shape, signature, issuer, audience, expiry, binding, revocation. A
/// revocation lookup on a forged token is work an attacker chose, which on a
/// busy enforcement point is a cheap denial of service.
///
/// `proof`, `method` and `url` are the RFC 9449 header and what THIS server
/// received. `now` is a Unix second, injected so an expiry is testable without
/// sleeping. `revoked` is consulted last and may be a closure that always
/// answers false, which is a caller deciding that a valid signature is enough.
/// [`revocations::Revocations::hook`] is the closure for a caller that has not
/// decided that.
pub fn verify_delegation(
    cfg: &DelegationConfig,
    token: &str,
    proof: Option<&str>,
    method: &str,
    url: &str,
    now: i64,
    revoked: impl Fn(&str, &str, i64) -> bool,
) -> Result<VerifiedDelegation, Refusal> {
    let header = decode_header(token).map_err(|_| Refusal::Malformed)?;
    let kid = header.kid.ok_or(Refusal::Malformed)?;
    let jwk = cfg.jwks.find(&kid).ok_or(Refusal::BadSignature)?;

    // The single copy of the alg rule. See `oidc::algorithms_for_key`.
    let algorithms = tokenfuse_dpop::algorithms_for_key(jwk).ok_or(Refusal::BadSignature)?;
    let key = DecodingKey::from_jwk(jwk).map_err(|_| Refusal::BadSignature)?;

    let mut validation = Validation::new(algorithms[0]);
    validation.algorithms = algorithms;
    validation.validate_exp = false; // checked below against the injected clock
    validation.set_required_spec_claims(&["exp", "iss"]);
    validation.set_issuer(&[&cfg.issuer]);
    if cfg.audience.is_empty() {
        validation.validate_aud = false;
    } else {
        validation.set_audience(&[&cfg.audience]);
    }
    let data = decode::<DelegationClaims>(token, &key, &validation).map_err(|e| {
        use jsonwebtoken::errors::ErrorKind;
        match e.kind() {
            ErrorKind::InvalidIssuer => Refusal::Issuer,
            ErrorKind::InvalidAudience => Refusal::Audience,
            _ => Refusal::BadSignature,
        }
    })?;
    let claims = data.claims;

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

    if revoked(&claims.jti, &claims.sub, claims.iat) {
        return Err(Refusal::Revoked);
    }

    Ok(VerifiedDelegation {
        chain: chain_of(&claims.sub, claims.act.as_ref())?,
        subject: claims.sub,
        jkt,
        jti: claims.jti,
        issued_at: claims.iat,
        expires_at: claims.exp,
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
}
