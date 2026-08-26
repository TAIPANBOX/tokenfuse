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

/// The chain cap agent-passport SPEC 5.1 sets, and the thing that stops a
/// self-referential `act` being walked for ever.
const MAX_DEPTH: usize = 32;

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
fn chain_of(sub: &str, act: Option<&Act>) -> Result<Vec<String>, Refusal> {
    // `act` nests current-first (RFC 8693 4.1: "The outermost `act` claim
    // represents the current actor"), and this estate records root-first, so
    // collecting then reversing is the mapping rather than a tidy-up.
    let mut current_first = Vec::new();
    let mut cursor = act;
    while let Some(a) = cursor {
        if current_first.len() >= MAX_DEPTH {
            return Err(Refusal::Malformed);
        }
        if a.sub.is_empty() {
            return Err(Refusal::Malformed);
        }
        current_first.push(a.sub.clone());
        cursor = a.act.as_deref();
    }
    let mut chain = Vec::with_capacity(current_first.len() + 1);
    chain.push(sub.to_string());
    chain.extend(current_first.into_iter().rev());
    Ok(chain)
}

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
}
