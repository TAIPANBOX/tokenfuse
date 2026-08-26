//! RFC 9449 proof of possession, RFC 7638 thumbprints, and the one place this
//! repository decides which algorithms a key may be used with.
//!
//! # Why this is a crate and not a copy
//!
//! Three things in this workspace need the same answers about a JWS: the Cloud's
//! OIDC bearer path (`tokenfuse-cloud`'s `oidc`), its delegation verifier
//! (`delegation`), and the MCP credential-broker's door
//! (`tokenfuse-gateway`'s `mcpdoor`). The first two live in one crate and had
//! already agreed to share rather than repeat, which is CLAUDE.md invariant 29.
//! The third lives in the OTHER plane, and the gateway must not depend on the
//! Cloud: that would put the whole control-plane API surface inside the
//! data-plane binary and invert a boundary this repository keeps on purpose.
//!
//! `tokenfuse-core` was the other candidate and is the wrong one. Invariant 1
//! pins core's dependencies to five crates so core stays provable and portable,
//! and a JWS verifier needs `jsonwebtoken` and `base64`, neither of which
//! belongs there.
//!
//! So: a small crate both planes depend on. The rule stays one copy, which is
//! what invariant 29 asked for; only its address changed.
//!
//! # What a proof is checked for, and why each one is not paranoia
//!
//! - **`typ` is `dpop+jwt`.** Without it an access token can be presented back
//!   as a proof of possession of its own key.
//! - **The embedded key carries no private member.** RFC 9449 wants the public
//!   key. A `d` here is a client handing over its signing key, and accepting it
//!   makes the receiving process a place private keys collect.
//! - **The signature is checked against the key the proof itself carries**, with
//!   the algorithm taken from that key's TYPE. Otherwise anybody staples a
//!   victim's public key to their own proof, or signs an HMAC with the public
//!   modulus and calls it `HS256`.
//! - **`htm`, `htu` and `iat` pin the request and the moment.** A proof is for
//!   ONE request; without them, one captured from a harmless call is replayed
//!   against a dangerous one.
//! - **`jti` is required and bounded.** RFC 9449 section 4.2 makes it REQUIRED,
//!   and it is what a [`ReplayCache`] keys on. A proof with no `jti` cannot be
//!   made single-use, so accepting one is accepting a replayable proof.
//!
//! # What a proof does NOT establish
//!
//! That the holder is entitled to anything. It says the caller holds the private
//! key for the public key in the proof, for this request, at about this moment.
//! Mapping that key to an identity, and that identity to a permission, belongs
//! to the caller: `delegation` does it from a token's `cnf.jkt`, `mcpdoor` from
//! a CIMD client metadata document.

use base64::Engine as _;
use jsonwebtoken::jwk::{AlgorithmParameters, Jwk};
use jsonwebtoken::{decode, decode_header, Algorithm, DecodingKey, Validation};
use sha2::{Digest, Sha256};
use std::collections::{HashMap, HashSet};
use std::sync::Mutex;

/// How far a proof's `iat` may be from now, either way.
///
/// Either way, and not only into the past: a client whose clock is fast would
/// otherwise be refused every time, which an operator diagnoses as "DPoP is
/// broken" rather than "our clock is wrong". Every verifier in this estate uses
/// this one number; two of them disagreeing about freshness would make a proof
/// work at one enforcement point and not at another.
pub const PROOF_WINDOW_SECS: i64 = 60;

/// The longest `jti` this verifier will look at.
///
/// A `jti` is an opaque identifier the CLIENT chooses, and a [`ReplayCache`]
/// stores it. Without a bound, a client with a valid key can grow that cache by
/// however many bytes it likes per request. 256 is far past any identifier a
/// real client mints and far short of anything worth remembering.
pub const MAX_JTI_BYTES: usize = 256;

/// The algorithms a key of this type may be used with.
///
/// **The single copy of this rule in this repository**, and it is a single copy
/// on purpose rather than tidiness. The permitted algorithms come from the KEY
/// TYPE and never from the token header, which is written by whoever presents
/// the token: without this an attacker takes a public RSA modulus or EC point
/// that anybody can fetch from a JWKS, signs an HMAC using those bytes as the
/// secret, sets `alg` to `HS256`, and the signature verifies. Symmetric and OKP
/// keys are refused outright, which is what closes `none` as well.
///
/// It was inline in the Cloud's `oidc::verify` until 2026-08-26, then shared
/// with `delegation` (invariant 29), and moved here on 2026-08-26 when the MCP
/// broker's door in the OTHER crate needed it too. Each move keeps the property
/// the invariant is about: one copy, so two verifiers in one estate cannot come
/// to disagree about which signatures are valid.
#[must_use]
pub fn algorithms_for_key(jwk: &Jwk) -> Option<Vec<Algorithm>> {
    match &jwk.algorithm {
        AlgorithmParameters::RSA(_) => {
            Some(vec![Algorithm::RS256, Algorithm::RS384, Algorithm::RS512])
        }
        AlgorithmParameters::EllipticCurve(_) => Some(vec![Algorithm::ES256, Algorithm::ES384]),
        _ => None,
    }
}

/// The RFC 7638 SHA-256 thumbprint of a JWK, base64url without padding.
///
/// This is the name a key has everywhere in this estate: what a delegation token
/// is BOUND to through `cnf.jkt`, and what the MCP broker's door looks a client
/// up by. What it hashes therefore decides whether a stolen token can be
/// replayed by a different holder, and whether renaming a key silently changes
/// who a live token belongs to.
///
/// RFC 7638 hashes the REQUIRED members only, in lexicographic order, with no
/// whitespace: `crv, kty, x, y` for EC and `e, kty, n` for RSA. `kid`, `use` and
/// `alg` are excluded, which is why re-labelling a key does not change it.
#[must_use]
pub fn thumbprint(jwk: &Jwk) -> Option<String> {
    let canonical = match &jwk.algorithm {
        AlgorithmParameters::EllipticCurve(ec) => format!(
            r#"{{"crv":"{}","kty":"EC","x":"{}","y":"{}"}}"#,
            curve_name(&ec.curve),
            ec.x,
            ec.y
        ),
        AlgorithmParameters::RSA(rsa) => {
            format!(r#"{{"e":"{}","kty":"RSA","n":"{}"}}"#, rsa.e, rsa.n)
        }
        _ => return None,
    };
    Some(
        base64::engine::general_purpose::URL_SAFE_NO_PAD
            .encode(Sha256::digest(canonical.as_bytes())),
    )
}

/// Why a published key cannot be used.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeyRefusal {
    /// Not a JWK this library can parse at all.
    Malformed,
    /// A JWK, of a type no algorithm allowlist admits: symmetric or OKP. Refused
    /// rather than skipped wherever a document lists it, because a key somebody
    /// published and this estate silently ignores is a disagreement about what
    /// is trusted, and it only surfaces as a client that mysteriously cannot get
    /// in.
    Unsupported,
}

/// [`thumbprint`], for a caller holding a key as JSON rather than as a parsed
/// `Jwk`.
///
/// Exists so a crate can name a key without depending on `jsonwebtoken`: the
/// gateway reads published client documents and should not acquire a JWS library
/// of its own to do it, which is the same duplication this crate exists to stop.
pub fn thumbprint_of_json(key: &serde_json::Value) -> Result<String, KeyRefusal> {
    let jwk: Jwk = serde_json::from_value(key.clone()).map_err(|_| KeyRefusal::Malformed)?;
    thumbprint(&jwk).ok_or(KeyRefusal::Unsupported)
}

fn curve_name(c: &jsonwebtoken::jwk::EllipticCurve) -> &'static str {
    use jsonwebtoken::jwk::EllipticCurve as C;
    match c {
        C::P384 => "P-384",
        C::P521 => "P-521",
        _ => "P-256",
    }
}

/// What a valid proof establishes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedProof {
    /// RFC 7638 thumbprint of the key that signed it: WHO holds it.
    pub jkt: String,
    /// RFC 9449 `jti`: what makes it single-use, given a [`ReplayCache`].
    pub jti: String,
}

/// Why a proof was refused.
///
/// Distinct because each sends an operator somewhere different, and this is the
/// INTERNAL vocabulary. What reaches a caller over the wire must not distinguish
/// them: a verifier that narrates which of six checks failed tells an attacker
/// whether their captured proof was still fresh, whether the key was known, and
/// which server the proof was made for.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProofRefusal {
    /// Not a JWS at all, or missing the embedded key.
    Malformed,
    /// `typ` is not `dpop+jwt`, so this is some other token being reused.
    NotAProof,
    /// The embedded JWK carries private key material.
    PrivateKeyMaterial,
    /// The signature does not verify against the key the proof carries, or that
    /// key is of a type no algorithm allowlist admits.
    BadSignature,
    /// `htm`/`htu` name a different request, or `jti` is missing or too long.
    WrongRequest,
    /// `iat` is too far from now, either way.
    Stale,
}

/// Verify an RFC 9449 proof against what THIS server received.
///
/// `method` and `url` are what this server actually handled, not what the
/// request said about itself: comparing a proof against a caller-supplied `Host`
/// header would let the caller make the two agree with anything, which is how an
/// `htu` check quietly becomes decoration.
///
/// `now` is a Unix second, injected so freshness is testable without sleeping.
pub fn verify_proof(
    proof: &str,
    method: &str,
    url: &str,
    now: i64,
) -> Result<VerifiedProof, ProofRefusal> {
    let header = decode_header(proof).map_err(|_| ProofRefusal::Malformed)?;
    // The `typ` is what stops a token being a proof: without it, an access token
    // could be presented back as a proof of possession of its own key.
    if header.typ.as_deref() != Some("dpop+jwt") {
        return Err(ProofRefusal::NotAProof);
    }
    let jwk = header.jwk.as_ref().ok_or(ProofRefusal::Malformed)?;
    if carries_private_member(proof) {
        // RFC 9449 requires the PUBLIC key. A `d` here is a client handing us its
        // signing key, and accepting it makes this process a place private keys
        // collect.
        return Err(ProofRefusal::PrivateKeyMaterial);
    }

    // Verified against the key the proof itself carries, which is the step the
    // whole scheme rests on: without it, anybody staples somebody else's public
    // key to their own proof and is accepted as its holder. The algorithm still
    // comes from the key type, so a proof cannot downgrade itself either.
    let algorithms = algorithms_for_key(jwk).ok_or(ProofRefusal::BadSignature)?;
    let key = DecodingKey::from_jwk(jwk).map_err(|_| ProofRefusal::BadSignature)?;
    let mut validation = Validation::new(algorithms[0]);
    validation.algorithms = algorithms;
    validation.validate_exp = false;
    validation.validate_aud = false;
    validation.required_spec_claims.clear();
    let data = decode::<HashMap<String, serde_json::Value>>(proof, &key, &validation)
        .map_err(|_| ProofRefusal::BadSignature)?;
    let claims = data.claims;

    let htm = claims
        .get("htm")
        .and_then(|v| v.as_str())
        .unwrap_or_default();
    if !htm.eq_ignore_ascii_case(method) {
        return Err(ProofRefusal::WrongRequest);
    }
    let htu = claims
        .get("htu")
        .and_then(|v| v.as_str())
        .unwrap_or_default();
    if trim_query(htu) != trim_query(url) {
        return Err(ProofRefusal::WrongRequest);
    }
    let iat = claims
        .get("iat")
        .and_then(serde_json::Value::as_i64)
        .ok_or(ProofRefusal::Stale)?;
    if (now - iat).abs() > PROOF_WINDOW_SECS {
        return Err(ProofRefusal::Stale);
    }
    // RFC 9449 4.2 makes `jti` REQUIRED, and it is the only thing that can make
    // a proof single-use. A proof without one is not merely incomplete: it is
    // one nothing can stop being replayed.
    let jti = claims
        .get("jti")
        .and_then(|v| v.as_str())
        .unwrap_or_default();
    if jti.is_empty() || jti.len() > MAX_JTI_BYTES {
        return Err(ProofRefusal::WrongRequest);
    }

    Ok(VerifiedProof {
        jkt: thumbprint(jwk).ok_or(ProofRefusal::BadSignature)?,
        jti: jti.to_string(),
    })
}

/// Whether a proof's embedded JWK carries anything only its holder should have.
///
/// Read off the RAW header rather than the parsed `Jwk`, because that type has
/// no field for `d` and drops it in silence: a client leaking its private key
/// would then be accepted, and the leak would be invisible.
fn carries_private_member(proof: &str) -> bool {
    let Some(encoded) = proof.split('.').next() else {
        return true;
    };
    let Ok(raw) = base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(encoded) else {
        return true;
    };
    let Ok(value) = serde_json::from_slice::<serde_json::Value>(&raw) else {
        return true;
    };
    let Some(jwk) = value.get("jwk").and_then(|j| j.as_object()) else {
        return true;
    };
    ["d", "p", "q", "dp", "dq", "qi", "k"]
        .iter()
        .any(|m| jwk.contains_key(*m))
}

/// RFC 9449 section 4.3: `htu` is the request URI with query and fragment
/// removed. Comparing them whole would refuse every proof for a URL carrying a
/// cache-buster, which an operator diagnoses as "DPoP is broken".
fn trim_query(u: &str) -> &str {
    match u.find(['?', '#']) {
        Some(i) => &u[..i],
        None => u,
    }
}

/// Why a `jti` was refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReplayRefusal {
    /// This `jti` has already been used inside the window.
    Seen,
    /// The cache is at its cap, so this verifier can no longer promise a proof
    /// is single-use. It refuses rather than forgetting one, because forgetting
    /// is how a replay guard stops guarding without saying so.
    Full,
}

/// Remembers which `jti` values have been seen, so a proof is single-use.
///
/// # Why a proof needs this at all
///
/// `htm` and `htu` pin a proof to one method and one URL, which is most of the
/// value when an API has many endpoints. It is nearly none when it has one: the
/// MCP credential-broker answers every JSON-RPC method as a POST to a single
/// path, so without single-use `jti` a proof captured from a harmless
/// `tools/list` is a valid credential for `tools/call` for the rest of the
/// window. That is the case this exists for.
///
/// # Two generations, and why the arithmetic is what it is
///
/// Nothing is scanned or evicted per entry. Two sets are kept; when the current
/// one is old enough it becomes the previous one and a fresh set starts. A
/// lookup consults both, so memory is bounded by traffic rather than by a timer,
/// and no entry inside the window is ever forgotten.
///
/// The generation length is **twice** [`PROOF_WINDOW_SECS`], not once, and that
/// is not a safety margin. `iat` is accepted up to a window either side of now,
/// so the longest interval over which one proof can be presented twice and be
/// fresh both times is two windows. Rotating every window would keep between one
/// and two windows of history, and the shortfall would be a replay that works.
///
/// # Where it says nothing
///
/// It is per PROCESS. Two brokers behind a load balancer each remember their
/// own, so a proof used at one can be replayed at the other. Closing that needs
/// shared state, which is a deployment decision rather than a function.
pub struct ReplayCache {
    generation: i64,
    cap: usize,
    inner: Mutex<Generations>,
}

struct Generations {
    started: i64,
    current: HashSet<String>,
    previous: HashSet<String>,
}

impl ReplayCache {
    /// `cap` bounds ONE generation, so at most `2 * cap` identifiers are held.
    #[must_use]
    pub fn new(cap: usize) -> Self {
        ReplayCache {
            generation: PROOF_WINDOW_SECS * 2,
            cap,
            inner: Mutex::new(Generations {
                started: i64::MIN,
                current: HashSet::new(),
                previous: HashSet::new(),
            }),
        }
    }

    /// Record `jti` as used at `now`, or say why it may not be.
    pub fn check_and_record(&self, jti: &str, now: i64) -> Result<(), ReplayRefusal> {
        let mut g = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        // `started` moves forward only. A clock that steps backwards must not
        // rotate the generations, or an attacker who can nudge it forwards and
        // back gets two rotations and an empty cache.
        if g.started == i64::MIN || now.saturating_sub(g.started) >= self.generation {
            if now.saturating_sub(g.started) >= self.generation.saturating_mul(2) {
                g.previous.clear();
            } else {
                g.previous = std::mem::take(&mut g.current);
            }
            g.current.clear();
            g.started = now;
        }
        if g.current.contains(jti) || g.previous.contains(jti) {
            return Err(ReplayRefusal::Seen);
        }
        if g.current.len() >= self.cap {
            return Err(ReplayRefusal::Full);
        }
        g.current.insert(jti.to_string());
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use p256::ecdsa::signature::Signer;

    const URL: &str = "https://mcp.acme.example/mcp";

    fn b64(b: &[u8]) -> String {
        base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(b)
    }

    struct Key {
        signing: p256::ecdsa::SigningKey,
    }

    impl Key {
        fn new() -> Self {
            Key {
                signing: p256::ecdsa::SigningKey::random(
                    &mut p256::elliptic_curve::rand_core::OsRng,
                ),
            }
        }
        fn jwk_value(&self) -> serde_json::Value {
            let point = self.signing.verifying_key().to_encoded_point(false);
            serde_json::json!({
                "kty": "EC", "crv": "P-256",
                "x": b64(point.x().unwrap()), "y": b64(point.y().unwrap()),
            })
        }
        fn sign(&self, header: serde_json::Value, claims: serde_json::Value) -> String {
            let signing = format!(
                "{}.{}",
                b64(header.to_string().as_bytes()),
                b64(claims.to_string().as_bytes())
            );
            let sig: p256::ecdsa::Signature = self.signing.sign(signing.as_bytes());
            format!("{signing}.{}", b64(&sig.to_bytes()))
        }
        fn proof(&self, claims: serde_json::Value) -> String {
            self.sign(
                serde_json::json!({"typ": "dpop+jwt", "alg": "ES256", "jwk": self.jwk_value()}),
                claims,
            )
        }
    }

    fn good(now: i64) -> serde_json::Value {
        serde_json::json!({"htm": "POST", "htu": URL, "iat": now, "jti": "p1"})
    }

    #[test]
    fn a_good_proof_names_the_key_that_signed_it_and_its_jti() {
        let (k, now) = (Key::new(), 1_800_000_000);
        let v = verify_proof(&k.proof(good(now)), "POST", URL, now).expect("a good proof");
        assert_eq!(v.jti, "p1");
        let jwk: Jwk = serde_json::from_value(k.jwk_value()).expect("a jwk");
        assert_eq!(v.jkt, thumbprint(&jwk).expect("a thumbprint"));
    }

    /// RFC 9449 4.2 makes `jti` REQUIRED, and a proof without one cannot be made
    /// single-use by anything. Accepting it is accepting a replayable proof.
    #[test]
    fn a_proof_with_no_jti_is_refused_because_nothing_could_make_it_single_use() {
        let (k, now) = (Key::new(), 1_800_000_000);
        for claims in [
            serde_json::json!({"htm": "POST", "htu": URL, "iat": now}),
            serde_json::json!({"htm": "POST", "htu": URL, "iat": now, "jti": ""}),
            serde_json::json!({"htm": "POST", "htu": URL, "iat": now, "jti": "x".repeat(MAX_JTI_BYTES + 1)}),
        ] {
            assert_eq!(
                verify_proof(&k.proof(claims), "POST", URL, now).unwrap_err(),
                ProofRefusal::WrongRequest
            );
        }
    }

    #[test]
    fn an_access_token_is_not_a_proof() {
        let (k, now) = (Key::new(), 1_800_000_000);
        let not_a_proof = k.sign(
            serde_json::json!({"typ": "JWT", "alg": "ES256", "jwk": k.jwk_value()}),
            good(now),
        );
        assert_eq!(
            verify_proof(&not_a_proof, "POST", URL, now).unwrap_err(),
            ProofRefusal::NotAProof
        );
    }

    #[test]
    fn a_client_leaking_its_private_key_is_refused_rather_than_helped() {
        let (k, now) = (Key::new(), 1_800_000_000);
        let mut jwk = k.jwk_value();
        jwk["d"] = serde_json::json!("bm90LWEtcmVhbC1rZXk");
        let leaky = k.sign(
            serde_json::json!({"typ": "dpop+jwt", "alg": "ES256", "jwk": jwk}),
            good(now),
        );
        assert_eq!(
            verify_proof(&leaky, "POST", URL, now).unwrap_err(),
            ProofRefusal::PrivateKeyMaterial
        );
    }

    /// Staple somebody else's public key to your own proof and you are not its
    /// holder. This is the step the whole scheme rests on.
    #[test]
    fn a_proof_signed_by_a_key_other_than_the_one_it_carries_is_refused() {
        let (mine, victim, now) = (Key::new(), Key::new(), 1_800_000_000);
        let stapled = mine.sign(
            serde_json::json!({"typ": "dpop+jwt", "alg": "ES256", "jwk": victim.jwk_value()}),
            good(now),
        );
        assert_eq!(
            verify_proof(&stapled, "POST", URL, now).unwrap_err(),
            ProofRefusal::BadSignature
        );
    }

    #[test]
    fn a_proof_for_another_request_or_another_moment_is_refused() {
        let (k, now) = (Key::new(), 1_800_000_000);
        let p = k.proof(good(now));
        assert_eq!(
            verify_proof(&p, "GET", URL, now).unwrap_err(),
            ProofRefusal::WrongRequest
        );
        assert_eq!(
            verify_proof(&p, "POST", "https://mcp.acme.example/kill", now).unwrap_err(),
            ProofRefusal::WrongRequest
        );
        for clock in [now + PROOF_WINDOW_SECS + 1, now - PROOF_WINDOW_SECS - 1] {
            assert_eq!(
                verify_proof(&p, "POST", URL, clock).unwrap_err(),
                ProofRefusal::Stale,
                "at {clock}"
            );
        }
    }

    /// RFC 9449 4.3. A server comparing them whole refuses every proof for a URL
    /// carrying a cache-buster, which reads as a broken feature.
    #[test]
    fn a_query_string_is_not_a_different_request() {
        let (k, now) = (Key::new(), 1_800_000_000);
        verify_proof(&k.proof(good(now)), "POST", &format!("{URL}?trace=1"), now)
            .expect("a query string is not a different request");
    }

    /// The single copy of the alg rule, asserted from the crate that now owns
    /// it. An EC key must never be offered a symmetric algorithm, and a
    /// symmetric key is refused outright, which is what closes `none` too.
    #[test]
    fn the_algorithm_comes_from_the_key_and_never_from_the_header() {
        let ec: Jwk = serde_json::from_value(Key::new().jwk_value()).expect("a jwk");
        let algs = algorithms_for_key(&ec).expect("an EC key is usable");
        assert!(
            algs.iter()
                .all(|a| matches!(a, Algorithm::ES256 | Algorithm::ES384)),
            "{algs:?}"
        );
        let oct: Jwk = serde_json::from_value(serde_json::json!({"kty": "oct", "k": "c2VjcmV0"}))
            .expect("a jwk");
        assert!(algorithms_for_key(&oct).is_none());
    }

    /// RFC 7638 hashes the required members only. `kid`, `use` and `alg` are
    /// excluded, which is why re-labelling a key does not silently change who a
    /// live token belongs to.
    #[test]
    fn a_thumbprint_ignores_the_labels_and_changes_with_the_key() {
        let k = Key::new();
        let bare: Jwk = serde_json::from_value(k.jwk_value()).expect("a jwk");
        let mut labelled_value = k.jwk_value();
        labelled_value["kid"] = serde_json::json!("k-1");
        labelled_value["use"] = serde_json::json!("sig");
        labelled_value["alg"] = serde_json::json!("ES256");
        let labelled: Jwk = serde_json::from_value(labelled_value).expect("a jwk");
        assert_eq!(thumbprint(&bare), thumbprint(&labelled));

        let other: Jwk = serde_json::from_value(Key::new().jwk_value()).expect("a jwk");
        assert_ne!(thumbprint(&bare), thumbprint(&other));
    }

    // --- the replay cache -------------------------------------------------

    #[test]
    fn a_second_use_of_one_jti_is_refused() {
        let c = ReplayCache::new(16);
        assert_eq!(c.check_and_record("j1", 1_000), Ok(()));
        assert_eq!(c.check_and_record("j1", 1_000), Err(ReplayRefusal::Seen));
        assert_eq!(
            c.check_and_record("j1", 1_010),
            Err(ReplayRefusal::Seen),
            "still the same window"
        );
    }

    /// The negative control. A cache that refused everything would pass the test
    /// above, and would take the door with it.
    #[test]
    fn distinct_jtis_are_all_admitted() {
        let c = ReplayCache::new(16);
        for i in 0..10 {
            assert_eq!(c.check_and_record(&format!("j{i}"), 1_000), Ok(()));
        }
    }

    /// A `jti` is forgotten only once no proof carrying it could still be fresh,
    /// which is why the generation is two windows rather than one. The pairing
    /// is load-bearing: forgetting is safe BECAUSE `verify_proof` refuses a
    /// stale `iat`, so this test states the coupling rather than assuming it.
    #[test]
    fn a_jti_survives_every_moment_a_proof_carrying_it_could_still_be_fresh() {
        let c = ReplayCache::new(16);
        let t0 = 1_000_000;
        assert_eq!(c.check_and_record("j1", t0), Ok(()));
        // The latest a proof minted for t0 can still be presented and be fresh:
        // iat may be a window ahead of now, and now a window past iat.
        assert_eq!(
            c.check_and_record("j1", t0 + PROOF_WINDOW_SECS * 2),
            Err(ReplayRefusal::Seen),
            "forgotten while a replay of it would still verify"
        );
        assert_eq!(
            c.check_and_record("j1", t0 + PROOF_WINDOW_SECS * 8),
            Ok(()),
            "long past any freshness, the identifier is no longer worth memory"
        );
    }

    /// At the cap it refuses rather than forgetting. Forgetting under pressure
    /// is a replay guard that stops guarding exactly when somebody is pushing on
    /// it, and says nothing.
    #[test]
    fn a_full_cache_refuses_rather_than_forgetting_something_it_promised() {
        let c = ReplayCache::new(2);
        assert_eq!(c.check_and_record("j1", 1_000), Ok(()));
        assert_eq!(c.check_and_record("j2", 1_000), Ok(()));
        assert_eq!(c.check_and_record("j3", 1_000), Err(ReplayRefusal::Full));
        assert_eq!(
            c.check_and_record("j1", 1_000),
            Err(ReplayRefusal::Seen),
            "a full cache still answers about what it does remember"
        );
    }

    /// A clock that steps backwards must not rotate the generations: two
    /// rotations is an empty cache, and an attacker who can nudge a clock would
    /// get one.
    #[test]
    fn a_clock_that_walks_backwards_does_not_empty_the_cache() {
        let c = ReplayCache::new(16);
        assert_eq!(c.check_and_record("j1", 1_000_000), Ok(()));
        assert_eq!(
            c.check_and_record("j1", 1_000_000 - PROOF_WINDOW_SECS * 10),
            Err(ReplayRefusal::Seen)
        );
    }
    #[test]
    fn a_key_can_be_named_from_json_without_a_jws_library() {
        let k = Key::new();
        let jwk: Jwk = serde_json::from_value(k.jwk_value()).expect("a jwk");
        assert_eq!(
            thumbprint_of_json(&k.jwk_value()),
            Ok(thumbprint(&jwk).expect("a thumbprint"))
        );
        assert_eq!(
            thumbprint_of_json(&serde_json::json!({"kty": "oct", "k": "c2VjcmV0"})),
            Err(KeyRefusal::Unsupported),
            "a key no algorithm rule admits is refused, never quietly named"
        );
        assert_eq!(
            thumbprint_of_json(&serde_json::json!({"not": "a key"})),
            Err(KeyRefusal::Malformed)
        );
    }
}
