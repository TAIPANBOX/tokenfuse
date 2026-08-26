//! The fixture that mints what vouchryx mints.
//!
//! Behind a feature rather than `#[cfg(test)]` because THREE things now need to
//! agree about this wire, not two: the verifier, the issuer, and every
//! enforcement point that has to test what it does with a real token. The
//! alternative was a copy of these sixty lines in the gateway's integration
//! tests, and a fixture copied is a fixture that will drift from the thing it
//! is a fixture for.
//!
//! Not compiled unless `features = ["testing"]` is asked for, so nothing here
//! reaches a release binary.

use base64::Engine as _;
use p256::ecdsa::signature::Signer;

use crate::{thumbprint, DelegationConfig};

pub const ISS: &str = "https://vouchryx.acme.example";
pub const AUD: &str = "https://tokenfuse.acme.example";
pub const URL: &str = "https://tokenfuse.acme.example/v1/messages";

pub fn b64(b: &[u8]) -> String {
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(b)
}

pub struct Key {
    pub signing: p256::ecdsa::SigningKey,
}

impl Default for Key {
    fn default() -> Self {
        Self::new()
    }
}

impl Key {
    pub fn new() -> Self {
        Key {
            signing: p256::ecdsa::SigningKey::random(&mut p256::elliptic_curve::rand_core::OsRng),
        }
    }
    pub fn jwk_value(&self, kid: Option<&str>) -> serde_json::Value {
        let point = self.signing.verifying_key().to_encoded_point(false);
        let mut v = serde_json::json!({
            "kty": "EC", "crv": "P-256",
            "x": b64(point.x().unwrap()), "y": b64(point.y().unwrap()),
        });
        if let Some(k) = kid {
            v["kid"] = serde_json::json!(k);
            v["use"] = serde_json::json!("sig");
            v["alg"] = serde_json::json!("ES256");
        }
        v
    }
    pub fn sign(&self, header: serde_json::Value, claims: serde_json::Value) -> String {
        let signing = format!(
            "{}.{}",
            b64(header.to_string().as_bytes()),
            b64(claims.to_string().as_bytes())
        );
        let sig: p256::ecdsa::Signature = self.signing.sign(signing.as_bytes());
        format!("{signing}.{}", b64(&sig.to_bytes()))
    }
}

pub fn cfg(issuer_key: &Key) -> DelegationConfig {
    let set = serde_json::json!({"keys": [issuer_key.jwk_value(Some("v-1"))]});
    DelegationConfig {
        jwks: serde_json::from_value(set).expect("a jwk set"),
        issuer: ISS.into(),
        audience: AUD.into(),
    }
}

pub fn token(issuer: &Key, holder: &Key, now: i64, over: serde_json::Value) -> String {
    let jkt = {
        let jwk: jsonwebtoken::jwk::Jwk =
            serde_json::from_value(holder.jwk_value(None)).expect("a jwk");
        thumbprint(&jwk).expect("a thumbprint")
    };
    let mut claims = serde_json::json!({
        "iss": ISS, "sub": "user://acme/alice", "aud": AUD,
        "iat": now, "exp": now + 300, "jti": "tok-1",
        "cnf": {"jkt": jkt},
        "act": {"sub": "agent://acme/runbook", "act": {"sub": "agent://acme/triage"}},
    });
    if let serde_json::Value::Object(o) = over {
        for (k, v) in o {
            if v.is_null() {
                claims.as_object_mut().unwrap().remove(&k);
            } else {
                claims[k] = v;
            }
        }
    }
    issuer.sign(
        serde_json::json!({"alg": "ES256", "typ": "JWT", "kid": "v-1"}),
        claims,
    )
}

pub fn proof(holder: &Key, now: i64) -> String {
    proof_at(holder, now, "POST", URL, "p1")
}

/// A proof for a NAMED request, because an enforcement point is reached at its
/// own URL and a proof is bound to one. Taking the url rather than assuming
/// [`URL`] is what lets a door's tests present what a real caller would send
/// instead of what this fixture finds convenient.
pub fn proof_at(holder: &Key, now: i64, method: &str, url: &str, jti: &str) -> String {
    holder.sign(
        serde_json::json!({
            "typ": "dpop+jwt", "alg": "ES256", "jwk": holder.jwk_value(None)
        }),
        serde_json::json!({"htm": method, "htu": url, "iat": now, "jti": jti}),
    )
}

pub fn never(_: &str, _: &str, _: i64) -> bool {
    false
}
