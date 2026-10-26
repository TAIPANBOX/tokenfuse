//! The audit manifest signed by keyryx custody (invariant 130).
//!
//! `TOKENFUSE_CLOUD_AUDIT_SIGNER=keyryx` moves the manifest's key out of this
//! process: keyryx holds it, and this process asks keyryx's sign route
//! (`POST /v1/keys/{name}/sign`) to sign each manifest's canonical bytes. The
//! answer is checked here before anything is served: an ES256 signature that
//! verifies over exactly those bytes under the public key keyryx named, and a
//! `kid` that is that key's RFC 7638 thumbprint, which is how keyryx names an
//! EC key and what an auditor looks the key up by in keyryx's published set. Any
//! other answer, and a keyryx that cannot be reached, is a manifest not signed:
//! the route answers `503` and says why, and nothing unsigned is served and no
//! other key signs instead.
//!
//! Unset (or `env`), the manifest is signed exactly as before, by the key in
//! `TOKENFUSE_CLOUD_AUDIT_SIGNING_KEY`, in this process ([`crate::audit_sign`]).
//!
//! keyryx signs "low-rate statements on request", and the manifest route is
//! readable by any viewer of an org, so a manifest keyryx signed is reused for
//! that org while its chain tip is unchanged, for at most [`REUSE_SECS`]. A
//! viewer can therefore ask keyryx for at most one signature per org per
//! [`REUSE_SECS`]; a new tip, which only a mutation makes, signs again.

use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::Mutex;
use std::time::Duration;

use base64::{
    engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD},
    Engine,
};
use p256::ecdsa::{signature::Verifier, Signature, SigningKey, VerifyingKey};

use crate::audit_sign::{AuditManifest, ChainTip, AUDIT_SIGNING_KEY_ENV};

/// Which signer signs the audit manifest: `env` (today's, the default) or
/// `keyryx`.
pub const SIGNER_ENV: &str = "TOKENFUSE_CLOUD_AUDIT_SIGNER";
/// keyryx custody's origin, `http(s)://host[:port]`.
pub const KEYRYX_URL_ENV: &str = "TOKENFUSE_CLOUD_AUDIT_KEYRYX_URL";
/// The held key keyryx signs manifests with, granted `sign` to this consumer.
pub const KEYRYX_KEY_ENV: &str = "TOKENFUSE_CLOUD_AUDIT_KEYRYX_KEY";
/// A file holding this consumer's bearer credential for keyryx: its key, or a
/// Kubernetes projected service-account token. Read on every sign, so a rotated
/// file is used at once.
pub const KEYRYX_CREDENTIAL_FILE_ENV: &str = "TOKENFUSE_CLOUD_AUDIT_KEYRYX_CREDENTIAL_FILE";

/// The words [`SIGNER_ENV`] reads, in the order a refusal names them.
pub const SIGNER_WORDS: &[&str] = &["env", "keyryx"];
/// The purpose keyryx writes beside each signature in its use log.
pub const PURPOSE: &str = "tokenfuse.audit-manifest";
/// How long a manifest keyryx signed is served again for an unchanged tip.
pub const REUSE_SECS: i64 = 60;
/// keyryx's own cap on a statement it signs on request (`keystore.MaxStatement`).
pub const MAX_STATEMENT: usize = 4096;

const REQUEST_TIMEOUT: Duration = Duration::from_secs(10);
/// keyryx answers four short fields; anything near this is not that answer.
const MAX_RESPONSE: usize = 64 << 10;
/// Orgs come from the key spec and the identity provider; past this many the
/// reuse map starts over rather than growing.
const REUSE_CAP: usize = 4096;

/// What the manifest is signed with.
pub enum AuditSigner {
    /// `TOKENFUSE_CLOUD_AUDIT_SIGNING_KEY`, held in this process (today's).
    Env(SigningKey),
    /// A key keyryx custody holds; this process asks it to sign.
    Keyryx(KeyryxSigner),
}

/// What the three keyryx variables configure.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KeyryxConfig {
    pub base_url: String,
    pub key_name: String,
    pub credential_file: PathBuf,
}

/// keyryx's name grammar, for key names.
fn is_keyryx_name(s: &str) -> bool {
    let b = s.as_bytes();
    !b.is_empty()
        && b.len() <= 64
        && (b[0].is_ascii_lowercase() || b[0].is_ascii_digit())
        && b.iter().all(|c| {
            c.is_ascii_lowercase() || c.is_ascii_digit() || matches!(c, b'.' | b'_' | b'-')
        })
}

/// An origin keyryx can be asked at: http or https, a host, an optional port,
/// and no path, query, fragment or credentials (the credential is the file's).
fn keyryx_origin(u: &str) -> Option<String> {
    let p = reqwest::Url::parse(u).ok()?;
    let ok = matches!(p.scheme(), "http" | "https")
        && p.host_str().is_some()
        && matches!(p.path(), "" | "/")
        && p.query().is_none()
        && p.fragment().is_none()
        && p.username().is_empty()
        && p.password().is_none();
    ok.then(|| u.trim_end_matches('/').to_string())
}

/// The credential a file holds: one word, never echoed. An error names the
/// operating system's reason, not the file's contents.
fn read_credential(path: &std::path::Path) -> Result<String, String> {
    let raw = std::fs::read_to_string(path)
        .map_err(|e| format!("the keyryx credential file cannot be read ({e})"))?;
    let tok = raw.trim();
    if tok.is_empty() || tok.contains(char::is_whitespace) {
        return Err("the keyryx credential file is empty or holds more than one word".into());
    }
    Ok(tok.to_string())
}

/// Read the signer through `get`. `Ok(None)` is signing off, the default when
/// no key is configured; an `Err` names every variable that is missing or
/// unusable, and the caller refuses to start.
///
/// Unset or `env` is today's behaviour byte for byte, an unparseable
/// `TOKENFUSE_CLOUD_AUDIT_SIGNING_KEY` still reading as signing off, so a
/// deployment that sets none of the new variables is unchanged. The new
/// variables are held to the set-but-unusable rule: a word this cannot read,
/// a keyryx variable set while the signer is not keyryx, keyryx beside an
/// in-process key, and a keyryx configuration missing anything each refuse.
pub fn signer_from(get: impl Fn(&str) -> Option<String>) -> Result<Option<AuditSigner>, String> {
    let read = |k: &str| {
        get(k)
            .map(|v| v.trim().to_string())
            .filter(|v| !v.is_empty())
    };
    let keyryx_vars = [KEYRYX_URL_ENV, KEYRYX_KEY_ENV, KEYRYX_CREDENTIAL_FILE_ENV];
    let word = read(SIGNER_ENV).map(|w| w.to_ascii_lowercase());
    match word.as_deref() {
        None | Some("env") => {
            let set: Vec<&str> = keyryx_vars
                .iter()
                .copied()
                .filter(|k| read(k).is_some())
                .collect();
            if !set.is_empty() {
                return Err(format!(
                    "refusing to start: {} set and {SIGNER_ENV} is not keyryx; set \
                     {SIGNER_ENV}=keyryx to sign audit manifests through keyryx, or unset them",
                    set.join(", ")
                ));
            }
            Ok(get(AUDIT_SIGNING_KEY_ENV)
                .and_then(|raw| crate::audit_sign::parse_signing_key(raw.trim()))
                .map(AuditSigner::Env))
        }
        Some("keyryx") => {
            let mut problems = vec![];
            if read(AUDIT_SIGNING_KEY_ENV).is_some() {
                problems.push(format!(
                    "{AUDIT_SIGNING_KEY_ENV} is set too; a manifest has one signer, and a key \
                     left in this environment is a key keyryx was meant to take out of it"
                ));
            }
            let base_url = match read(KEYRYX_URL_ENV) {
                None => {
                    problems.push(format!("{KEYRYX_URL_ENV} is not set"));
                    String::new()
                }
                Some(u) => keyryx_origin(&u).unwrap_or_else(|| {
                    problems.push(format!(
                        "{KEYRYX_URL_ENV} must be an http or https origin with no path, query or \
                         credentials"
                    ));
                    String::new()
                }),
            };
            let key_name = read(KEYRYX_KEY_ENV).unwrap_or_default();
            if !is_keyryx_name(&key_name) || key_name.starts_with("keyryx.") {
                problems.push(format!(
                    "{KEYRYX_KEY_ENV} must be a held key name in keyryx's grammar (a lowercase \
                     letter or digit, then lowercase letters, digits, '.', '_' or '-', at most \
                     64), outside its reserved keyryx. space"
                ));
            }
            let credential_file = match read(KEYRYX_CREDENTIAL_FILE_ENV) {
                None => {
                    problems.push(format!(
                        "{KEYRYX_CREDENTIAL_FILE_ENV} is not set; keyryx signs only for a \
                         consumer it can identify"
                    ));
                    PathBuf::new()
                }
                Some(f) => {
                    let path = PathBuf::from(f);
                    if let Err(why) = read_credential(&path) {
                        problems.push(format!(
                            "{KEYRYX_CREDENTIAL_FILE_ENV} '{}': {why}",
                            path.display()
                        ));
                    }
                    path
                }
            };
            if !problems.is_empty() {
                return Err(format!(
                    "refusing to start: {SIGNER_ENV}=keyryx, and {}",
                    problems.join("; ")
                ));
            }
            KeyryxSigner::new(KeyryxConfig {
                base_url,
                key_name,
                credential_file,
            })
            .map(|s| Some(AuditSigner::Keyryx(s)))
        }
        Some(other) => Err(format!(
            "refusing to start: {SIGNER_ENV}='{other}' is not one of {}",
            SIGNER_WORDS.join("|")
        )),
    }
}

/// Why keyryx did not sign a manifest. `reason` is what the route answers with,
/// and it names no URL, path or credential; `detail` is the operator's log.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NotSigned {
    pub reason: String,
    pub detail: String,
}

impl NotSigned {
    fn same(reason: impl Into<String>) -> Self {
        let reason = reason.into();
        NotSigned {
            detail: reason.clone(),
            reason,
        }
    }
}

/// A signature keyryx answered with, already checked over the bytes it signs.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KeyryxSignature {
    pub kid: String,
    pub signature_b64: String,
    /// base64 (standard) of the uncompressed SEC1 point, whatever encoding
    /// keyryx sent, so the manifest's own contract holds.
    pub public_key_b64: String,
}

/// The consumer side of keyryx's sign route, with the per-org reuse.
pub struct KeyryxSigner {
    cfg: KeyryxConfig,
    http: reqwest::Client,
    reuse: Mutex<HashMap<String, AuditManifest>>,
}

impl KeyryxSigner {
    pub fn new(cfg: KeyryxConfig) -> Result<Self, String> {
        let http = reqwest::Client::builder()
            // A proxy would see the credential, and keyryx never redirects:
            // following one would send the credential where the redirect says.
            .no_proxy()
            .redirect(reqwest::redirect::Policy::none())
            .timeout(REQUEST_TIMEOUT)
            .build()
            .map_err(|e| format!("refusing to start: cannot build the keyryx client: {e}"))?;
        Ok(KeyryxSigner {
            cfg,
            http,
            reuse: Mutex::new(HashMap::new()),
        })
    }

    pub fn key_name(&self) -> &str {
        &self.cfg.key_name
    }

    pub fn base_url(&self) -> &str {
        &self.cfg.base_url
    }

    /// Ask keyryx to sign `bytes` and check what it answered: status 200, a
    /// JSON body of keyryx's shape, `alg` ES256, a P-256 public key, a
    /// signature that verifies over `bytes` under it, and a `kid` that is that
    /// key's RFC 7638 thumbprint.
    pub async fn sign(&self, bytes: &[u8]) -> Result<KeyryxSignature, NotSigned> {
        if bytes.len() > MAX_STATEMENT {
            return Err(NotSigned::same(format!(
                "the manifest's signing bytes are {} long, over keyryx's {MAX_STATEMENT}-byte cap",
                bytes.len()
            )));
        }
        let bearer = read_credential(&self.cfg.credential_file).map_err(|why| NotSigned {
            detail: format!("{why} ({})", self.cfg.credential_file.display()),
            reason: why,
        })?;
        let body = serde_json::json!({
            "statement_b64": STANDARD.encode(bytes),
            "purpose": PURPOSE,
        })
        .to_string();
        let route = format!("/v1/keys/{}/sign", self.cfg.key_name);
        let sent = self
            .http
            .post(format!("{}{route}", self.cfg.base_url))
            .header("accept", "application/json")
            .header("content-type", "application/json")
            .bearer_auth(bearer)
            .body(body)
            .send()
            .await;
        let mut resp = match sent {
            Ok(r) => r,
            Err(e) => {
                let reason = if e.is_timeout() {
                    format!(
                        "keyryx did not answer within {} s",
                        REQUEST_TIMEOUT.as_secs()
                    )
                } else if e.is_connect() {
                    "keyryx could not be reached".to_string()
                } else {
                    "the request to keyryx failed".to_string()
                };
                return Err(NotSigned {
                    detail: format!("{reason}: {e}"),
                    reason,
                });
            }
        };
        let status = resp.status();
        let mut raw = Vec::new();
        loop {
            match resp.chunk().await {
                Ok(Some(chunk)) => {
                    if raw.len() + chunk.len() > MAX_RESPONSE {
                        return Err(NotSigned::same(format!(
                            "keyryx's answer is over {MAX_RESPONSE} bytes"
                        )));
                    }
                    raw.extend_from_slice(&chunk);
                }
                Ok(None) => break,
                Err(e) => {
                    let reason = "keyryx's answer could not be read".to_string();
                    return Err(NotSigned {
                        detail: format!("{reason}: {e}"),
                        reason,
                    });
                }
            }
        }
        // A refusal's reason is keyryx's to log; only the status is carried.
        if status != reqwest::StatusCode::OK {
            return Err(NotSigned::same(format!(
                "keyryx refused the sign with status {}",
                status.as_u16()
            )));
        }
        verify_answer(&raw, bytes)
    }

    /// The manifest over `tip`, signed by keyryx at `now_ms`, or the one it
    /// signed for this org and tip less than [`REUSE_SECS`] ago.
    pub async fn manifest(
        &self,
        org: &str,
        tip: ChainTip,
        now_ms: i64,
    ) -> Result<AuditManifest, NotSigned> {
        if let Some(m) = self.reused(org, &tip, now_ms) {
            return Ok(m);
        }
        let sig = self.sign(&tip.signing_bytes(org, now_ms)).await?;
        let m = AuditManifest {
            org: org.to_string(),
            tip_seq: tip.tip_seq,
            tip_hash: tip.tip_hash,
            entry_count: tip.entry_count,
            signed_at_millis: now_ms,
            algorithm: "ES256".to_string(),
            signature_b64: sig.signature_b64,
            public_key_b64: sig.public_key_b64,
            kid: Some(sig.kid),
        };
        let mut reuse = self.reuse.lock().unwrap();
        if reuse.len() >= REUSE_CAP && !reuse.contains_key(org) {
            reuse.clear();
        }
        reuse.insert(org.to_string(), m.clone());
        Ok(m)
    }

    fn reused(&self, org: &str, tip: &ChainTip, now_ms: i64) -> Option<AuditManifest> {
        let reuse = self.reuse.lock().unwrap();
        let m = reuse.get(org)?;
        let same_tip = m.tip_seq == tip.tip_seq
            && m.tip_hash == tip.tip_hash
            && m.entry_count == tip.entry_count;
        let age = now_ms.saturating_sub(m.signed_at_millis);
        (same_tip && (0..REUSE_SECS * 1000).contains(&age)).then(|| m.clone())
    }
}

/// keyryx's answer, checked: its four fields, ES256, a P-256 key, a signature
/// that verifies over `bytes`, and a kid that names that key. Nothing is taken
/// on its word.
fn verify_answer(raw: &[u8], bytes: &[u8]) -> Result<KeyryxSignature, NotSigned> {
    let v: serde_json::Value =
        serde_json::from_slice(raw).map_err(|_| NotSigned::same("keyryx's answer is not JSON"))?;
    let field = |k: &str| v.get(k).and_then(|x| x.as_str()).unwrap_or_default();
    let alg = field("alg");
    if alg != "ES256" {
        return Err(NotSigned::same(format!(
            "keyryx signed with '{}', and a manifest is ES256; give {KEYRYX_KEY_ENV} an ES256 key",
            alg.chars()
                .filter(char::is_ascii_graphic)
                .take(32)
                .collect::<String>()
        )));
    }
    let kid = field("kid");
    if kid.is_empty() {
        return Err(NotSigned::same("keyryx's answer names no kid"));
    }
    let public = STANDARD
        .decode(field("public_key_b64"))
        .ok()
        .and_then(|pk| VerifyingKey::from_sec1_bytes(&pk).ok())
        .ok_or_else(|| NotSigned::same("keyryx's answer carries no P-256 public key"))?;
    let sig = STANDARD
        .decode(field("signature_b64"))
        .ok()
        .and_then(|s| Signature::from_slice(&s).ok())
        .ok_or_else(|| NotSigned::same("keyryx's answer carries no ES256 signature"))?;
    public.verify(bytes, &sig).map_err(|_| {
        NotSigned::same("keyryx's signature does not verify over this manifest's bytes")
    })?;
    // An auditor anchors the manifest's key by its kid in keyryx's published
    // set, so a kid naming another key points the anchor away from the key
    // that signed while the manifest still verifies. keyryx names an EC key by
    // its RFC 7638 thumbprint (`kidFor`, `internal/keystore/keystore.go`).
    let thumbprint = thumbprint(&public)?;
    if kid != thumbprint {
        let reason = "keyryx's kid is not the RFC 7638 thumbprint of the key that signed";
        return Err(NotSigned {
            reason: reason.to_string(),
            detail: format!(
                "{reason}: keyryx named '{}', the key's thumbprint is '{thumbprint}'",
                kid.chars()
                    .filter(char::is_ascii_graphic)
                    .take(64)
                    .collect::<String>()
            ),
        });
    }
    Ok(KeyryxSignature {
        kid: kid.to_string(),
        signature_b64: STANDARD.encode(sig.to_bytes()),
        public_key_b64: STANDARD.encode(public.to_sec1_point(false).as_bytes()),
    })
}

/// The RFC 7638 thumbprint of a P-256 key, by the one function this estate
/// names a key with ([`tokenfuse_dpop::thumbprint_of_json`]).
fn thumbprint(public: &VerifyingKey) -> Result<String, NotSigned> {
    let point = public.to_sec1_point(false);
    let (Some(x), Some(y)) = (point.x(), point.y()) else {
        return Err(NotSigned::same(
            "keyryx's answer carries no P-256 public key",
        ));
    };
    tokenfuse_dpop::thumbprint_of_json(&serde_json::json!({
        "kty": "EC",
        "crv": "P-256",
        "x": URL_SAFE_NO_PAD.encode(x),
        "y": URL_SAFE_NO_PAD.encode(y),
    }))
    .map_err(|_| NotSigned::same("keyryx's public key has no RFC 7638 thumbprint"))
}

#[cfg(test)]
mod tests;
