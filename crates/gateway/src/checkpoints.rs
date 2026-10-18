//! Signed checkpoints of this process's agent-event stream, agent-passport SPEC
//! 6.5.1 format v1 (CLAUDE.md invariant 128).
//!
//! `@decided 2026-10-18`: a producer signs checkpoints of its own stream, and a
//! witness checks them; the stream's bytes, its line count and its chain head
//! are bound under a key the producer holds and keyryx certifies, so that a
//! rewrite of anything a kept checkpoint covers is detectable afterwards.
//!
//! The record format, the running prefix and when a record is due live in
//! `tokenfuse_core::checkpoint`, beside the exporter that writes the stream.
//! This module holds what core may not (invariant 1): the ES256 key, generated
//! in memory and never written anywhere, and the keyryx client that has it
//! certified.
//!
//! # How the key is certified
//!
//! keyryx's delegate exchange, as `agent-stack-go/keyclient` speaks it: ask
//! `POST /v1/keys/{name}/challenge`; sign, with the key being certified,
//! `keyryx/delegate/v1 NUL name NUL consumer NUL kid NUL challenge`; send
//! `POST /v1/keys/{name}/delegate` with the public JWK, the challenge, that proof
//! and the life asked for. The answer is a key statement; its claims are read
//! back and refused unless they certify this key, for this name and this
//! consumer, for the life asked. The statement's root signatures are a
//! verifier's to check, not this client's, as in the Go client.
//!
//! A key is renewed at half its life, by a new key: a key id is certified once.
//! A record is signed by the key valid at its own `at` (the latest started one
//! when two are), from `not_before` up to and not including `not_after`, in whole
//! seconds as keyryx's `ValidAt` reads them. With none valid the record is
//! written unsigned (`unsigned_reason: key_expired`, format v1's one word), never
//! dropped, and the event path never waits on keyryx.
//!
//! Off unless `TOKENFUSE_CHECKPOINTS_DIR` is set. Set, everything it needs is
//! required, and a configuration that cannot be used refuses to start (exit 2).

use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use base64::Engine as _;
use p256::ecdsa::{signature::Signer as _, Signature, SigningKey};
use serde_json::{json, Value};
use tokenfuse_core::checkpoint::{
    CheckpointConfig, CheckpointKey, CheckpointSigner, CheckpointStats, Clock, NoKey,
};

use crate::events::EventExporter;

/// The checkpoints directory. Unset or blank, checkpoints are off.
pub const DIR_ENV: &str = "TOKENFUSE_CHECKPOINTS_DIR";
/// keyryx custody's origin, `http(s)://host[:port]`.
pub const KEYRYX_URL_ENV: &str = "TOKENFUSE_CHECKPOINT_KEYRYX_URL";
/// The consumer name keyryx's policy grants `delegate` on the key name to.
pub const CONSUMER_ENV: &str = "TOKENFUSE_CHECKPOINT_KEYRYX_CONSUMER";
/// A file holding this consumer's bearer credential for keyryx: its key, or a
/// Kubernetes projected service-account token. Read on every request, so a
/// rotated file is used at once.
pub const CREDENTIAL_FILE_ENV: &str = "TOKENFUSE_CHECKPOINT_KEYRYX_CREDENTIAL_FILE";
/// The delegated key name the checkpoint keys are certified under, the name a
/// witness binds this stream to (`KEYRYX_WITNESS_STREAM_KEYS`).
pub const KEY_NAME_ENV: &str = "TOKENFUSE_CHECKPOINT_KEY_NAME";
/// The life asked for each key, in seconds.
pub const LIFETIME_ENV: &str = "TOKENFUSE_CHECKPOINT_KEY_LIFETIME_SECS";

/// The life asked for when none is configured: a day, renewed every twelve hours.
pub const DEFAULT_LIFETIME_SECS: u64 = 86_400;
/// keyryx's floor for a statement's life (`policy.MinLifetime`).
pub const MIN_LIFETIME_SECS: u64 = 600;
/// keyryx's ceiling for any name's life (`policy.MaxLifetime`).
pub const MAX_LIFETIME_SECS: u64 = 604_800;

const REQUEST_TIMEOUT: Duration = Duration::from_secs(10);
/// A statement is at most 16 KiB; the answer wrapping it is bounded with room.
const MAX_RESPONSE: usize = 64 << 10;
/// How long startup waits for the first certification before going on unsigned.
const FIRST_CERTIFICATION_WITHIN: Duration = Duration::from_secs(10);
const RETRY_FIRST: Duration = Duration::from_secs(5);
const RETRY_MAX: Duration = Duration::from_secs(300);

/// What `TOKENFUSE_CHECKPOINT*` configures.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Config {
    pub dir: PathBuf,
    pub base_url: String,
    pub consumer: String,
    pub credential_file: PathBuf,
    pub key_name: String,
    pub lifetime_secs: u64,
}

/// keyryx's name grammar, for consumers and key names alike.
fn is_keyryx_name(s: &str) -> bool {
    let b = s.as_bytes();
    !b.is_empty()
        && b.len() <= 64
        && (b[0].is_ascii_lowercase() || b[0].is_ascii_digit())
        && b.iter().all(|c| {
            c.is_ascii_lowercase() || c.is_ascii_digit() || matches!(c, b'.' | b'_' | b'-')
        })
}

/// Read the configuration through `get`. `Ok(None)` is off; an `Err` names
/// every variable that is missing or unusable, and the caller refuses to start.
pub fn config_from(get: impl Fn(&str) -> Option<String>) -> Result<Option<Config>, String> {
    let read = |k: &str| {
        get(k)
            .map(|v| v.trim().to_string())
            .filter(|v| !v.is_empty())
    };
    let others = [
        KEYRYX_URL_ENV,
        CONSUMER_ENV,
        CREDENTIAL_FILE_ENV,
        KEY_NAME_ENV,
        LIFETIME_ENV,
    ];
    let Some(dir) = read(DIR_ENV) else {
        let set: Vec<&str> = others
            .iter()
            .copied()
            .filter(|k| read(k).is_some())
            .collect();
        if set.is_empty() {
            return Ok(None);
        }
        return Err(format!(
            "tokenfuse: refusing to start: {} set and {DIR_ENV} is not; checkpoints are on only \
             when {DIR_ENV} names their directory",
            set.join(", ")
        ));
    };
    let mut problems = vec![];
    if read(tokenfuse_core::agent_event::EVENTS_PATH_ENV).is_none() {
        problems.push(format!(
            "{} is not set, so there is no stream to checkpoint",
            tokenfuse_core::agent_event::EVENTS_PATH_ENV
        ));
    }
    let base_url = match read(KEYRYX_URL_ENV) {
        None => {
            problems.push(format!("{KEYRYX_URL_ENV} is not set"));
            String::new()
        }
        Some(u) => match reqwest::Url::parse(&u) {
            Ok(p)
                if matches!(p.scheme(), "http" | "https")
                    && p.host_str().is_some()
                    && matches!(p.path(), "" | "/")
                    && p.query().is_none()
                    && p.fragment().is_none()
                    && p.username().is_empty()
                    && p.password().is_none() =>
            {
                u.trim_end_matches('/').to_string()
            }
            _ => {
                problems.push(format!(
                    "{KEYRYX_URL_ENV} must be an http or https origin with no path, query or credentials"
                ));
                String::new()
            }
        },
    };
    let consumer = read(CONSUMER_ENV).unwrap_or_default();
    if !is_keyryx_name(&consumer) {
        problems.push(format!(
            "{CONSUMER_ENV} must be keyryx's consumer name (a lowercase letter or digit, then \
             lowercase letters, digits, '.', '_' or '-', at most 64)"
        ));
    }
    let key_name = read(KEY_NAME_ENV).unwrap_or_default();
    if !is_keyryx_name(&key_name) || key_name.starts_with("keyryx.") {
        problems.push(format!(
            "{KEY_NAME_ENV} must be a delegated key name in keyryx's grammar, outside its reserved keyryx. space"
        ));
    }
    let credential_file = read(CREDENTIAL_FILE_ENV);
    if credential_file.is_none() {
        problems.push(format!(
            "{CREDENTIAL_FILE_ENV} is not set; keyryx answers a consumer it can identify, and this \
             client never runs without a credential"
        ));
    }
    let lifetime_secs = match read(LIFETIME_ENV) {
        None => DEFAULT_LIFETIME_SECS,
        Some(v) => match v.parse::<u64>() {
            Ok(n) if (MIN_LIFETIME_SECS..=MAX_LIFETIME_SECS).contains(&n) => n,
            _ => {
                problems.push(format!(
                    "{LIFETIME_ENV}='{v}' is not a whole number of seconds from \
                     {MIN_LIFETIME_SECS} to {MAX_LIFETIME_SECS}, keyryx's range"
                ));
                0
            }
        },
    };
    if !problems.is_empty() {
        return Err(format!(
            "tokenfuse: refusing to start: {DIR_ENV} turns signed checkpoints on, and {}",
            problems.join("; ")
        ));
    }
    Ok(Some(Config {
        dir: PathBuf::from(dir),
        base_url,
        consumer,
        credential_file: PathBuf::from(credential_file.unwrap_or_default()),
        key_name,
        lifetime_secs,
    }))
}

// -- the key ---------------------------------------------------------------

/// A P-256 key held in memory only. Its private half is never written or logged.
pub struct HeldKey {
    kid: String,
    jwk: Value,
    sk: SigningKey,
}

impl std::fmt::Debug for HeldKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("HeldKey")
            .field("kid", &self.kid)
            .finish_non_exhaustive()
    }
}

impl HeldKey {
    /// A fresh key from the operating system's random source.
    pub fn generate() -> Result<Self, String> {
        for _ in 0..8 {
            let mut bytes = [0u8; 32];
            getrandom::getrandom(&mut bytes)
                .map_err(|e| format!("no randomness for a key: {e}"))?;
            // Rejected only for zero or a value past the group order, which is
            // about one draw in 2^32.
            if let Ok(sk) = SigningKey::from_slice(&bytes) {
                return Self::from_signing_key(sk);
            }
        }
        Err("eight random draws were not P-256 scalars".into())
    }

    /// The key for a fixed secret, for tests that need repeatable bytes.
    pub fn from_secret(secret: &[u8; 32]) -> Result<Self, String> {
        let sk = SigningKey::from_slice(secret).map_err(|e| format!("not a P-256 scalar: {e}"))?;
        Self::from_signing_key(sk)
    }

    fn from_signing_key(sk: SigningKey) -> Result<Self, String> {
        let point = sk.verifying_key().to_encoded_point(false);
        let (Some(x), Some(y)) = (point.x(), point.y()) else {
            return Err("the public key has no coordinates".into());
        };
        let b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD;
        let (x, y) = (b64.encode(x), b64.encode(y));
        let kid = tokenfuse_dpop::thumbprint_of_json(
            &json!({"kty": "EC", "crv": "P-256", "x": x, "y": y}),
        )
        .map_err(|e| format!("cannot take the key's thumbprint: {e:?}"))?;
        let jwk = json!({"kty": "EC", "crv": "P-256", "x": x, "y": y, "kid": kid, "alg": "ES256", "use": "sig"});
        Ok(HeldKey { kid, jwk, sk })
    }

    /// The public JWK, as keyryx certifies it.
    pub fn public_jwk(&self) -> &Value {
        &self.jwk
    }

    /// ES256 over SHA-256 of `msg`, r then s (RFC 6979, so repeatable).
    pub fn sign_raw(&self, msg: &[u8]) -> [u8; 64] {
        let sig: Signature = self.sk.sign(msg);
        let mut out = [0u8; 64];
        out.copy_from_slice(&sig.to_bytes());
        out
    }
}

impl CheckpointKey for HeldKey {
    fn kid(&self) -> &str {
        &self.kid
    }
    fn sign(&self, signing_input: &[u8]) -> Result<[u8; 64], String> {
        Ok(self.sign_raw(signing_input))
    }
}

/// One key keyryx certified, with its statement's window in Unix seconds.
#[derive(Clone)]
pub struct Certified {
    pub key: Arc<HeldKey>,
    pub statement: Value,
    pub not_before: i64,
    pub not_after: i64,
}

impl Certified {
    fn half_life(&self) -> i64 {
        self.not_before + (self.not_after - self.not_before) / 2
    }
}

/// The keys this process holds, and the one each record is signed with.
#[derive(Default)]
pub struct DelegatedSigner {
    keys: Mutex<Vec<Certified>>,
}

impl DelegatedSigner {
    pub fn new() -> Self {
        Self::default()
    }

    /// Keep a newly certified key, and drop those that ran out by `now_secs`.
    pub fn install(&self, c: Certified, now_secs: i64) {
        let mut keys = self.keys.lock().unwrap_or_else(|e| e.into_inner());
        keys.retain(|k| now_secs < k.not_after);
        keys.push(c);
    }

    fn newest(keys: &[Certified]) -> Option<&Certified> {
        keys.iter().max_by_key(|k| k.not_before)
    }

    /// A new key is due when none is held or the newest reached half its life.
    pub fn renewal_due(&self, now_secs: i64) -> bool {
        let keys = self.keys.lock().unwrap_or_else(|e| e.into_inner());
        Self::newest(&keys).is_none_or(|k| now_secs >= k.half_life())
    }

    /// When the next renewal is due, in Unix seconds.
    pub fn next_due(&self, now_secs: i64) -> i64 {
        let keys = self.keys.lock().unwrap_or_else(|e| e.into_inner());
        Self::newest(&keys).map_or(now_secs, Certified::half_life)
    }

    /// How many keys are held.
    pub fn held(&self) -> usize {
        self.keys.lock().unwrap_or_else(|e| e.into_inner()).len()
    }
}

impl CheckpointSigner for DelegatedSigner {
    fn key_at(&self, at_millis: i64) -> Result<Arc<dyn CheckpointKey>, NoKey> {
        // keyryx's ValidAt: t.Unix() >= not_before && t.Unix() < not_after.
        let at = at_millis.div_euclid(1000);
        let keys = self.keys.lock().unwrap_or_else(|e| e.into_inner());
        if keys.is_empty() {
            return Err(NoKey::NeverCertified);
        }
        let valid = keys
            .iter()
            .filter(|k| k.not_before <= at && at < k.not_after)
            .max_by_key(|k| k.not_before);
        match valid {
            Some(k) => Ok(Arc::clone(&k.key) as Arc<dyn CheckpointKey>),
            None if keys.iter().any(|k| k.not_before > at) => Err(NoKey::NotYetValid),
            None => Err(NoKey::Expired),
        }
    }
}

// -- keyryx ------------------------------------------------------------------

/// keyryx's proof input: a domain separator, then the name, the consumer, the
/// key's kid and the challenge, each ended by a NUL so no field can borrow from
/// its neighbour (keyryx `statement.ProofInput`).
pub fn proof_input(name: &str, consumer: &str, kid: &str, challenge: &str) -> Vec<u8> {
    format!("keyryx/delegate/v1\0{name}\0{consumer}\0{kid}\0{challenge}").into_bytes()
}

/// The consumer side of keyryx's delegate exchange.
pub struct Keyryx {
    base: String,
    consumer: String,
    credential_file: PathBuf,
    http: reqwest::Client,
}

impl Keyryx {
    pub fn new(cfg: &Config) -> Result<Self, String> {
        let http = reqwest::Client::builder()
            // A proxy would see the credential, and keyryx never redirects:
            // following one would send the credential where the redirect says.
            .no_proxy()
            .redirect(reqwest::redirect::Policy::none())
            .timeout(REQUEST_TIMEOUT)
            .build()
            .map_err(|e| format!("cannot build the keyryx client: {e}"))?;
        Ok(Keyryx {
            base: cfg.base_url.clone(),
            consumer: cfg.consumer.clone(),
            credential_file: cfg.credential_file.clone(),
            http,
        })
    }

    /// The credential as the file holds it now. A file that is empty or holds
    /// more than one word is refused, and the error never says what it held.
    fn bearer(&self) -> Result<String, String> {
        let raw = std::fs::read_to_string(&self.credential_file).map_err(|e| {
            format!(
                "cannot read {CREDENTIAL_FILE_ENV} '{}': {e}",
                self.credential_file.display()
            )
        })?;
        let tok = raw.trim();
        if tok.is_empty() || tok.contains(char::is_whitespace) {
            return Err(format!(
                "{CREDENTIAL_FILE_ENV} '{}' is empty or holds more than one word",
                self.credential_file.display()
            ));
        }
        Ok(tok.to_string())
    }

    async fn post(&self, route: &str, body: Option<&Value>) -> Result<Value, String> {
        let mut req = self
            .http
            .post(format!("{}{route}", self.base))
            .header("accept", "application/json")
            .bearer_auth(self.bearer()?);
        if let Some(b) = body {
            req = req
                .header("content-type", "application/json")
                .body(serde_json::to_vec(b).map_err(|e| e.to_string())?);
        }
        let mut resp = req
            .send()
            .await
            .map_err(|e| format!("keyryx {route}: {e}"))?;
        let status = resp.status();
        let mut raw = Vec::new();
        while let Some(chunk) = resp
            .chunk()
            .await
            .map_err(|e| format!("reading keyryx's answer to {route}: {e}"))?
        {
            if raw.len() + chunk.len() > MAX_RESPONSE {
                return Err(format!(
                    "keyryx's answer to {route} is over {MAX_RESPONSE} bytes"
                ));
            }
            raw.extend_from_slice(&chunk);
        }
        // A refusal's reason is keyryx's to log; only the status is carried.
        if status != reqwest::StatusCode::OK {
            return Err(format!(
                "keyryx refused {route} with status {}",
                status.as_u16()
            ));
        }
        serde_json::from_slice(&raw).map_err(|_| format!("keyryx's answer to {route} is not JSON"))
    }

    /// Generate a key, prove to keyryx that it is held, and check the statement
    /// keyryx answers. Nothing is kept unless every check passes.
    pub async fn certify(&self, name: &str, lifetime_secs: u64) -> Result<Certified, String> {
        self.certify_key(HeldKey::generate()?, name, lifetime_secs)
            .await
    }

    async fn certify_key(
        &self,
        key: HeldKey,
        name: &str,
        lifetime_secs: u64,
    ) -> Result<Certified, String> {
        let ch = self
            .post(&format!("/v1/keys/{name}/challenge"), None)
            .await?;
        let challenge = ch["challenge"].as_str().unwrap_or("");
        let fits = !challenge.is_empty()
            && challenge.len() <= 256
            && challenge
                .bytes()
                .all(|c| c.is_ascii_alphanumeric() || matches!(c, b'-' | b'_'));
        if !fits {
            return Err("keyryx answered the challenge request with no usable challenge".into());
        }
        let proof = key.sign_raw(&proof_input(name, &self.consumer, &key.kid, challenge));
        let body = json!({
            "jwk": key.public_jwk(),
            "challenge": challenge,
            "proof_b64": base64::engine::general_purpose::STANDARD.encode(proof),
            "lifetime_s": lifetime_secs,
        });
        let out = self
            .post(&format!("/v1/keys/{name}/delegate"), Some(&body))
            .await?;
        let (Some(not_before), Some(not_after)) =
            (out["not_before"].as_i64(), out["not_after"].as_i64())
        else {
            return Err("keyryx's delegate answer has no not_before or not_after".into());
        };
        if out["kid"].as_str() != Some(key.kid.as_str()) {
            return Err("keyryx certified a key id other than the one offered".into());
        }
        self.check_statement(
            &out["statement"],
            &key,
            name,
            not_before,
            not_after,
            lifetime_secs,
        )?;
        Ok(Certified {
            statement: out["statement"].clone(),
            key: Arc::new(key),
            not_before,
            not_after,
        })
    }

    /// Read the claims of the statement and refuse one that does not certify
    /// this key, this name and this consumer, for the life asked, at the times
    /// answered (the same checks agent-stack-go's keyclient makes).
    fn check_statement(
        &self,
        statement: &Value,
        key: &HeldKey,
        name: &str,
        not_before: i64,
        not_after: i64,
        lifetime_secs: u64,
    ) -> Result<(), String> {
        let payload = statement["payload"].as_str().unwrap_or("");
        let signed = statement["signatures"]
            .as_array()
            .is_some_and(|s| !s.is_empty());
        if payload.is_empty() || !signed {
            return Err("keyryx's statement is not of the known shape".into());
        }
        let raw = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(payload)
            .map_err(|_| "keyryx's statement payload is not base64url".to_string())?;
        let cl: Value = serde_json::from_slice(&raw)
            .map_err(|_| "keyryx's statement claims are not JSON".to_string())?;
        let jwk = key.public_jwk();
        let same_key = ["kty", "crv", "x", "y"]
            .iter()
            .all(|m| cl["jwk"][m] == jwk[m])
            && cl["jwk"]["alg"] == "ES256";
        if cl["v"] != 1 || cl["iss"] != "keyryx" {
            return Err("keyryx's statement is not a version 1 statement from keyryx".into());
        }
        if cl["name"] != name || cl["owner"] != self.consumer.as_str() {
            return Err("keyryx's statement certifies another name or consumer".into());
        }
        if cl["kid"] != key.kid.as_str() || cl["jwk"]["kid"] != key.kid.as_str() || !same_key {
            return Err("keyryx's statement certifies another key".into());
        }
        if cl["not_before"] != not_before || cl["not_after"] != not_after {
            return Err("keyryx's statement times are not the times it answered".into());
        }
        if not_after - not_before != lifetime_secs as i64 {
            return Err("keyryx's statement life is not the life asked for".into());
        }
        Ok(())
    }
}

// -- running ---------------------------------------------------------------------

/// What a process keeps of its checkpoints once they are on.
pub struct Running {
    events: Arc<EventExporter>,
    pub signer: Arc<DelegatedSigner>,
}

impl Running {
    /// Write the `close` record, on a clean close, and say so.
    pub fn close(&self) {
        match self.events.close_checkpoints() {
            Ok(Some(count)) => tracing::info!(count, "checkpoint close record written"),
            Ok(None) => tracing::info!("checkpoint close: the stream holds no event to name"),
            Err(e) => tracing::warn!("checkpoint close record could not be written: {e}"),
        }
    }
}

/// Read the configuration from the process environment and turn checkpoints
/// on, or refuse to start (exit 2). `None` when they are off.
pub async fn from_env(events: &Arc<EventExporter>) -> Option<Running> {
    let cfg = crate::defaults::exit_on_refusal(config_from(|k| std::env::var(k).ok()))?;
    let running = start(cfg, events, tokenfuse_core::checkpoint::system_clock()).await;
    crate::defaults::exit_on_refusal(
        running.map_err(|e| format!("tokenfuse: refusing to start: {e}")),
    )
}

/// Turn checkpoints on for `events`: the first certification is asked for
/// (bounded, so a keyryx that is down does not hold the start), the sidecar is
/// attached, and the renewal and tick tasks are started. An `Err` is a sidecar
/// that cannot be attached; `Ok(None)` is an export that is itself off.
pub async fn start(
    cfg: Config,
    events: &Arc<EventExporter>,
    clock: Clock,
) -> Result<Option<Running>, String> {
    if !events.is_enabled() {
        tracing::warn!(
            "{DIR_ENV} is set and the agent-event export is off (its path could not be opened), \
             so there is no stream to checkpoint; checkpoints are off"
        );
        return Ok(None);
    }
    let keyryx = Arc::new(Keyryx::new(&cfg)?);
    let signer = Arc::new(DelegatedSigner::new());
    let now = (clock)() / 1000;
    match tokio::time::timeout(
        FIRST_CERTIFICATION_WITHIN,
        keyryx.certify(&cfg.key_name, cfg.lifetime_secs),
    )
    .await
    {
        Ok(Ok(c)) => {
            log_certified(&c);
            signer.install(c, now);
        }
        Ok(Err(e)) => tracing::warn!(
            "checkpoint key not certified at start: {e}; records are written unsigned until it is"
        ),
        Err(_) => tracing::warn!(
            "checkpoint key not certified at start: keyryx did not answer within {}s; records \
             are written unsigned until it does",
            FIRST_CERTIFICATION_WITHIN.as_secs()
        ),
    }
    let opened = events.attach_checkpoints(CheckpointConfig {
        dir: cfg.dir.clone(),
        signer: Arc::clone(&signer) as Arc<dyn CheckpointSigner>,
        clock: Arc::clone(&clock),
    })?;
    tracing::info!(
        sidecar = %opened.sidecar.display(),
        stream_lines = opened.stream_lines,
        continued = opened.continued,
        resume = ?opened.resume,
        key_name = %cfg.key_name,
        "signed agent-event checkpoints ON (SPEC 6.5.1 v1): a record every 64 lines or 10 seconds, and on close"
    );
    if opened.cut_torn_bytes > 0 {
        tracing::warn!(
            bytes = opened.cut_torn_bytes,
            "a torn final record was cut from the checkpoint file"
        );
    }
    if opened.resume_unfound {
        tracing::warn!(
            "the stream's tail cannot be chained from and no well-formed event was found among \
             its last lines, so no resume record was written"
        );
    }
    spawn_renewal(
        keyryx,
        Arc::clone(&signer),
        cfg.key_name,
        cfg.lifetime_secs,
        clock,
    );
    spawn_tick(Arc::clone(events));
    Ok(Some(Running {
        events: Arc::clone(events),
        signer,
    }))
}

fn log_certified(c: &Certified) {
    tracing::info!(
        kid = %c.key.kid,
        not_before = c.not_before,
        not_after = c.not_after,
        "checkpoint key certified by keyryx"
    );
}

/// Renew at half life; after a failure, retry from 5 seconds, doubling to 5
/// minutes. Runs off the event path: signing reads the keys and never waits on it.
fn spawn_renewal(
    keyryx: Arc<Keyryx>,
    signer: Arc<DelegatedSigner>,
    name: String,
    lifetime: u64,
    clock: Clock,
) {
    tokio::spawn(async move {
        let mut backoff = RETRY_FIRST;
        loop {
            let now = (clock)() / 1000;
            if signer.renewal_due(now) {
                match keyryx.certify(&name, lifetime).await {
                    Ok(c) => {
                        log_certified(&c);
                        signer.install(c, (clock)() / 1000);
                        backoff = RETRY_FIRST;
                    }
                    Err(e) => {
                        tracing::warn!(
                            "checkpoint key renewal failed: {e}; retrying in {}s",
                            backoff.as_secs()
                        );
                        tokio::time::sleep(backoff).await;
                        backoff = (backoff * 2).min(RETRY_MAX);
                        continue;
                    }
                }
            }
            let now = (clock)() / 1000;
            let wait = (signer.next_due(now) - now).clamp(1, RETRY_MAX.as_secs() as i64);
            tokio::time::sleep(Duration::from_secs(wait as u64)).await;
        }
    });
}

/// About once a second: write a record when lines have waited 10 seconds, and
/// log when records start or stop being signed, or fail.
fn spawn_tick(events: Arc<EventExporter>) {
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(Duration::from_secs(1));
        let mut last = CheckpointStats::default();
        loop {
            interval.tick().await;
            events.checkpoint_tick();
            if let Some(now) = events.checkpoint_stats() {
                for line in transitions(&last, &now) {
                    match line {
                        Transition::Warn(m) => tracing::warn!("{m}"),
                        Transition::Info(m) => tracing::info!("{m}"),
                    }
                }
                last = now;
            }
        }
    });
}

/// A line to log about the checkpoints, at its level.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Transition {
    Warn(String),
    Info(String),
}

/// What changed between two readings of the counters that an operator should
/// hear about: the first unsigned record of a streak, the first signed one after
/// it, and a failure the first time it happens after a record was written. A
/// steady state says nothing.
pub fn transitions(prev: &CheckpointStats, now: &CheckpointStats) -> Vec<Transition> {
    let mut out = vec![];
    if now.unsigned > prev.unsigned && prev.last_signed != Some(false) {
        let why = now
            .last_unsigned_reason
            .map_or("no key is valid", NoKey::describe);
        out.push(Transition::Warn(format!(
            "checkpoint records are being written UNSIGNED (unsigned_reason key_expired): {why}; \
             a witness reports them as unsigned until a key keyryx certified is valid again"
        )));
    }
    if now.signed > prev.signed && prev.last_signed == Some(false) && now.last_signed == Some(true)
    {
        out.push(Transition::Info(
            "checkpoint records are signed again".into(),
        ));
    }
    let wrote = now.signed + now.unsigned > prev.signed + prev.unsigned;
    if now.errors > prev.errors && (wrote || prev.errors == 0 || prev.last_error != now.last_error)
    {
        out.push(Transition::Warn(format!(
            "a checkpoint record could not be written ({} so far): {}; the events themselves are on disk",
            now.errors,
            now.last_error.as_deref().unwrap_or("unknown")
        )));
    }
    out
}

#[cfg(test)]
mod tests;
