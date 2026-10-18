//! Tests for the checkpoint key and its certification (invariant 128).
//! Scenarios: `features/signed-checkpoints-of-the-event-stream.feature`.

use super::*;
use axum::{extract::State, http::HeaderMap, routing::post, Json, Router};
use p256::ecdsa::{signature::Verifier as _, VerifyingKey};
use sha2::{Digest, Sha256};
use std::collections::{HashMap, HashSet};
use std::sync::atomic::{AtomicI64, Ordering};
use tokenfuse_core::agent_event::{EventType, Exporter};
use tokenfuse_core::checkpoint::{encode, Encoded, Fields, Kind, GENESIS};

const T0_SECS: i64 = 1_792_314_000; // 2026-10-18T09:00:00Z

fn temp_dir(tag: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("tf-gw-ckpt-{}-{tag}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(dir.join("events")).unwrap();
    std::fs::create_dir_all(dir.join("checkpoints")).unwrap();
    dir
}

fn b64url() -> base64::engine::GeneralPurpose {
    base64::engine::general_purpose::URL_SAFE_NO_PAD
}

/// The public key a JWK names.
fn verifying_key(jwk: &Value) -> VerifyingKey {
    let x = b64url().decode(jwk["x"].as_str().unwrap()).unwrap();
    let y = b64url().decode(jwk["y"].as_str().unwrap()).unwrap();
    let mut sec1 = vec![4u8];
    sec1.extend(x);
    sec1.extend(y);
    VerifyingKey::from_sec1_bytes(&sec1).unwrap()
}

/// Verify a record's signature under `jwk`, over the JCS form of the record
/// with `sig` removed, written here from the SPEC rather than taken from the
/// encoder.
fn signature_verifies(record: &[u8], jwk: &Value) -> bool {
    let mut obj: serde_json::Map<String, Value> = serde_json::from_slice(record).unwrap();
    let Some(sig) = obj.remove("sig") else {
        return false;
    };
    let input = tokenfuse_core::jcs::canonicalize(&Value::Object(obj));
    let raw = b64url().decode(sig.as_str().unwrap()).unwrap();
    let Ok(sig) = Signature::from_slice(&raw) else {
        return false;
    };
    verifying_key(jwk).verify(input.as_bytes(), &sig).is_ok()
}

fn lines(bytes: &[u8]) -> Vec<&[u8]> {
    let mut out = vec![];
    let mut start = 0;
    for (i, b) in bytes.iter().enumerate() {
        if *b == b'\n' {
            out.push(&bytes[start..i]);
            start = i + 1;
        }
    }
    out
}

fn sha(bytes: &[u8]) -> String {
    format!("sha256:{}", hex(&Sha256::digest(bytes)))
}

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

/// Every record of `sidecar` against `stream`: prev chained, prefix the stream's
/// first N bytes, and, when signed, the signature under `jwk`. Returns
/// "valid", "unsigned" or the first refusal per record.
fn check(stream: &[u8], sidecar: &[u8], jwk: &Value) -> Vec<String> {
    let mut prev = GENESIS.to_string();
    let mut ends = vec![];
    for (i, b) in stream.iter().enumerate() {
        if *b == b'\n' {
            ends.push(i + 1);
        }
    }
    let mut out = vec![];
    for rec in lines(sidecar) {
        let v: Value = serde_json::from_slice(rec).unwrap();
        let count = v["count"].as_u64().unwrap() as usize;
        let verdict = if v["prev"] != prev.as_str() {
            "prev".into()
        } else if count == 0 || count > ends.len() {
            "truncated".into()
        } else if v["prefix"] != sha(&stream[..ends[count - 1]]).as_str() {
            "prefix".into()
        } else if v.get("unsigned_reason").is_some() {
            "unsigned".into()
        } else if v["kid"] != jwk["kid"] || !signature_verifies(rec, jwk) {
            "signature".into()
        } else {
            "valid".to_string()
        };
        out.push(verdict);
        prev = sha(rec);
    }
    out
}

// -- configuration ------------------------------------------------------------

fn full_env() -> HashMap<&'static str, String> {
    HashMap::from([
        (DIR_ENV, "/var/lib/checkpoints".to_string()),
        (
            "TOKENFUSE_EVENTS_PATH",
            "/var/lib/events/tokenfuse.ndjson".to_string(),
        ),
        (KEYRYX_URL_ENV, "http://keyryx:4340".to_string()),
        (CONSUMER_ENV, "tokenfuse".to_string()),
        (CREDENTIAL_FILE_ENV, "/run/secrets/keyryx".to_string()),
        (KEY_NAME_ENV, "tokenfuse-stream".to_string()),
    ])
}

fn cfg_with(env: &HashMap<&'static str, String>) -> Result<Option<Config>, String> {
    config_from(|k| env.get(k).cloned())
}

#[test]
fn nothing_configured_is_off() {
    assert_eq!(config_from(|_| None), Ok(None));
    assert_eq!(
        config_from(|_| Some("  ".into())),
        Ok(None),
        "blank is unset"
    );
}

#[test]
fn a_full_configuration_is_read() {
    let cfg = cfg_with(&full_env()).unwrap().unwrap();
    assert_eq!(cfg.dir, PathBuf::from("/var/lib/checkpoints"));
    assert_eq!(cfg.base_url, "http://keyryx:4340");
    assert_eq!(cfg.consumer, "tokenfuse");
    assert_eq!(cfg.key_name, "tokenfuse-stream");
    assert_eq!(cfg.lifetime_secs, DEFAULT_LIFETIME_SECS);
}

#[test]
fn a_keyryx_setting_without_the_directory_refuses_to_start() {
    let env = HashMap::from([(KEYRYX_URL_ENV, "http://keyryx:4340".to_string())]);
    let err = cfg_with(&env).unwrap_err();
    assert!(
        err.contains(KEYRYX_URL_ENV) && err.contains(DIR_ENV),
        "{err}"
    );
}

#[test]
fn a_directory_with_anything_missing_refuses_to_start_naming_each() {
    for missing in [
        "TOKENFUSE_EVENTS_PATH",
        KEYRYX_URL_ENV,
        CONSUMER_ENV,
        CREDENTIAL_FILE_ENV,
        KEY_NAME_ENV,
    ] {
        let mut env = full_env();
        env.remove(missing);
        let err = cfg_with(&env).unwrap_err();
        assert!(err.contains(missing), "{missing}: {err}");
        assert!(err.contains("refusing to start"), "{err}");
    }
}

#[test]
fn an_unusable_value_refuses_to_start() {
    for (k, v) in [
        (KEYRYX_URL_ENV, "keyryx:4340"),
        (KEYRYX_URL_ENV, "ftp://keyryx"),
        (KEYRYX_URL_ENV, "http://keyryx:4340/v1"),
        (KEYRYX_URL_ENV, "http://user:pw@keyryx:4340"),
        (KEYRYX_URL_ENV, "http://keyryx:4340/?q=1"),
        (CONSUMER_ENV, "Tokenfuse"),
        (CONSUMER_ENV, "token fuse"),
        (KEY_NAME_ENV, "keyryx.delegation-root"),
        (KEY_NAME_ENV, &"a".repeat(65)),
        (LIFETIME_ENV, "599"),
        (LIFETIME_ENV, "604801"),
        (LIFETIME_ENV, "a day"),
    ] {
        let mut env = full_env();
        env.insert(k, v.to_string());
        let err = cfg_with(&env).unwrap_err();
        assert!(err.contains(k), "{k}={v}: {err}");
    }
    for ok in ["600", "604800"] {
        let mut env = full_env();
        env.insert(LIFETIME_ENV, ok.into());
        assert!(cfg_with(&env).unwrap().is_some(), "{ok}");
    }
}

// -- the key and the signer -----------------------------------------------------

fn certified(nb: i64, na: i64, seed: u8) -> Certified {
    Certified {
        key: Arc::new(HeldKey::from_secret(&[seed; 32]).unwrap()),
        statement: Value::Null,
        not_before: nb,
        not_after: na,
    }
}

#[test]
fn the_kid_is_the_rfc_7638_thumbprint_of_the_public_key() {
    let k = HeldKey::from_secret(&[7; 32]).unwrap();
    let jwk = k.public_jwk();
    let canonical = format!(
        r#"{{"crv":"P-256","kty":"EC","x":"{}","y":"{}"}}"#,
        jwk["x"].as_str().unwrap(),
        jwk["y"].as_str().unwrap()
    );
    assert_eq!(k.kid, b64url().encode(Sha256::digest(canonical.as_bytes())));
    assert_eq!(jwk["kid"], k.kid.as_str());
    assert!(
        jwk.get("d").is_none(),
        "the public JWK carries no private member"
    );
}

#[test]
fn a_signer_with_no_key_says_it_was_never_certified() {
    let s = DelegatedSigner::new();
    assert!(matches!(
        s.key_at(T0_SECS * 1000),
        Err(NoKey::NeverCertified)
    ));
}

#[test]
fn a_key_signs_only_inside_its_statement_window_in_whole_seconds() {
    let s = DelegatedSigner::new();
    s.install(certified(T0_SECS, T0_SECS + 600, 1), T0_SECS);
    assert!(matches!(
        s.key_at(T0_SECS * 1000 - 1),
        Err(NoKey::NotYetValid)
    ));
    assert!(s.key_at(T0_SECS * 1000).is_ok(), "from not_before");
    assert!(
        s.key_at((T0_SECS + 600) * 1000 - 1).is_ok(),
        "the last millisecond of the last second"
    );
    assert!(
        matches!(s.key_at((T0_SECS + 600) * 1000), Err(NoKey::Expired)),
        "not_after itself is outside, as keyryx's ValidAt reads it"
    );
}

#[test]
fn a_key_past_its_statement_is_never_used_and_the_record_is_unsigned() {
    let s = DelegatedSigner::new();
    s.install(certified(T0_SECS - 3600, T0_SECS, 1), T0_SECS - 10);
    let fields = Fields {
        kind: Kind::Checkpoint,
        stream: "tokenfuse.ndjson".into(),
        count: 1,
        head: GENESIS.into(),
        prefix: GENESIS.into(),
        at_millis: T0_SECS * 1000 + 5,
        prev: GENESIS.into(),
    };
    let e = encode(&fields, &s).unwrap();
    assert!(!e.is_signed());
    let rec: Value = serde_json::from_slice(e.record()).unwrap();
    assert_eq!(rec["unsigned_reason"], "key_expired");
    assert!(rec.get("sig").is_none() && rec.get("kid").is_none());
}

#[test]
fn of_two_valid_keys_the_one_that_started_last_signs() {
    let s = DelegatedSigner::new();
    let old = certified(T0_SECS - 100, T0_SECS + 500, 1);
    let new = certified(T0_SECS - 10, T0_SECS + 900, 2);
    let new_kid = new.key.kid.clone();
    s.install(old, T0_SECS - 100);
    s.install(new, T0_SECS - 10);
    assert_eq!(s.key_at(T0_SECS * 1000).unwrap().kid(), new_kid);
}

#[test]
fn a_key_is_renewed_at_half_its_life_and_run_out_keys_are_dropped() {
    let s = DelegatedSigner::new();
    assert!(s.renewal_due(T0_SECS), "none held: due at once");
    s.install(certified(T0_SECS, T0_SECS + 1000, 1), T0_SECS);
    assert!(!s.renewal_due(T0_SECS + 499));
    assert!(s.renewal_due(T0_SECS + 500));
    assert_eq!(s.next_due(T0_SECS), T0_SECS + 500);
    s.install(certified(T0_SECS + 500, T0_SECS + 1500, 2), T0_SECS + 1000);
    assert_eq!(
        s.held(),
        1,
        "the first key ran out at T0+1000 and is dropped"
    );
}

#[test]
fn a_record_signed_by_a_held_key_verifies_under_its_jwk() {
    let s = DelegatedSigner::new();
    s.install(certified(T0_SECS, T0_SECS + 600, 3), T0_SECS);
    let fields = Fields {
        kind: Kind::Close,
        stream: "tokenfuse.ndjson".into(),
        count: 7,
        head: GENESIS.into(),
        prefix: GENESIS.into(),
        at_millis: T0_SECS * 1000 + 1,
        prev: GENESIS.into(),
    };
    let e = encode(&fields, &s).unwrap();
    let jwk = HeldKey::from_secret(&[3; 32]).unwrap().public_jwk().clone();
    assert!(signature_verifies(e.record(), &jwk));
    let Encoded::Signed { signing_input, .. } = &e else {
        panic!("signed")
    };
    let mut obj: serde_json::Map<String, Value> = serde_json::from_slice(e.record()).unwrap();
    obj.remove("sig");
    assert_eq!(
        signing_input,
        tokenfuse_core::jcs::canonicalize(&Value::Object(obj)).as_bytes()
    );
}

/// The vectors' own signatures verify under the vectors' key here: the r||s
/// form this crate reads is the one agent-passport writes.
#[test]
fn the_vector_signatures_verify_under_the_vector_key() {
    let v: Value = serde_json::from_str(include_str!(
        "../../../core/testdata/checkpoint-vectors.json"
    ))
    .unwrap();
    let mut verified = 0;
    for c in v["checkpoints"].as_array().unwrap() {
        if c.get("signing_input").is_none() {
            continue;
        }
        assert!(signature_verifies(
            c["record"].as_str().unwrap().as_bytes(),
            &v["key"]
        ));
        verified += 1;
    }
    assert_eq!(verified, 3);
}

// -- a stub keyryx -----------------------------------------------------------------

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Mode {
    Honest,
    OtherKid,
    OtherOwner,
    OtherLife,
    TimesDiffer,
    Refuse401,
    Redirect,
}

struct StubState {
    bearer: String,
    consumer: String,
    now: i64,
    mode: Mutex<Mode>,
    challenges: Mutex<HashSet<String>>,
    hits: Mutex<Vec<String>>,
    certified: Mutex<Vec<Value>>,
    redirect_to: Mutex<String>,
}

struct Stub {
    url: String,
    state: Arc<StubState>,
}

async fn stub_challenge(
    State(st): State<Arc<StubState>>,
    axum::extract::Path(name): axum::extract::Path<String>,
    headers: HeaderMap,
) -> axum::response::Response {
    use axum::response::IntoResponse;
    st.hits.lock().unwrap().push(format!("challenge {name}"));
    let mode = *st.mode.lock().unwrap();
    if mode == Mode::Redirect {
        let to = st.redirect_to.lock().unwrap().clone();
        return (axum::http::StatusCode::FOUND, [("location", to)]).into_response();
    }
    if mode == Mode::Refuse401
        || headers.get("authorization").and_then(|v| v.to_str().ok())
            != Some(&format!("Bearer {}", st.bearer))
    {
        return axum::http::StatusCode::UNAUTHORIZED.into_response();
    }
    let c = format!("challenge{}", st.challenges.lock().unwrap().len()).repeat(3);
    st.challenges.lock().unwrap().insert(c.clone());
    Json(json!({"challenge": c, "expires_at": st.now + 60})).into_response()
}

async fn stub_delegate(
    State(st): State<Arc<StubState>>,
    axum::extract::Path(name): axum::extract::Path<String>,
    headers: HeaderMap,
    Json(body): Json<Value>,
) -> axum::response::Response {
    use axum::response::IntoResponse;
    st.hits.lock().unwrap().push(format!("delegate {name}"));
    if headers.get("authorization").and_then(|v| v.to_str().ok())
        != Some(&format!("Bearer {}", st.bearer))
    {
        return axum::http::StatusCode::UNAUTHORIZED.into_response();
    }
    let challenge = body["challenge"].as_str().unwrap_or("").to_string();
    if !st.challenges.lock().unwrap().remove(&challenge) {
        return axum::http::StatusCode::FORBIDDEN.into_response();
    }
    let jwk = &body["jwk"];
    if jwk.get("d").is_some() {
        return axum::http::StatusCode::BAD_REQUEST.into_response();
    }
    let kid = tokenfuse_dpop::thumbprint_of_json(
        &json!({"kty": "EC", "crv": "P-256", "x": jwk["x"], "y": jwk["y"]}),
    )
    .unwrap();
    if jwk["kid"] != kid.as_str() {
        return axum::http::StatusCode::BAD_REQUEST.into_response();
    }
    // keyryx: proof_b64 is standard base64 with padding, R||S over SHA-256.
    let Ok(proof) =
        base64::engine::general_purpose::STANDARD.decode(body["proof_b64"].as_str().unwrap_or(""))
    else {
        return axum::http::StatusCode::BAD_REQUEST.into_response();
    };
    let Ok(sig) = Signature::from_slice(&proof) else {
        return axum::http::StatusCode::BAD_REQUEST.into_response();
    };
    if verifying_key(jwk)
        .verify(&proof_input(&name, &st.consumer, &kid, &challenge), &sig)
        .is_err()
    {
        return axum::http::StatusCode::FORBIDDEN.into_response();
    }
    let life = body["lifetime_s"].as_i64().unwrap_or(0);
    let mode = *st.mode.lock().unwrap();
    let (nb, na) = (st.now, st.now + life);
    let mut claims = json!({
        "v": 1, "iss": "keyryx", "name": name, "owner": st.consumer, "kid": kid,
        "jwk": {"kty": "EC", "crv": "P-256", "x": jwk["x"], "y": jwk["y"], "kid": kid, "alg": "ES256", "use": "sig"},
        "not_before": nb, "not_after": na, "issued_at": st.now, "jti": "jti-0123456789abcdef",
        "roots": {"ES384": "r1", "ML-DSA-65": "r2"}
    });
    match mode {
        Mode::OtherKid => claims["kid"] = json!("another-kid"),
        Mode::OtherOwner => claims["owner"] = json!("someone-else"),
        Mode::OtherLife => claims["not_after"] = json!(na + 1),
        _ => {}
    }
    st.certified.lock().unwrap().push(claims["jwk"].clone());
    let statement = json!({
        "payload": b64url().encode(serde_json::to_vec(&claims).unwrap()),
        "signatures": [{"protected": "e30", "signature": "AA"}]
    });
    let (anb, ana) = if mode == Mode::TimesDiffer {
        (nb, na + 5)
    } else {
        (nb, if mode == Mode::OtherLife { na + 1 } else { na })
    };
    Json(json!({"statement": statement, "kid": kid, "not_before": anb, "not_after": ana}))
        .into_response()
}

async fn stub(now: i64) -> Stub {
    let state = Arc::new(StubState {
        bearer: "consumer-key-0123".into(),
        consumer: "tokenfuse".into(),
        now,
        mode: Mutex::new(Mode::Honest),
        challenges: Mutex::new(HashSet::new()),
        hits: Mutex::new(vec![]),
        certified: Mutex::new(vec![]),
        redirect_to: Mutex::new(String::new()),
    });
    let app = Router::new()
        .route("/v1/keys/{name}/challenge", post(stub_challenge))
        .route("/v1/keys/{name}/delegate", post(stub_delegate))
        .with_state(Arc::clone(&state));
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("http://{}", listener.local_addr().unwrap());
    tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });
    Stub { url, state }
}

fn cfg_for(stub_url: &str, dir: &std::path::Path, credential: &str) -> Config {
    let cred = dir.join("credential");
    std::fs::write(&cred, credential).unwrap();
    Config {
        dir: dir.join("checkpoints"),
        base_url: stub_url.to_string(),
        consumer: "tokenfuse".into(),
        credential_file: cred,
        key_name: "tokenfuse-stream".into(),
        lifetime_secs: 3600,
    }
}

#[tokio::test]
async fn a_key_is_certified_by_proving_possession_to_keyryx() {
    let s = stub(T0_SECS).await;
    let dir = temp_dir("certify");
    let k = Keyryx::new(&cfg_for(&s.url, &dir, "consumer-key-0123\n")).unwrap();
    let c = k.certify("tokenfuse-stream", 3600).await.unwrap();
    assert_eq!((c.not_before, c.not_after), (T0_SECS, T0_SECS + 3600));
    assert_eq!(
        *s.state.hits.lock().unwrap(),
        vec!["challenge tokenfuse-stream", "delegate tokenfuse-stream"]
    );
    assert_eq!(
        s.state.certified.lock().unwrap()[0]["kid"],
        c.key.kid.as_str()
    );
}

#[tokio::test]
async fn a_statement_that_does_not_certify_this_key_is_refused() {
    for (mode, why) in [
        (Mode::OtherKid, "another key"),
        (Mode::OtherOwner, "another name or consumer"),
        (Mode::OtherLife, "life"),
        (Mode::TimesDiffer, "times"),
    ] {
        let s = stub(T0_SECS).await;
        *s.state.mode.lock().unwrap() = mode;
        let dir = temp_dir(&format!("refuse-{mode:?}"));
        let k = Keyryx::new(&cfg_for(&s.url, &dir, "consumer-key-0123")).unwrap();
        let err = k.certify("tokenfuse-stream", 3600).await.err().unwrap();
        assert!(err.contains(why), "{mode:?}: {err}");
    }
}

#[tokio::test]
async fn a_refusal_carries_its_status_and_never_the_credential() {
    let s = stub(T0_SECS).await;
    *s.state.mode.lock().unwrap() = Mode::Refuse401;
    let dir = temp_dir("refused");
    let k = Keyryx::new(&cfg_for(&s.url, &dir, "consumer-key-0123")).unwrap();
    let err = k.certify("tokenfuse-stream", 3600).await.err().unwrap();
    assert!(err.contains("401"), "{err}");
    assert!(!err.contains("consumer-key-0123"), "{err}");
}

#[tokio::test]
async fn a_credential_file_that_is_missing_or_holds_two_words_sends_nothing() {
    let s = stub(T0_SECS).await;
    let dir = temp_dir("bad-credential");
    let mut cfg = cfg_for(&s.url, &dir, "two words");
    let err = Keyryx::new(&cfg)
        .unwrap()
        .certify("n", 3600)
        .await
        .err()
        .unwrap();
    assert!(
        err.contains("more than one word") && !err.contains("two words"),
        "{err}"
    );
    cfg.credential_file = dir.join("absent");
    let err = Keyryx::new(&cfg)
        .unwrap()
        .certify("n", 3600)
        .await
        .err()
        .unwrap();
    assert!(err.contains(CREDENTIAL_FILE_ENV), "{err}");
    assert!(
        s.state.hits.lock().unwrap().is_empty(),
        "no request without a credential"
    );
}

#[tokio::test]
async fn a_redirect_from_keyryx_is_not_followed() {
    let s = stub(T0_SECS).await;
    let elsewhere = stub(T0_SECS).await;
    *s.state.mode.lock().unwrap() = Mode::Redirect;
    *s.state.redirect_to.lock().unwrap() = format!("{}/v1/keys/n/challenge", elsewhere.url);
    let dir = temp_dir("redirect");
    let err = Keyryx::new(&cfg_for(&s.url, &dir, "consumer-key-0123"))
        .unwrap()
        .certify("n", 3600)
        .await
        .err()
        .unwrap();
    assert!(err.contains("302"), "{err}");
    assert!(
        elsewhere.state.hits.lock().unwrap().is_empty(),
        "the credential stayed home"
    );
}

// -- the stream, end to end --------------------------------------------------------

struct E2e {
    dir: PathBuf,
    events: Arc<EventExporter>,
    clock: Arc<AtomicI64>,
    running: Running,
}

impl E2e {
    fn emit(&self, n: usize) {
        for i in 0..n {
            self.events.emit(
                EventType::BreakerTripped,
                T0_SECS * 1000 + i as i64,
                Some("agent://acme.example/support/bot"),
                Some("run-1"),
                None,
                json!({"i": i}),
            );
        }
    }
    fn stream(&self) -> Vec<u8> {
        std::fs::read(self.dir.join("events/tokenfuse.ndjson")).unwrap()
    }
    fn sidecar(&self) -> Vec<u8> {
        std::fs::read(self.dir.join("checkpoints/tokenfuse.ndjson.ckpt.ndjson")).unwrap_or_default()
    }
}

async fn e2e(tag: &str, keyryx_url: &str) -> E2e {
    let dir = temp_dir(tag);
    let path = dir.join("events/tokenfuse.ndjson");
    let events = Arc::new(Exporter::open(path.to_str().unwrap()).unwrap());
    let clock = Arc::new(AtomicI64::new(T0_SECS * 1000 + 1000));
    let c = Arc::clone(&clock);
    let running = start(
        cfg_for(keyryx_url, &dir, "consumer-key-0123"),
        &events,
        Arc::new(move || c.load(Ordering::SeqCst)),
    )
    .await
    .unwrap()
    .unwrap();
    E2e {
        dir,
        events,
        clock,
        running,
    }
}

#[tokio::test]
async fn the_stream_gets_signed_records_that_verify_under_the_certified_key() {
    let s = stub(T0_SECS).await;
    let h = e2e("e2e-signed", &s.url).await;
    h.emit(70);
    h.running.close();
    let jwk = s.state.certified.lock().unwrap()[0].clone();
    let side = h.sidecar();
    assert_eq!(check(&h.stream(), &side, &jwk), vec!["valid", "valid"]);
    let recs: Vec<Value> = lines(&side)
        .iter()
        .map(|l| serde_json::from_slice(l).unwrap())
        .collect();
    assert_eq!(
        (recs[0]["kind"].as_str(), recs[0]["count"].as_u64()),
        (Some("checkpoint"), Some(64))
    );
    assert_eq!(
        (recs[1]["kind"].as_str(), recs[1]["count"].as_u64()),
        (Some("close"), Some(70))
    );
}

#[tokio::test]
async fn a_keyryx_that_is_down_at_start_gives_unsigned_records_until_a_key_is_certified() {
    let s = stub(T0_SECS).await;
    // Nothing listens on a port that was just freed.
    let dead = {
        let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        format!("http://{}", l.local_addr().unwrap())
    };
    let h = e2e("e2e-down", &dead).await;
    h.emit(64);
    let side = h.sidecar();
    assert_eq!(
        check(&h.stream(), &side, &Value::Null),
        vec!["unsigned"],
        "never dropped"
    );
    let before = h.events.checkpoint_stats().unwrap();
    // keyryx comes back and the renewal certifies a key.
    let cfg = cfg_for(&s.url, &h.dir, "consumer-key-0123");
    let c = Keyryx::new(&cfg)
        .unwrap()
        .certify(&cfg.key_name, 3600)
        .await
        .unwrap();
    h.running.signer.install(c, T0_SECS + 1);
    h.emit(64);
    let jwk = s.state.certified.lock().unwrap()[0].clone();
    assert_eq!(
        check(&h.stream(), &h.sidecar(), &jwk),
        vec!["unsigned", "valid"]
    );
    let after = h.events.checkpoint_stats().unwrap();
    assert_eq!(
        transitions(&CheckpointStats::default(), &before)
            .iter()
            .filter(|t| matches!(t, Transition::Warn(m) if m.contains("UNSIGNED")))
            .count(),
        1
    );
    assert_eq!(
        transitions(&before, &after),
        vec![Transition::Info(
            "checkpoint records are signed again".into()
        )]
    );
}

#[tokio::test]
async fn a_key_that_runs_out_mid_stream_gives_unsigned_records_not_stale_signatures() {
    let s = stub(T0_SECS).await;
    let h = e2e("e2e-expiry", &s.url).await;
    h.emit(64);
    h.clock.store((T0_SECS + 3600) * 1000, Ordering::SeqCst);
    h.emit(64);
    let jwk = s.state.certified.lock().unwrap()[0].clone();
    assert_eq!(
        check(&h.stream(), &h.sidecar(), &jwk),
        vec!["valid", "unsigned"]
    );
    let stats = h.events.checkpoint_stats().unwrap();
    assert_eq!(stats.last_unsigned_reason, Some(NoKey::Expired));
}

#[test]
fn transitions_say_each_change_once_and_a_steady_state_nothing() {
    let unsigned = CheckpointStats {
        unsigned: 1,
        last_signed: Some(false),
        last_unsigned_reason: Some(NoKey::NeverCertified),
        ..Default::default()
    };
    let t = transitions(&CheckpointStats::default(), &unsigned);
    assert_eq!(t.len(), 1);
    assert!(matches!(&t[0], Transition::Warn(m) if m.contains("no key has been certified")));
    let more = CheckpointStats {
        unsigned: 5,
        ..unsigned.clone()
    };
    assert!(
        transitions(&unsigned, &more).is_empty(),
        "the same streak is not said twice"
    );
    let failing = CheckpointStats {
        errors: 1,
        last_error: Some("disk full".into()),
        ..more.clone()
    };
    let t = transitions(&more, &failing);
    assert!(matches!(&t[..], [Transition::Warn(m)] if m.contains("disk full")));
    let still = CheckpointStats {
        errors: 9,
        ..failing.clone()
    };
    assert!(
        transitions(&failing, &still).is_empty(),
        "one failure, said once"
    );
}

// -- the fixture the Go verifiers were run against -----------------------------------

const FIXTURE_DIR: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/testdata/checkpoints");

/// The fixture's stream and sidecar, written by this writer with a fixed key and
/// a fixed clock: a stream left ending in a malformed line (a `resume`), a
/// `checkpoint` at 64 lines, the key running out (an unsigned `checkpoint`), and
/// an unsigned `close`. ECDSA here is RFC 6979, so the bytes repeat.
fn write_fixture(dir: &std::path::Path) -> (Vec<u8>, Vec<u8>, Value) {
    std::fs::create_dir_all(dir.join("events")).unwrap();
    std::fs::create_dir_all(dir.join("checkpoints")).unwrap();
    let path = dir.join("events/tokenfuse.ndjson");
    let mut existing = Vec::new();
    for i in 0..2 {
        existing.extend_from_slice(
            format!(
                "{{\"agent_id\":\"agent://acme.example/support/bot\",\"data\":{{\"i\":{i}}},\"run_id\":\"run-0\",\"schema\":\"taipanbox.dev/agent-event/v0.2\",\"severity\":\"medium\",\"source\":\"tokenfuse\",\"ts\":\"2026-10-18T08:59:59.000Z\",\"type\":\"breaker_tripped\"}}\n"
            )
            .as_bytes(),
        );
    }
    existing.extend_from_slice(b"{\"a crash left this\n");
    std::fs::write(&path, &existing).unwrap();
    let _ = std::fs::remove_file(dir.join("checkpoints/tokenfuse.ndjson.ckpt.ndjson"));
    let exporter = Exporter::open(path.to_str().unwrap()).unwrap();
    let key = HeldKey::from_secret(&[0x42; 32]).unwrap();
    let jwk = key.public_jwk().clone();
    let signer = Arc::new(DelegatedSigner::new());
    signer.install(
        Certified {
            key: Arc::new(key),
            statement: Value::Null,
            not_before: T0_SECS,
            not_after: T0_SECS + 600,
        },
        T0_SECS,
    );
    let clock = Arc::new(AtomicI64::new(T0_SECS * 1000 + 1_000));
    let c = Arc::clone(&clock);
    exporter
        .attach_checkpoints(tokenfuse_core::checkpoint::CheckpointConfig {
            dir: dir.join("checkpoints"),
            signer,
            clock: Arc::new(move || c.load(Ordering::SeqCst)),
        })
        .unwrap();
    let emit = |n: usize, base: i64| {
        for i in 0..n {
            exporter.emit(
                EventType::BreakerTripped,
                base + i as i64,
                Some("agent://acme.example/support/bot"),
                Some("run-1"),
                None,
                json!({"i": i}),
            );
        }
    };
    clock.store(T0_SECS * 1000 + 2_000, Ordering::SeqCst);
    emit(64, T0_SECS * 1000 + 2_000);
    clock.store(T0_SECS * 1000 + 5_000, Ordering::SeqCst);
    emit(3, T0_SECS * 1000 + 5_000);
    // The key's statement ran out at T0+600; the three lines waiting are
    // checkpointed then, unsigned.
    clock.store((T0_SECS + 600) * 1000, Ordering::SeqCst);
    exporter.checkpoint_tick();
    clock.store((T0_SECS + 700) * 1000, Ordering::SeqCst);
    exporter.close_checkpoints().unwrap();
    (
        std::fs::read(&path).unwrap(),
        std::fs::read(dir.join("checkpoints/tokenfuse.ndjson.ckpt.ndjson")).unwrap(),
        jwk,
    )
}

#[test]
fn the_committed_fixture_is_what_the_writer_writes_byte_for_byte() {
    let (stream, sidecar, jwk) = write_fixture(&temp_dir("fixture"));
    let fixture = std::path::Path::new(FIXTURE_DIR);
    assert_eq!(
        std::fs::read(fixture.join("events/tokenfuse.ndjson")).unwrap(),
        stream,
        "the stream"
    );
    assert_eq!(
        String::from_utf8(
            std::fs::read(fixture.join("checkpoints/tokenfuse.ndjson.ckpt.ndjson")).unwrap()
        )
        .unwrap(),
        String::from_utf8(sidecar.clone()).unwrap(),
        "the sidecar"
    );
    let committed: Value =
        serde_json::from_slice(&std::fs::read(fixture.join("key.json")).unwrap()).unwrap();
    assert_eq!(committed["jwk"], jwk);
    assert_eq!(
        check(&stream, &sidecar, &jwk),
        vec!["valid", "valid", "unsigned", "unsigned"],
        "resume and checkpoint signed; the key ran out at T0+600"
    );
}

/// Rewrites the committed fixture: `cargo test -p tokenfuse-gateway --lib
/// checkpoints::tests::write_the_fixture -- --ignored`.
#[test]
#[ignore = "writes testdata/checkpoints; run by hand after a deliberate change"]
fn write_the_fixture() {
    let dir = std::path::Path::new(FIXTURE_DIR);
    let _ = std::fs::remove_dir_all(dir);
    let (_, _, jwk) = write_fixture(dir);
    std::fs::write(
        dir.join("key.json"),
        serde_json::to_vec_pretty(&json!({
            "description": "The public key of the fixture's checkpoint records, certified (in the fixture's own terms) from 2026-10-18T09:00:00Z for 600 seconds. Its private scalar is 32 bytes of 0x42, a test value: never use it.",
            "not_before": T0_SECS,
            "not_after": T0_SECS + 600,
            "jwk": jwk
        }))
        .unwrap(),
    )
    .unwrap();
}

// -- hostile streams, signed with a real key -----------------------------------------

struct Rng(u64);
impl Rng {
    fn next(&mut self) -> u64 {
        self.0 ^= self.0 << 13;
        self.0 ^= self.0 >> 7;
        self.0 ^= self.0 << 17;
        self.0
    }
    fn below(&mut self, n: u64) -> u64 {
        self.next() % n
    }
}

fn foreign_bytes(r: &mut Rng) -> Vec<u8> {
    let mut out = vec![];
    for _ in 0..r.below(8) {
        match r.below(7) {
            0 => out.extend_from_slice(
                format!(
                    "{{\"agent_id\":\"agent://x.example/y\",\"schema\":\"s\",\"source\":\"other\",\"ts\":\"t\",\"type\":\"z\",\"data\":{{\"n\":{}}}}}\n",
                    r.below(1 << 40)
                )
                .as_bytes(),
            ),
            1 => out.extend_from_slice(b"\n\r\n   \n"),
            2 => out.extend((0..r.below(200)).map(|_| (r.next() & 0xff) as u8)),
            3 => out.extend_from_slice(b"{\"agent_id\":\"agent://torn.ex"),
            4 => out.extend_from_slice("{\"type\":\"é\",\"agent_id\":\"\u{a0}\"}\n".as_bytes()),
            5 => out.extend_from_slice(&[0, 0xff, b'\n']),
            _ => out.extend_from_slice(b"[1,2,3]\n"),
        }
    }
    out
}

/// Fifty seeded streams with foreign lines, torn fragments and garbage between
/// this writer's events, each record checked with ECDSA and against the
/// stream's bytes. With `CKPT_DUMP_DIR` set the streams are kept there, each
/// beside a key.json, for agent-stack-go's and keyryx's verifiers to read.
#[test]
fn hostile_streams_signed_with_a_real_key_verify() {
    let dump = std::env::var("CKPT_DUMP_DIR").ok().map(PathBuf::from);
    let mut signed = 0;
    for seed in 1..=50u64 {
        let mut r = Rng(seed.wrapping_mul(0x9E37_79B9_7F4A_7C15) | 1);
        let dir = match &dump {
            Some(d) => {
                let d = d.join(format!("seed-{seed:03}"));
                let _ = std::fs::remove_dir_all(&d);
                std::fs::create_dir_all(d.join("events")).unwrap();
                std::fs::create_dir_all(d.join("checkpoints")).unwrap();
                d
            }
            None => temp_dir(&format!("hostile-{seed}")),
        };
        let path = dir.join("events/tokenfuse.ndjson");
        std::fs::write(&path, foreign_bytes(&mut r)).unwrap();
        let exporter = Exporter::open(path.to_str().unwrap()).unwrap();
        let key = HeldKey::from_secret(&[seed as u8 + 1; 32]).unwrap();
        let jwk = key.public_jwk().clone();
        let signer = Arc::new(DelegatedSigner::new());
        signer.install(
            Certified {
                key: Arc::new(key),
                statement: Value::Null,
                not_before: T0_SECS,
                not_after: T0_SECS + 3600,
            },
            T0_SECS,
        );
        let clock = Arc::new(AtomicI64::new(T0_SECS * 1000));
        let c = Arc::clone(&clock);
        exporter
            .attach_checkpoints(tokenfuse_core::checkpoint::CheckpointConfig {
                dir: dir.join("checkpoints"),
                signer,
                clock: Arc::new(move || c.load(Ordering::SeqCst)),
            })
            .unwrap();
        for _ in 0..r.below(5) + 1 {
            for i in 0..r.below(70) {
                exporter.emit(
                    EventType::BreakerTripped,
                    T0_SECS * 1000 + i as i64,
                    Some("agent://acme.example/support/bot"),
                    Some("run-1"),
                    None,
                    json!({"i": i}),
                );
            }
            if r.below(2) == 0 {
                let mut f = std::fs::OpenOptions::new()
                    .append(true)
                    .open(&path)
                    .unwrap();
                std::io::Write::write_all(&mut f, &foreign_bytes(&mut r)).unwrap();
            }
            clock.fetch_add(r.below(20_000) as i64, Ordering::SeqCst);
            exporter.checkpoint_tick();
        }
        let _ = exporter.close_checkpoints();
        let stream = std::fs::read(&path).unwrap();
        let side =
            std::fs::read(dir.join("checkpoints/tokenfuse.ndjson.ckpt.ndjson")).unwrap_or_default();
        let verdicts = check(&stream, &side, &jwk);
        assert!(
            verdicts.iter().all(|v| v == "valid"),
            "seed {seed}: {verdicts:?}"
        );
        signed += verdicts.len();
        if dump.is_some() {
            std::fs::write(
                dir.join("key.json"),
                serde_json::to_vec(
                    &json!({"jwk": jwk, "not_before": T0_SECS, "not_after": T0_SECS + 3600}),
                )
                .unwrap(),
            )
            .unwrap();
        } else {
            let _ = std::fs::remove_dir_all(&dir);
        }
    }
    assert!(
        signed >= 50,
        "the sweep signed {signed} records, which measured too little"
    );
}
