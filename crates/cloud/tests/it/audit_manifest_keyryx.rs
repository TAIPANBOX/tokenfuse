//! Invariant 130: the audit manifest signed by keyryx custody.
//!
//! A stub keyryx serves `POST /v1/keys/{name}/sign` the way keyryx's
//! `internal/api` does: a consumer bearer, a body of `statement_b64` and
//! `purpose`, and an answer of `alg`, `kid`, `signature_b64` and
//! `public_key_b64`. Against it: a manifest keyryx signed verifies offline
//! under the key keyryx named; keyryx unreachable, refusing, or answering with
//! a signature that does not verify is `503` saying so, with nothing unsigned
//! served and no other key signing instead; an unchanged tip reuses the signed
//! manifest; and the credential file is read on every sign. The last two tests
//! run the real binary: a signer configuration it cannot use refuses to start.

use std::collections::HashMap;
use std::io::Read;
use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use axum::body::Body;
use axum::extract::{Path, State};
use axum::http::{HeaderMap, Request, StatusCode};
use axum::routing::post;
use axum::{Json, Router};
use base64::{engine::general_purpose::STANDARD, Engine};
use http_body_util::BodyExt;
use p256::ecdsa::{signature::Signer, signature::Verifier, Signature, SigningKey, VerifyingKey};
use tower::ServiceExt;

use tokenfuse_cloud::{app, audit_signer_from, AppState, AuditSigner, Principal, Store};

const KEY_NAME: &str = "tokenfuse-audit";

/// How the stub answers a sign.
#[derive(Clone, Copy, PartialEq)]
enum Answer {
    /// A real ES256 signature over the statement, as keyryx signs.
    Signs,
    /// A 403, keyryx's answer to a key not granted.
    Refuses,
    /// A valid signature over some other bytes.
    SignsOtherBytes,
    /// A signature labelled ES384, as an ES384 key's would be.
    SaysEs384,
}

/// One sign the stub was asked for, as it arrived.
struct Call {
    name: String,
    bearer: String,
    purpose: String,
    statement: Vec<u8>,
}

struct Stub {
    key: SigningKey,
    answer: Mutex<Answer>,
    bearer: Mutex<String>,
    calls: Mutex<Vec<Call>>,
}

async fn sign(
    State(stub): State<Arc<Stub>>,
    Path(name): Path<String>,
    headers: HeaderMap,
    Json(body): Json<serde_json::Value>,
) -> (StatusCode, Json<serde_json::Value>) {
    let bearer = headers
        .get("authorization")
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "))
        .unwrap_or_default()
        .to_string();
    let statement = STANDARD
        .decode(body["statement_b64"].as_str().unwrap_or_default())
        .unwrap_or_default();
    let purpose = body["purpose"].as_str().unwrap_or_default().to_string();
    stub.calls.lock().unwrap().push(Call {
        name: name.clone(),
        bearer: bearer.clone(),
        purpose,
        statement: statement.clone(),
    });
    if bearer != *stub.bearer.lock().unwrap() {
        return (StatusCode::UNAUTHORIZED, Json(serde_json::json!({})));
    }
    let answer = *stub.answer.lock().unwrap();
    if answer == Answer::Refuses || name != KEY_NAME {
        return (StatusCode::FORBIDDEN, Json(serde_json::json!({})));
    }
    let signed: Vec<u8> = if answer == Answer::SignsOtherBytes {
        b"some other statement".to_vec()
    } else {
        statement
    };
    let sig: Signature = stub.key.sign(&signed);
    let alg = if answer == Answer::SaysEs384 {
        "ES384"
    } else {
        "ES256"
    };
    (
        StatusCode::OK,
        Json(serde_json::json!({
            "alg": alg,
            "kid": "kid-audit-1",
            "signature_b64": STANDARD.encode(sig.to_bytes()),
            "public_key_b64": STANDARD.encode(
                stub.key.verifying_key().to_encoded_point(false).as_bytes()
            ),
        })),
    )
}

/// A stub keyryx on a free port, answering with `answer`, accepting `bearer`.
async fn keyryx(answer: Answer, bearer: &str) -> (String, Arc<Stub>) {
    let stub = Arc::new(Stub {
        key: SigningKey::from_slice(&[0x33u8; 32]).unwrap(),
        answer: Mutex::new(answer),
        bearer: Mutex::new(bearer.to_string()),
        calls: Mutex::new(vec![]),
    });
    let router = Router::new()
        .route("/v1/keys/{name}/sign", post(sign))
        .with_state(Arc::clone(&stub));
    let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = l.local_addr().unwrap();
    tokio::spawn(async move {
        let _ = axum::serve(l, router).await;
    });
    (format!("http://{addr}"), stub)
}

/// A file only the test with this label names: every test in this binary
/// shares one process id.
fn scratch(label: &str, contents: &str) -> PathBuf {
    let path = std::env::temp_dir().join(format!(
        "tf-cloud-keyryx-manifest-{label}-{}",
        std::process::id()
    ));
    std::fs::write(&path, contents).unwrap();
    path
}

fn keys() -> HashMap<String, Principal> {
    let mut keys = HashMap::new();
    for (k, role) in [("adminkey", "admin"), ("viewerkey", "viewer")] {
        keys.insert(
            k.into(),
            Principal {
                org: "acme".into(),
                role: role.into(),
                site: None,
            },
        );
    }
    keys
}

/// The keyryx signer, built through the same reading of the environment `main`
/// uses, pointed at `url` with the credential in `cred`.
fn keyryx_signer(url: &str, cred: &std::path::Path) -> tokenfuse_cloud::KeyryxSigner {
    let vars: HashMap<&str, String> = HashMap::from([
        ("TOKENFUSE_CLOUD_AUDIT_SIGNER", "keyryx".to_string()),
        ("TOKENFUSE_CLOUD_AUDIT_KEYRYX_URL", url.to_string()),
        ("TOKENFUSE_CLOUD_AUDIT_KEYRYX_KEY", KEY_NAME.to_string()),
        (
            "TOKENFUSE_CLOUD_AUDIT_KEYRYX_CREDENTIAL_FILE",
            cred.display().to_string(),
        ),
    ]);
    match audit_signer_from(|k| vars.get(k).cloned()) {
        Ok(Some(AuditSigner::Keyryx(s))) => s,
        Ok(_) => panic!("the keyryx variables must build the keyryx signer"),
        Err(why) => panic!("the keyryx variables must start: {why}"),
    }
}

fn state(url: &str, cred: &std::path::Path) -> AppState {
    AppState::new(Arc::new(Store::new()), Arc::new(keys()), 0.8)
        .with_audit_keyryx(Some(keyryx_signer(url, cred)))
}

async fn send(
    state: &AppState,
    method: &str,
    path: &str,
    key: &str,
) -> (StatusCode, serde_json::Value) {
    let req = Request::builder()
        .method(method)
        .uri(path)
        .header("authorization", format!("Bearer {key}"))
        .body(Body::empty())
        .unwrap();
    let resp = app(state.clone()).oneshot(req).await.unwrap();
    let status = resp.status();
    let bytes = resp.into_body().collect().await.unwrap().to_bytes();
    (
        status,
        serde_json::from_slice(&bytes).unwrap_or(serde_json::Value::Null),
    )
}

async fn mutate(state: &AppState, run: &str) {
    let (s, _) = send(state, "POST", &format!("/v1/runs/{run}/kill"), "adminkey").await;
    assert_eq!(s, StatusCode::OK);
}

/// The manifest's own canonical bytes, re-derived from its fields.
fn canonical(m: &serde_json::Value) -> Vec<u8> {
    tokenfuse_core::audit::manifest_signing_bytes(
        m["org"].as_str().unwrap(),
        m["tip_seq"].as_u64().unwrap(),
        m["tip_hash"].as_str().unwrap(),
        m["entry_count"].as_u64().unwrap(),
        m["signed_at_millis"].as_i64().unwrap(),
    )
}

/// Verify as an offline auditor would: the embedded key over the re-derived bytes.
fn verifies(m: &serde_json::Value) -> bool {
    let pk = STANDARD
        .decode(m["public_key_b64"].as_str().unwrap())
        .unwrap();
    let sig = STANDARD
        .decode(m["signature_b64"].as_str().unwrap())
        .unwrap();
    let vk = VerifyingKey::from_sec1_bytes(&pk).unwrap();
    vk.verify(&canonical(m), &Signature::from_slice(&sig).unwrap())
        .is_ok()
}

/// A manifest keyryx signed verifies under the key keyryx holds and names its
/// kid; keyryx was asked for exactly the manifest's canonical bytes, with the
/// purpose and the credential the file holds.
#[tokio::test]
async fn a_manifest_keyryx_signed_verifies_and_names_its_kid() {
    let (url, stub) = keyryx(Answer::Signs, "sk-cloud-1").await;
    let cred = scratch("signs", "sk-cloud-1\n");
    let st = state(&url, &cred);
    mutate(&st, "run-1").await;

    let (status, m) = send(&st, "GET", "/v1/audit/manifest", "viewerkey").await;
    let _ = std::fs::remove_file(&cred);
    assert_eq!(status, StatusCode::OK, "{m}");
    assert_eq!(m["algorithm"], "ES256");
    assert_eq!(m["kid"], "kid-audit-1");
    assert_eq!(m["entry_count"], 1);
    assert!(verifies(&m), "the manifest must verify offline: {m}");
    let keyryx_key = STANDARD.encode(stub.key.verifying_key().to_encoded_point(false).as_bytes());
    assert_eq!(m["public_key_b64"], keyryx_key, "signed by keyryx's key");

    let calls = stub.calls.lock().unwrap();
    assert_eq!(calls.len(), 1);
    let call = &calls[0];
    assert_eq!(call.name, KEY_NAME);
    assert_eq!(call.bearer, "sk-cloud-1");
    assert_eq!(call.purpose, "tokenfuse.audit-manifest");
    assert_eq!(call.statement, canonical(&m));
}

/// keyryx not listening: `503` saying it could not be reached, no signature in
/// the body, and the in-process key beside it does not sign instead.
#[tokio::test]
async fn an_unreachable_keyryx_fails_closed_and_no_other_key_signs_instead() {
    let closed = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let url = format!("http://{}", closed.local_addr().unwrap());
    drop(closed);
    let cred = scratch("unreachable", "sk-cloud-1\n");
    let st = state(&url, &cred)
        .with_audit_signing_key(Some(SigningKey::from_slice(&[0x11u8; 32]).unwrap()));

    let (status, body) = send(&st, "GET", "/v1/audit/manifest", "viewerkey").await;
    let _ = std::fs::remove_file(&cred);
    assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE, "{body}");
    let said = body["error"].as_str().unwrap_or_default();
    assert!(said.contains("not signed"), "{body}");
    assert!(said.contains("keyryx could not be reached"), "{body}");
    assert!(body.get("signature_b64").is_none(), "{body}");
    assert!(
        !said.contains("127.0.0.1"),
        "the answer names no URL: {body}"
    );
}

#[tokio::test]
async fn a_refusing_keyryx_fails_closed_with_its_status() {
    let (url, _stub) = keyryx(Answer::Refuses, "sk-cloud-1").await;
    let cred = scratch("refuses", "sk-cloud-1\n");
    let (status, body) = send(
        &state(&url, &cred),
        "GET",
        "/v1/audit/manifest",
        "viewerkey",
    )
    .await;
    let _ = std::fs::remove_file(&cred);
    assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE, "{body}");
    assert!(
        body["error"].as_str().unwrap_or_default().contains("403"),
        "{body}"
    );
}

/// A signature over other bytes, and one labelled ES384: neither is served.
#[tokio::test]
async fn an_answer_that_does_not_verify_or_is_not_es256_is_never_served() {
    for (answer, said) in [
        (Answer::SignsOtherBytes, "does not verify"),
        (Answer::SaysEs384, "ES384"),
    ] {
        let (url, _stub) = keyryx(answer, "sk-cloud-1").await;
        let cred = scratch("bad-answer", "sk-cloud-1\n");
        let (status, body) = send(
            &state(&url, &cred),
            "GET",
            "/v1/audit/manifest",
            "viewerkey",
        )
        .await;
        let _ = std::fs::remove_file(&cred);
        assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE, "{said}: {body}");
        assert!(
            body["error"].as_str().unwrap_or_default().contains(said),
            "{said}: {body}"
        );
        assert!(body.get("signature_b64").is_none(), "{said}: {body}");
    }
}

/// A viewer asking again while the tip is unchanged is served the manifest
/// keyryx already signed; a mutation moves the tip and signs again.
#[tokio::test]
async fn an_unchanged_tip_reuses_the_signed_manifest_and_a_new_tip_signs_again() {
    let (url, stub) = keyryx(Answer::Signs, "sk-cloud-1").await;
    let cred = scratch("reuse", "sk-cloud-1\n");
    let st = state(&url, &cred);
    mutate(&st, "run-1").await;
    let (_, a) = send(&st, "GET", "/v1/audit/manifest", "viewerkey").await;
    let (_, b) = send(&st, "GET", "/v1/audit/manifest", "viewerkey").await;
    assert_eq!(a, b, "an unchanged tip is served the same manifest");
    assert_eq!(stub.calls.lock().unwrap().len(), 1, "keyryx asked once");

    mutate(&st, "run-2").await;
    let (_, c) = send(&st, "GET", "/v1/audit/manifest", "viewerkey").await;
    let _ = std::fs::remove_file(&cred);
    assert_eq!(c["entry_count"], 2);
    assert!(verifies(&c), "{c}");
    assert_eq!(stub.calls.lock().unwrap().len(), 2, "a new tip signs again");
}

/// The reuse lasts sixty seconds and not a millisecond more.
#[tokio::test]
async fn a_reused_manifest_is_signed_again_after_sixty_seconds() {
    let (url, stub) = keyryx(Answer::Signs, "sk-cloud-1").await;
    let cred = scratch("expiry", "sk-cloud-1\n");
    let signer = keyryx_signer(&url, &cred);
    let tip = Store::new().audit_tip("acme");
    let t = 1_700_000_000_000;
    let first = signer.manifest("acme", tip.clone(), t).await.unwrap();
    let again = signer
        .manifest("acme", tip.clone(), t + 59_999)
        .await
        .unwrap();
    assert_eq!(first.signed_at_millis, again.signed_at_millis);
    assert_eq!(stub.calls.lock().unwrap().len(), 1);
    let fresh = signer.manifest("acme", tip, t + 60_000).await.unwrap();
    let _ = std::fs::remove_file(&cred);
    assert_eq!(fresh.signed_at_millis, t + 60_000);
    assert_eq!(stub.calls.lock().unwrap().len(), 2);
}

/// A rotated credential file is used at the next sign, without a restart.
#[tokio::test]
async fn the_credential_file_is_read_on_every_sign() {
    let (url, stub) = keyryx(Answer::Signs, "sk-cloud-1").await;
    let cred = scratch("rotate", "sk-cloud-1\n");
    let st = state(&url, &cred);
    let (s, _) = send(&st, "GET", "/v1/audit/manifest", "viewerkey").await;
    assert_eq!(s, StatusCode::OK);

    std::fs::write(&cred, "sk-cloud-2\n").unwrap();
    *stub.bearer.lock().unwrap() = "sk-cloud-2".into();
    mutate(&st, "run-1").await;
    let (s, body) = send(&st, "GET", "/v1/audit/manifest", "viewerkey").await;
    let _ = std::fs::remove_file(&cred);
    assert_eq!(
        s,
        StatusCode::OK,
        "the rotated credential must be used: {body}"
    );
    assert_eq!(stub.calls.lock().unwrap()[1].bearer, "sk-cloud-2");
}

// -- the real binary ----------------------------------------------------------

fn bin() -> &'static str {
    env!("CARGO_BIN_EXE_tokenfuse-cloud")
}

/// Run the control plane with `extra` on top of a clean environment; exit code
/// and log, or `None` and the log when it was still running after the deadline.
fn run_cloud(extra: &[(&str, &str)]) -> (Option<i32>, String) {
    let mut cmd = Command::new(bin());
    for name in [
        "TOKENFUSE_CLOUD_DATA",
        "TOKENFUSE_CLOUD_REPLAY_EVENTS",
        "TOKENFUSE_EVENTS_PATH",
        "TOKENFUSE_CLOUD_AUDIT_SIGNING_KEY",
        "TOKENFUSE_CLOUD_AUDIT_SIGNER",
        "TOKENFUSE_CLOUD_AUDIT_KEYRYX_URL",
        "TOKENFUSE_CLOUD_AUDIT_KEYRYX_KEY",
        "TOKENFUSE_CLOUD_AUDIT_KEYRYX_CREDENTIAL_FILE",
    ] {
        cmd.env_remove(name);
    }
    cmd.env("TOKENFUSE_CLOUD_KEYS", "k1:acme:admin")
        .env("TOKENFUSE_CLOUD_HOST", "127.0.0.1")
        .env("PORT", "0")
        .env("RUST_LOG", "info");
    for (k, v) in extra {
        cmd.env(k, v);
    }
    let mut child = cmd
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("failed to spawn the tokenfuse-cloud binary");
    let deadline = Instant::now() + Duration::from_secs(20);
    let status = loop {
        if let Some(status) = child.try_wait().unwrap() {
            break Some(status);
        }
        if Instant::now() >= deadline {
            break None;
        }
        std::thread::sleep(Duration::from_millis(50));
    };
    if status.is_none() {
        let _ = child.kill();
    }
    let mut log = String::new();
    if let Some(mut out) = child.stdout.take() {
        let _ = out.read_to_string(&mut log);
    }
    let _ = child.wait();
    (status.map(|s| s.code().unwrap_or(-1)), log)
}

/// `keyryx` with nothing else: exit 2 before listening, naming each variable it
/// needs. The binary before this change ignored the word and served manifests
/// as not configured.
#[test]
fn the_keyryx_signer_with_nothing_else_refuses_to_start() {
    let (code, log) = run_cloud(&[("TOKENFUSE_CLOUD_AUDIT_SIGNER", "keyryx")]);
    let Some(code) = code else {
        panic!("the control plane kept running with an unusable keyryx signer. Log:\n{log}");
    };
    assert_eq!(code, 2, "{log}");
    assert!(!log.contains("listening on"), "{log}");
    for name in [
        "TOKENFUSE_CLOUD_AUDIT_KEYRYX_URL",
        "TOKENFUSE_CLOUD_AUDIT_KEYRYX_KEY",
        "TOKENFUSE_CLOUD_AUDIT_KEYRYX_CREDENTIAL_FILE",
    ] {
        assert!(
            log.contains(name),
            "the refusal must name {name}. Log:\n{log}"
        );
    }
}

#[test]
fn a_mistyped_signer_refuses_to_start() {
    let (code, log) = run_cloud(&[("TOKENFUSE_CLOUD_AUDIT_SIGNER", "keyrix")]);
    let Some(code) = code else {
        panic!("the control plane kept running with a mistyped signer. Log:\n{log}");
    };
    assert_eq!(code, 2, "{log}");
    assert!(
        log.contains("TOKENFUSE_CLOUD_AUDIT_SIGNER") && log.contains("keyrix"),
        "{log}"
    );
}
