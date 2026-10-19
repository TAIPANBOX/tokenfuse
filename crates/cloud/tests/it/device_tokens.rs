//! Paired-device credentials at rest and across a restart (CLAUDE.md invariant
//! 132).
//!
//! Before this invariant a paired device's bearer token was the key of the
//! `devices` map, so the 0600 snapshot held every live device token in clear.
//! The replay defence was a nonce ring held only in memory, so a request a
//! device signed in the two minutes before a restart could be replayed after
//! it. These tests save and reload real snapshots and drive the real router.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use axum::body::Body;
use axum::http::{Request, StatusCode};
use base64::{engine::general_purpose::STANDARD, Engine};
use http_body_util::BodyExt;
use p256::ecdsa::{signature::Signer, Signature, SigningKey};
use tower::ServiceExt;

use tokenfuse_cloud::devices::canonical_string;
use tokenfuse_cloud::keys::digest;
use tokenfuse_cloud::{app, AppState, Principal, Store};

fn now_unix() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64
}

/// A unique scratch path per test: the pid is shared by every test here.
fn scratch(name: &str) -> std::path::PathBuf {
    std::env::temp_dir().join(format!(
        "tf-device-tokens-{}-{name}.json",
        std::process::id()
    ))
}

fn state_over(store: Arc<Store>) -> AppState {
    let mut keys = HashMap::new();
    keys.insert(
        digest("adm"),
        Principal {
            org: "acme".into(),
            role: "admin".into(),
            site: None,
        },
    );
    AppState::new(store, Arc::new(keys), 0.8)
}

fn keypair() -> (SigningKey, String) {
    let sk = SigningKey::from_slice(&[0x33u8; 32]).expect("valid scalar");
    let pubkey_b64 = STANDARD.encode(sk.verifying_key().to_encoded_point(false).as_bytes());
    (sk, pubkey_b64)
}

async fn send(state: &AppState, req: Request<Body>) -> (StatusCode, serde_json::Value) {
    let resp = app(state.clone()).oneshot(req).await.unwrap();
    let status = resp.status();
    let bytes = resp.into_body().collect().await.unwrap().to_bytes();
    let v = serde_json::from_slice(&bytes).unwrap_or(serde_json::Value::Null);
    (status, v)
}

/// Pair a device through the real endpoints and return (device_id, token).
async fn pair(state: &AppState, pubkey_b64: &str) -> (String, String) {
    let (st, v) = send(
        state,
        Request::post("/v1/pair/new")
            .header("authorization", "Bearer adm")
            .body(Body::from("{}"))
            .unwrap(),
    )
    .await;
    assert_eq!(st, StatusCode::OK, "pair/new failed: {v}");
    let code = v["code"].as_str().unwrap().to_string();
    let body = format!(
        r#"{{"code":"{code}","pubkey_b64":"{pubkey_b64}","platform":"linux","name":"test device"}}"#
    );
    let (st, v) = send(
        state,
        Request::post("/v1/pair").body(Body::from(body)).unwrap(),
    )
    .await;
    assert_eq!(st, StatusCode::OK, "pair failed: {v}");
    (
        v["device_id"].as_str().unwrap().to_string(),
        v["device_token"].as_str().unwrap().to_string(),
    )
}

/// A device-signed kill of run `r1` at `ts` with `nonce`.
fn signed_kill(
    sk: &SigningKey,
    device_id: &str,
    token: &str,
    ts: i64,
    nonce: &str,
) -> Request<Body> {
    let path = "/v1/runs/r1/kill";
    let canonical = canonical_string("POST", path, b"", &ts.to_string(), nonce);
    let sig: Signature = sk.sign(canonical.as_bytes());
    Request::post(path)
        .header("authorization", format!("Bearer {token}"))
        .header("x-fuse-device", device_id)
        .header("x-fuse-ts", ts.to_string())
        .header("x-fuse-nonce", nonce)
        .header("x-fuse-sig", STANDARD.encode(sig.to_bytes()))
        .body(Body::empty())
        .unwrap()
}

/// The snapshot a store writes, read back as text.
fn save_and_read(store: &Store, name: &str) -> String {
    let path = scratch(name);
    store.save(&path).expect("save");
    let text = std::fs::read_to_string(&path).expect("read snapshot");
    let _ = std::fs::remove_file(&path);
    text
}

#[tokio::test]
async fn a_device_token_is_stored_as_its_digest_and_never_in_the_snapshot() {
    let store = Arc::new(Store::new());
    let state = state_over(Arc::clone(&store));
    let (_sk, pubkey) = keypair();
    let (_id, token) = pair(&state, &pubkey).await;

    // The device still authenticates with the token it was given.
    let (st, _) = send(
        &state,
        Request::get("/v1/runs")
            .header("authorization", format!("Bearer {token}"))
            .body(Body::empty())
            .unwrap(),
    )
    .await;
    assert_eq!(st, StatusCode::OK);

    let on_disk = save_and_read(&store, "digest-at-rest");
    assert!(
        !on_disk.contains(&token),
        "the raw device token must not be in the snapshot"
    );
    assert!(
        on_disk.contains(&digest(&token)),
        "the digest is what is stored"
    );
}

#[tokio::test]
async fn a_snapshot_with_raw_device_tokens_is_migrated_and_rewritten_hashed() {
    // An old-format snapshot: the device token itself is the map key.
    let raw = "a".repeat(64);
    let old = format!(
        r#"{{"orgs":{{}},"killed":{{}},"budgets":{{}},"devices":{{"{raw}":{{"device_id":"d1","org":"acme","role":"admin","pubkey_b64":"AAAA"}}}}}}"#
    );
    let path = scratch("migrate");
    std::fs::write(&path, old).unwrap();

    let store = Arc::new(Store::new());
    store.load(&path).expect("an old snapshot loads");
    let _ = std::fs::remove_file(&path);
    let state = state_over(Arc::clone(&store));

    // The device authenticates after the migration, with the same token.
    let (st, _) = send(
        &state,
        Request::get("/v1/runs")
            .header("authorization", format!("Bearer {raw}"))
            .body(Body::empty())
            .unwrap(),
    )
    .await;
    assert_eq!(
        st,
        StatusCode::OK,
        "a migrated device must still authenticate"
    );

    // The next save writes it hashed, and the raw token is gone from the file.
    let on_disk = save_and_read(&store, "migrate-written");
    assert!(
        !on_disk.contains(&raw),
        "the raw token survives the rewrite"
    );
    assert!(on_disk.contains(&digest(&raw)));
}

#[tokio::test]
async fn a_device_request_signed_before_a_restart_is_refused_after_it() {
    let store = Arc::new(Store::new());
    let state = state_over(Arc::clone(&store));
    let (sk, pubkey) = keypair();
    let (device_id, token) = pair(&state, &pubkey).await;
    let snap = scratch("before-restart");
    store.save(&snap).unwrap();

    // The restart: a new process loads the snapshot. Its start is now.
    let restarted = Arc::new(Store::new());
    restarted.load(&snap).unwrap();
    let _ = std::fs::remove_file(&snap);
    let after = state_over(restarted);

    // Signed 5 s before this process started: inside the 120 s window, so only
    // the start-of-process rule refuses it.
    let (st, v) = send(
        &after,
        signed_kill(&sk, &device_id, &token, now_unix() - 5, "pre-restart-nonce"),
    )
    .await;
    assert_eq!(
        st,
        StatusCode::FORBIDDEN,
        "a request signed before this process started must not be accepted: {v}"
    );
}

#[tokio::test]
async fn a_device_request_signed_after_the_restart_is_accepted() {
    // The control: the same restart, a request signed after it. Green both ways.
    let store = Arc::new(Store::new());
    let state = state_over(Arc::clone(&store));
    let (sk, pubkey) = keypair();
    let (device_id, token) = pair(&state, &pubkey).await;
    let snap = scratch("after-restart");
    store.save(&snap).unwrap();

    let restarted = Arc::new(Store::new());
    restarted.load(&snap).unwrap();
    let _ = std::fs::remove_file(&snap);
    let after = state_over(restarted);

    let (st, v) = send(
        &after,
        signed_kill(&sk, &device_id, &token, now_unix(), "post-restart-nonce"),
    )
    .await;
    assert_eq!(st, StatusCode::OK, "a fresh request is accepted: {v}");
}

#[tokio::test]
async fn a_nonce_recorded_before_a_restart_is_refused_after_it() {
    let store = Arc::new(Store::new());
    let state = state_over(Arc::clone(&store));
    let (sk, pubkey) = keypair();
    let (device_id, token) = pair(&state, &pubkey).await;

    // Accepted once, before the restart, with a nonce the ring keeps.
    let (st, v) = send(
        &state,
        signed_kill(&sk, &device_id, &token, now_unix(), "kept-nonce"),
    )
    .await;
    assert_eq!(st, StatusCode::OK, "first use is accepted: {v}");
    let snap = scratch("nonce-restart");
    store.save(&snap).unwrap();

    // Restart, then replay the same signed request. The ts is taken after the
    // new process started, so the start rule does not decide it: the nonce does.
    let restarted = Arc::new(Store::new());
    restarted.load(&snap).unwrap();
    let _ = std::fs::remove_file(&snap);
    let after = state_over(restarted);
    let (st, v) = send(
        &after,
        signed_kill(&sk, &device_id, &token, now_unix(), "kept-nonce"),
    )
    .await;
    assert_eq!(
        st,
        StatusCode::FORBIDDEN,
        "a nonce seen before the restart must be refused after it: {v}"
    );
}
