//! Invariant 105: a call refused for its client key is on the bus, named by a
//! fingerprint of the key it presented and never the key, and a scan cannot
//! flood the bus.
//!
//! Measured on forge 2026-10-14: no key, an unknown key and the other door's
//! key all drew the same 401 and wrote nothing anywhere but an aggregate
//! counter, so a key scan against a gateway was invisible to every consumer of
//! the event bus. The answer to the caller stays exactly as it was (the two
//! causes indistinguishable to a caller, invariant of `clientkeys`); only the
//! operator's record learns which one it was.

use axum::body::Body;
use axum::http::{Request, StatusCode};
use sha2::{Digest, Sha256};
use std::path::PathBuf;
use std::sync::Arc;
use tokenfuse_core::{Ledger, Mode, Policy};
use tokenfuse_gateway::clientkeys::ClientKeys;
use tokenfuse_gateway::events::EventExporter;
use tokenfuse_gateway::provider::StubProvider;
use tokenfuse_gateway::state::AppState;
use tower::ServiceExt;

const GOOD: &str = "sk-gateway-good-0123456789";
const AGENT: &str = "agent://test/scanner";

fn gateway(tag: &str) -> (AppState, PathBuf) {
    let dir = std::env::temp_dir().join(format!("tf-refused-key-{}-{tag}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join("events.ndjson");
    let _ = std::fs::remove_file(&path);
    let exp = Arc::new(EventExporter::open(path.to_str().unwrap()).unwrap());
    let st = AppState::new(
        Arc::new(Ledger::new()),
        Arc::new(tokenfuse_gateway::pricebook::default_price_book()),
        Arc::new(Policy {
            mode: Mode::Enforce,
            ..Default::default()
        }),
        Arc::new(StubProvider::default()),
        "refused-key-test",
    )
    .with_client_keys(Arc::new(
        ClientKeys::from_spec(&format!("{GOOD}:billing")).unwrap(),
    ))
    .with_events(exp);
    (st, path)
}

async fn call(st: &AppState, key: Option<&str>, agent: Option<&str>) -> (StatusCode, String) {
    let mut req = Request::post("/v1/messages")
        .header("content-type", "application/json")
        .header("x-fuse-run-id", "run-scan");
    if let Some(k) = key {
        req = req.header("x-fuse-key", k);
    }
    if let Some(a) = agent {
        req = req.header("x-fuse-agent-id", a);
    }
    let resp = tokenfuse_gateway::app(st.clone())
        .oneshot(
            req.body(Body::from(
                r#"{"model":"claude-haiku-5-5","max_tokens":10,"messages":[{"role":"user","content":"hi"}]}"#,
            ))
            .unwrap(),
        )
        .await
        .unwrap();
    let status = resp.status();
    let bytes = axum::body::to_bytes(resp.into_body(), 1 << 16)
        .await
        .unwrap();
    (status, String::from_utf8_lossy(&bytes).into_owned())
}

fn refusals(path: &std::path::Path) -> Vec<serde_json::Value> {
    std::fs::read_to_string(path)
        .unwrap_or_default()
        .lines()
        .filter_map(|l| serde_json::from_str::<serde_json::Value>(l).ok())
        .filter(|e| e["type"] == "identity_mismatch")
        .collect()
}

fn fingerprint_of(key: &str) -> String {
    let digest = Sha256::digest(key.as_bytes());
    let hex: String = digest.iter().map(|b| format!("{b:02x}")).collect();
    format!("sha256:{}", &hex[..16])
}

#[tokio::test]
async fn a_missing_key_and_an_unknown_key_are_on_the_bus_by_reason() {
    let (st, bus) = gateway("reasons");
    let (missing_status, missing_body) = call(&st, None, Some(AGENT)).await;
    let (unknown_status, unknown_body) = call(&st, Some("sk-wrong-key-77"), Some(AGENT)).await;
    assert_eq!(missing_status, StatusCode::UNAUTHORIZED);
    assert_eq!(unknown_status, StatusCode::UNAUTHORIZED);
    assert_eq!(
        missing_body, unknown_body,
        "the caller still cannot tell the two causes apart"
    );
    let events = refusals(&bus);
    assert_eq!(events.len(), 2, "one event per refusal here: {events:?}");
    let missing = &events[0]["data"];
    assert_eq!(missing["reason"], "missing_key", "{missing}");
    assert!(missing["key_fingerprint"].is_null(), "{missing}");
    let unknown = &events[1]["data"];
    assert_eq!(unknown["reason"], "unknown_key", "{unknown}");
    assert_eq!(
        unknown["key_fingerprint"],
        fingerprint_of("sk-wrong-key-77")
    );
    assert_eq!(events[1]["agent_id"], AGENT);
    assert_eq!(events[1]["run_id"], "run-scan");
    let line = std::fs::read_to_string(&bus).unwrap();
    assert!(
        !line.contains("sk-wrong-key-77"),
        "the presented key never reaches the record: {line}"
    );
}

#[tokio::test]
async fn the_same_key_tried_again_and_again_is_one_event() {
    let (st, bus) = gateway("same");
    for _ in 0..50 {
        let (status, _) = call(&st, Some("sk-wrong-key-77"), Some(AGENT)).await;
        assert_eq!(status, StatusCode::UNAUTHORIZED);
    }
    let events = refusals(&bus);
    assert_eq!(
        events.len(),
        1,
        "fifty tries of one key within a minute are one event: {events:?}"
    );
}

#[tokio::test]
async fn a_scan_of_many_keys_cannot_flood_the_bus() {
    let (st, bus) = gateway("scan");
    for i in 0..200 {
        let (status, _) = call(&st, Some(&format!("sk-guess-{i}")), Some(AGENT)).await;
        assert_eq!(status, StatusCode::UNAUTHORIZED);
    }
    let events = refusals(&bus);
    assert!(
        !events.is_empty() && events.len() <= 60,
        "a scan is seen, and at most sixty events a minute say so: {}",
        events.len()
    );
}

#[tokio::test]
async fn a_good_key_writes_no_refusal() {
    let (st, bus) = gateway("good");
    let (status, body) = call(&st, Some(GOOD), Some(AGENT)).await;
    assert_ne!(status, StatusCode::UNAUTHORIZED, "{body}");
    assert!(refusals(&bus).is_empty());
}

/// A scanner sends no `x-fuse-agent-id`. Its refusals are on the bus too,
/// under the one reserved subject for a caller that presented no identity,
/// rate-limited like the rest.
#[tokio::test]
async fn a_scan_that_names_no_agent_is_on_the_bus_too() {
    let (st, bus) = gateway("anonymous");
    for i in 0..5 {
        let (status, _) = call(&st, Some(&format!("sk-anon-{i}")), None).await;
        assert_eq!(status, StatusCode::UNAUTHORIZED);
    }
    let (status, _) = call(&st, None, None).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    let events = refusals(&bus);
    assert_eq!(events.len(), 6, "{events:?}");
    for e in &events {
        assert_eq!(e["agent_id"], "agent://unidentified.invalid/caller", "{e}");
        assert!(e["data"]["agent_id"].is_null(), "no agent was claimed: {e}");
    }
    assert_eq!(events[5]["data"]["reason"], "missing_key");
}
