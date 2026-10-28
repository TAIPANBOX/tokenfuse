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
//!
//! The same holds at a door that requires an agent token
//! (`TOKENFUSE_AGENT_TOKENS=require`). Measured 2026-10-28 on a v1.20.1
//! gateway in that mode: an unknown key and no key were answered with a 401
//! of type `agent_token_required` and reached the bus not at all, so a key
//! scan against the managed door was the one nobody could see. The
//! `under_require_` tests below hold that door to the same record, and to the
//! same answer.

use axum::body::Body;
use axum::http::{Request, StatusCode};
use sha2::{Digest, Sha256};
use std::path::PathBuf;
use std::sync::Arc;
use tokenfuse_core::{Ledger, Mode, Policy};
use tokenfuse_delegation::testing::{cfg, Key};
use tokenfuse_gateway::agenttoken::{AgentTokens, Mode as TokenMode};
use tokenfuse_gateway::chainproof::Proving;
use tokenfuse_gateway::clientkeys::ClientKeys;
use tokenfuse_gateway::events::EventExporter;
use tokenfuse_gateway::provider::StubProvider;
use tokenfuse_gateway::state::AppState;
use tower::ServiceExt;

const GOOD: &str = "sk-gateway-good-0123456789";
const AGENT: &str = "agent://test/scanner";
const ORIGIN: &str = "https://tokenfuse.acme.example";

fn gateway(tag: &str) -> (AppState, PathBuf) {
    build(tag, true, None)
}

/// The same gateway with the agent-token door in `require`; `listed` are the
/// static client key ids it admits (invariant 138). `GOOD` is the key id
/// `billing`.
fn require_gateway(tag: &str, listed: &[&str]) -> (AppState, PathBuf) {
    let allow = listed.iter().map(|s| s.to_string()).collect();
    build(
        tag,
        true,
        Some(AgentTokens::with_static_keys(TokenMode::Require, allow)),
    )
}

/// A gateway with client keys configured or not, and the agent-token door
/// `door` when there is one, behind the delegation door it verifies against.
fn build(tag: &str, client_keys: bool, door: Option<AgentTokens>) -> (AppState, PathBuf) {
    let dir = std::env::temp_dir().join(format!("tf-refused-key-{}-{tag}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join("events.ndjson");
    let _ = std::fs::remove_file(&path);
    let exp = Arc::new(EventExporter::open(path.to_str().unwrap()).unwrap());
    let mut st = AppState::new(
        Arc::new(Ledger::new()),
        Arc::new(tokenfuse_gateway::pricebook::default_price_book()),
        Arc::new(Policy {
            mode: Mode::Enforce,
            ..Default::default()
        }),
        Arc::new(StubProvider::default()),
        "refused-key-test",
    );
    st = st.with_events(exp);
    if client_keys {
        let keys = Arc::new(ClientKeys::from_spec(&format!("{GOOD}:billing")).unwrap());
        st = st.with_client_keys(keys);
    }
    if let Some(door) = door {
        let proving = Proving {
            cfg: cfg(&Key::new()),
            origins: vec![ORIGIN.to_string()],
        };
        st = st.with_chain_proof(Some(Arc::new(proving)), None);
        st = st.with_agent_tokens(Some(Arc::new(door)));
    }
    (st, path)
}

/// What a caller sees of an answer: the status, the headers and the body bytes.
type Seen = (StatusCode, axum::http::HeaderMap, Vec<u8>);

async fn read_response(resp: axum::response::Response) -> Seen {
    let (parts, body) = resp.into_parts();
    let bytes = axum::body::to_bytes(body, 1 << 16).await.unwrap();
    (parts.status, parts.headers, bytes.to_vec())
}

/// The headers a caller keys on, as lines, so two answers compare by them.
fn keyed_headers(h: &axum::http::HeaderMap) -> Vec<String> {
    let mut out = Vec::new();
    for name in ["content-type", "x-fuse", "www-authenticate"] {
        let value = h.get(name).and_then(|v| v.to_str().ok());
        out.push(format!("{name}: {}", value.unwrap_or("-")));
    }
    out
}

async fn call(st: &AppState, key: Option<&str>, agent: Option<&str>) -> (StatusCode, String) {
    let (status, _, bytes) = call_seen(st, key, agent).await;
    (status, String::from_utf8_lossy(&bytes).into_owned())
}

async fn call_seen(st: &AppState, key: Option<&str>, agent: Option<&str>) -> Seen {
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
    read_response(resp).await
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

// ---------------------------------------------------------------------------
// The door that requires an agent token (`TOKENFUSE_AGENT_TOKENS=require`).
//
// Invariant 105 holds here too. The refusal has another body (invariant 138)
// and the rule is the same: the caller's answer is exactly what it was, and
// the operator's record learns the cause.
// ---------------------------------------------------------------------------

/// The answer this door gives a call with no agent token, as it builds it:
/// what every `under_require_` refusal is held to, byte for byte.
async fn the_required_answer() -> Seen {
    let required = tokenfuse_gateway::agenttoken::required_response();
    read_response(required).await
}

fn assert_the_required_answer(got: &Seen, want: &Seen, what: &str) {
    assert_eq!(got.0, StatusCode::UNAUTHORIZED, "{what}");
    assert_eq!(got.0, want.0, "{what}");
    let (got_headers, want_headers) = (keyed_headers(&got.1), keyed_headers(&want.1));
    assert_eq!(got_headers, want_headers, "{what}: headers");
    assert_eq!(got.2, want.2, "{what}: body");
}

#[tokio::test]
async fn under_require_a_missing_key_and_an_unknown_key_are_on_the_bus_by_reason() {
    let (st, bus) = require_gateway("req-reasons", &[]);
    let want = the_required_answer().await;
    let no_key = call_seen(&st, None, Some(AGENT)).await;
    let wrong_key = call_seen(&st, Some("sk-wrong-key-77"), Some(AGENT)).await;

    // The answer is what it was: one 401 and one body, whichever the cause.
    assert_the_required_answer(&no_key, &want, "no key");
    assert_the_required_answer(&wrong_key, &want, "an unknown key");
    assert_eq!(no_key.2, wrong_key.2);
    let body: serde_json::Value = serde_json::from_slice(&no_key.2).unwrap();
    assert_eq!(body["error"]["type"], "agent_token_required", "{body}");

    // The record learns which cause it was.
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
    let record = std::fs::read_to_string(&bus).unwrap();
    assert!(
        !record.contains("sk-wrong-key-77"),
        "the presented key never reaches the record: {record}"
    );
}

/// The record at this door is the record the open door writes: the same
/// fields, the same reason words, the same data.
#[tokio::test]
async fn under_require_the_record_has_the_shape_the_open_door_gives() {
    fn shape(e: &serde_json::Value) -> (Vec<String>, serde_json::Value) {
        let mut keys: Vec<String> = e.as_object().unwrap().keys().cloned().collect();
        keys.sort();
        let fields = serde_json::json!({
            "type": e["type"],
            "severity": e["severity"],
            "agent_id": e["agent_id"],
            "run_id": e["run_id"],
            "data": e["data"],
        });
        (keys, fields)
    }
    let (open, open_bus) = gateway("shape-open");
    let (required, required_bus) = require_gateway("shape-require", &[]);
    for st in [&open, &required] {
        call(st, None, Some(AGENT)).await;
        call(st, Some("sk-wrong-key-77"), Some(AGENT)).await;
    }
    let from_open = refusals(&open_bus);
    let from_required = refusals(&required_bus);
    assert_eq!(from_open.len(), 2, "{from_open:?}");
    assert_eq!(from_required.len(), 2, "{from_required:?}");
    for (a, b) in from_open.iter().zip(from_required.iter()) {
        assert_eq!(shape(a), shape(b), "{a} against {b}");
    }
}

#[tokio::test]
async fn under_require_the_same_key_tried_again_and_again_is_one_event() {
    let (st, bus) = require_gateway("req-same", &[]);
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
async fn under_require_a_scan_of_many_keys_cannot_flood_the_bus() {
    let (st, bus) = require_gateway("req-scan", &[]);
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
async fn under_require_a_scan_that_names_no_agent_is_on_the_bus_too() {
    let (st, bus) = require_gateway("req-anonymous", &[]);
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

/// With no client keys configured the door's only credential is the agent
/// token, and a call with none is still a refused call an operator wants to
/// see. A key header presented to a gateway that configures none is unknown.
#[tokio::test]
async fn under_require_with_no_client_keys_a_call_with_no_credential_is_on_the_bus_too() {
    let door = AgentTokens::new(TokenMode::Require);
    let (st, bus) = build("req-nokeys", false, Some(door));
    let want = the_required_answer().await;
    let no_key = call_seen(&st, None, None).await;
    let stray_key = call_seen(&st, Some("sk-stray-key-5"), None).await;
    assert_the_required_answer(&no_key, &want, "no credential");
    assert_the_required_answer(&stray_key, &want, "a key no one configured");
    let events = refusals(&bus);
    assert_eq!(events.len(), 2, "{events:?}");
    assert_eq!(events[0]["data"]["reason"], "missing_key");
    assert_eq!(events[1]["data"]["reason"], "unknown_key");
    assert_eq!(
        events[1]["data"]["key_fingerprint"],
        fingerprint_of("sk-stray-key-5")
    );
    for e in &events {
        assert_eq!(e["agent_id"], "agent://unidentified.invalid/caller", "{e}");
    }
}

/// The control: a key the operator lists is admitted at this door, and an
/// admitted call writes no refusal.
#[tokio::test]
async fn under_require_a_listed_key_writes_no_refusal() {
    let (st, bus) = require_gateway("req-listed", &["billing"]);
    let (status, body) = call(&st, Some(GOOD), Some(AGENT)).await;
    assert_ne!(status, StatusCode::UNAUTHORIZED, "{body}");
    assert!(refusals(&bus).is_empty());
}

/// A key the gateway knows and the operator did not list is refused, and it is
/// not an unknown key: calling it one would put a false record on the bus and
/// a fingerprint of a real secret beside it.
#[tokio::test]
async fn under_require_a_known_key_that_is_not_listed_is_never_filed_as_an_unknown_one() {
    let (st, bus) = require_gateway("req-unlisted", &[]);
    let want = the_required_answer().await;
    let got = call_seen(&st, Some(GOOD), Some(AGENT)).await;
    assert_the_required_answer(&got, &want, "a known key that is not listed");
    for e in &refusals(&bus) {
        assert_ne!(e["data"]["reason"], "unknown_key", "{e}");
    }
    let record = std::fs::read_to_string(&bus).unwrap_or_default();
    assert!(!record.contains(GOOD), "the key never reaches the record");
    let fingerprint = fingerprint_of(GOOD);
    assert!(!record.contains(&fingerprint), "nor a fingerprint of it");
}
