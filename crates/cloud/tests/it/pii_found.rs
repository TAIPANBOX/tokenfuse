//! Invariant 106: PII a gateway found in a prompt and let through (shadow or
//! mask) reaches the fleet view as kinds and counts, so a dashboard can show
//! what shadow mode is finding. Until 2026-10-14 a shadow finding was a
//! response note to the agent and nothing else.

use std::collections::HashMap;
use std::sync::Arc;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use http_body_util::BodyExt;
use tower::ServiceExt;

use tokenfuse_cloud::keys::digest;
use tokenfuse_cloud::{app, AppState, Principal, Store};

fn state(store: Arc<Store>) -> AppState {
    let mut keys = HashMap::new();
    keys.insert(
        digest("k"),
        Principal {
            org: "acme".into(),
            role: "admin".into(),
            site: None,
        },
    );
    AppState::new(store, Arc::new(keys), 0.8)
}

async fn send(
    store: &Arc<Store>,
    method: &str,
    uri: &str,
    body: Option<&str>,
) -> (StatusCode, serde_json::Value) {
    let router = app(state(Arc::clone(store)));
    let req = Request::builder()
        .method(method)
        .uri(uri)
        .header("authorization", "Bearer k")
        .header("content-type", "application/json")
        .body(Body::from(body.unwrap_or("").to_string()))
        .unwrap();
    let resp = router.oneshot(req).await.unwrap();
    let status = resp.status();
    let bytes = resp.into_body().collect().await.unwrap().to_bytes();
    (
        status,
        serde_json::from_slice(&bytes).unwrap_or(serde_json::Value::Null),
    )
}

#[tokio::test]
async fn pii_a_gateway_let_through_reaches_the_runs_and_summary_reads() {
    let store = Arc::new(Store::new());
    let payload = r#"{"records":[
        {"ts_millis":100,"run_id":"r-shadow","model":"m","decision":"allow","input_tokens":10,"output_tokens":5,"cost_microusd":10,"step":1,"pii_findings":"pii_card=1,pii_email=2"},
        {"ts_millis":200,"run_id":"r-shadow","model":"m","decision":"allow","input_tokens":10,"output_tokens":5,"cost_microusd":10,"step":2,"pii_findings":"pii_email=1"},
        {"ts_millis":300,"run_id":"r-clean","model":"m","decision":"allow","input_tokens":10,"output_tokens":5,"cost_microusd":10,"step":1}
    ]}"#;
    let (status, _) = send(&store, "POST", "/v1/ingest", Some(payload)).await;
    assert_eq!(status, StatusCode::OK);
    let (_, runs) = send(&store, "GET", "/v1/runs", None).await;
    let run = |id: &str| {
        runs.as_array()
            .unwrap()
            .iter()
            .find(|r| r["run_id"] == id)
            .cloned()
            .unwrap_or_default()
    };
    assert_eq!(run("r-shadow")["pii_calls"], 2, "{runs}");
    assert_eq!(run("r-clean")["pii_calls"], 0, "{runs}");
    let (_, sum) = send(&store, "GET", "/v1/summary", None).await;
    assert_eq!(sum["pii_calls"], 2, "{sum}");
    assert_eq!(
        sum["pii_kinds"],
        serde_json::json!([{"kind": "pii_email", "calls": 2}, {"kind": "pii_card", "calls": 1}]),
        "{sum}"
    );
}

#[tokio::test]
async fn a_findings_string_without_the_scanners_shape_is_not_counted() {
    let store = Arc::new(Store::new());
    let payload = r#"{"records":[
        {"ts_millis":100,"run_id":"r-x","model":"m","decision":"allow","input_tokens":1,"output_tokens":1,"cost_microusd":1,"step":1,"pii_findings":"<img src=x>=1,PII_EMAIL=3,pii_email=0,pii_card=999999999,=,pii_="},
        {"ts_millis":200,"run_id":"r-y","model":"m","decision":"budget_exceeded","input_tokens":0,"output_tokens":0,"cost_microusd":0,"step":1,"pii_findings":"pii_email=1"}
    ]}"#;
    let (status, _) = send(&store, "POST", "/v1/ingest", Some(payload)).await;
    assert_eq!(status, StatusCode::OK);
    let (_, sum) = send(&store, "GET", "/v1/summary", None).await;
    assert_eq!(
        sum["pii_calls"], 0,
        "nothing shaped like the scanner's output, and a refused call is not a forwarded one: {sum}"
    );
    assert_eq!(sum["pii_kinds"], serde_json::json!([]), "{sum}");
}
