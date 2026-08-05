//! End-to-end test of the ingest path: a JSON batch shaped exactly like a
//! gateway `CloudSink` POST (`{"records":[…]}`) flows through `/v1/ingest`,
//! authorizes by bearer key, and lands in the store's per-org aggregates.

use std::collections::HashMap;
use std::sync::Arc;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use http_body_util::BodyExt;
use tower::ServiceExt;

use tokenfuse_cloud::{app, AppState, Principal, Store};

fn state_with(store: Arc<Store>) -> AppState {
    let mut keys = HashMap::new();
    keys.insert(
        "k".to_string(),
        Principal {
            org: "acme".into(),
            role: "admin".into(),
        },
    );
    // A read-only credential for the SAME org. Every other test here uses the
    // admin key; this one exists so the ingest route can be pinned against the
    // role that must not reach it.
    keys.insert(
        "viewerkey".to_string(),
        Principal {
            org: "acme".into(),
            role: "viewer".into(),
        },
    );
    AppState::new(store, Arc::new(keys), 0.8)
}

#[tokio::test]
async fn ingest_authorized_aggregates_into_store() {
    let store = Arc::new(Store::new());
    let router = app(state_with(Arc::clone(&store)));

    // Exactly the shape crates/gateway/src/cloudsink.rs POSTs (`unit` is the
    // docs/20-identity-map.md section 4 addition - additive, so it rides
    // along on the same batch as every other field).
    let payload = r#"{"records":[
        {"ts_millis":100,"run_id":"r1","model":"claude","decision":"allow","input_tokens":10,"output_tokens":5,"cost_microusd":1000,"step":1,"unit":"treasury"},
        {"ts_millis":200,"run_id":"r1","model":"claude","decision":"cache_hit","input_tokens":0,"output_tokens":0,"cost_microusd":0,"step":2,"unit":"treasury"}
    ]}"#;

    let resp = router
        .oneshot(
            Request::post("/v1/ingest")
                .header("authorization", "Bearer k")
                .header("content-type", "application/json")
                .body(Body::from(payload))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(resp.status(), StatusCode::OK);
    let bytes = resp.into_body().collect().await.unwrap().to_bytes();
    let v: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(v["accepted"], 2);

    let runs = store.runs("acme");
    assert_eq!(runs.len(), 1);
    assert_eq!(runs[0].spent_microusd, 1000);
    assert_eq!(runs[0].calls, 2);
    assert_eq!(runs[0].cache_hits, 1);
    assert_eq!(runs[0].steps, 2);
    assert_eq!(runs[0].unit, "treasury");
}

/// A gateway that predates docs/20-identity-map.md simply omits `unit` -
/// additive means the batch still ingests, and the run's `unit` stays empty
/// (folded into the "unassigned" bucket by `Store::units`, never a hard error).
#[tokio::test]
async fn ingest_without_unit_is_additive() {
    let store = Arc::new(Store::new());
    let router = app(state_with(Arc::clone(&store)));

    let payload = r#"{"records":[
        {"ts_millis":100,"run_id":"r1","model":"claude","decision":"allow","cost_microusd":1000,"step":1}
    ]}"#;

    let resp = router
        .oneshot(
            Request::post("/v1/ingest")
                .header("authorization", "Bearer k")
                .header("content-type", "application/json")
                .body(Body::from(payload))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(resp.status(), StatusCode::OK);
    let runs = store.runs("acme");
    assert_eq!(runs.len(), 1);
    assert_eq!(runs[0].unit, "");
    let units = store.units("acme");
    assert_eq!(units.len(), 1);
    assert_eq!(units[0].unit, "unassigned");
}

/// I1 (docs/21-tool-runs.md): `tool_calls` on the wire (exactly what a
/// NEW gateway's `CloudSink` would POST) rolls up into the run and the
/// org-wide summary total.
#[tokio::test]
async fn ingest_with_tool_calls_rolls_up_into_runs_and_summary() {
    let store = Arc::new(Store::new());
    let router = app(state_with(Arc::clone(&store)));

    let payload = r#"{"records":[
        {"ts_millis":100,"run_id":"r1","model":"claude","decision":"allow","cost_microusd":1000,"step":1,"tool_calls":2},
        {"ts_millis":200,"run_id":"r1","model":"claude","decision":"allow","cost_microusd":1000,"step":2,"tool_calls":0}
    ]}"#;

    let resp = router
        .oneshot(
            Request::post("/v1/ingest")
                .header("authorization", "Bearer k")
                .header("content-type", "application/json")
                .body(Body::from(payload))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(resp.status(), StatusCode::OK);
    let runs = store.runs("acme");
    assert_eq!(runs.len(), 1);
    assert_eq!(runs[0].tool_calls, 2);
    let summary = store.summary("acme");
    assert_eq!(summary.tool_calls, 2);
}

/// A gateway that predates I1 simply omits `tool_calls` - additive means the
/// batch still ingests, and the run's `tool_calls` stays at 0 (an unknown
/// observation contributes nothing, never a hard error).
#[tokio::test]
async fn ingest_without_tool_calls_is_additive() {
    let store = Arc::new(Store::new());
    let router = app(state_with(Arc::clone(&store)));

    let payload = r#"{"records":[
        {"ts_millis":100,"run_id":"r1","model":"claude","decision":"allow","cost_microusd":1000,"step":1}
    ]}"#;

    let resp = router
        .oneshot(
            Request::post("/v1/ingest")
                .header("authorization", "Bearer k")
                .header("content-type", "application/json")
                .body(Body::from(payload))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(resp.status(), StatusCode::OK);
    let runs = store.runs("acme");
    assert_eq!(runs.len(), 1);
    assert_eq!(runs[0].tool_calls, 0);
}

#[tokio::test]
async fn ingest_without_a_key_is_unauthorized() {
    let router = app(state_with(Arc::new(Store::new())));
    let resp = router
        .oneshot(
            Request::post("/v1/ingest")
                .body(Body::from(r#"{"records":[]}"#))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
}

/// A read-only credential may not write telemetry.
///
/// Ingest is a WRITE, and it was authorized as a read: `org_for` resolves any
/// principal that maps to an org, so a viewer key, a paired device token of
/// any role, and a viewer-scoped OIDC token all reached it. The role exists to
/// say what a credential may change, and everything this route accepts becomes
/// state the org is then graded on.
#[tokio::test]
async fn a_viewer_key_cannot_ingest() {
    let store = Arc::new(Store::new());
    let router = app(state_with(Arc::clone(&store)));

    let payload = r#"{"records":[
        {"ts_millis":100,"run_id":"r1","model":"claude","decision":"allow","cost_microusd":1000,"step":1}
    ]}"#;

    let resp = router
        .oneshot(
            Request::post("/v1/ingest")
                .header("authorization", "Bearer viewerkey")
                .header("content-type", "application/json")
                .body(Body::from(payload))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(
        resp.status(),
        StatusCode::FORBIDDEN,
        "a read-only key must be refused at the ingest route, not merely resolved to an org"
    );
    assert!(
        store.runs("acme").is_empty(),
        "nothing the refused caller sent may reach the store"
    );
}

/// The reason the role matters, end to end.
///
/// Ingested records are not inert evidence: three of them, with a decision
/// this plane recognizes and a `run_id` the caller picked, raise a High
/// `budget_exhausted` incident (`Store::ingest_at`, `budget_blocks` = 3 by
/// default). That incident is exported as a Critical agent-event into the
/// shared NDJSON log and mailed to a human by heraldyx, and the same records
/// feed the `decision_counts` that `/v1/compliance` grades an org's controls
/// from. So a read-only credential could wake somebody at three in the morning
/// about a budget that was never touched, and manufacture regulator-facing
/// evidence that a control fired.
///
/// The admin arm is not decoration: it proves the payload really does trip the
/// detector, so the viewer arm is refused authorization rather than merely
/// failing to reach a threshold.
#[tokio::test]
async fn a_viewer_cannot_manufacture_a_budget_exhausted_incident() {
    const BLOCKS: &str = r#"{"records":[
        {"run_id":"forged","model":"claude","decision":"budget_exceeded","cost_microusd":0,"step":1,"agent_id":"agent://bank.example/treasury/recon"},
        {"run_id":"forged","model":"claude","decision":"budget_exceeded","cost_microusd":0,"step":2,"agent_id":"agent://bank.example/treasury/recon"},
        {"run_id":"forged","model":"claude","decision":"budget_exceeded","cost_microusd":0,"step":3,"agent_id":"agent://bank.example/treasury/recon"}
    ]}"#;

    let store = Arc::new(Store::new());
    let state = state_with(Arc::clone(&store));

    let resp = app(state.clone())
        .oneshot(
            Request::post("/v1/ingest")
                .header("authorization", "Bearer viewerkey")
                .header("content-type", "application/json")
                .body(Body::from(BLOCKS))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);
    assert!(
        store.incidents("acme").is_empty(),
        "a read-only credential must not be able to raise an incident that pages a human \
         and grades a compliance control"
    );

    // The same batch from an admin credential still does everything it always
    // did: the route is gated, not broken.
    let resp = app(state)
        .oneshot(
            Request::post("/v1/ingest")
                .header("authorization", "Bearer k")
                .header("content-type", "application/json")
                .body(Body::from(BLOCKS))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let incidents = store.incidents("acme");
    assert_eq!(
        incidents.len(),
        1,
        "the payload really does trip a detector"
    );
    assert_eq!(incidents[0].kind, "budget_exhausted");
    assert_eq!(
        store.decision_counts("acme").get("budget_exceeded"),
        Some(&3),
        "and really does land in the counts /v1/compliance grades controls from"
    );
}

#[tokio::test]
async fn healthz_is_ok() {
    let router = app(state_with(Arc::new(Store::new())));
    let resp = router
        .oneshot(Request::get("/healthz").body(Body::empty()).unwrap())
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
}
