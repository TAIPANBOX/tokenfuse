//! HTTP-level tests for `run_stalled` (invariant 60): the incidents endpoint
//! and the SSE stream see a stall the same way they see any other incident.
//! Keys and the `get` helper are the `tests/reads.rs:14-60` shape; the SSE
//! draining loop is the `tests/streaming.rs:101-155` shape.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use axum::body::Body;
use axum::http::{Request, StatusCode};
use http_body_util::BodyExt;
use tower::ServiceExt;

use tokenfuse_cloud::{app, AppState, CallRecord, IncidentConfig, Principal, Store};

const PLANNER: &str = "agent://acme.example/planner";

fn now_ms() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_millis() as i64
}

fn call_at(run: &str, agent: &str, step: u32, ts: i64) -> CallRecord {
    CallRecord {
        run_id: run.into(),
        agent_id: agent.into(),
        decision: "allow".into(),
        cost_microusd: 1,
        step,
        ts_millis: ts,
        ..Default::default()
    }
}

/// A store with the stall floor set to one millisecond, so a short, real
/// sleep is enough silence to trip the detector without a test waiting on
/// the production default of five minutes.
fn state_with_a_fast_stall_floor() -> (AppState, Arc<Store>) {
    let store = Arc::new(Store::with_incident_config(IncidentConfig {
        stall_after_ms: 1,
        ..Default::default()
    }));
    let mut keys = HashMap::new();
    keys.insert(
        "devkey".into(),
        Principal {
            org: "acme".into(),
            role: "admin".into(),
        },
    );
    keys.insert(
        "viewerkey".into(),
        Principal {
            org: "acme".into(),
            role: "viewer".into(),
        },
    );
    (
        AppState::new(Arc::clone(&store), Arc::new(keys), 0.8),
        store,
    )
}

/// GET a path with an optional bearer key; returns (status, parsed JSON body).
async fn get(state: &AppState, path: &str, key: Option<&str>) -> (StatusCode, serde_json::Value) {
    let mut req = Request::get(path);
    if let Some(k) = key {
        req = req.header("authorization", format!("Bearer {k}"));
    }
    let resp = app(state.clone())
        .oneshot(req.body(Body::empty()).unwrap())
        .await
        .unwrap();
    let status = resp.status();
    let bytes = resp.into_body().collect().await.unwrap().to_bytes();
    let v = serde_json::from_slice(&bytes).unwrap_or(serde_json::Value::Null);
    (status, v)
}

#[tokio::test]
async fn a_stalled_run_is_listed_on_the_incidents_endpoint_for_a_viewer() {
    let (state, store) = state_with_a_fast_stall_floor();
    let t0 = now_ms();
    store.ingest("acme", &[call_at("r1", PLANNER, 6, t0)]);
    store.ingest("acme", &[call_at("r1", PLANNER, 7, t0 + 1)]);
    tokio::time::sleep(Duration::from_millis(100)).await;
    store.sweep_stalled();

    let (status, body) = get(&state, "/v1/incidents", Some("viewerkey")).await;
    assert_eq!(status, StatusCode::OK);
    let arr = body.as_array().expect("incidents is an array");
    assert_eq!(arr.len(), 1, "incidents: {body}");
    assert_eq!(arr[0]["kind"], "run_stalled");
    assert_eq!(arr[0]["severity"], "medium");
    assert_eq!(arr[0]["run_id"], "r1");
    assert_eq!(arr[0]["agent_id"], PLANNER);
    assert!(arr[0]["summary"]
        .as_str()
        .unwrap_or_default()
        .contains("went quiet"));
}

#[tokio::test]
async fn a_stalled_run_reaches_the_sse_stream() {
    let (state, store) = state_with_a_fast_stall_floor();

    let resp = app(state.clone())
        .oneshot(
            Request::get("/v1/stream")
                .header("authorization", "Bearer devkey")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let mut body = resp.into_body();

    let t0 = now_ms();
    store.ingest("acme", &[call_at("r1", PLANNER, 6, t0)]);
    store.ingest("acme", &[call_at("r1", PLANNER, 7, t0 + 1)]);
    tokio::time::sleep(Duration::from_millis(100)).await;
    store.sweep_stalled();

    let mut acc = String::new();
    for _ in 0..20 {
        match tokio::time::timeout(Duration::from_secs(2), body.frame()).await {
            Ok(Some(Ok(f))) => {
                if let Ok(data) = f.into_data() {
                    acc.push_str(&String::from_utf8_lossy(&data));
                    if acc.contains("\"type\":\"incident\"") {
                        break;
                    }
                }
            }
            _ => break,
        }
    }
    assert!(acc.contains("\"type\":\"incident\""), "sse stream:\n{acc}");
    assert!(acc.contains("run_stalled:r1"), "sse stream:\n{acc}");
}
