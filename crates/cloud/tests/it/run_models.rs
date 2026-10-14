//! Invariant 111: the fleet view keeps every model a run used, how often the
//! run changed model, the model of its LATEST call by time rather than by
//! arrival, and a run a gateway refused as killed reads killed.
//!
//! Measured 2026-10-14 on forge: an Opus then Haiku run with 96% of its spend
//! on Opus read as `claude-haiku-5-5`, and the console's copilot said the run
//! "used claude-haiku-5-5"; a kill made on one gateway's own admin route left
//! the Cloud row `killed: false`.

use std::collections::HashMap;
use std::sync::Arc;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use http_body_util::BodyExt;
use serde_json::Value;
use tower::ServiceExt;

use tokenfuse_cloud::{app, AppState, Principal, Store};

fn state(store: Arc<Store>) -> AppState {
    let mut keys = HashMap::new();
    keys.insert(
        "k".to_string(),
        Principal {
            org: "acme".into(),
            role: "admin".into(),
            site: None,
        },
    );
    AppState::new(store, Arc::new(keys), 0.8)
}

async fn send(store: &Arc<Store>, method: &str, uri: &str, body: &str) -> (StatusCode, Value) {
    let resp = app(state(Arc::clone(store)))
        .oneshot(
            Request::builder()
                .method(method)
                .uri(uri)
                .header("authorization", "Bearer k")
                .header("content-type", "application/json")
                .body(Body::from(body.to_string()))
                .unwrap(),
        )
        .await
        .unwrap();
    let status = resp.status();
    let bytes = resp.into_body().collect().await.unwrap().to_bytes();
    (
        status,
        serde_json::from_slice(&bytes).unwrap_or(Value::Null),
    )
}

fn record(ts: i64, run: &str, model: &str, decision: &str, cost: i64) -> String {
    format!(
        r#"{{"ts_millis":{ts},"run_id":"{run}","model":"{model}","decision":"{decision}","input_tokens":10,"output_tokens":5,"cost_microusd":{cost},"step":1}}"#
    )
}

async fn run_row(store: &Arc<Store>, run: &str) -> Value {
    let (_, runs) = send(store, "GET", "/v1/runs", "").await;
    runs.as_array()
        .and_then(|a| a.iter().find(|r| r["run_id"] == run).cloned())
        .unwrap_or_else(|| panic!("no row for {run}: {runs}"))
}

#[tokio::test]
async fn a_run_that_changed_model_says_which_and_how_often() {
    let store = Arc::new(Store::new());
    // The forge run, Opus then Haiku, pushed newest first: arrival order must
    // not decide which model the row names.
    let batch = format!(
        r#"{{"records":[{},{},{}]}}"#,
        record(3000, "r-switch", "claude-haiku-5-5", "allow", 6),
        record(1000, "r-switch", "claude-opus-5-5", "allow", 152),
        record(2000, "r-switch", "claude-opus-5-5", "allow", 152),
    );
    let (status, _) = send(&store, "POST", "/v1/ingest", &batch).await;
    assert_eq!(status, StatusCode::OK);
    let row = run_row(&store, "r-switch").await;
    assert_eq!(
        row["model"], "claude-haiku-5-5",
        "the latest call by time: {row}"
    );
    assert_eq!(
        row["models"],
        serde_json::json!([
            {"model": "claude-haiku-5-5", "calls": 1, "spent_microusd": 6},
            {"model": "claude-opus-5-5", "calls": 2, "spent_microusd": 304}
        ]),
        "{row}"
    );
    assert_eq!(row["model_switches"], 1, "{row}");

    // A later call on Opus again: a second change.
    let (status, _) = send(
        &store,
        "POST",
        "/v1/ingest",
        &format!(
            r#"{{"records":[{}]}}"#,
            record(4000, "r-switch", "claude-opus-5-5", "allow", 152)
        ),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let row = run_row(&store, "r-switch").await;
    assert_eq!(row["model"], "claude-opus-5-5");
    assert_eq!(row["model_switches"], 2, "{row}");
}

#[tokio::test]
async fn an_older_record_never_takes_the_model_from_a_later_call() {
    let store = Arc::new(Store::new());
    for rec in [
        record(5000, "r-late", "claude-opus-5-5", "allow", 10),
        record(1000, "r-late", "claude-haiku-5-5", "allow", 1),
    ] {
        let (status, _) = send(
            &store,
            "POST",
            "/v1/ingest",
            &format!(r#"{{"records":[{rec}]}}"#),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
    }
    let row = run_row(&store, "r-late").await;
    assert_eq!(row["model"], "claude-opus-5-5", "{row}");
    assert_eq!(row["models"].as_array().map(Vec::len), Some(2), "{row}");
}

#[tokio::test]
async fn a_refusal_names_no_model_the_run_used_and_changes_nothing() {
    let store = Arc::new(Store::new());
    let batch = format!(
        r#"{{"records":[{},{}]}}"#,
        record(1000, "r-ref", "claude-haiku-5-5", "allow", 4),
        record(2000, "r-ref", "claude-opus-5-5", "budget_exceeded", 0),
    );
    let (status, _) = send(&store, "POST", "/v1/ingest", &batch).await;
    assert_eq!(status, StatusCode::OK);
    let row = run_row(&store, "r-ref").await;
    assert_eq!(
        row["models"],
        serde_json::json!([{"model": "claude-haiku-5-5", "calls": 1, "spent_microusd": 4}]),
        "a refused call did not use a model: {row}"
    );
    assert_eq!(row["model_switches"], 0, "{row}");
}

#[tokio::test]
async fn a_run_a_gateway_refused_as_killed_reads_killed() {
    let store = Arc::new(Store::new());
    let batch = format!(
        r#"{{"records":[{},{}]}}"#,
        record(1000, "r-local-kill", "claude-haiku-5-5", "allow", 4),
        record(2000, "r-local-kill", "claude-haiku-5-5", "killed", 0),
    );
    let (status, _) = send(&store, "POST", "/v1/ingest", &batch).await;
    assert_eq!(status, StatusCode::OK);
    let row = run_row(&store, "r-local-kill").await;
    assert_eq!(row["killed"], true, "a gateway refused it as killed: {row}");
    let (_, kills) = send(&store, "GET", "/v1/kills", "").await;
    assert!(
        !kills.to_string().contains("r-local-kill"),
        "a gateway's kill is shown, not added to the Cloud's own kill list: {kills}"
    );
}
