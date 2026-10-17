//! `/v1/fuse/check-tool-call` answers only for the caller's own runs once
//! client keys are configured (agent-security review 2026-10-17, F-024),
//! through the real router.
//!
//! Measured 2026-10-17 against a deployed configuration (client keys on): the
//! route answered a caller with no credential at all, for a run another caller
//! had opened, with that run's taint labels. The labels say what the run read
//! (`web`, `secrets`, `suspected_injection`), which is the one thing an
//! attacker steering a run wants to know.

use axum::body::Body;
use axum::http::{Request, StatusCode};
use std::sync::Arc;
use tokenfuse_core::taint::FirewallMode;
use tokenfuse_core::{Ledger, Mode, ModelPrice, Policy, PriceBook};
use tokenfuse_gateway::clientkeys::{ClientKeys, CLIENT_KEY_HEADER};
use tokenfuse_gateway::firewall::FirewallConfig;
use tokenfuse_gateway::provider::StubProvider;
use tokenfuse_gateway::state::AppState;
use tokenfuse_gateway::wire::Wire;
use tower::ServiceExt;

const TEXT_ONLY: &str = r#"{"content":[{"type":"text","text":"done"}]}"#;

fn gateway(keys: Option<&str>) -> AppState {
    let prices = PriceBook::new().with(
        "test-model",
        ModelPrice::per_mtok_usd(3.0, 15.0, 0.30, 3.75),
    );
    let st = AppState::new(
        Arc::new(Ledger::new()),
        Arc::new(prices),
        Arc::new(Policy {
            mode: Mode::Shadow,
            ..Default::default()
        }),
        Arc::new(StubProvider {
            body_override: Some(TEXT_ONLY.into()),
            ..StubProvider::default()
        }),
        "check-owner-test",
    )
    .with_wire(Wire::Anthropic)
    .with_firewall(Arc::new(FirewallConfig::defaults(FirewallMode::Enforce)));
    match keys {
        Some(spec) => st.with_client_keys(Arc::new(
            ClientKeys::from_spec(spec).expect("a usable key spec"),
        )),
        None => st,
    }
}

/// A metered call that reads the web in run `run`, made with `key`.
async fn open_web_run(st: &AppState, run: &str, key: Option<&str>) {
    let body = serde_json::json!({"model":"test-model","max_tokens":100,"messages":[
        {"role":"user","content":"hi"},
        {"role":"assistant","content":[{"type":"tool_use","id":"w1","name":"web_search","input":{}}]},
        {"role":"user","content":[{"type":"tool_result","tool_use_id":"w1","content":"ok"}]},
        {"role":"user","content":"continue"}
    ]})
    .to_string();
    let mut req = Request::post("/v1/messages")
        .header("content-type", "application/json")
        .header("x-fuse-run-id", run)
        .header("x-fuse-agent-id", "agent://test.local/owner")
        .header("x-fuse-budget-usd", "5.0");
    if let Some(k) = key {
        req = req.header(CLIENT_KEY_HEADER, k);
    }
    let resp = tokenfuse_gateway::app(st.clone())
        .oneshot(req.body(Body::from(body)).unwrap())
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK, "the run must open");
}

async fn check(st: &AppState, run: &str, key: Option<&str>) -> (StatusCode, serde_json::Value) {
    let mut req = Request::post("/v1/fuse/check-tool-call")
        .header("content-type", "application/json")
        .header("x-fuse-agent-id", "agent://test.local/asker");
    if let Some(k) = key {
        req = req.header(CLIENT_KEY_HEADER, k);
    }
    let body = serde_json::json!({"run_id": run, "tool": "run_shell"}).to_string();
    let resp = tokenfuse_gateway::app(st.clone())
        .oneshot(req.body(Body::from(body)).unwrap())
        .await
        .unwrap();
    let status = resp.status();
    let bytes = http_body_util::BodyExt::collect(resp.into_body())
        .await
        .unwrap()
        .to_bytes();
    (
        status,
        serde_json::from_slice(&bytes).unwrap_or(serde_json::Value::Null),
    )
}

#[tokio::test]
async fn a_check_about_another_keys_run_says_nothing_about_it() {
    // Red on the unfixed tree: key B was told run-a carries `web`.
    let st = gateway(Some("sk-a:agent-a,sk-b:agent-b"));
    open_web_run(&st, "run-owned-by-a", Some("sk-a")).await;

    let (status, body) = check(&st, "run-owned-by-a", Some("sk-b")).await;
    assert_eq!(
        status,
        StatusCode::OK,
        "the decision is in the body: {body}"
    );
    assert_eq!(
        body["decision"], "deny",
        "a check about a run the caller does not own is not a permission: {body}"
    );
    assert!(
        body.get("carrying").is_none() && body.get("rule").is_none(),
        "no label and no rule of another caller's run: {body}"
    );
    assert!(
        !body.to_string().contains("web"),
        "nothing the run read appears anywhere in the answer: {body}"
    );
}

#[tokio::test]
async fn the_owner_of_a_run_is_answered_as_before() {
    let st = gateway(Some("sk-a:agent-a,sk-b:agent-b"));
    open_web_run(&st, "run-mine", Some("sk-a")).await;

    let (status, body) = check(&st, "run-mine", Some("sk-a")).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["decision"], "deny", "{body}");
    assert_eq!(body["rule"], "no-exec-after-untrusted");
    assert_eq!(body["carrying"], serde_json::json!(["web"]));
}

#[tokio::test]
async fn with_client_keys_a_check_with_no_key_is_refused_before_anything_is_read() {
    let st = gateway(Some("sk-a:agent-a"));
    open_web_run(&st, "run-nokey", Some("sk-a")).await;

    let (status, body) = check(&st, "run-nokey", None).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED, "{body}");
    assert!(!body.to_string().contains("web"), "{body}");
}

#[tokio::test]
async fn without_client_keys_the_check_is_unchanged() {
    // A gateway with no client keys authenticates nobody, at any door. That is
    // documented rather than changed: requiring a key here would break every
    // executor of a deployment that never configured one.
    let st = gateway(None);
    open_web_run(&st, "run-open-gateway", None).await;

    let (status, body) = check(&st, "run-open-gateway", None).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["decision"], "deny");
    assert_eq!(body["carrying"], serde_json::json!(["web"]));
}
