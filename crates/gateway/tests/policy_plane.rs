//! `GET /v1/policy-plane`: whether the policy plane actually answered, as
//! opposed to whether it is configured.
//!
//! WHY THIS ENDPOINT EXISTS
//!
//! The 2026-08-04 cloud range ran the shipped stack against a real provider and
//! recorded this as the critical finding: the deployment check for "the policy
//! plane is on the data path" read environment variables. It never asked
//! whether a verdict had ever come back. So a deployment could pass every check
//! it had and be governed on paper, and the run proved it could happen by
//! accident: a missing identity header made a healthy PDP answer nothing, the
//! gateway reported `wardryx unreachable`, and an operator would have gone to
//! fix a machine that was fine.
//!
//! This is the invariant trailryx already carries: a check that cannot fail
//! reports zero forever. The one fact that closes it is whether a REAL allow
//! and a REAL deny came back inside a window, which is the fact this endpoint
//! answers and nothing else in this repository did.

use axum::body::{to_bytes, Body};
use axum::http::{Request, StatusCode};
use std::sync::Arc;
use std::time::Duration;
use tokenfuse_core::{Ledger, Policy, PriceBook};
use tokenfuse_gateway::provider::StubProvider;
use tokenfuse_gateway::state::AppState;
use tokenfuse_gateway::wardryx::{FailMode, Wardryx, WardryxMode};
use tower::ServiceExt;

fn state() -> AppState {
    AppState::new(
        Arc::new(Ledger::new()),
        Arc::new(PriceBook::new()),
        Arc::new(Policy::default()),
        Arc::new(StubProvider::default()),
        "test-policy",
    )
}

async fn report(st: AppState, query: &str) -> serde_json::Value {
    let req = Request::get(format!("/v1/policy-plane{query}"))
        .body(Body::empty())
        .unwrap();
    let resp = tokenfuse_gateway::app(st).oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let bytes = to_bytes(resp.into_body(), usize::MAX).await.unwrap();
    serde_json::from_slice(&bytes).unwrap()
}

/// The default deployment: no policy plane at all. The honest answer is that
/// nothing here is governed by one, and it is not a 404 or an error, because an
/// operator running this check wants an answer rather than an exception.
#[tokio::test]
async fn a_gateway_with_no_policy_hook_says_so_plainly() {
    let v = report(state(), "").await;
    assert_eq!(v["mode"], "off");
    assert_eq!(v["on_data_path"], false);
    assert_eq!(v["allow_and_deny_seen"], false);
    assert_eq!(v["verdicts"]["allow"], 0);
    assert_eq!(v["verdicts"]["deny"], 0);
}

/// The finding itself: configuration is not evidence. A hook in `enforce`
/// against a URL that has never answered must not report as governed.
#[tokio::test]
async fn a_configured_plane_that_never_answered_is_not_proven() {
    let st = state().with_wardryx(Arc::new(Wardryx::new(
        WardryxMode::Enforce,
        FailMode::Closed,
        "http://127.0.0.1:1/v1/decide",
        None,
        Duration::from_millis(50),
        Duration::from_millis(0),
    )));
    let v = report(st, "").await;
    assert_eq!(
        v["mode"], "enforce",
        "the configuration is reported as it is"
    );
    assert_eq!(
        v["on_data_path"], false,
        "configured is not the same fact as answering"
    );
    assert_eq!(v["allow_and_deny_seen"], false);
}

/// A window is a window: a verdict older than the one asked about does not
/// count, or the check reports a plane that answered once in March as live.
#[tokio::test]
async fn a_verdict_older_than_the_window_does_not_count() {
    let w = Wardryx::new(
        WardryxMode::Enforce,
        FailMode::Open,
        "http://127.0.0.1:1/v1/decide",
        None,
        Duration::from_millis(50),
        Duration::from_millis(0),
    );
    w.record_verdict_at(tokenfuse_gateway::wardryx::WardryxDecision::Allow, 1_000);
    w.record_verdict_at(tokenfuse_gateway::wardryx::WardryxDecision::Deny, 1_000);
    let st = state().with_wardryx(Arc::new(w));

    let wide = report(st.clone(), "?window_ms=99999999999999").await;
    assert_eq!(wide["allow_and_deny_seen"], true);

    let narrow = report(st, "?window_ms=1000").await;
    assert_eq!(
        narrow["allow_and_deny_seen"], false,
        "a verdict from before the window is not a verdict in it"
    );
    assert_eq!(
        narrow["verdicts"]["allow"], 1,
        "the totals are since startup and say so; only the in-window facts move"
    );
}
