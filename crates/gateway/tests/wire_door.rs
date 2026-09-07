//! A process serves the door that matches its upstream, and says so about the
//! other one instead of reserving budget for a call the upstream will refuse.
//!
//! **Why these calls go through `proxy::handle` directly rather than through
//! HTTP on `/v1/chat/completions`.** That route is not registered on the
//! router yet - it is the next task's work, `docs/26-the-openai-door.md` -
//! so `tokenfuse_gateway::app(state)` has nothing to dispatch a
//! `/v1/chat/completions` request to and would answer 404 regardless of
//! `AppState.wire`. A test built on that 404 would pass whether or not the
//! guard in `handle` exists, which is passing for the wrong reason. Calling
//! `handle(Wire::OpenAi, ..)` is what this task actually adds, so it is what
//! gets exercised; the third test below hits the guard through real HTTP,
//! since `/v1/messages` is already routed and already calls `handle`.

mod common;

use axum::body::{to_bytes, Body};
use axum::http::{HeaderMap, HeaderValue, Request, StatusCode};
use tokenfuse_gateway::wire::Wire;
use tower::ServiceExt;

fn openai_body() -> &'static str {
    r#"{"model":"test-model","max_tokens":16,"messages":[{"role":"user","content":"hi"}]}"#
}

fn headers_with_run_id(run_id: &str) -> HeaderMap {
    let mut headers = HeaderMap::new();
    headers.insert("content-type", HeaderValue::from_static("application/json"));
    headers.insert("x-fuse-run-id", HeaderValue::from_str(run_id).unwrap());
    headers
}

#[tokio::test]
async fn a_gateway_pointed_at_anthropic_refuses_the_openai_door_before_it_reserves_anything() {
    let state = common::app_with_wire(Wire::Anthropic);
    let resp = tokenfuse_gateway::proxy::handle(
        Wire::OpenAi,
        state,
        headers_with_run_id("r-wire-1"),
        axum::body::Bytes::from_static(openai_body().as_bytes()),
    )
    .await;

    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    let bytes = axum::body::to_bytes(resp.into_body(), 64 * 1024)
        .await
        .unwrap();
    let v: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(v["error"]["type"], "wire_mismatch");
    assert!(
        v["error"]["message"]
            .as_str()
            .unwrap()
            .contains("TOKENFUSE_WIRE"),
        "the refusal must name the variable that fixes it, got {v}"
    );
}

#[tokio::test]
async fn a_gateway_pointed_at_openai_still_serves_its_own_door() {
    let state = common::app_with_wire(Wire::OpenAi);
    let resp = tokenfuse_gateway::proxy::handle(
        Wire::OpenAi,
        state,
        headers_with_run_id("r-wire-2"),
        axum::body::Bytes::from_static(openai_body().as_bytes()),
    )
    .await;

    assert_eq!(resp.status(), StatusCode::OK);
}

#[tokio::test]
async fn the_anthropic_door_is_refused_on_a_gateway_pointed_at_openai() {
    // Unlike the two tests above, `/v1/messages` IS already registered and
    // already calls `handle(Wire::Anthropic, ..)` - see `proxy::messages` -
    // so this one goes through the real router and real HTTP rather than
    // calling `handle` directly, and is a second, independent path to the
    // same guard.
    let state = common::app_with_wire(Wire::OpenAi);
    let app = tokenfuse_gateway::app(state);

    let resp = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/v1/messages")
                .header("content-type", "application/json")
                .header("x-fuse-run-id", "r-wire-3")
                .body(Body::from(
                    r#"{"model":"claude-haiku-4-5","max_tokens":16,"messages":[]}"#,
                ))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    let bytes = to_bytes(resp.into_body(), 64 * 1024).await.unwrap();
    let v: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(v["error"]["type"], "wire_mismatch");
}
