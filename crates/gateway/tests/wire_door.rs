//! A process serves the door that matches its upstream, and says so about the
//! other one instead of reserving budget for a call the upstream will refuse.
//!
//! Every test here drives real HTTP through `tokenfuse_gateway::app(state)`,
//! the same router `main.rs` serves. `proxy::handle` used to be `pub` only so
//! these tests could reach a door that had no route yet
//! (`docs/26-the-openai-door.md`); now that `/v1/chat/completions` is
//! registered (see `lib.rs`), going through the router is what these tests
//! were always meant to exercise, and it is also what makes going through
//! `handle` directly for either door no longer necessary as a workaround.

mod common;

use axum::body::{to_bytes, Body};
use axum::http::{Request, StatusCode};
use tokenfuse_gateway::wire::Wire;
use tower::ServiceExt;

fn openai_body() -> &'static str {
    r#"{"model":"test-model","max_tokens":16,"messages":[{"role":"user","content":"hi"}]}"#
}

#[tokio::test]
async fn a_gateway_pointed_at_anthropic_refuses_the_openai_door_before_it_reserves_anything() {
    let state = common::app_with_wire(Wire::Anthropic);
    // A second handle onto the SAME ledger (`AppState` is `Clone`, all fields
    // are `Arc` - see `state.rs`), kept independently of the app the request
    // below is served through, so this test can ask the ledger itself
    // whether it ever heard of this run id rather than trusting the response
    // alone.
    let ledger = state.ledger.clone();
    let app = tokenfuse_gateway::app(state);

    let resp = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/v1/chat/completions")
                .header("content-type", "application/json")
                .header("x-fuse-run-id", "r-wire-1")
                .body(Body::from(openai_body()))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    let bytes = to_bytes(resp.into_body(), 64 * 1024).await.unwrap();
    let v: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(v["error"]["type"], "wire_mismatch");
    assert!(
        v["error"]["message"]
            .as_str()
            .unwrap()
            .contains("TOKENFUSE_WIRE"),
        "the refusal must name the variable that fixes it, got {v}"
    );

    // The claim in this test's name is the guard's POSITION: refused before
    // anything is reserved. A body assertion alone cannot tell "refused
    // first" from "refused after opening the run and reserving against it,
    // then still answering 400" - both produce the same response. Asking the
    // ledger directly closes that gap: if `open_run` had already run for
    // this id, `snapshot` would return `Some`.
    assert!(
        ledger.snapshot("r-wire-1").await.is_none(),
        "the ledger must never have heard of this run id - the guard is \
         supposed to refuse before open_run, not merely before this response \
         is built"
    );
}

#[tokio::test]
async fn a_gateway_pointed_at_openai_still_serves_its_own_door() {
    let state = common::app_with_wire(Wire::OpenAi);
    let app = tokenfuse_gateway::app(state);

    let resp = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/v1/chat/completions")
                .header("content-type", "application/json")
                .header("x-fuse-run-id", "r-wire-2")
                .body(Body::from(openai_body()))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(resp.status(), StatusCode::OK);
}

#[tokio::test]
async fn the_anthropic_door_is_refused_on_a_gateway_pointed_at_openai() {
    // A second, independent path to the same guard as the first test above,
    // this time hitting `/v1/messages` on a gateway declared for OpenAI.
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

/// `estimate_cost(&default_price_book(), "gpt-4o", 97, Some(4000), completions)`
/// (97 is this test's exact request body length):
///   - completions=1: Microusd(46069) = $0.046069
///   - completions=4: Microusd(184069) = $0.184069
/// (`cargo test -p tokenfuse-gateway --lib estimate:: -- --nocapture` with a
/// throwaway `println!` of both, run 2026-09-07). $0.06 sits strictly between
/// them: it admits one completion of this size and refuses four. If the
/// estimate ignored `n` (passed a literal `1` regardless of what the request
/// asked for), this call would price at $0.046069 against a $0.06 budget and
/// be served.
#[tokio::test]
async fn four_completions_are_reserved_for_before_the_call_is_forwarded() {
    let state = common::app_with_wire_and_budget(Wire::OpenAi, 0.06);
    let app = tokenfuse_gateway::app(state);
    let resp = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/v1/chat/completions")
                .header("content-type", "application/json")
                .header("x-fuse-run-id", "r-n-1")
                .body(Body::from(
                    r#"{"model":"gpt-4o","n":4,"max_completion_tokens":4000,"messages":[{"role":"user","content":"hi"}]}"#,
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::PAYMENT_REQUIRED);
}
