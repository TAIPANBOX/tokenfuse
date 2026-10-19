//! Invariant 135, on the wire: a caller's raise of an open run's budget is
//! refused, and the answer to that call says so in `x-fuse-budget`, on both
//! doors and on both the buffered and the streamed answer.
//!
//! The header is `raise-refused; kept=<usd>`, where `<usd>` is the budget the
//! run kept, in the same exact-dollar form as `x-fuse-budget-clamped`.

use axum::body::Body;
use axum::http::{Request, Response, StatusCode};
use std::sync::Arc;
use tokenfuse_core::{Ledger, Mode, ModelPrice, Policy, PriceBook};
use tokenfuse_gateway::provider::StubProvider;
use tokenfuse_gateway::state::AppState;
use tokenfuse_gateway::wire::Wire;
use tower::ServiceExt;

fn gateway(wire: Wire) -> AppState {
    let prices = PriceBook::new().with(
        "test-model",
        ModelPrice::per_mtok_usd(3.0, 15.0, 0.30, 3.75),
    );
    AppState::new(
        Arc::new(Ledger::new()),
        Arc::new(prices),
        Arc::new(Policy {
            mode: Mode::Enforce,
            ..Default::default()
        }),
        Arc::new(StubProvider::default()),
        "refused-raise-test",
    )
    .with_wire(wire)
}

fn path(wire: Wire) -> &'static str {
    match wire {
        Wire::Anthropic => "/v1/messages",
        Wire::OpenAi => "/v1/chat/completions",
    }
}

/// A small call on `run`, declaring `budget` dollars, buffered or streamed.
async fn call(st: &AppState, wire: Wire, run: &str, budget: &str, stream: bool) -> Response<Body> {
    let body = match wire {
        Wire::Anthropic => serde_json::json!({
            "model": "test-model", "max_tokens": 100, "stream": stream,
            "messages": [{"role": "user", "content": "hi"}]
        }),
        Wire::OpenAi => serde_json::json!({
            "model": "test-model", "max_tokens": 100, "stream": stream,
            "messages": [{"role": "user", "content": "hi"}]
        }),
    };
    let req = Request::post(path(wire))
        .header("content-type", "application/json")
        .header("x-fuse-run-id", run)
        .header("x-fuse-budget-usd", budget)
        .body(Body::from(body.to_string()))
        .unwrap();
    tokenfuse_gateway::app(st.clone()).oneshot(req).await.unwrap()
}

fn budget_header(resp: &Response<Body>) -> Option<String> {
    resp.headers()
        .get("x-fuse-budget")
        .map(|v| v.to_str().unwrap().to_string())
}

/// Opens the run at 0.50 dollar, then declares 1000 dollars on the next call.
async fn refused_raise(wire: Wire, run: &str, stream: bool) -> Response<Body> {
    let st = gateway(wire);
    let first = call(&st, wire, run, "0.50", false).await;
    assert_eq!(first.status(), StatusCode::OK);
    call(&st, wire, run, "1000", stream).await
}

#[tokio::test]
async fn anthropic_buffered_answer_names_the_refused_raise_and_the_kept_budget() {
    let resp = refused_raise(Wire::Anthropic, "wire-a-buf", false).await;
    assert_eq!(resp.status(), StatusCode::OK, "a refused raise refuses the raise, not the call");
    assert_eq!(
        budget_header(&resp).as_deref(),
        Some("raise-refused; kept=0.50"),
        "the buffered answer must say the raise was refused and what the run kept"
    );
}

#[tokio::test]
async fn anthropic_streamed_answer_names_the_refused_raise_and_the_kept_budget() {
    let resp = refused_raise(Wire::Anthropic, "wire-a-stream", true).await;
    assert_eq!(resp.status(), StatusCode::OK);
    assert_eq!(
        budget_header(&resp).as_deref(),
        Some("raise-refused; kept=0.50"),
        "the streamed answer carries the same header as the buffered one"
    );
}

#[tokio::test]
async fn openai_buffered_answer_names_the_refused_raise_and_the_kept_budget() {
    let resp = refused_raise(Wire::OpenAi, "wire-o-buf", false).await;
    assert_eq!(resp.status(), StatusCode::OK);
    assert_eq!(
        budget_header(&resp).as_deref(),
        Some("raise-refused; kept=0.50"),
        "the OpenAI door answers the same header"
    );
}

#[tokio::test]
async fn openai_streamed_answer_names_the_refused_raise_and_the_kept_budget() {
    let resp = refused_raise(Wire::OpenAi, "wire-o-stream", true).await;
    assert_eq!(resp.status(), StatusCode::OK);
    assert_eq!(
        budget_header(&resp).as_deref(),
        Some("raise-refused; kept=0.50")
    );
}

/// The header belongs to the call that was refused a raise. A call that lowers
/// the budget, or that declares nothing new, is not told about a refusal.
#[tokio::test]
async fn no_header_when_no_raise_was_refused() {
    let st = gateway(Wire::Anthropic);
    let first = call(&st, Wire::Anthropic, "wire-none", "0.50", false).await;
    assert!(budget_header(&first).is_none(), "the opening call raised nothing");
    let lower = call(&st, Wire::Anthropic, "wire-none", "0.25", false).await;
    assert_eq!(lower.status(), StatusCode::OK);
    assert!(
        budget_header(&lower).is_none(),
        "a lower declaration is accepted and is not a refusal"
    );
}

/// A refused raise that then fails the budget still tells the caller why its
/// run is at the figure it is: the header rides the 402 too.
#[tokio::test]
async fn the_header_rides_a_refusal_that_the_kept_budget_then_causes() {
    let st = gateway(Wire::Anthropic);
    call(&st, Wire::Anthropic, "wire-402", "0.50", false).await;
    let raised = call(&st, Wire::Anthropic, "wire-402", "1000", false).await;
    assert_eq!(raised.status(), StatusCode::OK);
    assert_eq!(budget_header(&raised).as_deref(), Some("raise-refused; kept=0.50"));
    // A USD 1.50 reservation does not fit a run kept at 0.50: a 402, with the header.
    let big = serde_json::json!({
        "model": "test-model", "max_tokens": 100000,
        "messages": [{"role": "user", "content": "hi"}]
    });
    let req = Request::post("/v1/messages")
        .header("content-type", "application/json")
        .header("x-fuse-run-id", "wire-402")
        .header("x-fuse-budget-usd", "1000")
        .body(Body::from(big.to_string()))
        .unwrap();
    let refused = tokenfuse_gateway::app(st).oneshot(req).await.unwrap();
    assert_eq!(refused.status(), StatusCode::PAYMENT_REQUIRED);
    assert_eq!(budget_header(&refused).as_deref(), Some("raise-refused; kept=0.50"));
}
