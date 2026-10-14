//! Invariant 107: an `openai/<id>` model id, as OpenRouter names OpenAI's
//! models, is priced at OpenAI's list rate for that id, and the GPT-4.1 family
//! has rows of its own.
//!
//! Measured on forge 2026-10-14 through the OpenAI door over OpenRouter:
//! `openai/gpt-4.1-mini` had no row, so 14 input and 2 output tokens settled at
//! the 15 / 75 fallback, USD 0.000360 for a call whose list price is under one
//! hundredth of a cent, and run budgets of USD 0.004 and 0.012 were refused
//! before their first call. An id the book does not know stays at the fallback.

use crate::common;

use axum::body::{to_bytes, Body};
use axum::http::{Request, StatusCode};
use tokenfuse_gateway::wire::Wire;
use tower::ServiceExt;

/// What OpenRouter answered for the forge call, buffered.
const ANSWER: &[u8] = br#"{"id":"gen-1","object":"chat.completion","created":1,"model":"openai/gpt-4.1-mini","choices":[{"index":0,"message":{"role":"assistant","content":"OK"},"finish_reason":"stop"}],"usage":{"prompt_tokens":14,"completion_tokens":2,"total_tokens":16}}"#;

async fn call(model: &str, budget: &str, max_tokens: u32) -> (StatusCode, String, String) {
    let (state, _) = common::app_with_wire_parsing(Wire::OpenAi, ANSWER);
    let body = serde_json::json!({
        "model": model,
        "max_tokens": max_tokens,
        "messages": [{"role": "user", "content": "Reply OK."}],
    })
    .to_string();
    let resp = tokenfuse_gateway::app(state)
        .oneshot(
            Request::post("/v1/chat/completions")
                .header("content-type", "application/json")
                .header("x-fuse-run-id", "run-openrouter")
                .header("x-fuse-budget-usd", budget)
                .body(Body::from(body))
                .unwrap(),
        )
        .await
        .unwrap();
    let status = resp.status();
    let header = |name: &str| {
        resp.headers()
            .get(name)
            .and_then(|v| v.to_str().ok())
            .unwrap_or_default()
            .to_string()
    };
    let (price, cost) = (header("x-fuse-price"), header("x-fuse-cost-usd"));
    let _ = to_bytes(resp.into_body(), 1 << 20).await;
    (status, price, cost)
}

#[tokio::test]
async fn the_measured_openrouter_call_is_priced_at_openais_list_rate() {
    let (status, price, cost) = call("openai/gpt-4.1-mini", "1", 16).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(price, "known", "openai/gpt-4.1-mini has a row now");
    // 14 x 0.40 + 2 x 1.60 per Mtok = 8.8 micro-USD, rounded up once.
    assert_eq!(cost, "0.000009", "was 0.000360 at the fallback");
}

#[tokio::test]
async fn a_small_budget_is_no_longer_refused_before_its_first_call() {
    let (status, price, _) = call("openai/gpt-4.1-mini", "0.004", 1024).await;
    assert_eq!(
        status,
        StatusCode::OK,
        "1024 output tokens at 1.60 per Mtok fit USD 0.004; at the fallback's 75 they did not"
    );
    assert_eq!(price, "known");
}

#[tokio::test]
async fn the_gpt_4_1_family_is_priced_under_its_own_ids() {
    for model in [
        "gpt-4.1",
        "gpt-4.1-mini",
        "gpt-4.1-nano",
        "openai/gpt-4.1-nano",
    ] {
        let (status, price, _) = call(model, "1", 16).await;
        assert_eq!(status, StatusCode::OK, "{model}");
        assert_eq!(price, "known", "{model}");
    }
}

#[tokio::test]
async fn an_openai_id_the_book_does_not_know_still_takes_the_fallback() {
    let (status, price, _) = call("openai/gpt-9-turbo", "1", 16).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(price, "fallback");
}
