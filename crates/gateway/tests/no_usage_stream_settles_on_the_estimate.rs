//! tokenfuse#283: a 2xx stream that carries no usage block settles on the
//! pre-flight estimate, never at zero.
//!
//! The caller may set `stream_options.include_usage: false`, and the gateway
//! never overrules a caller who set the field (`Wire::prepare_upstream_body`).
//! A provider that honours it (OpenAI, Ollama, Bedrock's OpenAI door) then
//! streams content chunks and `[DONE]` with no usage anywhere. Those chunks
//! still parse as JSON, so the tool-call counter answers `Some(0)`, and the
//! parsed `Usage` is zero tokens beside `tool_calls: Some(0)`. Measured live on
//! 2026-09-13 (go-to-market-2026-09/evidence/1.0/r3-providers-2026-09-13):
//! the gateway settled 0 tokens, 0 microusd, `spent_usd` unmoved, for a
//! completion delivered in full.
//!
//! `settle::tests::settle_amount_treats_zero_tokens_beside_a_tool_call_count_as_no_usage`
//! pins the decision function. This file drives the whole path through the
//! router with the REAL `UsageParser` reading a body shaped exactly like that
//! stream, so it also fails if a settle path stops calling `settle_amount`, or
//! if the guard's `unmeasured` is ever zero on a 2xx.

mod common;

use axum::body::{to_bytes, Body};
use axum::http::{Request, StatusCode};
use tokenfuse_core::Microusd;
use tokenfuse_gateway::wire::Wire;
use tower::ServiceExt;

/// What Ollama sent for `Count from 1 to 12` with `include_usage: false`, cut
/// to three content chunks: no `usage` key on any line, then `[DONE]`.
const NO_USAGE_STREAM: &[u8] = b"data: {\"id\":\"chatcmpl-1\",\"object\":\"chat.completion.chunk\",\"created\":1,\"model\":\"qwen2.5:3b\",\"choices\":[{\"index\":0,\"delta\":{\"role\":\"assistant\",\"content\":\"1\"},\"finish_reason\":null}]}\n\n\
data: {\"id\":\"chatcmpl-1\",\"object\":\"chat.completion.chunk\",\"created\":1,\"model\":\"qwen2.5:3b\",\"choices\":[{\"index\":0,\"delta\":{\"content\":\"\\n2\"},\"finish_reason\":null}]}\n\n\
data: {\"id\":\"chatcmpl-1\",\"object\":\"chat.completion.chunk\",\"created\":1,\"model\":\"qwen2.5:3b\",\"choices\":[{\"index\":0,\"delta\":{},\"finish_reason\":\"stop\"}]}\n\n\
data: [DONE]\n\n";

/// The same stream with the usage chunk OpenAI-compatible providers append
/// when `include_usage` is on: the control, which must settle on the usage.
const USAGE_STREAM: &[u8] = b"data: {\"id\":\"chatcmpl-1\",\"object\":\"chat.completion.chunk\",\"created\":1,\"model\":\"qwen2.5:3b\",\"choices\":[{\"index\":0,\"delta\":{\"role\":\"assistant\",\"content\":\"1\"},\"finish_reason\":null}],\"usage\":null}\n\n\
data: {\"id\":\"chatcmpl-1\",\"object\":\"chat.completion.chunk\",\"created\":1,\"model\":\"qwen2.5:3b\",\"choices\":[{\"index\":0,\"delta\":{},\"finish_reason\":\"stop\"}],\"usage\":null}\n\n\
data: {\"id\":\"chatcmpl-1\",\"object\":\"chat.completion.chunk\",\"created\":1,\"model\":\"qwen2.5:3b\",\"choices\":[],\"usage\":{\"prompt_tokens\":46,\"completion_tokens\":27,\"total_tokens\":73}}\n\n\
data: [DONE]\n\n";

/// A non-streaming completion with no `usage` object at all: the buffered
/// settle path (`proxy::buffered_managed`) calls the same `settle_amount`,
/// and a provider that omits usage from a plain JSON answer is the same fact
/// arriving unstreamed.
const NO_USAGE_JSON: &[u8] = b"{\"id\":\"chatcmpl-2\",\"object\":\"chat.completion\",\"created\":1,\"model\":\"qwen2.5:3b\",\"choices\":[{\"index\":0,\"message\":{\"role\":\"assistant\",\"content\":\"1\\n2\"},\"finish_reason\":\"stop\"}]}";

async fn stream_through(body: &'static [u8], run_id: &str) -> (StatusCode, Microusd, Microusd) {
    call_through(body, run_id, true).await
}

async fn call_through(
    body: &'static [u8],
    run_id: &str,
    stream: bool,
) -> (StatusCode, Microusd, Microusd) {
    let (state, ledger) = common::app_with_wire_parsing(Wire::OpenAi, body);
    let app = tokenfuse_gateway::app(state);
    let resp = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/v1/chat/completions")
                .header("content-type", "application/json")
                .header("x-fuse-run-id", run_id)
                .header("x-fuse-budget-usd", "1.00")
                .body(Body::from(if stream {
                    r#"{"model":"qwen2.5:3b","max_tokens":40,"stream":true,"stream_options":{"include_usage":false},"messages":[{"role":"user","content":"Count from 1 to 12, one number per line, nothing else."}]}"#
                } else {
                    r#"{"model":"qwen2.5:3b","max_tokens":40,"messages":[{"role":"user","content":"Count from 1 to 12, one number per line, nothing else."}]}"#
                }))
                .unwrap(),
        )
        .await
        .unwrap();
    let status = resp.status();
    // On a stream the open reservation IS the gateway's estimate, read while
    // the body is still unconsumed, before the guard settles. A buffered call
    // has already settled by now (its reservation reads zero here), so that
    // test recomputes the estimate instead.
    let reserved_before = ledger.snapshot(run_id).expect("the run exists").reserved;
    let _ = to_bytes(resp.into_body(), 64 * 1024).await.unwrap();
    let snap = ledger.snapshot(run_id).expect("the run exists");
    assert_eq!(
        snap.reserved,
        Microusd::ZERO,
        "the reservation is settled once the body ends"
    );
    (status, reserved_before, snap.spent)
}

#[tokio::test]
async fn a_buffered_answer_with_no_usage_object_settles_on_the_estimate_not_zero() {
    let (status, _reserved_after_settle, spent) =
        call_through(NO_USAGE_JSON, "r-283-buffered", false).await;
    assert_eq!(status, StatusCode::OK);
    // The call has settled before the response is returned, so the estimate
    // is recomputed exactly as the gateway did it: the request body's length,
    // its `max_tokens`, one completion, at the fallback rate of the default
    // price book (the model is unknown to it).
    let body = r#"{"model":"qwen2.5:3b","max_tokens":40,"messages":[{"role":"user","content":"Count from 1 to 12, one number per line, nothing else."}]}"#;
    let estimate = tokenfuse_gateway::estimate::estimate_cost(
        &tokenfuse_gateway::pricebook::default_price_book(),
        "qwen2.5:3b",
        body.len(),
        Some(40),
        1,
    )
    .expect("the default book prices an unknown model at the fallback rate");
    assert!(estimate > Microusd::ZERO);
    assert_eq!(
        spent, estimate,
        "a 2xx answer with no usage object settles on the estimate, not zero; the buffered path shares settle_amount"
    );
}

#[tokio::test]
async fn a_stream_with_no_usage_block_settles_on_the_estimate_not_zero() {
    let (status, estimate, spent) = stream_through(NO_USAGE_STREAM, "r-283-no-usage").await;
    assert_eq!(status, StatusCode::OK);
    assert!(
        estimate > Microusd::ZERO,
        "the pre-flight estimate was reserved"
    );
    assert_eq!(
        spent, estimate,
        "a 2xx stream that reported no usage settles on the estimate; before #283 it settled at zero"
    );
}

#[tokio::test]
async fn a_stream_with_a_usage_block_settles_on_the_usage_not_the_estimate() {
    let (status, estimate, spent) = stream_through(USAGE_STREAM, "r-283-usage").await;
    assert_eq!(status, StatusCode::OK);
    assert!(spent > Microusd::ZERO);
    assert_ne!(
        spent, estimate,
        "46 in / 27 out at the fallback price is not the 40-token estimate"
    );
    // 46 x 15 + 27 x 75 USD per Mtok at the fallback rate = 2715 microusd.
    assert_eq!(spent, Microusd(2715));
}
