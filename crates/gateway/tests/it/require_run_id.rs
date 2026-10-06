//! Integration test for `TOKENFUSE_REQUIRE_RUN_ID`, the setting that lets a
//! deployment say that a call it cannot meter is not a call it makes.
//!
//! The default is the opposite and stays the opposite: a request with no
//! `x-fuse-run-id` passes through to the provider unmetered, which is what
//! makes this gateway safe to put in front of an existing client. That default
//! is also why the setting is needed. On a live run on 2026-08-04 a successful
//! call left all three NDJSON files at zero bytes, the deployment's whole claim
//! was that every call is accounted for, and nothing anywhere had said the two
//! were compatible.
//!
//! So both halves are tested here. A setting whose ON case works and whose OFF
//! case was never checked has not been tested, it has been demonstrated.

use async_trait::async_trait;
use axum::body::{to_bytes, Body, Bytes};
use axum::http::{HeaderMap, Request, StatusCode};
use serde_json::Value;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use tokenfuse_core::{Ledger, Mode, ModelPrice, Policy, PriceBook};
use tokenfuse_gateway::provider::{
    ParsedUsage, Provider, ProviderError, ProviderResponse, UsageSlot,
};
use tokenfuse_gateway::state::AppState;
use tower::ServiceExt;

/// A provider that counts how many times it was asked to forward anything.
///
/// The count is the assertion that matters. A 400 with the call still going
/// upstream would be the worst of both: the caller is told the request failed
/// and the money is spent anyway.
#[derive(Clone, Default)]
struct CountingProvider {
    calls: Arc<AtomicUsize>,
}

#[async_trait]
impl Provider for CountingProvider {
    async fn send(
        &self,
        _headers: HeaderMap,
        _body: Bytes,
    ) -> Result<ProviderResponse, ProviderError> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        let usage = tokenfuse_core::Usage {
            input_tokens: 10,
            output_tokens: 10,
            ..Default::default()
        };
        let slot: UsageSlot = Arc::new(Mutex::new(Some(ParsedUsage {
            usage,
            truncated: false,
        })));
        let chunk = Bytes::from_static(br#"{"stub":true}"#);
        let stream = futures::stream::once(async move { Ok(chunk) });
        Ok(ProviderResponse {
            status: 200,
            content_type: Some("application/json".to_string()),
            body: Box::pin(stream),
            usage: slot,
        })
    }
}

fn state(provider: CountingProvider, require_run_id: bool) -> AppState {
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
        Arc::new(provider),
        "require-run-id-test-policy",
    )
    .with_require_run_id(require_run_id)
}

fn body() -> String {
    r#"{"model":"test-model","max_tokens":100,"messages":[{"role":"user","content":"hi"}]}"#
        .to_string()
}

/// A request with no run id at all. Nothing else is missing.
fn request_without_a_run_id() -> Request<Body> {
    Request::post("/v1/messages")
        .body(Body::from(body()))
        .unwrap()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn requiring_metering_refuses_an_unmeterable_call_before_it_costs_anything() {
    let provider = CountingProvider::default();
    let app = tokenfuse_gateway::app(state(provider.clone(), true));

    let resp = app.oneshot(request_without_a_run_id()).await.unwrap();

    assert_eq!(
        resp.status(),
        StatusCode::BAD_REQUEST,
        "nothing here is forbidden: the request is missing the header that would let it be \
         accounted for, so it is the caller's error to fix and not a 403"
    );

    let bytes = to_bytes(resp.into_body(), 64 * 1024).await.unwrap();
    let error: Value = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(error["error"]["type"], "metering_required");
    let reason = error["error"]["reason"].as_str().unwrap();
    assert!(
        reason.contains("x-fuse-run-id"),
        "an operator can only fix what they are told about, so the refusal names the header, \
         got {reason:?}"
    );

    assert_eq!(
        provider.calls.load(Ordering::SeqCst),
        0,
        "a refused call must not reach the provider: a 400 with the tokens spent anyway is \
         worse than either outcome on its own"
    );
}

/// The default, and the half that keeps this gateway droppable in front of an
/// existing client.
///
/// This test is the one that would catch the setting being wired the wrong way
/// round, or defaulting to on. That failure would not look like a bug in a
/// test run: it would look like every unmetered caller in production suddenly
/// getting a 400 after an upgrade.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_default_still_lets_an_unmetered_call_through() {
    let provider = CountingProvider::default();
    let app = tokenfuse_gateway::app(state(provider.clone(), false));

    let resp = app.oneshot(request_without_a_run_id()).await.unwrap();

    assert_eq!(resp.status(), StatusCode::OK);
    assert_eq!(
        provider.calls.load(Ordering::SeqCst),
        1,
        "pass-through is the default and has to stay measured, not assumed"
    );
}
