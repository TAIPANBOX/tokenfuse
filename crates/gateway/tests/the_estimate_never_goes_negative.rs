//! Regression test for the pricing wrap: a bigger `max_tokens` must never pass
//! where a smaller one is refused. Measured on 2026-09-07, before the fix in
//! `crates/core/src/pricing.rs`, `output_tokens = 1e18` priced negative, and a
//! negative estimate passed every budget check the gateway has.
//!
//! Harness copied from `crates/gateway/tests/require_run_id.rs`: same
//! `CountingProvider`, same `state()`/`Request::post` shape. The counter is
//! half the assertion here too - a 402 with the call still forwarded would be
//! the worst of both.

use async_trait::async_trait;
use axum::body::{Body, Bytes};
use axum::http::{HeaderMap, Request, StatusCode};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use tokenfuse_core::{Ledger, Microusd, Mode, ModelPrice, Policy, PriceBook};
use tokenfuse_gateway::provider::{
    ParsedUsage, Provider, ProviderError, ProviderResponse, UsageSlot,
};
use tokenfuse_gateway::state::AppState;
use tower::ServiceExt;

/// A provider that counts how many times it was asked to forward anything.
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

fn state(provider: CountingProvider) -> AppState {
    let prices = PriceBook::new().with(
        "test-model",
        ModelPrice::per_mtok_usd(3.0, 15.0, 0.30, 3.75),
    );
    AppState::new(
        Arc::new(Ledger::new()),
        Arc::new(prices),
        Arc::new(Policy {
            mode: Mode::Enforce,
            budget_per_run: Some(Microusd(10_000)),
            ..Default::default()
        }),
        Arc::new(provider),
        "the-estimate-never-goes-negative-test-policy",
    )
}

/// A bigger ask must never pass where a smaller one is refused.
///
/// Measured before the fix, on this exact harness: max_tokens of 1e3, 1e6 and
/// 1e12 were all refused with 402 and never forwarded, and u64::MAX returned
/// 200 and WAS forwarded, because the estimate had wrapped negative.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_absurd_output_cap_is_refused_like_every_smaller_one() {
    for max_tokens in ["1000", "1000000", "1000000000000", "18446744073709551615"] {
        let provider = CountingProvider::default();
        let app = tokenfuse_gateway::app(state(provider.clone()));
        let resp = app
            .oneshot(
                Request::post("/v1/messages")
                    .header("x-fuse-run-id", format!("r-{max_tokens}"))
                    .body(Body::from(format!(
                        r#"{{"model":"test-model","max_tokens":{max_tokens},"messages":[{{"role":"user","content":"hi"}}]}}"#
                    )))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(
            resp.status(),
            StatusCode::PAYMENT_REQUIRED,
            "max_tokens={max_tokens} was not refused on a one-cent budget"
        );
        assert_eq!(
            provider.calls.load(Ordering::SeqCst),
            0,
            "max_tokens={max_tokens} reached the provider after a refusal was due"
        );
    }
}
