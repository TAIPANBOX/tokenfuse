//! Shared construction helpers for gateway integration tests.
//!
//! Not `tests/common.rs`: a file directly under `tests/` compiles as its own
//! test binary, and this one has no tests of its own to run - only helpers
//! other test files pull in with `mod common;`.

use async_trait::async_trait;
use axum::body::Bytes;
use axum::http::HeaderMap;
use std::sync::{Arc, Mutex};
use tokenfuse_core::{Ledger, Microusd, Mode, ModelPrice, Policy, PriceBook};
use tokenfuse_gateway::provider::{
    ParsedUsage, Provider, ProviderError, ProviderResponse, UsageSlot,
};
use tokenfuse_gateway::state::AppState;
use tokenfuse_gateway::wire::Wire;

/// A provider that always answers successfully with a fixed usage.
///
/// Used where a test needs to tell "reached the provider and got an answer"
/// apart from "was refused before it got that far" - here, whether the wire
/// guard let a matching request through.
#[derive(Clone, Default)]
pub struct StubOkProvider;

#[async_trait]
impl Provider for StubOkProvider {
    async fn send(
        &self,
        _headers: HeaderMap,
        _body: Bytes,
    ) -> Result<ProviderResponse, ProviderError> {
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

/// State for a gateway that serves `wire` and nothing else.
///
/// Construction copied from `require_run_id.rs`'s own `state()` helper, with
/// the one field this task adds set explicitly rather than left at
/// `AppState::new`'s default.
pub fn app_with_wire(wire: Wire) -> AppState {
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
        Arc::new(StubOkProvider),
        "wire-door-test-policy",
    )
    .with_wire(wire)
}

/// State for a gateway that serves `wire`, priced from the real default price
/// book (so `gpt-4o` and every other shipped model name resolve), with
/// `policy.budget_per_run` set to `budget_usd`.
///
/// Used by tests that need the estimate to actually bind against a budget
/// rather than merely observe the wire guard - see
/// `four_completions_are_reserved_for_before_the_call_is_forwarded` in
/// `wire_door.rs` for how the figure is derived.
pub fn app_with_wire_and_budget(wire: Wire, budget_usd: f64) -> AppState {
    AppState::new(
        Arc::new(Ledger::new()),
        Arc::new(tokenfuse_gateway::pricebook::default_price_book()),
        Arc::new(Policy {
            mode: Mode::Enforce,
            budget_per_run: Some(Microusd::from_usd(budget_usd)),
            ..Default::default()
        }),
        Arc::new(StubOkProvider),
        "wire-door-test-policy",
    )
    .with_wire(wire)
}
