//! Per-key rate and concurrency limits on the LLM doors (`ratelimit`), through
//! the real router.

use async_trait::async_trait;
use axum::body::{Body, Bytes};
use axum::http::{HeaderMap, Request, StatusCode};
use http_body_util::BodyExt;
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokenfuse_core::{Ledger, Mode, Policy};
use tokenfuse_gateway::clientkeys::{ClientKeys, CLIENT_KEY_HEADER};
use tokenfuse_gateway::provider::{Provider, ProviderError, ProviderResponse, UsageSlot};
use tokenfuse_gateway::ratelimit::Limits;
use tokenfuse_gateway::state::AppState;
use tokenfuse_gateway::wire::Wire;
use tower::ServiceExt;

const BODY: &str = "{\"type\":\"message\",\"usage\":{\"input_tokens\":3,\"output_tokens\":2}}";

/// Answers at once with a first chunk, then waits `hold` before the last one,
/// so a call stays in flight while its body streams.
struct SlowBody {
    hold: Duration,
}

#[async_trait]
impl Provider for SlowBody {
    async fn send(
        &self,
        _headers: HeaderMap,
        _body: Bytes,
    ) -> Result<ProviderResponse, ProviderError> {
        let slot: UsageSlot = Arc::new(Mutex::new(None));
        let writer = Arc::clone(&slot);
        let hold = self.hold;
        let stream = async_stream::try_stream! {
            let mut parser = tokenfuse_gateway::provider::UsageParser::new();
            let (a, b) = BODY.as_bytes().split_at(10);
            parser.feed(a);
            yield Bytes::copy_from_slice(a);
            tokio::time::sleep(hold).await;
            parser.feed(b);
            yield Bytes::copy_from_slice(b);
            *writer.lock().unwrap() = Some(parser.finish());
        };
        Ok(ProviderResponse {
            status: 200,
            content_type: Some("application/json".to_string()),
            body: Box::pin(stream),
            usage: slot,
        })
    }
}

fn gate(limits: Limits, hold: Duration) -> AppState {
    AppState::new(
        Arc::new(Ledger::new()),
        Arc::new(tokenfuse_gateway::pricebook::default_price_book()),
        Arc::new(Policy {
            mode: Mode::Enforce,
            ..Default::default()
        }),
        Arc::new(SlowBody { hold }),
        "key-limits-test",
    )
    .with_wire(Wire::Anthropic)
    .with_client_keys(Arc::new(
        ClientKeys::from_spec("sk-a:a,sk-b:b").expect("a usable key spec"),
    ))
    .with_key_limits(limits)
}

fn call(key: &str, run: &str, stream: bool) -> Request<Body> {
    let body = serde_json::json!({
        "model": "claude-haiku-5-5",
        "max_tokens": 16,
        "stream": stream,
        "messages": [{"role": "user", "content": "hi"}],
    })
    .to_string();
    Request::post("/v1/messages")
        .header("content-type", "application/json")
        .header("x-fuse-run-id", run)
        .header(CLIENT_KEY_HEADER, key)
        .body(Body::from(body))
        .unwrap()
}

/// Red until the door admits through the limiter: one call a second, burst one,
/// so the second call on one key inside the second is refused 429 with
/// `Retry-After`, and another key is not.
#[tokio::test]
async fn a_key_over_its_rate_is_refused_429_and_another_key_is_not() {
    let st = gate(
        Limits {
            rps: Some(1.0),
            burst: 1.0,
            concurrency: None,
        },
        Duration::ZERO,
    );
    let first = tokenfuse_gateway::app(st.clone())
        .oneshot(call("sk-a", "r-a1", false))
        .await
        .unwrap();
    assert_eq!(first.status(), StatusCode::OK);
    let second = tokenfuse_gateway::app(st.clone())
        .oneshot(call("sk-a", "r-a2", false))
        .await
        .unwrap();
    assert_eq!(second.status(), StatusCode::TOO_MANY_REQUESTS);
    assert_eq!(second.headers()["retry-after"], "1");
    let bytes = second.into_body().collect().await.unwrap().to_bytes();
    let v: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(v["error"]["type"], "rate_limited", "{v}");
    assert_eq!(v["error"]["limit"], "rate", "{v}");
    let other = tokenfuse_gateway::app(st.clone())
        .oneshot(call("sk-b", "r-b1", false))
        .await
        .unwrap();
    assert_eq!(
        other.status(),
        StatusCode::OK,
        "another key has its own bucket"
    );
}

/// A call is in flight until its answer has gone out: while one streamed
/// answer is still streaming, the key's second call is refused, and once that
/// body has been read the key is admitted again.
#[tokio::test]
async fn a_call_counts_against_concurrency_until_its_body_has_gone_out() {
    let st = gate(
        Limits {
            rps: None,
            burst: 1.0,
            concurrency: Some(1),
        },
        Duration::from_millis(400),
    );
    let first = tokenfuse_gateway::app(st.clone())
        .oneshot(call("sk-a", "r-c1", true))
        .await
        .unwrap();
    assert_eq!(first.status(), StatusCode::OK);
    let second = tokenfuse_gateway::app(st.clone())
        .oneshot(call("sk-a", "r-c2", true))
        .await
        .unwrap();
    assert_eq!(
        second.status(),
        StatusCode::TOO_MANY_REQUESTS,
        "the first body is still streaming"
    );
    let bytes = second.into_body().collect().await.unwrap().to_bytes();
    let v: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(v["error"]["limit"], "concurrency", "{v}");
    let _ = first.into_body().collect().await.unwrap();
    let third = tokenfuse_gateway::app(st.clone())
        .oneshot(call("sk-a", "r-c3", true))
        .await
        .unwrap();
    assert_eq!(
        third.status(),
        StatusCode::OK,
        "the first call's place was given back"
    );
}

/// Guard: with nothing set, nothing is limited.
#[tokio::test]
async fn with_no_limits_set_nothing_is_refused() {
    let st = gate(
        Limits {
            rps: None,
            burst: 1.0,
            concurrency: None,
        },
        Duration::ZERO,
    );
    for i in 0..20 {
        let resp = tokenfuse_gateway::app(st.clone())
            .oneshot(call("sk-a", &format!("r-n{i}"), false))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK, "call {i}");
    }
}
