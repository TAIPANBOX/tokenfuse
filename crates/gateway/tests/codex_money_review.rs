// @codex 2026-09-17: review-only probes, written against 80e0d42 without product changes
// (F03, F04 and their held controls). Moved into the suite by the settle-guard PR
// (invariant 50); codex_f03's send-cancel probe is renamed and its assertion moved to
// retention under D7, see its own comment; every other test is verbatim. PR 3 (invariant 55)
// moves the F05 and F06 probes in the same way, verbatim, plus the `parse` helper they share.
use async_trait::async_trait;
use axum::body::{to_bytes, Body};
use axum::http::{HeaderMap, Request, StatusCode};
use bytes::Bytes;
use serde_json::json;
use std::sync::{Arc, Mutex};
use tokenfuse_core::{Ledger, Microusd, Mode, Policy};
use tokenfuse_gateway::estimate::estimate_cost;
use tokenfuse_gateway::provider::{
    ParsedUsage, Provider, ProviderError, ProviderResponse, UsageParser,
};
use tokenfuse_gateway::{pricebook::default_price_book, state::AppState, wire::Wire};
use tower::ServiceExt;

fn parse(bytes: &[u8]) -> ParsedUsage {
    let mut p = UsageParser::new();
    p.feed(bytes);
    p.finish()
}

#[test]
fn codex_f05_inv45_cached_details_in_a_later_chunk_are_netted_once() {
    let bytes=b"data: {\"usage\":{\"prompt_tokens\":950}}\n\ndata: {\"usage\":{\"completion_tokens\":0,\"prompt_tokens_details\":{\"cached_tokens\":128}}}\n\ndata: [DONE]\n\n";
    let u = parse(bytes).usage;
    let cost = default_price_book().cost("gpt-4o", &u).unwrap();
    println!("usage={u:?}; actual={cost:?}; expected=2215");
    assert_eq!(cost,Microusd(2215),"invariant 45: a cached subset arriving after prompt_tokens still removes that subset from input");
}

#[test]
fn codex_f05_inv45_details_only_chunk_is_not_discarded() {
    let bytes=b"data: {\"usage\":{\"prompt_tokens\":950}}\n\ndata: {\"usage\":{\"prompt_tokens_details\":{\"cached_tokens\":128}}}\n\ndata: [DONE]\n\n";
    let u = parse(bytes).usage;
    let cost = default_price_book().cost("gpt-4o", &u).unwrap();
    println!("usage={u:?}; actual={cost:?}; expected=2215");
    assert_eq!(
        cost,
        Microusd(2215),
        "invariant 45: usage details on a separate chunk must not disappear at shape detection"
    );
}

#[tokio::test]
async fn codex_f06_multiline_sse_usage_is_not_silently_partial() {
    // One valid SSE event can contain several data fields joined with LF.
    let bytes=b"data: {\"type\":\"message_start\",\"message\":{\"usage\":{\"input_tokens\":10}}}\n\ndata: {\"type\":\"message_delta\",\ndata: \"usage\":{\"output_tokens\":1000}}\n\nevent: message_stop\ndata: {\"type\":\"message_stop\"}\n\n".to_vec();
    let (st, l) = state(
        Arc::new(BytesProvider {
            bytes,
            status: 200,
            fail: false,
            publish_before_error: false,
        }),
        Wire::Anthropic,
    );
    let request = Request::post("/v1/messages")
        .header("content-type", "application/json")
        .header("x-fuse-run-id", "multiline")
        .header("x-fuse-budget-usd", "10")
        .body(Body::from(
            r#"{"model":"claude-sonnet","max_tokens":1000,"stream":true}"#,
        ))
        .unwrap();
    let r = tokenfuse_gateway::app(st).oneshot(request).await.unwrap();
    assert_eq!(r.status(), StatusCode::OK);
    to_bytes(r.into_body(), usize::MAX).await.unwrap();
    let got = l.snapshot("multiline").unwrap();
    println!("settled={got:?}; expected cost=15030");
    assert_eq!(got.spent,Microusd(15030),"UsageParser SSE contract and review priced-once invariant: final multiline usage must not vanish while initial usage is priced");
}

struct BytesProvider {
    bytes: Vec<u8>,
    status: u16,
    fail: bool,
    publish_before_error: bool,
}
#[async_trait]
impl Provider for BytesProvider {
    async fn send(&self, _: HeaderMap, _: Bytes) -> Result<ProviderResponse, ProviderError> {
        let bytes = Bytes::from(self.bytes.clone());
        let slot = Arc::new(Mutex::new(None));
        let writer = slot.clone();
        let fail = self.fail;
        let early = self.publish_before_error;
        let body = async_stream::try_stream! {
            let mut p = UsageParser::new();
            p.feed(&bytes);
            if early { *writer.lock().unwrap() = Some(p.finish()); }
            yield bytes;
            if fail { Err(ProviderError::Upstream("review: body broke".into()))?; }
            *writer.lock().unwrap() = Some(p.finish());
        };
        Ok(ProviderResponse {
            status: self.status,
            content_type: Some("text/event-stream".into()),
            body: Box::pin(body),
            usage: slot,
        })
    }
}

fn state(p: Arc<dyn Provider>, wire: Wire) -> (AppState, Arc<Ledger>) {
    let l = Arc::new(Ledger::new());
    let st = AppState::new(
        l.clone(),
        Arc::new(default_price_book()),
        Arc::new(Policy {
            mode: Mode::Enforce,
            ..Default::default()
        }),
        p,
        "codex-review",
    )
    .with_wire(wire);
    (st, l)
}
fn req(stream: bool, run: &str) -> Request<Body> {
    Request::post("/v1/chat/completions")
        .header("content-type", "application/json")
        .header("x-fuse-run-id", run)
        .header("x-fuse-budget-usd", "10")
        .body(Body::from(
            json!({"model":"gpt-4o","max_tokens":1000,"stream":stream}).to_string(),
        ))
        .unwrap()
}

struct PendingProvider {
    body_pending: bool,
    entered: Arc<tokio::sync::Notify>,
}

struct NotSentProvider;
#[async_trait]
impl Provider for NotSentProvider {
    async fn send(&self, _: HeaderMap, _: Bytes) -> Result<ProviderResponse, ProviderError> {
        Err(ProviderError::NotSent(
            "review: request building failed".into(),
        ))
    }
}

#[tokio::test]
async fn codex_held_not_sent_error_releases_without_spend_on_both_paths() {
    for stream in [false, true] {
        let (st, ledger) = state(Arc::new(NotSentProvider), Wire::OpenAi);
        let response = tokenfuse_gateway::app(st)
            .oneshot(req(stream, "unreachable"))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::BAD_GATEWAY);
        let snapshot = ledger.snapshot("unreachable").unwrap();
        assert_eq!(snapshot.reserved, Microusd(0));
        assert_eq!(snapshot.spent, Microusd(0));
        println!(
            "send error stream={stream} HTTP={} snapshot={snapshot:?}",
            response.status()
        );
    }
}
#[async_trait]
impl Provider for PendingProvider {
    async fn send(&self, _: HeaderMap, _: Bytes) -> Result<ProviderResponse, ProviderError> {
        if !self.body_pending {
            self.entered.notify_one();
            return std::future::pending().await;
        }
        let entered = self.entered.clone();
        let body = async_stream::try_stream! {
            entered.notify_one();
            std::future::pending::<()>().await;
            yield Bytes::from_static(b"{}");
        };
        Ok(ProviderResponse {
            status: 200,
            content_type: None,
            body: Box::pin(body),
            usage: Arc::new(Mutex::new(None)),
        })
    }
}

struct Cancelled {
    // Read by neither E1 nor E2 today; kept because `cancel_pending`'s own
    // precondition assert reads it before the struct is built, and a future
    // probe reading the before/after pair together should not have to widen
    // this shape again.
    #[allow(dead_code)]
    before: tokenfuse_core::RunSnapshot,
    after: tokenfuse_core::RunSnapshot,
    retained: Vec<tokenfuse_gateway::settle::RetainedReservation>,
    estimate: Microusd,
}

async fn cancel_pending(body_pending: bool, stream: bool) -> Cancelled {
    let entered = Arc::new(tokio::sync::Notify::new());
    let (st, l) = state(
        Arc::new(PendingProvider {
            body_pending,
            entered: entered.clone(),
        }),
        Wire::OpenAi,
    );
    let retained = st.retained.clone();
    let body_len = json!({"model":"gpt-4o","max_tokens":1000,"stream":stream})
        .to_string()
        .len();
    let estimate = tokenfuse_gateway::estimate::estimate_cost(
        &default_price_book(),
        "gpt-4o",
        body_len,
        Some(1000),
        1,
    )
    .unwrap();
    assert_eq!(
        estimate,
        Microusd(11_535),
        "spec section 6 arithmetic; if this fails, report it, do not edit it"
    );
    let task = tokio::spawn(async move {
        tokenfuse_gateway::app(st)
            .oneshot(req(stream, "cancel"))
            .await
    });
    tokio::time::timeout(std::time::Duration::from_secs(5), entered.notified())
        .await
        .unwrap();
    let before = l.snapshot("cancel").unwrap();
    assert_eq!(
        before.reserved, estimate,
        "precondition: the provider wait was entered with the estimate reserved"
    );
    task.abort();
    assert!(task.await.unwrap_err().is_cancelled());
    let after = l.snapshot("cancel").unwrap();
    println!(
        "body_pending={body_pending} stream={stream} before={before:?} after={after:?} retained={}",
        retained.len()
    );
    Cancelled {
        before,
        after,
        retained: retained.for_run("cancel"),
        estimate,
    }
}

#[tokio::test]
async fn codex_f03_cancel_during_provider_send_is_retained_not_released() {
    // The review's probe was `codex_f03_cancel_during_provider_send_releases_reservation` and
    // asserted a release. Under D7 (@decided 2026-09-18) a call the provider holds when the
    // caller leaves has an unknown outcome and keeps its reservation: neither a leak (the
    // review's finding: reserved stayed up with nothing saying so) nor a release (a write-off
    // of a call the provider may have run). The registry entry and the warn line are what
    // separate the two; the ledger figure alone cannot.
    let c = cancel_pending(false, true).await;
    assert_eq!(c.after.reserved, c.estimate, "retained, not released");
    assert_eq!(
        c.after.spent,
        Microusd::ZERO,
        "and never settled at zero: spent is untouched"
    );
    assert_eq!(c.retained.len(), 1, "listed exactly once");
    assert_eq!(c.retained[0].run.amount, c.estimate);
    assert_eq!(c.retained[0].run.step, 1);
    assert!(c.retained[0].unit.is_none(), "no unit cap in this fixture");
    assert_eq!(c.retained[0].model, "gpt-4o");
}

#[tokio::test]
async fn codex_f03_cancel_during_buffered_body_releases_reservation() {
    // Unchanged in name and in its release assertion: after a 2xx the provider did the work,
    // so the estimate is the honest charge and the reservation is settled, not leaked.
    let c = cancel_pending(true, false).await;
    assert_eq!(c.after.reserved, Microusd::ZERO, "ADR-2 and settle.rs cancellation promise: dropping the request future must release its reservation");
    assert_eq!(
        c.after.spent, c.estimate,
        "at the estimate: a 2xx arrived, so the outcome is not unknown (invariant 43)"
    );
    assert!(c.retained.is_empty());
}

#[tokio::test]
async fn codex_f04_buffered_body_error_preserves_reported_usage() {
    let (st, l) = state(
        Arc::new(BytesProvider {
            bytes: br#"{"usage":{"prompt_tokens":1000,"completion_tokens":500}}"#.to_vec(),
            status: 200,
            fail: true,
            publish_before_error: true,
        }),
        Wire::OpenAi,
    );
    let response = tokenfuse_gateway::app(st)
        .oneshot(req(false, "broken"))
        .await
        .unwrap();
    let got = l.snapshot("broken").unwrap();
    println!(
        "response={} snapshot={got:?}; reported cost=7500",
        response.status()
    );
    assert_eq!(response.status(), StatusCode::BAD_GATEWAY);
    assert_eq!(got.reserved, Microusd(0));
    assert_eq!(
        got.spent,
        Microusd(7500),
        "invariant 47 money rule: reported generated usage must be settled even if delivery fails"
    );
}

#[tokio::test]
async fn codex_held_stream_drop_before_first_poll_settles_once() {
    let (st, l) = state(
        Arc::new(BytesProvider {
            bytes: b"{}".to_vec(),
            status: 200,
            fail: false,
            publish_before_error: false,
        }),
        Wire::OpenAi,
    );
    let response = tokenfuse_gateway::app(st)
        .oneshot(req(true, "drop"))
        .await
        .unwrap();
    let before = l.snapshot("drop").unwrap();
    drop(response);
    let after = l.snapshot("drop").unwrap();
    assert_eq!(after.reserved, Microusd(0));
    assert_eq!(after.spent, before.reserved);
    println!("before={before:?} after={after:?}");
}

async fn real_broken_http(stream: bool) -> (tokenfuse_core::RunSnapshot, Microusd) {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let upstream = tokio::spawn(async move {
        let (mut socket, _) = listener.accept().await.unwrap();
        let mut request = [0u8; 4096];
        // A partial read is fine here: this mock never parses the request,
        // it only needs to drain enough that the client's write completes
        // before this task answers with the fixed response below.
        #[allow(clippy::unused_io_amount)]
        socket.read(&mut request).await.unwrap();
        let body = br#"{"usage":{"prompt_tokens":1000,"completion_tokens":500}}"#;
        let headers = format!("HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n", body.len() + 1);
        socket.write_all(headers.as_bytes()).await.unwrap();
        socket.write_all(body).await.unwrap();
        socket.shutdown().await.unwrap();
    });
    let (st, ledger) = state(
        Arc::new(tokenfuse_gateway::provider::HttpProvider::new(format!(
            "http://{address}"
        ))),
        Wire::OpenAi,
    );
    let request = req(stream, "http-broken");
    let body_len = if stream {
        r#"{"max_tokens":1000,"model":"gpt-4o","stream":true}"#.len()
    } else {
        r#"{"max_tokens":1000,"model":"gpt-4o","stream":false}"#.len()
    };
    let estimate = estimate_cost(&default_price_book(), "gpt-4o", body_len, Some(1000), 1).unwrap();
    let response = tokenfuse_gateway::app(st).oneshot(request).await.unwrap();
    let status = response.status();
    let body_result = to_bytes(response.into_body(), usize::MAX).await;
    upstream.await.unwrap();
    let snapshot = ledger.snapshot("http-broken").unwrap();
    println!("real HttpProvider stream={stream} HTTP={status} body_error={} estimate={estimate:?} snapshot={snapshot:?}", body_result.is_err());
    assert_eq!(snapshot.reserved, Microusd(0));
    if stream {
        assert!(body_result.is_err());
    } else {
        assert_eq!(status, StatusCode::BAD_GATEWAY);
    }
    (snapshot, estimate)
}

#[tokio::test]
async fn codex_f04_real_http_2xx_body_error_must_not_silently_settle_zero() {
    let (snapshot, estimate) = real_broken_http(false).await;
    assert_eq!(snapshot.spent, estimate, "invariant 43 and review fallback requirement: upstream answered 200 but its body broke; usage is unavailable, so reserve estimate must not become a zero settlement");
}

#[tokio::test]
async fn codex_held_real_http_stream_error_releases_and_uses_estimate() {
    let (snapshot, estimate) = real_broken_http(true).await;
    assert_eq!(snapshot.spent, estimate);
}
