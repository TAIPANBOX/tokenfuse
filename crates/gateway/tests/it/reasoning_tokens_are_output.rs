//! Invariant 80, end to end: a thinking call through the OpenAI door settles the
//! reasoning tokens its provider bills.
//!
//! Measured 2026-10-07 against Vertex AI's OpenAI-compatible endpoint
//! (google/gemini-2.5-flash, one non-streamed answer):
//! `{"completion_tokens":59,"completion_tokens_details":{"reasoning_tokens":560},
//! "prompt_tokens":14,"total_tokens":633}`. Google's `completion_tokens` leaves
//! the reasoning out and bills it at the output rate; the gateway settled the
//! call on the 59 alone. These tests drive the real `HttpProvider` against a
//! local upstream that answers with that usage, through `app()`, and read the
//! run's spend off the ledger the budget is enforced against.
use axum::body::{to_bytes, Body};
use axum::http::{Request, StatusCode};
use serde_json::json;
use std::sync::Arc;
use tokenfuse_core::{Ledger, Microusd, Mode, ModelPrice, Policy, PriceBook};
use tokenfuse_gateway::provider::HttpProvider;
use tokenfuse_gateway::{state::AppState, wire::Wire};
use tower::ServiceExt;

const MODEL: &str = "google/gemini-2.5-flash";

/// The measured usage, verbatim.
const USAGE: &str = r#"{"completion_tokens":59,"completion_tokens_details":{"reasoning_tokens":560},"prompt_tokens":14,"total_tokens":633}"#;

/// 14 x $0.30 + 619 x $2.50 per Mtok = 1551.7 micro-USD, ceiled once to 1552
/// (invariant 67). Settling on `completion_tokens` alone gave 152.
const BILLED: Microusd = Microusd(1552);

/// Serves one HTTP answer on a local port and returns its address.
async fn upstream(content_type: &'static str, body: String) -> std::net::SocketAddr {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    tokio::spawn(async move {
        let (mut socket, _) = listener.accept().await.unwrap();
        let mut request = [0u8; 8192];
        // This upstream never parses the request; it only drains enough that
        // the client's write completes before the fixed answer goes back.
        #[allow(clippy::unused_io_amount)]
        socket.read(&mut request).await.unwrap();
        let head = format!(
            "HTTP/1.1 200 OK\r\nContent-Type: {content_type}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
            body.len()
        );
        socket.write_all(head.as_bytes()).await.unwrap();
        socket.write_all(body.as_bytes()).await.unwrap();
        socket.shutdown().await.unwrap();
    });
    address
}

fn state(address: std::net::SocketAddr) -> (AppState, Arc<Ledger>) {
    let ledger = Arc::new(Ledger::new());
    let prices = PriceBook::new().with(MODEL, ModelPrice::per_mtok_usd(0.30, 2.50, 0.03, 0.30));
    let st = AppState::new(
        ledger.clone(),
        Arc::new(prices),
        Arc::new(Policy {
            mode: Mode::Enforce,
            ..Default::default()
        }),
        Arc::new(HttpProvider::new(format!("http://{address}"))),
        "reasoning-tokens",
    )
    .with_wire(Wire::OpenAi);
    (st, ledger)
}

fn request(run: &str, stream: bool) -> Request<Body> {
    Request::post("/v1/chat/completions")
        .header("content-type", "application/json")
        .header("x-fuse-run-id", run)
        .header("x-fuse-budget-usd", "10")
        .body(Body::from(
            json!({
                "model": MODEL,
                "max_tokens": 1000,
                "stream": stream,
                "messages": [{"role": "user", "content": "hi"}]
            })
            .to_string(),
        ))
        .unwrap()
}

#[tokio::test]
async fn a_vertex_thinking_call_through_the_openai_door_settles_its_reasoning() {
    let body = format!(
        r#"{{"id":"vertex-1","object":"chat.completion","model":"{MODEL}","choices":[{{"index":0,"message":{{"role":"assistant","content":"hi"}},"finish_reason":"stop"}}],"usage":{USAGE}}}"#
    );
    let address = upstream("application/json", body).await;
    let (st, ledger) = state(address);
    let response = tokenfuse_gateway::app(st)
        .oneshot(request("vertex-buffered", false))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let cost = response
        .headers()
        .get("x-fuse-cost-usd")
        .map(|v| v.to_str().unwrap().to_string());
    let _ = to_bytes(response.into_body(), usize::MAX).await.unwrap();
    let snapshot = ledger.snapshot("vertex-buffered").unwrap();
    println!("x-fuse-cost-usd={cost:?} snapshot={snapshot:?}");
    assert_eq!(snapshot.reserved, Microusd(0));
    assert_eq!(
        snapshot.spent, BILLED,
        "the run must carry the 560 reasoning tokens at the output rate; 152 is the visible answer alone"
    );
    assert_eq!(cost.as_deref(), Some("0.001552"));
}

#[tokio::test]
async fn a_streamed_vertex_thinking_call_settles_its_reasoning() {
    let body = format!(
        "data: {{\"choices\":[{{\"index\":0,\"delta\":{{\"content\":\"hi\"}}}}],\"usage\":null}}\n\n\
         data: {{\"choices\":[],\"usage\":{USAGE}}}\n\n\
         data: [DONE]\n\n"
    );
    let address = upstream("text/event-stream", body).await;
    let (st, ledger) = state(address);
    let response = tokenfuse_gateway::app(st)
        .oneshot(request("vertex-streamed", true))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let _ = to_bytes(response.into_body(), usize::MAX).await.unwrap();
    let snapshot = ledger.snapshot("vertex-streamed").unwrap();
    println!("snapshot={snapshot:?}");
    assert_eq!(snapshot.reserved, Microusd(0));
    assert_eq!(
        snapshot.spent, BILLED,
        "the streamed final usage chunk must settle the reasoning too"
    );
}

/// Invariant 82: the same measured call priced by the book the binary ships,
/// not a book the test wrote. Until the Gemini rows existed it settled at
/// the 15 / 75 fallback, 46635 micro-USD, and said `x-fuse-price: fallback`.
#[tokio::test]
async fn the_shipped_book_prices_the_measured_vertex_call_at_its_list_rate() {
    let body = format!(
        r#"{{"id":"vertex-2","object":"chat.completion","model":"{MODEL}","choices":[{{"index":0,"message":{{"role":"assistant","content":"hi"}},"finish_reason":"stop"}}],"usage":{USAGE}}}"#
    );
    let address = upstream("application/json", body).await;
    let ledger = Arc::new(Ledger::new());
    let st = AppState::new(
        ledger.clone(),
        Arc::new(tokenfuse_gateway::pricebook::default_price_book()),
        Arc::new(Policy {
            mode: Mode::Enforce,
            ..Default::default()
        }),
        Arc::new(HttpProvider::new(format!("http://{address}"))),
        "shipped-book",
    )
    .with_wire(Wire::OpenAi);
    let response = tokenfuse_gateway::app(st)
        .oneshot(request("vertex-shipped-book", false))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let price = response
        .headers()
        .get("x-fuse-price")
        .map(|v| v.to_str().unwrap().to_string());
    let _ = to_bytes(response.into_body(), usize::MAX).await.unwrap();
    let snapshot = ledger.snapshot("vertex-shipped-book").unwrap();
    assert_eq!(price.as_deref(), Some("known"));
    assert_eq!(
        snapshot.spent, BILLED,
        "the shipped book must price google/gemini-2.5-flash at 0.30 / 2.50, not the fallback"
    );
}
