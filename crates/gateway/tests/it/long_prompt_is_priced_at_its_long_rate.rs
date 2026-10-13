//! Invariant 99, end to end: a call whose prompt is above a model's long-prompt
//! threshold settles at the long rate, through `app()`, the real
//! `HttpProvider` and the book the binary ships.
//!
//! gpt-6.1-sol, 300000 prompt tokens and 1000 output: above OpenAI's 272K
//! threshold, so every token at the long rate, 4 input / 15 output USD per
//! Mtok: 1,200,000 + 15,000 = 1,215,000 micro-USD. Before the row existed it
//! settled at the 15 / 75 fallback (4,500,000 + 75,000 = 4,575,000); at the
//! short rate it would be 600,000 + 10,000 = 610,000.
use axum::body::{to_bytes, Body};
use axum::http::{Request, StatusCode};
use serde_json::json;
use std::sync::Arc;
use tokenfuse_core::{Ledger, Microusd, Mode, Policy};
use tokenfuse_gateway::provider::HttpProvider;
use tokenfuse_gateway::{state::AppState, wire::Wire};
use tower::ServiceExt;

const MODEL: &str = "gpt-6.1-sol";
const USAGE: &str = r#"{"prompt_tokens":300000,"completion_tokens":1000,"total_tokens":301000}"#;
const BILLED: Microusd = Microusd(1_215_000);

async fn upstream(body: String) -> std::net::SocketAddr {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    tokio::spawn(async move {
        let (mut socket, _) = listener.accept().await.unwrap();
        let mut request = [0u8; 8192];
        // Drained only so the client's write completes; never parsed.
        #[allow(clippy::unused_io_amount)]
        socket.read(&mut request).await.unwrap();
        let head = format!(
            "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
            body.len()
        );
        socket.write_all(head.as_bytes()).await.unwrap();
        socket.write_all(body.as_bytes()).await.unwrap();
        socket.shutdown().await.unwrap();
    });
    address
}

#[tokio::test]
async fn a_long_prompt_on_a_tiered_id_settles_at_its_long_rate_through_the_gateway() {
    let body = format!(
        r#"{{"id":"sol-1","object":"chat.completion","model":"{MODEL}","choices":[{{"index":0,"message":{{"role":"assistant","content":"hi"}},"finish_reason":"stop"}}],"usage":{USAGE}}}"#
    );
    let address = upstream(body).await;
    let ledger = Arc::new(Ledger::new());
    let st = AppState::new(
        ledger.clone(),
        Arc::new(tokenfuse_gateway::pricebook::default_price_book()),
        Arc::new(Policy {
            mode: Mode::Enforce,
            ..Default::default()
        }),
        Arc::new(HttpProvider::new(format!("http://{address}"))),
        "long-prompt",
    )
    .with_wire(Wire::OpenAi);
    let request = Request::post("/v1/chat/completions")
        .header("content-type", "application/json")
        .header("x-fuse-run-id", "long-prompt")
        .header("x-fuse-budget-usd", "10")
        .body(Body::from(
            json!({
                "model": MODEL,
                "max_tokens": 1000,
                "messages": [{"role": "user", "content": "hi"}]
            })
            .to_string(),
        ))
        .unwrap();
    let response = tokenfuse_gateway::app(st).oneshot(request).await.unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let price = response
        .headers()
        .get("x-fuse-price")
        .map(|v| v.to_str().unwrap().to_string());
    let _ = to_bytes(response.into_body(), usize::MAX).await.unwrap();
    let snapshot = ledger.snapshot("long-prompt").unwrap();
    println!("x-fuse-price={price:?} snapshot={snapshot:?}");
    assert_eq!(price.as_deref(), Some("known"));
    assert_eq!(snapshot.reserved, Microusd(0));
    assert_eq!(
        snapshot.spent, BILLED,
        "300000 prompt tokens is above 272K: every token at 4 / 15, not the short 2 / 10 or the fallback"
    );
}
