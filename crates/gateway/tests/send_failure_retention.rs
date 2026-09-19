// @codex 2026-09-19: real transport regressions for D9, without paid upstream calls.
use axum::{
    body::{to_bytes, Body},
    http::{Request, StatusCode},
};
use std::{
    sync::{
        atomic::{AtomicU64, Ordering},
        Arc,
    },
    time::Duration,
};
use tokenfuse_core::{Ledger, Microusd, Mode, Policy};
use tokenfuse_gateway::{
    identitymap::{IdentityMap, StrictMode},
    pricebook::default_price_book,
    provider::HttpProvider,
    sink::now_millis,
    state::AppState,
    unitledger::UnitLedger,
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpListener,
};
use tower::ServiceExt;

async fn check(endpoint: String, stream: bool, retained: bool) {
    static NEXT: AtomicU64 = AtomicU64::new(0);
    let dir = std::env::temp_dir().join(format!(
        "tf-d9-{}-{}",
        std::process::id(),
        NEXT.fetch_add(1, Ordering::Relaxed)
    ));
    std::fs::create_dir_all(&dir).unwrap();
    let map_path = dir.join("identity.json");
    std::fs::write(&map_path, r#"{"units":[{"id":"ops","budget_usd_month":10}],"prefixes":[{"match":"agent://test/*","unit":"ops"}]}"#).unwrap();
    let map = Arc::new(IdentityMap::from_path(&map_path).unwrap());
    let units = Arc::new(UnitLedger::new(map.unit_budgets()));
    let ledger = Arc::new(Ledger::new());
    ledger
        .open_run("parent", Microusd(10_000_000), None)
        .unwrap();
    let state = AppState::new(
        ledger.clone(),
        Arc::new(default_price_book()),
        Arc::new(Policy {
            mode: Mode::Enforce,
            ..Default::default()
        }),
        Arc::new(HttpProvider::new(endpoint)),
        "d9",
    )
    .with_identity(map, StrictMode::Off, units.clone());
    let registry = state.retained.clone();
    let request = Request::post("/v1/messages")
        .header("content-type", "application/json")
        .header("x-fuse-run-id", "child")
        .header("x-fuse-parent-run-id", "parent")
        .header("x-fuse-agent-id", "agent://test/bot")
        .header("x-fuse-budget-usd", "10")
        .body(Body::from(
            serde_json::json!({"model":"claude-sonnet","max_tokens":100,"stream":stream})
                .to_string(),
        ))
        .unwrap();
    let response = tokio::time::timeout(
        Duration::from_secs(5),
        tokenfuse_gateway::app(state).oneshot(request),
    )
    .await
    .unwrap()
    .unwrap();
    assert_eq!(response.status(), StatusCode::BAD_GATEWAY);
    let body: serde_json::Value =
        serde_json::from_slice(&to_bytes(response.into_body(), usize::MAX).await.unwrap()).unwrap();
    assert_eq!(body["error"]["type"], "upstream_error");
    let child = ledger.snapshot("child").unwrap();
    let parent = ledger.snapshot("parent").unwrap();
    println!(
        "stream={stream} retained={retained} child={child:?} parent={parent:?} listed={}",
        registry.len()
    );
    assert_eq!(child.spent, Microusd::ZERO);
    assert_eq!(parent.spent, Microusd::ZERO);
    assert_eq!(units.spent("ops", now_millis()), Microusd::ZERO);
    if retained {
        assert!(
            child.reserved > Microusd::ZERO,
            "an ambiguous send must keep its exposure"
        );
        let entries = registry.for_run("child");
        assert_eq!(
            entries.len(),
            1,
            "one retained handle, never an unlisted leak"
        );
        assert_eq!(entries[0].run.amount, child.reserved);
        assert!(entries[0].unit.is_some());
    } else {
        assert_eq!(child.reserved, Microusd::ZERO);
        assert!(registry.is_empty());
    }
    assert_eq!(parent.reserved, child.reserved);
    assert_eq!(units.reserved("ops", now_millis()), child.reserved);
    std::fs::remove_dir_all(dir).unwrap();
}

// Read the WHOLE POST before replying or disconnecting: accepting a socket alone
// would not establish that the provider received the request being accounted for.
async fn read_post(socket: &mut tokio::net::TcpStream) {
    let mut bytes = Vec::new();
    let mut buf = [0; 1024];
    loop {
        let n = socket.read(&mut buf).await.unwrap();
        assert!(n > 0, "caller closed before sending the body");
        bytes.extend_from_slice(&buf[..n]);
        assert!(bytes.len() < 16384);
        if let Some(end) = bytes.windows(4).position(|w| w == b"\r\n\r\n") {
            let head = String::from_utf8_lossy(&bytes[..end]);
            assert!(head.starts_with("POST "));
            let length: usize = head
                .lines()
                .find_map(|line| {
                    let (name, value) = line.split_once(':')?;
                    name.eq_ignore_ascii_case("content-length")
                        .then(|| value.trim().parse().unwrap())
                })
                .unwrap();
            if bytes.len() >= end + 4 + length {
                assert!(length > 0);
                println!("upstream accepted {length} POST body bytes");
                return;
            }
        }
    }
}

#[tokio::test]
async fn a_post_received_before_eof_retains_both_ledgers_on_both_paths() {
    for stream in [false, true] {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let endpoint = format!("http://{}/v1/messages", listener.local_addr().unwrap());
        let server = tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await.unwrap();
            read_post(&mut socket).await;
            socket.shutdown().await.unwrap();
        });
        check(endpoint, stream, true).await;
        server.await.unwrap();
    }
}

#[tokio::test]
async fn a_post_redirected_to_a_refused_connection_is_not_unsent() {
    for stream in [false, true] {
        let dead = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let dead_addr = dead.local_addr().unwrap();
        drop(dead);
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let endpoint = format!("http://{}/v1/messages", listener.local_addr().unwrap());
        let server = tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await.unwrap();
            read_post(&mut socket).await;
            socket.write_all(format!("HTTP/1.1 307 Temporary Redirect\r\nLocation: http://{dead_addr}/next\r\nContent-Length: 0\r\nConnection: close\r\n\r\n").as_bytes()).await.unwrap();
        });
        check(endpoint, stream, true).await;
        server.await.unwrap();
    }
}

#[tokio::test]
async fn a_connect_error_without_dispatch_evidence_conservatively_retains() {
    for stream in [false, true] {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let endpoint = format!("http://{}/", listener.local_addr().unwrap());
        drop(listener);
        check(endpoint, stream, true).await;
    }
}

#[tokio::test]
async fn a_request_that_cannot_be_built_releases_both_ledgers() {
    for stream in [false, true] {
        check("not a URL".into(), stream, false).await;
    }
}
