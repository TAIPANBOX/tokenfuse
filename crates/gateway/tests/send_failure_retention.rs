// @codex 2026-09-19: real transport regressions for D9, without paid upstream calls.
use axum::{
    body::{to_bytes, Body},
    http::{Request, StatusCode},
};
use std::{
    sync::{
        atomic::{AtomicU64, AtomicUsize, Ordering},
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

// D9: the provider client follows no redirect, so a 307/308 is a status line
// like any other, never a second hop. Listener A is the configured provider;
// listener B is the host a followed redirect would have reached. B only ever
// needs to count acceptances: whether a connection to it exists at all is
// what tells a followed redirect apart from one that was not, not anything B
// says back.
#[tokio::test]
async fn a_redirect_from_the_provider_is_not_followed_and_the_key_stays_home() {
    for stream in [false, true] {
        let listener_b = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let b_addr = listener_b.local_addr().unwrap();
        let b_accepted = Arc::new(AtomicUsize::new(0));
        let b_counter = b_accepted.clone();
        let b_task = tokio::spawn(async move {
            while let Ok((socket, _)) = listener_b.accept().await {
                b_counter.fetch_add(1, Ordering::Relaxed);
                drop(socket);
            }
        });

        let listener_a = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let endpoint = format!("http://{}/v1/messages", listener_a.local_addr().unwrap());
        let server = tokio::spawn(async move {
            let (mut socket, _) = listener_a.accept().await.unwrap();
            read_post(&mut socket).await;
            socket
                .write_all(
                    format!(
                        "HTTP/1.1 307 Temporary Redirect\r\nLocation: http://{b_addr}/v1/messages\r\ncontent-length: 0\r\nconnection: close\r\n\r\n"
                    )
                    .as_bytes(),
                )
                .await
                .unwrap();
            socket.shutdown().await.unwrap();
        });

        static NEXT: AtomicU64 = AtomicU64::new(0);
        let dir = std::env::temp_dir().join(format!(
            "tf-d9-redirect-{}-{}",
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
            .header("x-api-key", "sk-test-must-not-leave")
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
        let status = response.status();
        // Drain the body: the streaming path settles at end of stream
        // (`guard.complete()`), so the ledger below is only trustworthy to
        // read once every byte, none in this case, has actually been polled
        // through.
        let _ = to_bytes(response.into_body(), usize::MAX).await.unwrap();
        server.await.unwrap();

        // A bounded wait, not an unbounded one: if the redirect had been
        // followed, the connection to B would already exist by the time the
        // response completed, so this is headroom rather than a race.
        tokio::time::sleep(Duration::from_millis(500)).await;
        assert_eq!(
            b_accepted.load(Ordering::Relaxed),
            0,
            "the redirect must not be followed: the key and the body must never reach the second host"
        );
        b_task.abort();

        assert_eq!(
            status,
            StatusCode::TEMPORARY_REDIRECT,
            "the provider's own status line is forwarded verbatim, the same as any other non-2xx"
        );

        let child = ledger.snapshot("child").unwrap();
        let parent = ledger.snapshot("parent").unwrap();
        println!(
            "stream={stream} status={status} child={child:?} parent={parent:?} listed={}",
            registry.len()
        );
        assert_eq!(child.spent, Microusd::ZERO);
        assert_eq!(parent.spent, Microusd::ZERO);
        assert_eq!(
            child.reserved,
            Microusd::ZERO,
            "a refusal with no usage releases at zero, same as any other non-2xx with nothing priced"
        );
        assert_eq!(parent.reserved, Microusd::ZERO);
        assert_eq!(units.spent("ops", now_millis()), Microusd::ZERO);
        assert_eq!(units.reserved("ops", now_millis()), Microusd::ZERO);
        assert!(registry.is_empty(), "a refusal is never retained");

        std::fs::remove_dir_all(dir).unwrap();
    }
}

// D9: with no redirect followed there is exactly one hop, so a refused
// connection is proof the request never left this process.
#[tokio::test]
async fn a_refused_connection_on_the_only_hop_releases_both_ledgers() {
    for stream in [false, true] {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let endpoint = format!("http://{}/", listener.local_addr().unwrap());
        drop(listener);
        check(endpoint, stream, false).await;
    }
}

#[tokio::test]
async fn a_request_that_cannot_be_built_releases_both_ledgers() {
    for stream in [false, true] {
        check("not a URL".into(), stream, false).await;
    }
}
