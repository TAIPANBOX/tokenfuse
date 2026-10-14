//! W03, first PR: a retained reservation (invariant 50, D7) survives a gateway
//! restart. Until this change the registry and the ledgers behind it were
//! process-local, so a gateway that restarted after a call whose outcome was
//! unknown forgot the exposure entirely: the run and the unit came back with
//! nothing outstanding, and the next call was admitted against room the
//! provider may already have billed.
//!
//! This runs the real binary twice on one `TOKENFUSE_DATA_DIR`. The first
//! process admits a parent call (the provider answers), then a child call the
//! provider receives in full and never answers (D9: retained). The process is
//! killed with SIGKILL, not stopped, so nothing a graceful shutdown would write
//! can be what the second process reads. The second process must list the
//! same exposure on the child AND its parent, and must refuse a call whose
//! unit cap only the restored reservation fills.

use std::io::{BufRead, BufReader};
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{mpsc, Arc};
use std::thread;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

const LISTENING_NEEDLE: &str = "tokenfuse gateway listening";
const AGENT: &str = "agent://test/bot";
const CALL: &str = r#"{"model":"claude-sonnet","max_tokens":1000,"messages":[{"role":"user","content":"hello there"}]}"#;

fn free_addr() -> String {
    let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let a = l.local_addr().unwrap();
    drop(l);
    a.to_string()
}

/// A provider that reads each POST whole, then either answers it (a tiny
/// usage, so the parent's settled spend is near zero) or closes the socket
/// without a status line, which D9 reads as an unknown outcome and retains.
async fn provider(hold: Arc<AtomicBool>) -> String {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let endpoint = format!("http://{}/v1/messages", listener.local_addr().unwrap());
    tokio::spawn(async move {
        loop {
            let Ok((mut socket, _)) = listener.accept().await else {
                return;
            };
            let hold = hold.clone();
            tokio::spawn(async move {
                if !read_post(&mut socket).await {
                    return;
                }
                if hold.load(Ordering::SeqCst) {
                    let _ = socket.shutdown().await;
                    return;
                }
                let body = r#"{"id":"msg_1","type":"message","role":"assistant","model":"claude-sonnet","content":[{"type":"text","text":"ok"}],"stop_reason":"end_turn","usage":{"input_tokens":1,"output_tokens":1}}"#;
                let resp = format!(
                    "HTTP/1.1 200 OK\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{body}",
                    body.len()
                );
                let _ = socket.write_all(resp.as_bytes()).await;
                let _ = socket.shutdown().await;
            });
        }
    });
    endpoint
}

async fn read_post(socket: &mut tokio::net::TcpStream) -> bool {
    let mut bytes = Vec::new();
    let mut buf = [0; 4096];
    loop {
        let Ok(n) = socket.read(&mut buf).await else {
            return false;
        };
        if n == 0 {
            return false;
        }
        bytes.extend_from_slice(&buf[..n]);
        if let Some(end) = bytes.windows(4).position(|w| w == b"\r\n\r\n") {
            let head = String::from_utf8_lossy(&bytes[..end]).to_string();
            let length: usize = head
                .lines()
                .find_map(|line| {
                    let (name, value) = line.split_once(':')?;
                    name.eq_ignore_ascii_case("content-length")
                        .then(|| value.trim().parse().unwrap())
                })
                .unwrap_or(0);
            if bytes.len() >= end + 4 + length {
                return true;
            }
        }
    }
}

fn spawn(addr: &str, upstream: &str, data_dir: &str, identity_map: &str) -> Child {
    Command::new(env!("CARGO_BIN_EXE_tokenfuse"))
        .env_remove("TOKENFUSE_ALLOW_STUB")
        .env_remove("TOKENFUSE_CLIENT_KEYS")
        .env_remove("TOKENFUSE_CLOUD_URL")
        .env_remove("TOKENFUSE_CLOUD_KEY")
        .env_remove("TOKENFUSE_MAX_RUN_BUDGET_USD")
        .env_remove("TOKENFUSE_ADMIN_KEYS")
        .env("TOKENFUSE_UPSTREAM", upstream)
        .env("TOKENFUSE_MODE", "enforce")
        .env("TOKENFUSE_ADDR", addr)
        .env("TOKENFUSE_DATA_DIR", data_dir)
        .env("TOKENFUSE_IDENTITY_MAP", identity_map)
        .env("TOKENFUSE_IDENTITY_STRICT", "off")
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("failed to spawn the tokenfuse binary")
}

fn wait_for_listening(child: &mut Child) -> bool {
    let stdout = child.stdout.take().expect("stdout piped");
    let (tx, rx) = mpsc::channel::<()>();
    thread::spawn(move || {
        for line in BufReader::new(stdout).lines().map_while(Result::ok) {
            if line.contains(LISTENING_NEEDLE) {
                tx.send(()).ok();
            }
        }
    });
    rx.recv_timeout(Duration::from_secs(15)).is_ok()
}

async fn call(addr: &str, run: &str, parent: Option<&str>) -> reqwest::Response {
    let mut req = reqwest::Client::new()
        .post(format!("http://{addr}/v1/messages"))
        .header("x-fuse-run-id", run)
        .header("x-fuse-budget-usd", "10")
        .header("x-fuse-agent-id", AGENT)
        .header("content-type", "application/json")
        .body(CALL);
    if let Some(p) = parent {
        req = req.header("x-fuse-parent-run-id", p);
    }
    req.send().await.expect("the gateway must answer")
}

async fn runs(addr: &str) -> Vec<serde_json::Value> {
    reqwest::get(format!("http://{addr}/v1/runs"))
        .await
        .unwrap()
        .json()
        .await
        .unwrap()
}

fn row<'a>(rows: &'a [serde_json::Value], run: &str) -> Option<&'a serde_json::Value> {
    rows.iter().find(|r| r["run_id"] == run)
}

fn identity_map(dir: &std::path::Path, name: &str, cap_usd: f64) -> String {
    let p = dir.join(name);
    std::fs::write(
        &p,
        format!(
            r#"{{"units":[{{"id":"ops","budget_usd_month":{cap_usd}}}],"prefixes":[{{"match":"agent://test/*","unit":"ops"}}]}}"#
        ),
    )
    .unwrap();
    p.to_string_lossy().into_owned()
}

fn stop(mut child: Child) {
    // SIGKILL: no graceful shutdown, no Drop, no flush. What the second
    // process reads is what was on disk the moment the call returned.
    child.kill().ok();
    child.wait().ok();
}

#[tokio::test]
async fn a_retained_reservation_survives_a_gateway_restart() {
    let dir = std::env::temp_dir().join(format!("tf-retained-restart-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let data_dir = dir.join("data");
    std::fs::create_dir_all(&data_dir).unwrap();
    let data_dir = data_dir.to_string_lossy().into_owned();
    let hold = Arc::new(AtomicBool::new(false));
    let upstream = provider(hold.clone()).await;

    // Process one: a parent that is answered, then a child the provider holds.
    let addr = free_addr();
    let mut first = spawn(
        &addr,
        &upstream,
        &data_dir,
        &identity_map(&dir, "map1.json", 100.0),
    );
    assert!(
        wait_for_listening(&mut first),
        "the first gateway never listened"
    );
    let parent = call(&addr, "parent", None).await;
    assert_eq!(parent.status().as_u16(), 200);
    hold.store(true, Ordering::SeqCst);
    let child = call(&addr, "child", Some("parent")).await;
    assert_eq!(
        child.status().as_u16(),
        502,
        "an unknown outcome is a 502 and retained"
    );
    let before = runs(&addr).await;
    let held = row(&before, "child")
        .expect("the child run is listed")
        .clone();
    assert_eq!(held["retained"], 1, "{held}");
    let exposure = held["reserved_usd"].as_f64().unwrap();
    assert!(exposure > 0.0, "{held}");
    assert!((held["retained_usd"].as_f64().unwrap() - exposure).abs() < 1e-12);
    let parent_before = row(&before, "parent").unwrap()["reserved_usd"]
        .as_f64()
        .unwrap();
    assert!((parent_before - exposure).abs() < 1e-12);
    stop(first);

    // Process two, same data dir. The unit cap is set so that one call of this
    // shape fits on its own and does NOT fit beside the restored reservation:
    // it is the restored unit liability, nothing else, that refuses it.
    hold.store(false, Ordering::SeqCst);
    let addr = free_addr();
    let mut second = spawn(
        &addr,
        &upstream,
        &data_dir,
        &identity_map(&dir, "map2.json", exposure * 1.5),
    );
    assert!(
        wait_for_listening(&mut second),
        "the second gateway never listened"
    );
    let after = runs(&addr).await;
    let other = call(&addr, "other", None).await;
    let other_status = other.status().as_u16();
    let other_body: serde_json::Value = other.json().await.unwrap_or_default();
    stop(second);
    std::fs::remove_dir_all(&dir).ok();
    println!("after restart: runs={after:?} other={other_status} {other_body}");

    let child = row(&after, "child")
        .unwrap_or_else(|| panic!("the restarted gateway forgot the retained run: {after:?}"));
    assert_eq!(child["retained"], 1, "{child}");
    assert!(
        (child["reserved_usd"].as_f64().unwrap() - exposure).abs() < 1e-12,
        "the child's exposure after the restart: {child}"
    );
    assert!((child["retained_usd"].as_f64().unwrap() - exposure).abs() < 1e-12);
    let parent = row(&after, "parent").expect("the ancestor is restored with it");
    assert!(
        (parent["reserved_usd"].as_f64().unwrap() - exposure).abs() < 1e-12,
        "the ancestor's share of the exposure: {parent}"
    );
    assert_eq!(parent["retained"], 0, "listed once, on its own run");
    assert_eq!(
        other_status, 402,
        "the restored unit reservation must fill the cap: {other_body}"
    );
    assert_eq!(other_body["error"]["type"], "unit_budget_exceeded");
}

/// A control plane that serves one Cloud-managed budget, for `parent`, on
/// `/v1/budgets`, knows no run's spend (`/v1/runs` is an empty list), and
/// answers 404 to everything else (the ingest then fails on its own, which
/// nothing here depends on). The run list is served because a gateway that
/// cannot read run spend admits nothing a budget governs (invariant 103).
/// Returns its base URL and a counter of budget polls, so a test can wait
/// until the gateway has the budget instead of sleeping on a guess.
async fn cloud_with_parent_budget(parent_budget_micros: i64) -> (String, Arc<AtomicUsize>) {
    use axum::routing::get;
    let polls = Arc::new(AtomicUsize::new(0));
    let seen = polls.clone();
    let app = axum::Router::new()
        .route(
            "/v1/budgets",
            get(move || {
                let seen = seen.clone();
                async move {
                    seen.fetch_add(1, Ordering::SeqCst);
                    axum::Json(serde_json::json!({ "parent": parent_budget_micros }))
                }
            }),
        )
        .route(
            "/v1/runs",
            get(|| async { axum::Json(serde_json::json!([])) }),
        )
        .fallback(|| async { axum::http::StatusCode::NOT_FOUND });
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let base = format!("http://{}", listener.local_addr().unwrap());
    tokio::spawn(async move {
        axum::serve(listener, app).await.ok();
    });
    (base, polls)
}

fn spawn_with_cloud(addr: &str, upstream: &str, data_dir: &str, cloud: &str) -> Child {
    Command::new(env!("CARGO_BIN_EXE_tokenfuse"))
        .env_remove("TOKENFUSE_ALLOW_STUB")
        .env_remove("TOKENFUSE_CLIENT_KEYS")
        .env_remove("TOKENFUSE_IDENTITY_MAP")
        .env_remove("TOKENFUSE_MAX_RUN_BUDGET_USD")
        .env_remove("TOKENFUSE_ADMIN_KEYS")
        .env("TOKENFUSE_UPSTREAM", upstream)
        .env("TOKENFUSE_MODE", "enforce")
        .env("TOKENFUSE_ADDR", addr)
        .env("TOKENFUSE_DATA_DIR", data_dir)
        .env("TOKENFUSE_CLOUD_URL", cloud)
        .env("TOKENFUSE_CLOUD_KEY", "test-org-key")
        .env("TOKENFUSE_CLOUD_HEARTBEAT_SECONDS", "0")
        .env("TOKENFUSE_IDENTITY_STRICT", "off")
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("failed to spawn the tokenfuse binary")
}

/// Wait until the gateway has polled `/v1/budgets` at least `n` times in total,
/// then a moment more so the poller has applied what it read.
async fn wait_for_budget_polls(polls: &AtomicUsize, n: usize) {
    for _ in 0..200 {
        if polls.load(Ordering::SeqCst) >= n {
            tokio::time::sleep(Duration::from_millis(300)).await;
            return;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    panic!("the gateway never polled the Cloud's budgets");
}

/// A parent whose budget lives in the Cloud is never opened by a call of its
/// own: the first child call opens it at that budget on first sight (D1's
/// exception, invariant 49). After a restart the journal recreates that parent
/// (it carries the retained child's share), and the replay leaves its budget at
/// zero until something opens it. Since the parent now HAS a snapshot, the
/// first-sight path never fired again, so every child call was refused 402
/// naming the parent until the parent itself called. The restored parent must
/// get its Cloud budget the same way a declared parent does.
#[tokio::test]
async fn a_restored_parent_gets_its_cloud_budget_back_after_a_restart() {
    let dir = std::env::temp_dir().join(format!("tf-retained-cloud-parent-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let data_dir = dir.join("data");
    std::fs::create_dir_all(&data_dir).unwrap();
    let data_dir = data_dir.to_string_lossy().into_owned();
    let hold = Arc::new(AtomicBool::new(true));
    let upstream = provider(hold.clone()).await;
    let (cloud, polls) = cloud_with_parent_budget(5_000_000).await;

    // Process one: the parent never calls. The child's call opens it at its
    // Cloud budget and is held by the provider, so it is retained.
    let addr = free_addr();
    let mut first = spawn_with_cloud(&addr, &upstream, &data_dir, &cloud);
    assert!(
        wait_for_listening(&mut first),
        "the first gateway never listened"
    );
    wait_for_budget_polls(&polls, 1).await;
    let child = call(&addr, "child", Some("parent")).await;
    let child_status = child.status().as_u16();
    let before = runs(&addr).await;
    stop(first);
    assert_eq!(
        child_status, 502,
        "the first child call is admitted against the Cloud-budgeted parent and retained: {before:?}"
    );
    assert_eq!(
        row(&before, "child").expect("the child is listed")["retained"],
        1
    );

    // Process two, same data dir and the same Cloud.
    hold.store(false, Ordering::SeqCst);
    let addr = free_addr();
    let polled = polls.load(Ordering::SeqCst);
    let mut second = spawn_with_cloud(&addr, &upstream, &data_dir, &cloud);
    assert!(
        wait_for_listening(&mut second),
        "the second gateway never listened"
    );
    wait_for_budget_polls(&polls, polled + 1).await;
    let next = call(&addr, "child-2", Some("parent")).await;
    let status = next.status().as_u16();
    let body: serde_json::Value = next.json().await.unwrap_or_default();
    let after = runs(&addr).await;
    stop(second);
    std::fs::remove_dir_all(&dir).ok();
    println!("after restart: child-2={status} {body} runs={after:?}");

    assert_eq!(
        status, 200,
        "a new child of a restored, Cloud-budgeted parent must be admitted: {body}"
    );
    let parent = row(&after, "parent").expect("the parent is listed");
    assert!(
        (parent["budget_usd"].as_f64().unwrap() - 5.0).abs() < 1e-9,
        "the restored parent carries its Cloud budget: {parent}"
    );
}
