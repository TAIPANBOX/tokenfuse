//! Invariant 112: a call the gateway served reaches the Cloud even when the
//! gateway is stopped right after serving it.
//!
//! Measured on GCP 2026-10-14 (phase D1): a gateway pod was deleted while an
//! agent loop ran on it. The agent had 43 answered calls; the Cloud held 41,
//! and the restarted gateway seeded the run from those 41. The two missing
//! calls were the ones `CloudSink` held in memory between its 2 s flush
//! ticks: on SIGTERM the server stopped, `main` returned, and the runtime
//! dropped the buffer with no push.
//!
//! These run the real binary against a stub Cloud and stop it the way an
//! orchestrator does, with SIGTERM.

#![cfg(unix)]

use super::retained_closure::{call, free_addr, provider};
use axum::extract::State;
use axum::http::Uri;
use axum::routing::post;
use axum::{Json, Router};
use serde_json::{json, Value};
use std::io::{BufRead, BufReader};
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{mpsc, Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

const LISTENING_NEEDLE: &str = "tokenfuse gateway listening";

#[derive(Clone, Default)]
struct Cloud {
    seen: Arc<Mutex<Vec<Value>>>,
    /// While set, `/v1/ingest` takes the request and never answers.
    hang: Arc<AtomicBool>,
}

async fn ingest(State(cloud): State<Cloud>, Json(body): Json<Value>) -> Json<Value> {
    if cloud.hang.load(Ordering::SeqCst) {
        tokio::time::sleep(Duration::from_secs(120)).await;
    }
    if let Some(records) = body["records"].as_array() {
        cloud.seen.lock().unwrap().extend(records.iter().cloned());
    }
    Json(json!({}))
}

/// Every read a gateway makes of the Cloud at startup and while it runs
/// (run spend, kills, budgets, unit months) answered empty, so the gateway
/// starts as it does against a fresh control plane.
async fn empty(uri: Uri) -> Json<Value> {
    if uri.path().ends_with("budgets") {
        Json(json!({}))
    } else {
        Json(json!([]))
    }
}

async fn stub_cloud(hang: bool) -> (String, Cloud) {
    let cloud = Cloud::default();
    cloud.hang.store(hang, Ordering::SeqCst);
    let app = Router::new()
        .route("/v1/ingest", post(ingest))
        .fallback(empty)
        .with_state(cloud.clone());
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let base = format!("http://{}", listener.local_addr().unwrap());
    tokio::spawn(async move {
        axum::serve(listener, app).await.ok();
    });
    (base, cloud)
}

fn spawn(addr: &str, upstream: &str, cloud: &str) -> Child {
    Command::new(env!("CARGO_BIN_EXE_tokenfuse"))
        .env("TOKENFUSE_PROFILE", "observe")
        .env_remove("TOKENFUSE_ALLOW_STUB")
        .env_remove("TOKENFUSE_CLIENT_KEYS")
        .env_remove("TOKENFUSE_MAX_RUN_BUDGET_USD")
        .env_remove("TOKENFUSE_ADMIN_KEYS")
        .env_remove("TOKENFUSE_EVENTS_PATH")
        .env_remove("TOKENFUSE_IDENTITY_MAP")
        .env_remove("TOKENFUSE_DATA_DIR")
        .env_remove("TOKENFUSE_CLOSURE_SECRET")
        .env("TOKENFUSE_CLOUD_URL", cloud)
        .env("TOKENFUSE_CLOUD_KEY", "org-key")
        .env("TOKENFUSE_CLOUD_HEARTBEAT_SECONDS", "0")
        .env("TOKENFUSE_UPSTREAM", upstream)
        .env("TOKENFUSE_MODE", "enforce")
        .env("TOKENFUSE_ADDR", addr)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("failed to spawn the tokenfuse binary")
}

/// Wait for the listener, keeping every stdout line (the tracing output).
fn listening(child: &mut Child) -> (bool, Arc<Mutex<Vec<String>>>) {
    let stdout = child.stdout.take().expect("stdout piped");
    let lines: Arc<Mutex<Vec<String>>> = Arc::default();
    let keep = lines.clone();
    let (tx, rx) = mpsc::channel::<()>();
    thread::spawn(move || {
        for line in BufReader::new(stdout).lines().map_while(Result::ok) {
            let up = line.contains(LISTENING_NEEDLE);
            keep.lock().unwrap().push(line);
            if up {
                tx.send(()).ok();
            }
        }
    });
    (rx.recv_timeout(Duration::from_secs(15)).is_ok(), lines)
}

/// SIGTERM, what `docker stop` and a Kubernetes pod deletion send, then wait
/// for the process to exit; the time it took, `None` past `within`.
async fn terminate(child: &mut Child, within: Duration) -> Option<Duration> {
    let started = Instant::now();
    let status = Command::new("kill")
        .arg("-TERM")
        .arg(child.id().to_string())
        .status()
        .expect("kill(1) runs");
    assert!(status.success(), "SIGTERM was not delivered");
    while started.elapsed() < within {
        if child.try_wait().ok().flatten().is_some() {
            return Some(started.elapsed());
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    child.kill().ok();
    child.wait().ok();
    None
}

fn rows_for(cloud: &Cloud, run: &str) -> Vec<Value> {
    cloud
        .seen
        .lock()
        .unwrap()
        .iter()
        .filter(|r| r["run_id"] == run)
        .cloned()
        .collect()
}

/// The GCP loss, reproduced: three calls answered, the gateway stopped at
/// once, before its next 2 s flush tick. Every answered call is in the
/// Cloud when the process has exited.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_call_served_just_before_sigterm_reaches_the_cloud() {
    let (cloud_url, cloud) = stub_cloud(false).await;
    let upstream = provider(Arc::new(AtomicBool::new(false))).await;
    let addr = free_addr();
    let mut child = spawn(&addr, &upstream, &cloud_url);
    let (up, lines) = listening(&mut child);
    assert!(up, "the gateway never listened");
    for _ in 0..3 {
        assert_eq!(call(&addr, "r-stopped", None).await.status().as_u16(), 200);
    }
    let took = terminate(&mut child, Duration::from_secs(20)).await;
    assert!(
        took.is_some(),
        "the gateway did not exit within 20 s of SIGTERM"
    );
    tokio::time::sleep(Duration::from_millis(300)).await;
    let rows = rows_for(&cloud, "r-stopped");
    assert_eq!(
        rows.len(),
        3,
        "every answered call reaches the Cloud before the gateway exits: {rows:?}\n{}",
        lines.lock().unwrap().join("\n")
    );
    assert!(rows.iter().all(|r| r["decision"] == "allow"), "{rows:?}");
}

/// A Cloud that takes the push and never answers: the gateway still exits
/// within its bound, and says how many answered calls the Cloud did not get,
/// rather than exiting as if nothing were owed.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_stop_while_the_cloud_does_not_answer_says_what_was_not_delivered() {
    let (cloud_url, cloud) = stub_cloud(true).await;
    let upstream = provider(Arc::new(AtomicBool::new(false))).await;
    let addr = free_addr();
    let mut child = spawn(&addr, &upstream, &cloud_url);
    let (up, lines) = listening(&mut child);
    assert!(up, "the gateway never listened");
    for _ in 0..3 {
        assert_eq!(call(&addr, "r-unsent", None).await.status().as_u16(), 200);
    }
    let took = terminate(&mut child, Duration::from_secs(25)).await;
    assert!(
        took.is_some_and(|t| t < Duration::from_secs(20)),
        "a Cloud that never answers must not hold the exit: {took:?}"
    );
    assert!(rows_for(&cloud, "r-unsent").is_empty());
    tokio::time::sleep(Duration::from_millis(300)).await;
    let all = lines.lock().unwrap().join("\n");
    let line = lines
        .lock()
        .unwrap()
        .iter()
        .find(|l| l.contains("before exit") && l.contains("WARN"))
        .cloned()
        .unwrap_or_default();
    assert!(
        strip_ansi(&line).contains("unsent=3"),
        "the exit says how many answered calls did not reach the Cloud:\n{all}"
    );
}

/// The log line's fields are coloured (`unsent` and `=` sit in separate CSI
/// sequences), so a plain substring match on `unsent=3` cannot see them.
fn strip_ansi(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let mut chars = s.chars().peekable();
    while let Some(c) = chars.next() {
        if c == '\u{1b}' && chars.peek() == Some(&'[') {
            chars.next();
            for c2 in chars.by_ref() {
                if c2.is_ascii_alphabetic() {
                    break;
                }
            }
            continue;
        }
        out.push(c);
    }
    out
}
