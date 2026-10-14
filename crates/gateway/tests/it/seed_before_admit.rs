//! Invariant 103: a gateway that starts before its control plane admits
//! nothing a budget governs until it has read the control plane's money state.
//!
//! Measured on forge 2026-10-14 (`systemctl restart docker`): the gateway
//! started 60 ms before the control plane, logged that run spend and the unit
//! month could not be seeded "until the next restart", then admitted a call
//! for a unit already over its monthly cap (200) and a call on a run whose
//! Cloud-known spend, 0.000456, was past its 0.0004 budget.
//!
//! These run the real binary against a control plane that is not listening
//! when the gateway starts and comes up a moment later on the same address,
//! which is that race with the timing pinned rather than left to luck.

use super::retained_closure::{free_addr, now_millis, provider};
use axum::http::StatusCode;
use axum::routing::{get, post};
use axum::{Json, Router};
use serde_json::{json, Value};
use std::io::{BufRead, BufReader};
use std::process::{Child, Command, Stdio};
use std::sync::atomic::AtomicBool;
use std::sync::{mpsc, Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

const LISTENING_NEEDLE: &str = "tokenfuse gateway listening";
const OPENED_NEEDLE: &str = "the control plane answered the seed";
/// A listed model, priced at its own row: the estimate of this call is far
/// below 0.0004, so nothing but the seed can refuse it.
const CALL: &str = r#"{"model":"claude-haiku-5-5","max_tokens":16,"messages":[{"role":"user","content":"hello"}]}"#;
/// No prefix of the identity map matches it, so a call naming it has no unit.
const FREE_AGENT: &str = "agent://free/bot";
/// Mapped to unit `ops`, whose file cap is 0.001 USD.
const UNIT_AGENT: &str = "agent://test/bot";

struct Gateway {
    child: Child,
    log: Arc<Mutex<Vec<String>>>,
}

impl Drop for Gateway {
    fn drop(&mut self) {
        self.child.kill().ok();
        self.child.wait().ok();
    }
}

impl Gateway {
    fn logged(&self, needle: &str) -> bool {
        self.log.lock().unwrap().iter().any(|l| l.contains(needle))
    }
}

fn spawn(addr: &str, upstream: &str, cloud: &str, map: &str, events: &str, mode: &str) -> Gateway {
    let mut child = Command::new(env!("CARGO_BIN_EXE_tokenfuse"))
        .env_remove("TOKENFUSE_ALLOW_STUB")
        .env_remove("TOKENFUSE_CLIENT_KEYS")
        .env_remove("TOKENFUSE_MAX_RUN_BUDGET_USD")
        .env_remove("TOKENFUSE_ADMIN_KEYS")
        .env_remove("TOKENFUSE_DATA_DIR")
        .env("TOKENFUSE_UPSTREAM", upstream)
        .env("TOKENFUSE_MODE", mode)
        .env("TOKENFUSE_ADDR", addr)
        .env("TOKENFUSE_CLOUD_URL", cloud)
        .env("TOKENFUSE_CLOUD_KEY", "org-key")
        .env("TOKENFUSE_CLOUD_HEARTBEAT_SECONDS", "0")
        .env("TOKENFUSE_IDENTITY_MAP", map)
        .env("TOKENFUSE_IDENTITY_STRICT", "off")
        .env("TOKENFUSE_EVENTS_PATH", events)
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .expect("failed to spawn the tokenfuse binary");
    let stdout = child.stdout.take().expect("stdout piped");
    let log: Arc<Mutex<Vec<String>>> = Arc::default();
    let keep = Arc::clone(&log);
    let (tx, rx) = mpsc::channel::<()>();
    thread::spawn(move || {
        for line in BufReader::new(stdout).lines().map_while(Result::ok) {
            if line.contains(LISTENING_NEEDLE) {
                tx.send(()).ok();
            }
            keep.lock().unwrap().push(line);
        }
    });
    let listening = rx.recv_timeout(Duration::from_secs(20)).is_ok();
    let gw = Gateway { child, log };
    assert!(
        listening,
        "the gateway never listened: {:?}",
        gw.log.lock().unwrap()
    );
    gw
}

fn identity_map(dir: &std::path::Path) -> String {
    let p = dir.join("map.json");
    std::fs::write(
        &p,
        r#"{"units":[{"id":"ops","budget_usd_month":0.001}],"prefixes":[{"match":"agent://test/*","unit":"ops"}]}"#,
    )
    .unwrap();
    p.to_string_lossy().into_owned()
}

async fn call(addr: &str, run: &str, agent: &str, budget: &str) -> reqwest::Response {
    reqwest::Client::new()
        .post(format!("http://{addr}/v1/messages"))
        .header("x-fuse-run-id", run)
        .header("x-fuse-budget-usd", budget)
        .header("x-fuse-agent-id", agent)
        .header("content-type", "application/json")
        .body(CALL)
        .send()
        .await
        .expect("the gateway must answer")
}

async fn status_and_body(resp: reqwest::Response) -> (u16, Value) {
    let status = resp.status().as_u16();
    let body = resp.json::<Value>().await.unwrap_or(Value::Null);
    (status, body)
}

/// The control plane the forge box had: run `run-over` already spent 456
/// micro-USD, unit `ops` already spent 2145 this month (past its 1000 cap),
/// run `run-killed` killed by an operator. `/v1/run-spend` answers 404, so the
/// gateway reads `/v1/runs` as it does from a Cloud older than that route.
async fn control_plane_on(addr: &str) {
    let month = tokenfuse_gateway::unitledger::month_key(now_millis());
    let units = json!([{"unit": "ops", "month": month, "month_spent_microusd": 2145}]);
    let app = Router::new()
        .route("/v1/run-spend", get(|| async { StatusCode::NOT_FOUND }))
        .route(
            "/v1/runs",
            get(|| async {
                Json(json!([{"run_id": "run-over", "spent_microusd": 456, "killed": false}]))
            }),
        )
        .route(
            "/v1/units",
            get(move || {
                let units = units.clone();
                async move { Json(units) }
            }),
        )
        .route("/v1/budgets", get(|| async { Json(json!({})) }))
        .route("/v1/unit-budgets", get(|| async { Json(json!({})) }))
        .route("/v1/kills", get(|| async { Json(json!(["run-killed"])) }))
        .route("/v1/ingest", post(|| async { Json(json!({})) }));
    let listener = tokio::net::TcpListener::bind(addr)
        .await
        .expect("the control plane's address was taken in the meantime");
    tokio::spawn(async move {
        axum::serve(listener, app).await.ok();
    });
}

fn events_of(path: &std::path::Path, kind: &str) -> Vec<Value> {
    std::fs::read_to_string(path)
        .unwrap_or_default()
        .lines()
        .filter_map(|l| serde_json::from_str::<Value>(l).ok())
        .filter(|e| e["type"] == kind)
        .collect()
}

fn scratch(name: &str) -> std::path::PathBuf {
    let dir = std::env::temp_dir().join(format!(
        "tf-seed-before-admit-{name}-{}",
        std::process::id()
    ));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_gateway_that_starts_before_its_control_plane_admits_nothing_a_budget_governs() {
    let dir = scratch("enforce");
    let events = dir.join("events.ndjson");
    let upstream = provider(Arc::new(AtomicBool::new(false))).await;
    let cloud_addr = free_addr();
    let addr = free_addr();
    let gw = spawn(
        &addr,
        &upstream,
        &format!("http://{cloud_addr}"),
        &identity_map(&dir),
        &events.to_string_lossy(),
        "enforce",
    );

    // The control plane is not up. The run's Cloud-known spend is past the
    // budget this call declares, and the unit's month is past its cap: the
    // gateway knows neither, so it admits neither.
    let (status, body) = status_and_body(call(&addr, "run-over", FREE_AGENT, "0.0004").await).await;
    assert_eq!(
        status, 503,
        "a run whose spend the gateway cannot read must not be admitted: {body}"
    );
    assert_eq!(body["error"]["type"], "seed_pending", "{body}");
    assert_eq!(body["error"]["retryable"], true, "{body}");
    let unit = call(&addr, "run-unit", UNIT_AGENT, "10").await;
    assert_eq!(
        unit.headers()
            .get("retry-after")
            .and_then(|v| v.to_str().ok()),
        Some("1")
    );
    let (status, body) = status_and_body(unit).await;
    assert_eq!(
        status, 503,
        "a unit whose month the gateway cannot read must not be admitted: {body}"
    );
    // A second refusal on the same run writes no second event.
    let (status, _) = status_and_body(call(&addr, "run-over", FREE_AGENT, "0.0004").await).await;
    assert_eq!(status, 503);

    let failed = events_of(&events, "dependency_failed");
    let seed_events: Vec<&Value> = failed
        .iter()
        .filter(|e| e["data"]["dependency"] == "control_plane")
        .collect();
    assert_eq!(
        seed_events.len(),
        2,
        "one event per run while the seed is missing: {failed:?}"
    );
    let over = seed_events
        .iter()
        .find(|e| e["run_id"] == "run-over")
        .expect("the refused run is on the bus");
    assert_eq!(over["agent_id"], FREE_AGENT);
    assert_eq!(over["data"]["stage"], "seed");
    assert_eq!(over["data"]["effect"], "denied_unasked");

    // The control plane comes up on the address the gateway was given.
    control_plane_on(&cloud_addr).await;
    let deadline = Instant::now() + Duration::from_secs(30);
    let (status, body) = loop {
        let (status, body) =
            status_and_body(call(&addr, "run-over", FREE_AGENT, "0.0004").await).await;
        if status != 503 || Instant::now() > deadline {
            break (status, body);
        }
        tokio::time::sleep(Duration::from_millis(200)).await;
    };
    assert_eq!(
        status, 402,
        "once read, the run's 456 micro-USD is past its 400 budget: {body}"
    );
    assert_eq!(body["error"]["type"], "budget_exceeded", "{body}");
    let (status, body) = status_and_body(call(&addr, "run-unit", UNIT_AGENT, "10").await).await;
    assert_eq!(status, 402, "{body}");
    assert_eq!(body["error"]["type"], "unit_budget_exceeded", "{body}");
    let (status, body) = status_and_body(call(&addr, "run-killed", FREE_AGENT, "10").await).await;
    assert_eq!(
        status, 402,
        "a run killed in the Cloud is killed here: {body}"
    );
    assert_eq!(body["error"]["type"], "killed", "{body}");
    let (status, body) = status_and_body(call(&addr, "run-fresh", FREE_AGENT, "10").await).await;
    assert_eq!(
        status, 200,
        "a run the control plane knows nothing against: {body}"
    );
    assert!(
        gw.logged(OPENED_NEEDLE),
        "one line says the seed landed: {:?}",
        gw.log.lock().unwrap()
    );
    drop(gw);
    let _ = std::fs::remove_dir_all(&dir);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn shadow_forwards_while_the_seed_is_missing_and_says_so() {
    let dir = scratch("shadow");
    let events = dir.join("events.ndjson");
    let upstream = provider(Arc::new(AtomicBool::new(false))).await;
    let cloud_addr = free_addr();
    let addr = free_addr();
    let gw = spawn(
        &addr,
        &upstream,
        &format!("http://{cloud_addr}"),
        &identity_map(&dir),
        &events.to_string_lossy(),
        "shadow",
    );
    let resp = call(&addr, "run-shadow", FREE_AGENT, "10").await;
    let status = resp.status().as_u16();
    let would = resp
        .headers()
        .get("x-fuse-would-block")
        .and_then(|v| v.to_str().ok())
        .unwrap_or_default()
        .to_string();
    assert_eq!(status, 200, "shadow refuses nothing for money");
    assert!(
        would.contains("seed_pending"),
        "shadow records what enforce would have refused: {would:?}"
    );
    let failed = events_of(&events, "dependency_failed");
    let seed: Vec<&Value> = failed
        .iter()
        .filter(|e| e["data"]["dependency"] == "control_plane")
        .collect();
    assert_eq!(seed.len(), 1, "{failed:?}");
    assert_eq!(seed[0]["data"]["effect"], "allowed_ungoverned");
    drop(gw);
    let _ = std::fs::remove_dir_all(&dir);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_control_plane_that_answers_at_startup_opens_the_gate_before_the_first_call() {
    let dir = scratch("up");
    let events = dir.join("events.ndjson");
    let upstream = provider(Arc::new(AtomicBool::new(false))).await;
    let cloud_addr = free_addr();
    control_plane_on(&cloud_addr).await;
    let addr = free_addr();
    let gw = spawn(
        &addr,
        &upstream,
        &format!("http://{cloud_addr}"),
        &identity_map(&dir),
        &events.to_string_lossy(),
        "enforce",
    );
    // The first call already meets the seeded state: no 503 at all.
    let (status, body) = status_and_body(call(&addr, "run-over", FREE_AGENT, "0.0004").await).await;
    assert_eq!(status, 402, "{body}");
    assert_eq!(body["error"]["type"], "budget_exceeded", "{body}");
    let (status, body) = status_and_body(call(&addr, "run-fresh", FREE_AGENT, "10").await).await;
    assert_eq!(status, 200, "{body}");
    assert!(
        !gw.logged(OPENED_NEEDLE),
        "nothing was missing, so nothing landed late"
    );
    drop(gw);
    let _ = std::fs::remove_dir_all(&dir);
}
