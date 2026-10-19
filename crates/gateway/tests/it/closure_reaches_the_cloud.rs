//! D8.1: an observed closure of a retained reservation reaches the control
//! plane by the same path a settled call does, so the Cloud seeds a restarted
//! gateway takes (invariant 70 for the run, invariant 52 for the unit)
//! include it, exactly once. A no-charge closure sends nothing.
//!
//! The control plane here is a stub that records every record it ingests and
//! answers `/v1/runs` and `/v1/units` from what it recorded, the way the real
//! one folds them: per run and per unit, admitted rows only. `/v1/run-spend`
//! answers 404, so the gateway falls back to `/v1/runs` as an older Cloud
//! makes it (invariant 75).

use super::retained_closure::{
    call, close, free_addr, identity_map, mint, no_charge, now_millis, observed, provider,
    retained, row, runs, stop, AGENT, SECRET,
};
use axum::extract::State;
use axum::http::StatusCode;
use axum::routing::{get, post};
use axum::{Json, Router};
use serde_json::{json, Value};
use std::io::{BufRead, BufReader};
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{mpsc, Arc, Mutex};
use std::thread;
use std::time::Duration;

const LISTENING_NEEDLE: &str = "tokenfuse gateway listening";
const RUN_SEED_NEEDLE: &str = "seeded pending run spend from the control plane";
const UNIT_SEED_NEEDLE: &str = "seeded the unit month from the control plane";

type Ingested = Arc<Mutex<Vec<Value>>>;

async fn ingest(State(seen): State<Ingested>, Json(body): Json<Value>) -> Json<Value> {
    if let Some(records) = body["records"].as_array() {
        seen.lock().unwrap().extend(records.iter().cloned());
    }
    Json(json!({}))
}

fn admitted(r: &Value) -> bool {
    matches!(r["decision"].as_str(), Some("allow" | "cache_hit"))
}

async fn cloud_runs(State(seen): State<Ingested>) -> Json<Value> {
    let mut by_run: std::collections::BTreeMap<String, i64> = Default::default();
    for r in seen.lock().unwrap().iter().filter(|r| admitted(r)) {
        *by_run
            .entry(r["run_id"].as_str().unwrap_or_default().to_string())
            .or_default() += r["cost_microusd"].as_i64().unwrap_or(0);
    }
    Json(json!(by_run
        .into_iter()
        .map(|(run_id, spent)| json!({"run_id": run_id, "spent_microusd": spent, "killed": false}))
        .collect::<Vec<_>>()))
}

async fn cloud_units(State(seen): State<Ingested>) -> Json<Value> {
    let month = tokenfuse_gateway::unitledger::month_key(now_millis());
    let mut by_unit: std::collections::BTreeMap<String, i64> = Default::default();
    for r in seen.lock().unwrap().iter().filter(|r| admitted(r)) {
        let unit = r["unit"].as_str().unwrap_or_default();
        if !unit.is_empty() {
            *by_unit.entry(unit.to_string()).or_default() +=
                r["cost_microusd"].as_i64().unwrap_or(0);
        }
    }
    Json(json!(by_unit
        .into_iter()
        .map(|(unit, spent)| json!({"unit": unit, "month": month, "month_spent_microusd": spent}))
        .collect::<Vec<_>>()))
}

async fn stub_cloud() -> (String, Ingested) {
    let seen: Ingested = Arc::default();
    let app = Router::new()
        .route("/v1/ingest", post(ingest))
        .route("/v1/runs", get(cloud_runs))
        .route("/v1/units", get(cloud_units))
        .route("/v1/run-spend", get(|| async { StatusCode::NOT_FOUND }))
        .with_state(seen.clone());
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let base = format!("http://{}", listener.local_addr().unwrap());
    tokio::spawn(async move {
        axum::serve(listener, app).await.ok();
    });
    (base, seen)
}

fn spawn(addr: &str, upstream: &str, data_dir: &str, map: &str, cloud: &str) -> Child {
    Command::new(env!("CARGO_BIN_EXE_tokenfuse"))
        .env("TOKENFUSE_PROFILE", "observe")
        .env_remove("TOKENFUSE_ALLOW_STUB")
        .env_remove("TOKENFUSE_CLIENT_KEYS")
        .env_remove("TOKENFUSE_MAX_RUN_BUDGET_USD")
        .env_remove("TOKENFUSE_ADMIN_KEYS")
        .env_remove("TOKENFUSE_EVENTS_PATH")
        .env("TOKENFUSE_CLOUD_URL", cloud)
        .env("TOKENFUSE_CLOUD_KEY", "org-key")
        .env("TOKENFUSE_CLOUD_HEARTBEAT_SECONDS", "0")
        .env("TOKENFUSE_UPSTREAM", upstream)
        .env("TOKENFUSE_MODE", "enforce")
        .env("TOKENFUSE_ADDR", addr)
        .env("TOKENFUSE_DATA_DIR", data_dir)
        .env("TOKENFUSE_IDENTITY_MAP", map)
        .env("TOKENFUSE_IDENTITY_STRICT", "off")
        .env("TOKENFUSE_CLOSURE_SECRET", SECRET)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("failed to spawn the tokenfuse binary")
}

/// Wait for the listener, keeping every stdout line (the tracing output) so a test can read
/// what the startup seeds said.
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

fn line_with(lines: &Arc<Mutex<Vec<String>>>, needle: &str) -> String {
    lines
        .lock()
        .unwrap()
        .iter()
        .find(|l| l.contains(needle))
        .cloned()
        .unwrap_or_default()
}

fn rows_for(seen: &Ingested, run: &str) -> Vec<Value> {
    seen.lock()
        .unwrap()
        .iter()
        .filter(|r| r["run_id"] == run)
        .cloned()
        .collect()
}

/// Poll until `pred` holds or `secs` pass; the gateway flushes its cloud sink every 2 s.
async fn wait_until(secs: u64, pred: impl Fn() -> bool) -> bool {
    for _ in 0..secs * 10 {
        if pred() {
            return true;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    pred()
}

struct Retained {
    dir: std::path::PathBuf,
    data_dir: String,
    map: String,
    upstream: String,
    addr: String,
    child: Child,
    id: u64,
    revision: String,
}

/// A gateway pushing to `cloud`, with one call settled on `parent` and one retained on
/// `child` (parent `parent`), the way the W03 and D8 tests retain one.
async fn retained_with_cloud(name: &str, cloud: &str) -> Retained {
    let dir = std::env::temp_dir().join(format!("tf-closure-cloud-{name}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(dir.join("data")).unwrap();
    let data_dir = dir.join("data").to_string_lossy().into_owned();
    let map = identity_map(&dir, "map.json", 100.0);
    let hold = Arc::new(AtomicBool::new(false));
    let upstream = provider(hold.clone()).await;
    let addr = free_addr();
    let mut child = spawn(&addr, &upstream, &data_dir, &map, cloud);
    assert!(listening(&mut child).0, "the gateway never listened");
    assert_eq!(call(&addr, "parent", None).await.status().as_u16(), 200);
    hold.store(true, Ordering::SeqCst);
    assert_eq!(
        call(&addr, "child", Some("parent")).await.status().as_u16(),
        502
    );
    hold.store(false, Ordering::SeqCst);
    let (status, list) = retained(&addr).await;
    assert_eq!(status, 200, "{list}");
    let id = list[0]["reservation_id"].as_u64().unwrap();
    let revision = list[0]["revision"].as_str().unwrap().to_string();
    Retained {
        dir,
        data_dir,
        map,
        upstream,
        addr,
        child,
        id,
        revision,
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_observed_closure_reaches_the_cloud_once_and_the_restart_seeds_include_it() {
    const COST: i64 = 4_321;
    let (cloud, seen) = stub_cloud().await;
    let f = retained_with_cloud("observed", &cloud).await;
    // The parent's own settled call reaches the Cloud first: that is the path being reused.
    assert!(
        wait_until(10, || !rows_for(&seen, "parent").is_empty()).await,
        "the settled parent call never reached the stub Cloud"
    );
    let parent_cost: i64 = rows_for(&seen, "parent")
        .iter()
        .map(|r| r["cost_microusd"].as_i64().unwrap())
        .sum();

    let token = mint(SECRET, f.id, &f.revision, now_millis() + 60_000);
    let body = observed(f.id, &f.revision, "op-cloud", COST);
    let first = close(&f.addr, Some(&token), body.clone()).await;
    let reached = wait_until(8, || !rows_for(&seen, "child").is_empty()).await;
    // The same operation again: answered from the books, and no second row.
    let replayed = close(&f.addr, Some(&token), body.clone()).await;
    tokio::time::sleep(Duration::from_millis(2_600)).await;
    let child_rows_before_restart = rows_for(&seen, "child");
    stop(f.child);

    // Restart on the same data dir and the same Cloud.
    let mut again = spawn(&f.addr, &f.upstream, &f.data_dir, &f.map, &cloud);
    let (up, lines) = listening(&mut again);
    assert!(up, "the restarted gateway never listened");
    let run_seed = line_with(&lines, RUN_SEED_NEEDLE);
    let unit_seed = line_with(&lines, UNIT_SEED_NEEDLE);
    // A retry of the same operation across the restart is still not a second row.
    let replayed_after_restart = close(&f.addr, Some(&token), body).await;
    // The seed is credited on the run's first request in this process. The parent is opened
    // first: a child naming a parent this process has not opened is refused (invariant 49).
    let parent_status = call(&f.addr, "parent", None).await.status().as_u16();
    let next = call(&f.addr, "child", Some("parent")).await;
    let next_status = next.status().as_u16();
    let next_cost: f64 = next
        .headers()
        .get("x-fuse-cost-usd")
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.parse().ok())
        .unwrap_or(0.0);
    let after = runs(&f.addr).await;
    tokio::time::sleep(Duration::from_millis(2_600)).await;
    let closure_rows: Vec<Value> = rows_for(&seen, "child")
        .into_iter()
        .filter(|r| r["cost_microusd"] == COST)
        .collect();
    stop(again);
    std::fs::remove_dir_all(&f.dir).ok();
    println!(
        "close={first:?} replayed={replayed:?} replayed_after_restart={replayed_after_restart:?}"
    );
    println!("child rows before restart: {child_rows_before_restart:?}");
    for l in lines.lock().unwrap().iter().filter(|l| l.contains("seed")) {
        println!("startup: {l}");
    }
    println!("run seed: {run_seed}");
    println!("unit seed: {unit_seed}");
    println!("after restart: {after:?}");

    assert_eq!(first.0, 200, "the closure is accepted: {}", first.1);
    assert_eq!(replayed.0, 200, "{}", replayed.1);
    assert_eq!(replayed.1["replayed"], true, "{}", replayed.1);
    assert!(
        reached,
        "the observed closure never reached the Cloud: rows for child {child_rows_before_restart:?}"
    );
    assert_eq!(
        child_rows_before_restart.len(),
        1,
        "one row for one closure, the replay wrote none: {child_rows_before_restart:?}"
    );
    let r = &child_rows_before_restart[0];
    assert_eq!(r["decision"], "allow", "{r}");
    assert_eq!(r["cost_microusd"], COST, "{r}");
    assert_eq!(r["agent_id"], AGENT, "{r}");
    assert_eq!(r["unit"], "ops", "{r}");
    assert_eq!(r["parent_run_id"], "parent", "{r}");
    assert!(
        run_seed.contains(&format!("child={COST}")),
        "the run seed after a restart includes the observed cost: {run_seed}"
    );
    assert!(
        unit_seed.contains(&format!("ops={}", parent_cost + COST)),
        "the unit seed after a restart includes the observed cost on top of the parent's {parent_cost}: {unit_seed}"
    );
    assert_eq!(
        replayed_after_restart.1["replayed"], true,
        "{}",
        replayed_after_restart.1
    );
    assert_eq!(
        closure_rows.len(),
        1,
        "exactly one row for the closure across a replay and a restart: {closure_rows:?}"
    );
    assert_eq!(parent_status, 200);
    assert_eq!(next_status, 200);
    let spent = row(&after, "child").unwrap()["spent_usd"].as_f64().unwrap();
    assert!(
        (spent - (COST as f64 / 1e6 + next_cost)).abs() < 2e-6,
        "the restarted child starts from the closed cost: spent {spent}, next call {next_cost}"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_no_charge_closure_sends_no_row_to_the_cloud() {
    let (cloud, seen) = stub_cloud().await;
    let f = retained_with_cloud("no-charge", &cloud).await;
    let token = mint(SECRET, f.id, &f.revision, now_millis() + 60_000);
    let closed = close(&f.addr, Some(&token), no_charge(f.id, &f.revision, "op-nc")).await;
    // Long enough for two flush ticks.
    tokio::time::sleep(Duration::from_millis(4_500)).await;
    let child_rows = rows_for(&seen, "child");
    let parent_rows = rows_for(&seen, "parent");
    stop(f.child);
    std::fs::remove_dir_all(&f.dir).ok();
    assert_eq!(closed.0, 200, "{}", closed.1);
    assert!(
        !parent_rows.is_empty(),
        "the stub Cloud is reached at all, so silence about the child means something"
    );
    assert!(
        child_rows.is_empty(),
        "a no_charge closure adds no spend and writes no row: {child_rows:?}"
    );
}
