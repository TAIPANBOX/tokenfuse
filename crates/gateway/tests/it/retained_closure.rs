//! D8, gateway side: a person closes one retained reservation (invariant 50,
//! D7) with evidence, through an admin route that takes a short-lived HMAC
//! token bound to the reservation id and its revision.
//!
//! These run the real binary on a `TOKENFUSE_DATA_DIR`, retain a call the way
//! W03's restart test does (the provider reads the POST whole and closes the
//! socket with no status line), then close it. The token is minted here by
//! code written independently of the gateway's own, from the format the
//! closure module documents, so a test cannot pass by sharing a bug with the
//! verifier.

use hmac::{Hmac, Mac};
use sha2::Sha256;
use std::io::{BufRead, BufReader};
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{mpsc, Arc};
use std::thread;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

const LISTENING_NEEDLE: &str = "tokenfuse gateway listening";
pub(super) const AGENT: &str = "agent://test/bot";
const CALL: &str = r#"{"model":"claude-sonnet","max_tokens":1000,"messages":[{"role":"user","content":"hello there"}]}"#;
pub(super) const SECRET: &str = "closure-test-secret-0123456789abcdef0123456789";
const TOKEN_HEADER: &str = "x-fuse-closure-token";
const JOURNAL: &str = "retained-reservations.ndjson";

pub(super) fn free_addr() -> String {
    let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let a = l.local_addr().unwrap();
    drop(l);
    a.to_string()
}

pub(super) fn now_millis() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_millis() as i64
}

/// The token the operator console mints after a passkey assertion:
/// `v1.<reservation id>.<revision>.<expiry, unix millis>.<hex HMAC-SHA256>`,
/// the MAC over `tokenfuse-closure-v1\n<id>\n<revision>\n<expiry>`.
pub(super) fn mint(secret: &str, id: u64, revision: &str, exp_millis: i64) -> String {
    let mut mac = Hmac::<Sha256>::new_from_slice(secret.as_bytes()).unwrap();
    mac.update(format!("tokenfuse-closure-v1\n{id}\n{revision}\n{exp_millis}").as_bytes());
    let sig: String = mac
        .finalize()
        .into_bytes()
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect();
    format!("v1.{id}.{revision}.{exp_millis}.{sig}")
}

pub(super) async fn provider(hold: Arc<AtomicBool>) -> String {
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

pub(super) fn identity_map(dir: &std::path::Path, name: &str, cap_usd: f64) -> String {
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

fn spawn(
    addr: &str,
    upstream: &str,
    data_dir: &str,
    identity_map: &str,
    secret: Option<&str>,
) -> Child {
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_tokenfuse"));
    cmd.env("TOKENFUSE_PROFILE", "observe");
    cmd.env_remove("TOKENFUSE_ALLOW_STUB")
        .env_remove("TOKENFUSE_CLIENT_KEYS")
        .env_remove("TOKENFUSE_CLOUD_URL")
        .env_remove("TOKENFUSE_CLOUD_KEY")
        .env_remove("TOKENFUSE_MAX_RUN_BUDGET_USD")
        .env_remove("TOKENFUSE_ADMIN_KEYS")
        .env_remove("TOKENFUSE_CLOSURE_SECRET")
        .env("TOKENFUSE_UPSTREAM", upstream)
        .env("TOKENFUSE_MODE", "enforce")
        .env("TOKENFUSE_ADDR", addr)
        .env("TOKENFUSE_DATA_DIR", data_dir)
        .env("TOKENFUSE_IDENTITY_MAP", identity_map)
        .env("TOKENFUSE_IDENTITY_STRICT", "off")
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    if let Some(s) = secret {
        cmd.env("TOKENFUSE_CLOSURE_SECRET", s);
    }
    cmd.spawn().expect("failed to spawn the tokenfuse binary")
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

pub(super) fn stop(mut child: Child) {
    child.kill().ok();
    child.wait().ok();
}

pub(super) async fn call(addr: &str, run: &str, parent: Option<&str>) -> reqwest::Response {
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

pub(super) async fn runs(addr: &str) -> Vec<serde_json::Value> {
    reqwest::get(format!("http://{addr}/v1/runs"))
        .await
        .unwrap()
        .json()
        .await
        .unwrap()
}

pub(super) fn row<'a>(rows: &'a [serde_json::Value], run: &str) -> Option<&'a serde_json::Value> {
    rows.iter().find(|r| r["run_id"] == run)
}

/// `GET /v1/retained`: the id and revision a console needs to mint a token.
pub(super) async fn retained(addr: &str) -> (u16, serde_json::Value) {
    let r = reqwest::get(format!("http://{addr}/v1/retained"))
        .await
        .unwrap();
    let status = r.status().as_u16();
    (status, r.json().await.unwrap_or_default())
}

pub(super) async fn close(
    addr: &str,
    token: Option<&str>,
    body: serde_json::Value,
) -> (u16, serde_json::Value) {
    let mut req = reqwest::Client::new()
        .post(format!("http://{addr}/v1/retained/close"))
        .header("content-type", "application/json")
        .body(body.to_string());
    if let Some(t) = token {
        req = req.header(TOKEN_HEADER, t);
    }
    let r = req.send().await.expect("the gateway must answer");
    let status = r.status().as_u16();
    (status, r.json().await.unwrap_or_default())
}

pub(super) fn observed(id: u64, revision: &str, op: &str, cost: i64) -> serde_json::Value {
    serde_json::json!({
        "reservation_id": id,
        "expected_revision": revision,
        "operation_id": op,
        "evidence_kind": "observed",
        "observed_microusd": cost,
        "evidence_ref": "provider usage msg_01HX",
    })
}

pub(super) fn no_charge(id: u64, revision: &str, op: &str) -> serde_json::Value {
    serde_json::json!({
        "reservation_id": id,
        "expected_revision": revision,
        "operation_id": op,
        "evidence_kind": "no_charge",
        "evidence_ref": "invoice 2026-10 line 14: no charge",
    })
}

/// A gateway with one retained reservation on run `child` (parent `parent`).
struct Fixture {
    dir: std::path::PathBuf,
    data_dir: String,
    upstream: String,
    hold: Arc<AtomicBool>,
    addr: String,
    child: Child,
    exposure: f64,
    id: u64,
    revision: String,
}

async fn retained_fixture(name: &str, secret: Option<&str>, cap_usd: f64) -> Fixture {
    let dir = std::env::temp_dir().join(format!("tf-closure-{name}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(dir.join("data")).unwrap();
    let data_dir = dir.join("data").to_string_lossy().into_owned();
    let hold = Arc::new(AtomicBool::new(false));
    let upstream = provider(hold.clone()).await;
    let addr = free_addr();
    let mut child = spawn(
        &addr,
        &upstream,
        &data_dir,
        &identity_map(&dir, "map.json", cap_usd),
        secret,
    );
    assert!(wait_for_listening(&mut child), "the gateway never listened");
    assert_eq!(call(&addr, "parent", None).await.status().as_u16(), 200);
    hold.store(true, Ordering::SeqCst);
    assert_eq!(
        call(&addr, "child", Some("parent")).await.status().as_u16(),
        502
    );
    hold.store(false, Ordering::SeqCst);
    let before = runs(&addr).await;
    let held = row(&before, "child").expect("the child is listed").clone();
    assert_eq!(held["retained"], 1, "{held}");
    let exposure = held["reserved_usd"].as_f64().unwrap();
    let (status, list) = retained(&addr).await;
    let (id, revision) = if status == 200 {
        let e = &list[0];
        (
            e["reservation_id"].as_u64().unwrap_or(0),
            e["revision"].as_str().unwrap_or_default().to_string(),
        )
    } else {
        (0, String::new())
    };
    Fixture {
        dir,
        data_dir,
        upstream,
        hold,
        addr,
        child,
        exposure,
        id,
        revision,
    }
}

fn spent(rows: &[serde_json::Value], run: &str) -> f64 {
    row(rows, run).unwrap()["spent_usd"].as_f64().unwrap()
}

#[tokio::test]
async fn an_observed_closure_settles_the_run_at_the_given_cost_exactly_once() {
    let f = retained_fixture("observed", Some(SECRET), 100.0).await;
    let (status, list) = retained(&f.addr).await;
    let before = runs(&f.addr).await;
    let token = mint(SECRET, f.id, &f.revision, now_millis() + 60_000);
    let first = close(
        &f.addr,
        Some(&token),
        observed(f.id, &f.revision, "op-1", 4_321),
    )
    .await;
    let after = runs(&f.addr).await;
    let (_, list_after) = retained(&f.addr).await;
    stop(f.child);
    std::fs::remove_dir_all(&f.dir).ok();
    println!("list={status} {list} close={first:?} after={after:?}");

    assert_eq!(
        status, 200,
        "GET /v1/retained lists the reservation: {list}"
    );
    assert_eq!(list.as_array().map(Vec::len), Some(1), "{list}");
    assert_eq!(
        list[0]["run_id"], "child",
        "the listing names the run: {list}"
    );
    assert_eq!(first.0, 200, "the closure is accepted: {}", first.1);
    assert_eq!(first.1["settled_microusd"], 4_321, "{}", first.1);
    assert_eq!(first.1["replayed"], false, "{}", first.1);
    let child = row(&after, "child").unwrap();
    assert_eq!(child["retained"], 0, "{child}");
    assert!(
        child["reserved_usd"].as_f64().unwrap().abs() < 1e-12,
        "{child}"
    );
    let parent = row(&after, "parent").unwrap();
    assert!(
        parent["reserved_usd"].as_f64().unwrap().abs() < 1e-12,
        "the ancestor's share is settled too: {parent}"
    );
    for run in ["child", "parent"] {
        let delta = spent(&after, run) - spent(&before, run);
        assert!(
            (delta - 0.004_321).abs() < 1e-9,
            "{run} is charged the observed cost once: {delta}"
        );
    }
    assert_eq!(list_after.as_array().map(Vec::len), Some(0), "{list_after}");
}

#[tokio::test]
async fn a_no_charge_closure_releases_both_halves_at_zero() {
    // One call of this shape fits the unit's cap on its own, and not beside
    // the retained reservation: only releasing the unit half admits it.
    let probe = retained_fixture("probe", Some(SECRET), 100.0).await;
    let cap = probe.exposure * 1.5;
    stop(probe.child);
    std::fs::remove_dir_all(&probe.dir).ok();

    let f = retained_fixture("no-charge", Some(SECRET), cap).await;
    let refused = call(&f.addr, "other-before", None).await.status().as_u16();
    let before = runs(&f.addr).await;
    let token = mint(SECRET, f.id, &f.revision, now_millis() + 60_000);
    let closed = close(&f.addr, Some(&token), no_charge(f.id, &f.revision, "op-nc")).await;
    let after = runs(&f.addr).await;
    let admitted = call(&f.addr, "other-after", None).await.status().as_u16();
    stop(f.child);
    std::fs::remove_dir_all(&f.dir).ok();
    println!("refused={refused} close={closed:?} admitted={admitted} after={after:?}");

    assert_eq!(refused, 402, "the retained unit half fills the cap");
    assert_eq!(closed.0, 200, "{}", closed.1);
    assert_eq!(closed.1["settled_microusd"], 0, "{}", closed.1);
    for run in ["child", "parent"] {
        assert!(
            row(&after, run).unwrap()["reserved_usd"]
                .as_f64()
                .unwrap()
                .abs()
                < 1e-12
        );
        assert!(
            (spent(&after, run) - spent(&before, run)).abs() < 1e-12,
            "{run}: no_charge adds no spend"
        );
    }
    assert_eq!(
        admitted, 200,
        "the unit half is released, so the cap has room"
    );
}

#[tokio::test]
async fn the_same_operation_returns_its_recorded_result_and_different_content_conflicts() {
    let f = retained_fixture("idempotent", Some(SECRET), 100.0).await;
    let token = mint(SECRET, f.id, &f.revision, now_millis() + 60_000);
    let body = observed(f.id, &f.revision, "op-same", 1_000);
    let first = close(&f.addr, Some(&token), body.clone()).await;
    let mid = runs(&f.addr).await;
    let again = close(&f.addr, Some(&token), body).await;
    let changed = close(
        &f.addr,
        Some(&token),
        observed(f.id, &f.revision, "op-same", 2_000),
    )
    .await;
    let other_op = close(
        &f.addr,
        Some(&token),
        observed(f.id, &f.revision, "op-other", 1_000),
    )
    .await;
    let after = runs(&f.addr).await;
    stop(f.child);
    std::fs::remove_dir_all(&f.dir).ok();
    println!("first={first:?} again={again:?} changed={changed:?} other={other_op:?}");

    assert_eq!(first.0, 200, "{}", first.1);
    assert_eq!(again.0, 200, "the recorded result: {}", again.1);
    assert_eq!(again.1["replayed"], true, "{}", again.1);
    assert_eq!(again.1["settled_microusd"], 1_000);
    assert_eq!(changed.0, 409, "{}", changed.1);
    assert_eq!(
        changed.1["error"]["type"], "closure_conflict",
        "{}",
        changed.1
    );
    assert_eq!(other_op.0, 409, "{}", other_op.1);
    assert_eq!(
        other_op.1["error"]["type"], "already_closed",
        "{}",
        other_op.1
    );
    for run in ["child", "parent"] {
        assert!(
            (spent(&after, run) - spent(&mid, run)).abs() < 1e-12,
            "{run}: neither the replay nor the conflict charged again"
        );
    }
}

#[tokio::test]
async fn a_missing_expired_misbound_or_stale_token_changes_nothing() {
    let f = retained_fixture("refusals", Some(SECRET), 100.0).await;
    let before = runs(&f.addr).await;
    let now = now_millis();
    let body = observed(f.id, &f.revision, "op-r", 500);
    let missing = close(&f.addr, None, body.clone()).await;
    let expired = close(
        &f.addr,
        Some(&mint(SECRET, f.id, &f.revision, now - 1_000)),
        body.clone(),
    )
    .await;
    let long_lived = close(
        &f.addr,
        Some(&mint(SECRET, f.id, &f.revision, now + 3_600_000)),
        body.clone(),
    )
    .await;
    let forged = close(
        &f.addr,
        Some(&mint(
            "another-secret-that-is-long-enough-0123456789",
            f.id,
            &f.revision,
            now + 60_000,
        )),
        body.clone(),
    )
    .await;
    let other_id = close(
        &f.addr,
        Some(&mint(SECRET, f.id + 1, &f.revision, now + 60_000)),
        body.clone(),
    )
    .await;
    let other_rev = close(
        &f.addr,
        Some(&mint(SECRET, f.id, "0000000000000000", now + 60_000)),
        body.clone(),
    )
    .await;
    // A token correctly bound to a revision that is not the reservation's.
    let stale = close(
        &f.addr,
        Some(&mint(SECRET, f.id, "0000000000000000", now + 60_000)),
        observed(f.id, "0000000000000000", "op-r", 500),
    )
    .await;
    let after = runs(&f.addr).await;
    let (_, list) = retained(&f.addr).await;
    stop(f.child);
    std::fs::remove_dir_all(&f.dir).ok();
    println!(
        "missing={missing:?} expired={expired:?} long={long_lived:?} forged={forged:?} id={other_id:?} rev={other_rev:?} stale={stale:?}"
    );

    assert_eq!(missing.0, 401, "{}", missing.1);
    assert_eq!(missing.1["error"]["type"], "closure_token_required");
    assert_eq!(expired.0, 401, "{}", expired.1);
    assert_eq!(expired.1["error"]["type"], "closure_token_expired");
    assert_eq!(long_lived.0, 401, "{}", long_lived.1);
    assert_eq!(long_lived.1["error"]["type"], "closure_token_invalid");
    assert_eq!(forged.0, 401, "{}", forged.1);
    assert_eq!(forged.1["error"]["type"], "closure_token_invalid");
    assert_eq!(other_id.0, 403, "{}", other_id.1);
    assert_eq!(other_id.1["error"]["type"], "closure_token_mismatch");
    assert_eq!(other_rev.0, 403, "{}", other_rev.1);
    assert_eq!(other_rev.1["error"]["type"], "closure_token_mismatch");
    assert_eq!(stale.0, 409, "{}", stale.1);
    assert_eq!(stale.1["error"]["type"], "stale_revision");
    assert_eq!(list.as_array().map(Vec::len), Some(1), "still open: {list}");
    for run in ["child", "parent"] {
        let (b, a) = (row(&before, run).unwrap(), row(&after, run).unwrap());
        assert_eq!(b["reserved_usd"], a["reserved_usd"], "{run}");
        assert_eq!(b["spent_usd"], a["spent_usd"], "{run}");
    }
}

#[tokio::test]
async fn a_closed_reservation_stays_closed_after_a_restart_and_the_journal_keeps_only_open_ones() {
    let f = retained_fixture("restart", Some(SECRET), 100.0).await;
    let journal = std::path::Path::new(&f.data_dir).join(JOURNAL);
    let token = mint(SECRET, f.id, &f.revision, now_millis() + 60_000);
    let closed = close(&f.addr, Some(&token), no_charge(f.id, &f.revision, "op-x")).await;
    // A second call the provider holds: retained, and never closed.
    f.hold.store(true, Ordering::SeqCst);
    let open = call(&f.addr, "still-open", None).await.status().as_u16();
    f.hold.store(false, Ordering::SeqCst);
    let lines_before = std::fs::read_to_string(&journal).unwrap_or_default();
    stop(f.child);

    let addr = free_addr();
    let mut second = spawn(
        &addr,
        &f.upstream,
        &f.data_dir,
        &identity_map(&f.dir, "map2.json", 100.0),
        Some(SECRET),
    );
    assert!(
        wait_for_listening(&mut second),
        "the restart never listened"
    );
    let after = runs(&addr).await;
    let (_, list) = retained(&addr).await;
    let replay = close(&addr, Some(&token), no_charge(f.id, &f.revision, "op-x")).await;
    let lines_after = std::fs::read_to_string(&journal).unwrap_or_default();
    stop(second);
    std::fs::remove_dir_all(&f.dir).ok();
    println!(
        "closed={closed:?} open={open} after={after:?} list={list} replay={replay:?}\nbefore:\n{lines_before}\nafter:\n{lines_after}"
    );

    assert_eq!(closed.0, 200, "{}", closed.1);
    assert_eq!(open, 502);
    assert!(
        row(&after, "child").is_none_or(|c| c["retained"] == 0),
        "the closed reservation is not resurrected: {after:?}"
    );
    assert_eq!(
        row(&after, "still-open").map(|r| r["retained"].clone()),
        Some(serde_json::json!(1)),
        "the open one is restored: {after:?}"
    );
    assert_eq!(list.as_array().map(Vec::len), Some(1), "{list}");
    assert_eq!(
        replay.0, 200,
        "the recorded result survives one restart: {}",
        replay.1
    );
    assert_eq!(replay.1["replayed"], true, "{}", replay.1);
    let records: Vec<serde_json::Value> = lines_after
        .lines()
        .filter(|l| !l.trim().is_empty())
        .map(|l| serde_json::from_str(l).unwrap())
        .collect();
    assert_eq!(
        records.len(),
        1,
        "only the open record is kept: {lines_after}"
    );
    assert_eq!(records[0]["kind"], "retained");
    assert_eq!(records[0]["run"]["run_id"], "still-open");
}

#[tokio::test]
async fn with_no_closure_secret_the_route_is_off() {
    let f = retained_fixture("off", None, 100.0).await;
    let token = mint(SECRET, 1, "0000000000000000", now_millis() + 60_000);
    let closed = close(
        &f.addr,
        Some(&token),
        no_charge(1, "0000000000000000", "op"),
    )
    .await;
    let (list_status, _) = retained(&f.addr).await;
    let after = runs(&f.addr).await;
    stop(f.child);
    std::fs::remove_dir_all(&f.dir).ok();
    assert_eq!(closed.0, 404, "{}", closed.1);
    assert_eq!(list_status, 404);
    assert_eq!(row(&after, "child").unwrap()["retained"], 1);
}

#[test]
fn a_closure_secret_too_short_refuses_to_start() {
    let mut child = Command::new(env!("CARGO_BIN_EXE_tokenfuse"))
        .env("TOKENFUSE_PROFILE", "observe")
        .env_remove("TOKENFUSE_ALLOW_STUB")
        .env_remove("TOKENFUSE_DATA_DIR")
        .env_remove("TOKENFUSE_CLOUD_URL")
        .env("TOKENFUSE_UPSTREAM", "http://127.0.0.1:9/v1/messages")
        .env("TOKENFUSE_ADDR", free_addr())
        .env("TOKENFUSE_CLOSURE_SECRET", "short")
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("runs");
    // A gateway that ignores the variable starts and serves; give it a bounded
    // time to exit, then stop it so the failure is an assertion, not a hang.
    for _ in 0..100 {
        if child.try_wait().unwrap().is_some() {
            break;
        }
        thread::sleep(Duration::from_millis(50));
    }
    if child.try_wait().unwrap().is_none() {
        child.kill().ok();
    }
    let out = child.wait_with_output().expect("collects");
    let text = format!(
        "{}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    assert_eq!(out.status.code(), Some(2), "{text}");
    assert!(text.contains("TOKENFUSE_CLOSURE_SECRET"), "{text}");
    assert!(!text.contains(LISTENING_NEEDLE), "{text}");
}
