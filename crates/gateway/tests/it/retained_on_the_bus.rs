//! D10 (invariant 90): a retained call and its closure reach the agent-event
//! bus, once each, and a restart adds neither.
//!
//! These run the real binary with `TOKENFUSE_EVENTS_PATH` set, retain calls
//! the way `retained_closure.rs` does (the provider reads the POST whole and
//! closes the socket with no status line), close one with a token minted by
//! that file's independent minter, and read the NDJSON file the gateway wrote.
//! The same file is handed to the restarted process, so a line written by the
//! journal's replay would be counted here.

use super::retained_closure::{
    close, free_addr, identity_map, mint, now_millis, observed, provider, retained, stop, AGENT,
    SECRET,
};
use std::io::{BufRead, BufReader};
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{mpsc, Arc, Mutex};
use std::thread;
use std::time::Duration;

const LISTENING_NEEDLE: &str = "tokenfuse gateway listening";
const CALL: &str = r#"{"model":"claude-sonnet","max_tokens":1000,"messages":[{"role":"user","content":"hello there"}]}"#;
const ON_BEHALF_OF: &str = "user://test/alice";

/// A running gateway and every line it has written to stdout so far.
struct Gateway {
    child: Child,
    log: Arc<Mutex<Vec<String>>>,
}

/// `tracing_subscriber::fmt()` colours its output even into a pipe, which
/// splits `skipped_total=1` with escape sequences; `cache_default_startup.rs`
/// has the same function for the same reason.
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

fn spawn(addr: &str, upstream: &str, data_dir: &str, events: &str, map: &str) -> Gateway {
    let mut child = Command::new(env!("CARGO_BIN_EXE_tokenfuse"))
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
        .env("TOKENFUSE_EVENTS_PATH", events)
        .env("TOKENFUSE_IDENTITY_MAP", map)
        .env("TOKENFUSE_IDENTITY_STRICT", "off")
        .env("TOKENFUSE_CLOSURE_SECRET", SECRET)
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .expect("failed to spawn the tokenfuse binary");
    let stdout = child.stdout.take().expect("stdout piped");
    let log = Arc::new(Mutex::new(Vec::new()));
    let lines = Arc::clone(&log);
    let (tx, rx) = mpsc::channel::<()>();
    thread::spawn(move || {
        for line in BufReader::new(stdout).lines().map_while(Result::ok) {
            let line = strip_ansi(&line);
            if line.contains(LISTENING_NEEDLE) {
                tx.send(()).ok();
            }
            lines.lock().unwrap().push(line);
        }
    });
    let listening = rx.recv_timeout(Duration::from_secs(15)).is_ok();
    assert!(
        listening,
        "the gateway never listened: {:?}",
        log.lock().unwrap()
    );
    Gateway { child, log }
}

/// One call on `run`, naming `agent` when given, with a declared chain.
async fn call(addr: &str, run: &str, parent: Option<&str>, agent: Option<&str>) -> u16 {
    let mut req = reqwest::Client::new()
        .post(format!("http://{addr}/v1/messages"))
        .header("x-fuse-run-id", run)
        .header("x-fuse-budget-usd", "10")
        .header("x-fuse-on-behalf-of", ON_BEHALF_OF)
        .header("content-type", "application/json")
        .body(CALL);
    if let Some(a) = agent {
        req = req.header("x-fuse-agent-id", a);
    }
    if let Some(p) = parent {
        req = req.header("x-fuse-parent-run-id", p);
    }
    req.send()
        .await
        .expect("the gateway must answer")
        .status()
        .as_u16()
}

/// Every event of `kind` the gateway has written to `path`.
fn on_bus(path: &std::path::Path, kind: &str) -> Vec<serde_json::Value> {
    std::fs::read_to_string(path)
        .unwrap_or_default()
        .lines()
        .filter(|l| !l.trim().is_empty())
        .map(|l| serde_json::from_str::<serde_json::Value>(l).expect("one JSON object per line"))
        .filter(|e| e["type"] == kind)
        .collect()
}

fn scratch(name: &str) -> (std::path::PathBuf, String, std::path::PathBuf) {
    let dir = std::env::temp_dir().join(format!("tf-bus-{name}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(dir.join("data")).unwrap();
    let data_dir = dir.join("data").to_string_lossy().into_owned();
    let events = dir.join("events.ndjson");
    (dir, data_dir, events)
}

#[tokio::test]
async fn a_retained_call_and_its_closure_each_reach_the_bus_once_and_a_restart_adds_neither() {
    let (dir, data_dir, events) = scratch("once");
    let events_path = events.to_string_lossy().into_owned();
    let hold = Arc::new(AtomicBool::new(false));
    let upstream = provider(hold.clone()).await;
    let addr = free_addr();
    let gw = spawn(
        &addr,
        &upstream,
        &data_dir,
        &events_path,
        &identity_map(&dir, "map.json", 100.0),
    );
    let parent = call(&addr, "parent", None, Some(AGENT)).await;
    hold.store(true, Ordering::SeqCst);
    let child = call(&addr, "child", Some("parent"), Some(AGENT)).await;
    let still_open = call(&addr, "still-open", None, Some(AGENT)).await;
    hold.store(false, Ordering::SeqCst);
    let (_, list) = retained(&addr).await;
    let listed = |run: &str| {
        list.as_array()
            .and_then(|rows| rows.iter().find(|r| r["run_id"] == run))
            .cloned()
            .unwrap_or_default()
    };
    let held = listed("child");
    let id = held["reservation_id"].as_u64().unwrap_or(0);
    let revision = held["revision"].as_str().unwrap_or_default().to_string();
    let retained_events = on_bus(&events, "call_retained");

    let now = now_millis();
    let forged = close(
        &addr,
        Some(&mint(
            "another-secret-that-is-long-enough-0123456789",
            id,
            &revision,
            now + 60_000,
        )),
        observed(id, &revision, "op-forged", 4_321),
    )
    .await;
    let stale = close(
        &addr,
        Some(&mint(SECRET, id, "0000000000000000", now + 60_000)),
        observed(id, "0000000000000000", "op-stale", 4_321),
    )
    .await;
    let after_refusals = on_bus(&events, "retained_closed").len();
    let token = mint(SECRET, id, &revision, now + 60_000);
    let closed = close(&addr, Some(&token), observed(id, &revision, "op-1", 4_321)).await;
    let replayed = close(&addr, Some(&token), observed(id, &revision, "op-1", 4_321)).await;
    let closed_events = on_bus(&events, "retained_closed");
    stop(gw.child);

    // The same data dir and the same events file: the journal's replay
    // restores `still-open`, and must not report it a second time.
    let addr2 = free_addr();
    let gw2 = spawn(
        &addr2,
        &upstream,
        &data_dir,
        &events_path,
        &identity_map(&dir, "map2.json", 100.0),
    );
    let (_, list2) = retained(&addr2).await;
    let replayed_after = close(
        &addr2,
        Some(&mint(SECRET, id, &revision, now_millis() + 60_000)),
        observed(id, &revision, "op-1", 4_321),
    )
    .await;
    stop(gw2.child);
    let retained_after = on_bus(&events, "call_retained");
    let closed_after = on_bus(&events, "retained_closed");
    std::fs::remove_dir_all(&dir).ok();
    println!(
        "list={list} retained={retained_events:?} forged={forged:?} stale={stale:?} closed={closed:?} replayed={replayed:?} closed_events={closed_events:?} list2={list2} replayed_after={replayed_after:?}"
    );

    assert_eq!((parent, child, still_open), (200, 502, 502));
    assert_eq!(
        retained_events.len(),
        2,
        "one call_retained per retained call: {retained_events:?}"
    );
    for e in &retained_events {
        assert_eq!(e["schema"], "taipanbox.dev/agent-event/v0.2", "{e}");
        assert_eq!(e["severity"], "medium", "{e}");
        assert_eq!(e["agent_id"], AGENT, "{e}");
        assert_eq!(e["on_behalf_of"], serde_json::json!([ON_BEHALF_OF]), "{e}");
        assert_eq!(e["data"]["unit"], "ops", "{e}");
        assert_eq!(e["data"]["model"], "claude-sonnet", "{e}");
        assert_eq!(e["data"]["journaled"], true, "{e}");
        assert_eq!(e["data"]["listed"], true, "{e}");
    }
    let child_event = retained_events
        .iter()
        .find(|e| e["run_id"] == "child")
        .expect("the child's call_retained");
    assert_eq!(child_event["data"]["reservation_id"], id, "{child_event}");
    assert_eq!(
        child_event["data"]["amount_microusd"], held["amount_microusd"],
        "the amount the listing holds: {child_event} {held}"
    );

    assert_eq!(forged.0, 401, "{}", forged.1);
    assert_eq!(stale.0, 409, "{}", stale.1);
    assert_eq!(after_refusals, 0, "a refused closure is not on the bus");
    assert_eq!(closed.0, 200, "{}", closed.1);
    assert_eq!(replayed.1["replayed"], true, "{}", replayed.1);
    assert_eq!(
        closed_events.len(),
        1,
        "one applied closure, one retained_closed, none for its replay: {closed_events:?}"
    );
    let c = &closed_events[0];
    assert_eq!(c["severity"], "high", "{c}");
    assert_eq!(c["agent_id"], AGENT, "{c}");
    assert_eq!(c["run_id"], "child", "{c}");
    assert_eq!(
        c["data"],
        serde_json::json!({
            "reservation_id": id,
            "revision": revision,
            "operation_id": "op-1",
            "evidence_kind": "observed",
            "settled_microusd": 4_321,
            "evidence_ref": "provider usage msg_01HX",
            "unit": "ops",
        }),
        "{c}"
    );

    assert_eq!(
        list2.as_array().map(Vec::len),
        Some(1),
        "the restart restored the open one: {list2}"
    );
    assert_eq!(replayed_after.1["replayed"], true, "{}", replayed_after.1);
    assert_eq!(
        retained_after.len(),
        2,
        "the replay restored a reservation and reported nothing new: {retained_after:?}"
    );
    assert_eq!(
        closed_after.len(),
        1,
        "the closure answered after the restart is a replay: {closed_after:?}"
    );
}

#[tokio::test]
async fn a_retained_call_that_names_no_agent_is_skipped_and_counted_in_the_log() {
    let (dir, data_dir, events) = scratch("no-agent");
    let hold = Arc::new(AtomicBool::new(true));
    let upstream = provider(hold.clone()).await;
    let addr = free_addr();
    let gw = spawn(
        &addr,
        &upstream,
        &data_dir,
        &events.to_string_lossy(),
        &identity_map(&dir, "map.json", 100.0),
    );
    let status = call(&addr, "anonymous", None, None).await;
    let (_, list) = retained(&addr).await;
    let retained_events = on_bus(&events, "call_retained");
    // The line is written before the 502 is answered, and reaches this process
    // through a pipe and a reader thread: wait for it, bounded.
    for _ in 0..50 {
        let seen = gw
            .log
            .lock()
            .unwrap()
            .iter()
            .any(|l| l.contains("agent-event skipped") && l.contains("call_retained"));
        if seen {
            break;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    let log = gw.log.lock().unwrap().clone();
    stop(gw.child);
    std::fs::remove_dir_all(&dir).ok();

    assert_eq!(status, 502);
    assert_eq!(
        list.as_array().map(Vec::len),
        Some(1),
        "retained whether or not it names an agent: {list}"
    );
    assert!(retained_events.is_empty(), "{retained_events:?}");
    let skips: Vec<&String> = log
        .iter()
        .filter(|l| l.contains("agent-event skipped"))
        .collect();
    let position = skips
        .iter()
        .position(|l| l.contains("call_retained"))
        .unwrap_or_else(|| panic!("no skip line names call_retained: {log:#?}"));
    assert!(
        skips[position].contains(&format!("skipped_total={}", position + 1)),
        "the skip is counted with the ones before it: {}",
        skips[position]
    );
}
