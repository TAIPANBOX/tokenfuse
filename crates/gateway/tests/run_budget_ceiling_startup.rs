//! Seam test for CLAUDE.md invariant 73: `defaults::max_run_budget_from` and
//! the clamp in `proxy.rs` are proven by unit tests, but nothing there proves
//! `main.rs`'s `serve()` READS `TOKENFUSE_MAX_RUN_BUDGET_USD` and hands it to
//! `AppState`. Deleting that one line leaves every unit test green, since
//! they build `AppState` by hand. This file runs the real binary, as
//! `tests/cache_default_startup.rs` and `tests/xaa_startup.rs` do, for the
//! two things only the binary can show: a value nobody can read exits 2
//! naming the variable, and a configured ceiling actually caps a declared
//! budget over real HTTP.

use std::io::{BufRead, BufReader};
use std::process::{Child, Command, Stdio};
use std::sync::mpsc;
use std::thread;
use std::time::{Duration, Instant};

fn bin() -> &'static str {
    env!("CARGO_BIN_EXE_tokenfuse")
}

const LISTENING_NEEDLE: &str = "tokenfuse gateway listening";
const CEILING: Duration = Duration::from_secs(10);

fn base_cmd(addr: &str) -> Command {
    let mut cmd = Command::new(bin());
    cmd.env_remove("TOKENFUSE_UPSTREAM")
        .env_remove("TOKENFUSE_MAX_RUN_BUDGET_USD")
        .env_remove("TOKENFUSE_CLIENT_KEYS")
        .env_remove("TOKENFUSE_IDENTITY_MAP")
        .env("TOKENFUSE_ALLOW_STUB", "1")
        .env("TOKENFUSE_MODE", "enforce")
        .env("TOKENFUSE_ADDR", addr);
    cmd
}

/// RED-FIRST: before `main.rs` called `max_run_budget_from_env`, the variable
/// was read nowhere, so every one of these started a serving gateway (the
/// run below would block until the harness killed it, never `Some(2)`).
#[test]
fn an_unreadable_ceiling_exits_2_and_names_the_variable() {
    // A binary that wrongly serves never exits, so a deadline kills it and a
    // RED run is bounded instead of hanging the suite.
    for bad in ["abc", "0", "-1", "1e9", "1.2.3"] {
        let mut child = base_cmd("127.0.0.1:0")
            .env("TOKENFUSE_MAX_RUN_BUDGET_USD", bad)
            .stdout(Stdio::null())
            .stderr(Stdio::piped())
            .spawn()
            .expect("failed to spawn the tokenfuse binary");
        let deadline = Instant::now() + CEILING;
        let status = loop {
            if let Some(s) = child.try_wait().unwrap() {
                break Some(s);
            }
            if Instant::now() >= deadline {
                break None;
            }
            thread::sleep(Duration::from_millis(20));
        };
        let Some(status) = status else {
            child.kill().ok();
            child.wait().ok();
            panic!("{bad:?}: the gateway kept serving with an unreadable ceiling");
        };
        let mut stderr = String::new();
        std::io::Read::read_to_string(&mut child.stderr.take().unwrap(), &mut stderr).ok();
        assert_eq!(status.code(), Some(2), "{bad:?}: stderr was: {stderr}");
        assert!(
            stderr.contains("TOKENFUSE_MAX_RUN_BUDGET_USD"),
            "{bad:?}: stderr did not name the variable: {stderr}"
        );
    }
}

/// Unset and empty are the historical behaviour: start, no refusal.
#[test]
fn an_empty_ceiling_is_not_an_error() {
    let mut child = spawn_serving("127.0.0.1:0", Some(""));
    let seen = wait_for_listening(&mut child);
    child.kill().ok();
    child.wait().ok();
    assert!(
        seen,
        "an empty TOKENFUSE_MAX_RUN_BUDGET_USD must still start"
    );
}

fn spawn_serving(addr: &str, ceiling: Option<&str>) -> Child {
    let mut cmd = base_cmd(addr);
    if let Some(v) = ceiling {
        cmd.env("TOKENFUSE_MAX_RUN_BUDGET_USD", v);
    }
    cmd.stdout(Stdio::piped())
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
    rx.recv_timeout(CEILING).is_ok()
}

fn free_addr() -> String {
    let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let a = l.local_addr().unwrap();
    drop(l);
    a.to_string()
}

/// One call declaring USD 1000 and reserving about USD 1.50 (100_000 output
/// tokens at the default book's USD 15 per million for `claude-sonnet`).
async fn big_call(addr: &str, run: &str) -> reqwest::Response {
    reqwest::Client::new()
        .post(format!("http://{addr}/v1/messages"))
        .header("x-fuse-run-id", run)
        .header("x-fuse-budget-usd", "1000")
        .header("content-type", "application/json")
        .body(r#"{"model":"claude-sonnet","max_tokens":100000,"messages":[{"role":"user","content":"hi"}]}"#)
        .send()
        .await
        .expect("the gateway must answer")
}

/// The wiring end to end through the real binary: with the ceiling at USD 1
/// the declared USD 1000 is clamped and a USD 1.50 reservation is a 402 that
/// names the clamp; with it unset the same call is admitted.
#[tokio::test]
async fn the_binary_applies_the_ceiling_to_a_declared_budget() {
    let addr = free_addr();
    let mut child = spawn_serving(&addr, Some("1.00"));
    let up = wait_for_listening(&mut child);
    let capped = if up {
        Some(big_call(&addr, "bin-capped").await)
    } else {
        None
    };
    child.kill().ok();
    child.wait().ok();
    assert!(up, "the gateway never reported listening");
    let capped = capped.unwrap();
    assert_eq!(
        capped.status().as_u16(),
        402,
        "the ceiling must cap the declared budget"
    );
    assert_eq!(
        capped
            .headers()
            .get("x-fuse-budget-clamped")
            .map(|v| v.to_str().unwrap()),
        Some("1.00")
    );

    let addr = free_addr();
    let mut child = spawn_serving(&addr, None);
    let up = wait_for_listening(&mut child);
    let open = if up {
        Some(big_call(&addr, "bin-open").await)
    } else {
        None
    };
    child.kill().ok();
    child.wait().ok();
    assert!(up, "the gateway never reported listening");
    let open = open.unwrap();
    assert_eq!(open.status().as_u16(), 200, "unset means today's behaviour");
    assert!(!open.headers().contains_key("x-fuse-budget-clamped"));
}
