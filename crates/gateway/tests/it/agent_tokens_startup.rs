//! `TOKENFUSE_AGENT_TOKENS` read by the real binary, in both processes, before
//! the listener binds: a word it cannot read, or a door it cannot verify with,
//! exits 2 naming what is missing. The unit tests in `agenttoken` prove the
//! decision; only the binary proves `main.rs` asks it.

use std::io::{BufRead, BufReader, Read};
use std::process::{Child, Command, Stdio};
use std::sync::mpsc;
use std::thread;
use std::time::{Duration, Instant};

use axum::routing::get;
use axum::{Json, Router};
use tokenfuse_delegation::testing::Key;

const GATEWAY_LISTENING: &str = "tokenfuse gateway listening";
const CEILING: Duration = Duration::from_secs(10);

fn bin() -> &'static str {
    env!("CARGO_BIN_EXE_tokenfuse")
}

fn free_addr() -> String {
    let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let a = l.local_addr().unwrap();
    drop(l);
    a.to_string()
}

fn gateway(extra: &[(&str, String)]) -> Command {
    let mut cmd = Command::new(bin());
    cmd.env("TOKENFUSE_PROFILE", "observe");
    cmd.env_remove("TOKENFUSE_UPSTREAM")
        .env_remove("TOKENFUSE_CLIENT_KEYS")
        .env_remove("TOKENFUSE_DELEGATION_ISSUER")
        .env_remove("TOKENFUSE_DELEGATION_JWKS")
        .env_remove("TOKENFUSE_DELEGATION_URL")
        .env_remove("TOKENFUSE_DELEGATION_AUDIENCE")
        .env_remove("TOKENFUSE_DELEGATION_REVOCATIONS")
        .env("TOKENFUSE_ALLOW_STUB", "1")
        .env("TOKENFUSE_ADDR", free_addr());
    for (k, v) in extra {
        cmd.env(k, v);
    }
    cmd
}

fn broker(extra: &[(&str, String)]) -> Command {
    let mut cmd = Command::new(bin());
    cmd.env("TOKENFUSE_PROFILE", "observe");
    cmd.arg("mcp-broker")
        .env("TOKENFUSE_MCP_UPSTREAM", "http://127.0.0.1:1")
        .env("TOKENFUSE_MCP_ADDR", free_addr())
        .env_remove("TOKENFUSE_MCP_KEYS")
        .env_remove("TOKENFUSE_DELEGATION_ISSUER")
        .env_remove("TOKENFUSE_DELEGATION_JWKS")
        .env_remove("TOKENFUSE_DELEGATION_URL")
        .env_remove("TOKENFUSE_DELEGATION_REVOCATIONS");
    for (k, v) in extra {
        cmd.env(k, v);
    }
    cmd
}

fn spawn(mut cmd: Command) -> Child {
    cmd.stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("failed to spawn the tokenfuse binary")
}

fn exits_within(child: &mut Child) -> Option<std::process::ExitStatus> {
    let deadline = Instant::now() + CEILING;
    loop {
        if let Some(s) = child.try_wait().unwrap() {
            return Some(s);
        }
        if Instant::now() >= deadline {
            return None;
        }
        thread::sleep(Duration::from_millis(20));
    }
}

fn listens_within(child: &mut Child, needle: &'static str) -> bool {
    let stdout = child.stdout.take().expect("stdout piped");
    let (tx, rx) = mpsc::channel::<()>();
    thread::spawn(move || {
        for line in BufReader::new(stdout).lines().map_while(Result::ok) {
            if line.contains(needle) {
                tx.send(()).ok();
            }
        }
    });
    rx.recv_timeout(CEILING).is_ok()
}

/// Exit 2, and stderr names every one of `names`.
fn assert_refused(mut child: Child, what: &str, names: &[&str]) {
    let Some(status) = exits_within(&mut child) else {
        child.kill().ok();
        child.wait().ok();
        panic!("{what}: the process kept running instead of refusing to start");
    };
    let mut stderr = String::new();
    child
        .stderr
        .take()
        .unwrap()
        .read_to_string(&mut stderr)
        .ok();
    assert_eq!(status.code(), Some(2), "{what}: stderr was: {stderr}");
    for name in names {
        assert!(
            stderr.contains(name),
            "{what}: stderr did not name {name}: {stderr}"
        );
    }
}

#[test]
fn a_mistyped_agent_tokens_switch_stops_the_gateway_before_it_serves() {
    let child = spawn(gateway(&[("TOKENFUSE_AGENT_TOKENS", "acept".to_string())]));
    assert_refused(
        child,
        "a mistyped switch",
        &["TOKENFUSE_AGENT_TOKENS", "acept", "off|accept|require"],
    );
}

#[test]
fn agent_tokens_with_no_delegation_door_stop_the_broker_before_it_serves() {
    let child = spawn(broker(&[("TOKENFUSE_AGENT_TOKENS", "accept".to_string())]));
    assert_refused(
        child,
        "agent tokens with no issuer",
        &["TOKENFUSE_AGENT_TOKENS", "TOKENFUSE_DELEGATION_ISSUER"],
    );
}

/// Everything but the audience, a revocation list that answers included: the
/// one thing missing is named.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn agent_tokens_with_an_empty_audience_stop_the_gateway_before_it_serves() {
    let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = l.local_addr().unwrap();
    let list = Router::new().route(
        "/v1/revocations",
        get(|| async {
            let now = tokenfuse_gateway::sink::now_millis() / 1000;
            Json(serde_json::json!({"revocations": [], "as_of": now}))
        }),
    );
    tokio::spawn(async move {
        let _ = axum::serve(l, list).await;
    });
    let jwks = std::env::temp_dir().join(format!(
        "tf-agent-tokens-startup-jwks-{}.json",
        std::process::id()
    ));
    std::fs::write(
        &jwks,
        serde_json::json!({"keys": [Key::new().jwk_value(Some("v-1"))]}).to_string(),
    )
    .unwrap();
    let child = spawn(gateway(&[
        ("TOKENFUSE_AGENT_TOKENS", "accept".to_string()),
        (
            "TOKENFUSE_DELEGATION_ISSUER",
            "https://vouchryx.acme.example".to_string(),
        ),
        ("TOKENFUSE_DELEGATION_JWKS", jwks.display().to_string()),
        (
            "TOKENFUSE_DELEGATION_URL",
            "https://tokenfuse.acme.example".to_string(),
        ),
        ("TOKENFUSE_DELEGATION_AUDIENCE", String::new()),
        (
            "TOKENFUSE_DELEGATION_REVOCATIONS",
            format!("http://{addr}/v1/revocations"),
        ),
    ]));
    let result = tokio::task::spawn_blocking(move || {
        assert_refused(
            child,
            "an empty audience",
            &["TOKENFUSE_AGENT_TOKENS", "TOKENFUSE_DELEGATION_AUDIENCE"],
        )
    })
    .await;
    let _ = std::fs::remove_file(&jwks);
    result.unwrap();
}

#[test]
fn agent_tokens_off_still_start_the_gateway() {
    let mut child = spawn(gateway(&[("TOKENFUSE_AGENT_TOKENS", "off".to_string())]));
    let seen = listens_within(&mut child, GATEWAY_LISTENING);
    child.kill().ok();
    child.wait().ok();
    assert!(
        seen,
        "TOKENFUSE_AGENT_TOKENS=off must still start the gateway"
    );
}
