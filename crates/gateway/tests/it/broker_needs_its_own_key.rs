//! Invariant 129, read by the real binary: an MCP broker with agent tokens on
//! and a taint gateway named refuses to start without its own key for relaying
//! a token to the tool-call check, naming the variable, before it listens.
//!
//! Without that key the broker sends the check no credential for a call a token
//! admitted, a gateway with client keys answers 401, and the taint fail mode
//! (open by default) decides the call with nothing judging it. The unit test in
//! `mcpbroker` proves the decision; only the binary proves `main.rs` asks it.

use std::io::{BufRead, BufReader, Read};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::mpsc;
use std::thread;
use std::time::{Duration, Instant};

use axum::routing::get;
use axum::{Json, Router};
use tokenfuse_delegation::testing::Key;

const BROKER_LISTENING: &str = "mcp credential-broker listening";
const CEILING: Duration = Duration::from_secs(10);
const ISS: &str = "https://vouchryx.acme.example";
const ORIGIN: &str = "https://mcp.acme.example";
const AUDIENCE: &str = "https://mcp.acme.example/mcp";
const KEY_FILE: &str = "TOKENFUSE_MCP_TAINT_GATEWAY_KEY_FILE";

fn bin() -> &'static str {
    env!("CARGO_BIN_EXE_tokenfuse")
}

fn free_addr() -> String {
    let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let a = l.local_addr().unwrap();
    drop(l);
    a.to_string()
}

/// The broker with nothing of the agent-token door, the taint gate or the
/// delegation door inherited from the test's own environment, and the variables
/// a test names set on top.
fn broker(extra: &[(&str, String)]) -> Command {
    let mut cmd = Command::new(bin());
    cmd.arg("mcp-broker")
        .env("TOKENFUSE_MCP_UPSTREAM", "http://127.0.0.1:1")
        .env("TOKENFUSE_MCP_ADDR", free_addr());
    for name in [
        "TOKENFUSE_MCP_KEYS",
        "TOKENFUSE_MCP_ACCEPT_XAA",
        "TOKENFUSE_MCP_RESOURCE",
        "TOKENFUSE_MCP_TAINT_GATEWAY",
        KEY_FILE,
        "TOKENFUSE_MCP_TAINT_FAILMODE",
        "TOKENFUSE_AGENT_TOKENS",
        "TOKENFUSE_DELEGATION_ISSUER",
        "TOKENFUSE_DELEGATION_JWKS",
        "TOKENFUSE_DELEGATION_JWKS_URL",
        "TOKENFUSE_DELEGATION_URL",
        "TOKENFUSE_DELEGATION_AUDIENCE",
        "TOKENFUSE_DELEGATION_REVOCATIONS",
        "TOKENFUSE_CHECKPOINTS_DIR",
    ] {
        cmd.env_remove(name);
    }
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

/// Whether the process logs that it is listening within the ceiling. The
/// process is killed either way, so a guard leaves nothing running.
fn listens(mut child: Child) -> bool {
    let stdout = child.stdout.take().expect("stdout piped");
    let (tx, rx) = mpsc::channel::<()>();
    thread::spawn(move || {
        for line in BufReader::new(stdout).lines().map_while(Result::ok) {
            if line.contains(BROKER_LISTENING) {
                tx.send(()).ok();
            }
        }
    });
    let seen = rx.recv_timeout(CEILING).is_ok();
    child.kill().ok();
    child.wait().ok();
    seen
}

/// Exit 2, and stderr names every one of `names`. A process still running is
/// killed before the test fails, so a red run leaves nothing listening.
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

/// A revocation list that answers with nothing revoked and a current cursor, so
/// the agent-token door has everything it needs and the one thing a test leaves
/// out is the one thing it names.
async fn list_server() -> String {
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
    addr.to_string()
}

/// A file only the test with this label names: every test in this binary
/// shares one process id.
fn scratch(label: &str, contents: &str) -> PathBuf {
    let path =
        std::env::temp_dir().join(format!("tf-broker-own-key-{label}-{}", std::process::id()));
    std::fs::write(&path, contents).unwrap();
    path
}

/// Everything the agent-token door needs to be on in `mode`, a key set and a
/// revocation list included.
fn agent_door(mode: &str, jwks: &Path, list: &str) -> Vec<(&'static str, String)> {
    vec![
        ("TOKENFUSE_AGENT_TOKENS", mode.to_string()),
        ("TOKENFUSE_DELEGATION_ISSUER", ISS.to_string()),
        ("TOKENFUSE_DELEGATION_JWKS", jwks.display().to_string()),
        ("TOKENFUSE_DELEGATION_URL", ORIGIN.to_string()),
        ("TOKENFUSE_DELEGATION_AUDIENCE", AUDIENCE.to_string()),
        (
            "TOKENFUSE_DELEGATION_REVOCATIONS",
            format!("http://{list}/v1/revocations"),
        ),
    ]
}

fn jwks_file(label: &str) -> PathBuf {
    scratch(
        label,
        &serde_json::json!({"keys": [Key::new().jwk_value(Some("v-1"))]}).to_string(),
    )
}

/// The gap the review found: agent tokens on, a taint gateway named, and no key
/// of the broker's own. Refused in both modes, naming the variable that fixes
/// it.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn agent_tokens_and_a_taint_gateway_without_the_brokers_key_stop_the_broker() {
    let list = list_server().await;
    let jwks = jwks_file("refused-jwks.json");
    for mode in ["accept", "require"] {
        let mut env = agent_door(mode, &jwks, &list);
        env.push((
            "TOKENFUSE_MCP_TAINT_GATEWAY",
            "http://127.0.0.1:4100".into(),
        ));
        let child = spawn(broker(&env));
        let what = format!("agent tokens {mode}, a taint gateway, no broker key");
        let result = tokio::task::spawn_blocking(move || {
            assert_refused(
                child,
                &what,
                &[
                    KEY_FILE,
                    "TOKENFUSE_MCP_TAINT_GATEWAY",
                    "TOKENFUSE_AGENT_TOKENS",
                ],
            )
        })
        .await;
        if result.is_err() {
            let _ = std::fs::remove_file(&jwks);
        }
        result.unwrap();
    }
    let _ = std::fs::remove_file(&jwks);
}

/// The guard on the other side: the same configuration with the broker's own
/// key in a file starts and listens.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn with_the_brokers_own_key_the_broker_starts() {
    let list = list_server().await;
    let jwks = jwks_file("keyed-jwks.json");
    let key = scratch("keyed-key", "sk-broker-1\n");
    let mut env = agent_door("accept", &jwks, &list);
    env.push((
        "TOKENFUSE_MCP_TAINT_GATEWAY",
        "http://127.0.0.1:4100".into(),
    ));
    env.push((KEY_FILE, key.display().to_string()));
    let child = spawn(broker(&env));
    let seen = tokio::task::spawn_blocking(move || listens(child))
        .await
        .unwrap();
    let _ = std::fs::remove_file(&jwks);
    let _ = std::fs::remove_file(&key);
    assert!(
        seen,
        "agent tokens on, a taint gateway and the broker's own key must start"
    );
}

/// No taint gateway, so nothing to relay a token to and nothing to refuse.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn agent_tokens_with_no_taint_gateway_need_no_broker_key() {
    let list = list_server().await;
    let jwks = jwks_file("ungated-jwks.json");
    let child = spawn(broker(&agent_door("accept", &jwks, &list)));
    let seen = tokio::task::spawn_blocking(move || listens(child))
        .await
        .unwrap();
    let _ = std::fs::remove_file(&jwks);
    assert!(
        seen,
        "agent tokens on with no taint gateway must start without a broker key"
    );
}

/// Agent tokens off: the taint gateway is asked with each caller's own key, as
/// it always was, and the broker needs no key of its own.
#[test]
fn a_taint_gateway_with_agent_tokens_off_needs_no_broker_key() {
    let child = spawn(broker(&[(
        "TOKENFUSE_MCP_TAINT_GATEWAY",
        "http://127.0.0.1:4100".to_string(),
    )]));
    assert!(
        listens(child),
        "a taint gateway with agent tokens off must start as it did"
    );
}
