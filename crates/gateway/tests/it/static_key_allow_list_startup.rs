//! `TOKENFUSE_AGENT_TOKENS_STATIC_KEYS` and `TOKENFUSE_MCP_AGENT_TOKENS_STATIC_KEYS`
//! read by the real binaries before the listener binds (invariants 138 and 139).
//! The unit tests in `agenttoken` prove the decision; only the binary proves
//! `main.rs` asks it, with the key set it was configured with.

use std::io::{BufRead, BufReader, Read};
use std::process::{Child, Command, Stdio};
use std::sync::{mpsc, Arc, Mutex};
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
    cmd.env_remove("TOKENFUSE_UPSTREAM")
        .env_remove("TOKENFUSE_CLIENT_KEYS")
        .env_remove("TOKENFUSE_AGENT_TOKENS")
        .env_remove("TOKENFUSE_AGENT_TOKENS_STATIC_KEYS")
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
    cmd.arg("mcp-broker")
        .env("TOKENFUSE_MCP_UPSTREAM", "http://127.0.0.1:1")
        .env("TOKENFUSE_MCP_ADDR", free_addr())
        .env_remove("TOKENFUSE_MCP_KEYS")
        .env_remove("TOKENFUSE_AGENT_TOKENS")
        .env_remove("TOKENFUSE_MCP_AGENT_TOKENS_STATIC_KEYS")
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

/// Every stdout line the process prints until it reports listening, so a test
/// can read the startup line it wrote on the way.
fn lines_until_listening(child: &mut Child) -> Option<Vec<String>> {
    let stdout = child.stdout.take().expect("stdout piped");
    let lines = Arc::new(Mutex::new(Vec::new()));
    let seen = lines.clone();
    let (tx, rx) = mpsc::channel::<()>();
    thread::spawn(move || {
        for line in BufReader::new(stdout).lines().map_while(Result::ok) {
            let listening = line.contains(GATEWAY_LISTENING);
            seen.lock().unwrap().push(line);
            if listening {
                tx.send(()).ok();
            }
        }
    });
    rx.recv_timeout(CEILING).ok()?;
    let out = lines.lock().unwrap().clone();
    Some(out)
}

#[test]
fn a_static_key_list_outside_require_stops_the_gateway_naming_it() {
    let child = spawn(gateway(&[
        ("TOKENFUSE_AGENT_TOKENS", "accept".to_string()),
        ("TOKENFUSE_AGENT_TOKENS_STATIC_KEYS", "key-a".to_string()),
    ]));
    assert_refused(
        child,
        "a static-key list under accept",
        &["TOKENFUSE_AGENT_TOKENS_STATIC_KEYS"],
    );
}

#[test]
fn a_static_key_list_naming_an_unconfigured_key_stops_the_gateway_naming_the_id() {
    let child = spawn(gateway(&[
        ("TOKENFUSE_AGENT_TOKENS", "require".to_string()),
        ("TOKENFUSE_CLIENT_KEYS", "sk-a:key-a".to_string()),
        ("TOKENFUSE_AGENT_TOKENS_STATIC_KEYS", "key-zz".to_string()),
    ]));
    assert_refused(child, "a listed id no key configures", &["key-zz"]);
}

#[test]
fn a_static_key_list_outside_require_stops_the_broker_naming_it() {
    let child = spawn(broker(&[
        ("TOKENFUSE_AGENT_TOKENS", "accept".to_string()),
        (
            "TOKENFUSE_MCP_AGENT_TOKENS_STATIC_KEYS",
            "bkey".to_string(),
        ),
    ]));
    assert_refused(
        child,
        "a broker static-key list under accept",
        &["TOKENFUSE_MCP_AGENT_TOKENS_STATIC_KEYS"],
    );
}

/// The full delegation door, with a revocation list that answers, so the one
/// thing this process can refuse on is the allow-list it is given.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_listed_key_on_a_fully_configured_gateway_starts_and_names_the_list_at_startup() {
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
        "tf-static-keys-startup-jwks-{}.json",
        std::process::id()
    ));
    std::fs::write(
        &jwks,
        serde_json::json!({"keys": [Key::new().jwk_value(Some("v-1"))]}).to_string(),
    )
    .unwrap();
    let mut child = spawn(gateway(&[
        ("TOKENFUSE_AGENT_TOKENS", "require".to_string()),
        ("TOKENFUSE_CLIENT_KEYS", "sk-a:key-a".to_string()),
        ("TOKENFUSE_AGENT_TOKENS_STATIC_KEYS", "key-a".to_string()),
        (
            "TOKENFUSE_DELEGATION_ISSUER",
            "https://vouchryx.acme.example".to_string(),
        ),
        ("TOKENFUSE_DELEGATION_JWKS", jwks.display().to_string()),
        (
            "TOKENFUSE_DELEGATION_URL",
            "https://tokenfuse.acme.example".to_string(),
        ),
        (
            "TOKENFUSE_DELEGATION_AUDIENCE",
            "https://tokenfuse.acme.example".to_string(),
        ),
        (
            "TOKENFUSE_DELEGATION_REVOCATIONS",
            format!("http://{addr}/v1/revocations"),
        ),
    ]));
    let lines = tokio::task::spawn_blocking(move || {
        let lines = lines_until_listening(&mut child);
        child.kill().ok();
        child.wait().ok();
        lines
    })
    .await
    .unwrap();
    let _ = std::fs::remove_file(&jwks);
    let lines = lines.expect("a gateway with a listed key must start");
    assert!(
        lines.iter().any(|l| l.contains("key-a")),
        "the startup lines name the listed key id: {lines:?}"
    );
}
