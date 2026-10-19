//! The governed profile reaches the MCP broker and the firewall's policy file
//! (CLAUDE.md invariant 136, as amended for the supervisor's review of PR #468),
//! proved on the real binary.
//!
//! Two gaps the first version of the profile left open:
//!
//! - The broker kept `Profile::Observe` for its policy hook, so under the
//!   governed default a tool call the policy plane denied was still forwarded
//!   to the upstream whenever `TOKENFUSE_WARDRYX_URL` was set.
//! - A firewall policy file that names no `mode` ran off under both profiles.
//!   Under governed it now runs in enforce, and under observe it stays off as
//!   it did in v1.18.0.
//!
//! Every test here names its profile, so the assertion never depends on what the
//! default happens to be.

use crate::common::binary::Running;
use axum::routing::post;
use axum::{Json, Router};
use serde_json::{json, Value};
use std::io::{BufRead, BufReader, Read};
use std::process::{Child, Command, Stdio};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

const BROKER_LISTENING: &str = "mcp credential-broker listening";
const CEILING: Duration = Duration::from_secs(10);

fn bin() -> &'static str {
    env!("CARGO_BIN_EXE_tokenfuse")
}

fn free_port() -> u16 {
    let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    l.local_addr().unwrap().port()
}

/// Serves `router` on a free loopback port and returns its base URL.
async fn serve(router: Router) -> String {
    let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = l.local_addr().unwrap();
    tokio::spawn(async move {
        let _ = axum::serve(l, router).await;
    });
    format!("http://{addr}")
}

/// A policy plane that answers every decide with `decision`.
async fn policy_plane(decision: &'static str) -> String {
    serve(Router::new().route(
        "/v1/decide",
        post(move |Json(_req): Json<Value>| async move {
            Json(json!({ "decision": decision, "policy_version": "test-v1" }))
        }),
    ))
    .await
}

/// An upstream MCP server that counts the `tools/call` requests it is sent.
async fn counting_upstream() -> (String, Arc<Mutex<usize>>) {
    let calls = Arc::new(Mutex::new(0usize));
    let seen = calls.clone();
    let router = Router::new().route(
        "/",
        post(move |Json(req): Json<Value>| {
            let seen = seen.clone();
            async move {
                if req["method"] == "tools/call" {
                    *seen.lock().unwrap() += 1;
                }
                let id = req.get("id").cloned().unwrap_or(Value::Null);
                Json(json!({ "jsonrpc": "2.0", "id": id, "result": { "ok": true } }))
            }
        }),
    );
    (serve(router).await, calls)
}

/// A running `tokenfuse mcp-broker`, with its output kept for the test to read.
struct Broker {
    child: Child,
    output: Arc<Mutex<String>>,
    url: String,
}

impl Broker {
    fn output(&self) -> String {
        self.output.lock().unwrap().clone()
    }
}

impl Drop for Broker {
    fn drop(&mut self) {
        self.child.kill().ok();
        self.child.wait().ok();
    }
}

/// Starts the broker against `upstream` with the profile `profile` named, the
/// variables in `extra` set on top, and waits for its listening line.
fn start_broker(profile: &str, upstream: &str, extra: &[(&str, &str)]) -> Broker {
    let port = free_port();
    let mut cmd = Command::new(bin());
    cmd.arg("mcp-broker")
        .env_remove("TOKENFUSE_WARDRYX_MODE")
        .env_remove("TOKENFUSE_WARDRYX_URL")
        .env_remove("TOKENFUSE_WARDRYX_FAILMODE")
        .env_remove("TOKENFUSE_MCP_KEYS")
        .env_remove("TOKENFUSE_AGENT_TOKENS")
        .env_remove("TOKENFUSE_MCP_TAINT_GATEWAY")
        .env("TOKENFUSE_PROFILE", profile)
        .env("TOKENFUSE_MCP_UPSTREAM", upstream)
        .env("TOKENFUSE_MCP_ADDR", format!("127.0.0.1:{port}"));
    for (k, v) in extra {
        cmd.env(k, v);
    }
    let mut child = cmd
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("failed to spawn the broker");
    let output = Arc::new(Mutex::new(String::new()));
    for stream in [
        Box::new(child.stdout.take().unwrap()) as Box<dyn Read + Send>,
        Box::new(child.stderr.take().unwrap()),
    ] {
        let into = output.clone();
        thread::spawn(move || {
            for line in BufReader::new(stream).lines().map_while(Result::ok) {
                let mut out = into.lock().unwrap();
                out.push_str(&line);
                out.push('\n');
            }
        });
    }
    let deadline = Instant::now() + CEILING;
    loop {
        if output.lock().unwrap().contains(BROKER_LISTENING) {
            break;
        }
        if let Some(status) = child.try_wait().unwrap() {
            panic!("the broker exited ({status}) before listening:\n{}", output.lock().unwrap());
        }
        if Instant::now() >= deadline {
            child.kill().ok();
            panic!("the broker did not listen:\n{}", output.lock().unwrap());
        }
        thread::sleep(Duration::from_millis(20));
    }
    thread::sleep(Duration::from_millis(150));
    Broker {
        child,
        output,
        url: format!("http://127.0.0.1:{port}/"),
    }
}

async fn call_tool(url: &str) -> Value {
    reqwest::Client::new()
        .post(url)
        .header("x-fuse-agent-id", "agent://acme.example/tool-user")
        .json(&json!({
            "jsonrpc": "2.0", "id": 7, "method": "tools/call",
            "params": { "name": "shell_exec", "arguments": { "cmd": "ls" } }
        }))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap()
}

/// RED-FIRST: the broker kept `Profile::Observe` for its policy hook, so a
/// governed broker with a policy plane named started with the hook off, and its
/// startup line did not say it was governed.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_governed_broker_enforces_its_policy_hook_once_a_plane_is_named() {
    let (upstream, _) = counting_upstream().await;
    let pdp = policy_plane("allow").await;
    let broker = start_broker("governed", &upstream, &[("TOKENFUSE_WARDRYX_URL", &pdp)]);
    let out = broker.output();
    assert!(out.contains("governance profile=governed"), "{out}");
    assert!(out.contains("policy_hook=enforce(profile)"), "{out}");
    assert!(out.contains("failmode=Closed"), "{out}");
}

/// RED-FIRST: under the governed profile a deny from the policy plane did not
/// refuse the call. The broker forwarded it, because the hook was off.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_policy_plane_deny_refuses_a_tool_call_under_the_governed_profile() {
    let (upstream, forwarded) = counting_upstream().await;
    let pdp = policy_plane("deny").await;
    let broker = start_broker("governed", &upstream, &[("TOKENFUSE_WARDRYX_URL", &pdp)]);
    let resp = call_tool(&broker.url).await;
    assert_eq!(resp["error"]["code"], json!(-32004), "{resp}");
    assert!(resp.get("result").is_none(), "{resp}");
    assert_eq!(
        *forwarded.lock().unwrap(),
        0,
        "a denied call must never reach the upstream: {}",
        broker.output()
    );
}

/// The guard: an explicit mode is read, not replaced by the governed default.
/// Shadow forwards whatever the plane says.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_explicit_shadow_hook_still_forwards_under_the_governed_broker() {
    let (upstream, forwarded) = counting_upstream().await;
    let pdp = policy_plane("deny").await;
    let broker = start_broker(
        "governed",
        &upstream,
        &[
            ("TOKENFUSE_WARDRYX_URL", &pdp),
            ("TOKENFUSE_WARDRYX_MODE", "shadow"),
        ],
    );
    let resp = call_tool(&broker.url).await;
    assert!(resp.get("error").is_none(), "shadow must forward: {resp}");
    assert_eq!(*forwarded.lock().unwrap(), 1, "{}", broker.output());
}

/// RED-FIRST: a governed broker with no policy plane said nothing about it.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_governed_broker_with_no_policy_plane_says_so() {
    let (upstream, _) = counting_upstream().await;
    let broker = start_broker("governed", &upstream, &[]);
    let out = broker.output();
    assert!(out.contains("policy_hook=off(no-url)"), "{out}");
}

/// Writes `json` to a file unique to this test and returns its path.
fn policy_file(name: &str, json: &str) -> String {
    let path = std::env::temp_dir().join(format!(
        "tokenfuse-governed-scope-{name}-{}.json",
        std::process::id()
    ));
    std::fs::write(&path, json).unwrap();
    path.to_string_lossy().into_owned()
}

/// A policy file that names no `mode`, with one rule: nothing a tainted run does
/// may write. Its `mode` is what each test varies, or leaves out.
fn no_mode_file() -> &'static str {
    r#"{
        "capabilities": { "write_file": "write" },
        "rules": [ { "name": "no-write-after-web", "when_any": ["web"], "deny": ["write"] } ]
    }"#
}

/// Asks the tool-call check about a write in a run that has read the web. The
/// label is declared by the caller, as a framework declares it.
async fn write_after_web(gw: &Running) -> Value {
    let client = reqwest::Client::new();
    let call = client
        .post(format!("{}/v1/messages", gw.url()))
        .header("x-fuse-run-id", "policy-file-run")
        .header("x-fuse-taint", "web")
        .json(&json!({
            "model": "claude-haiku-5-5",
            "max_tokens": 10,
            "messages": [{"role": "user", "content": "hi"}],
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(call.status(), reqwest::StatusCode::OK, "{}", gw.output());
    client
        .post(format!("{}/v1/fuse/check-tool-call", gw.url()))
        .json(&json!({ "run_id": "policy-file-run", "tool": "write_file" }))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap()
}

/// RED-FIRST: a policy file with no `mode` ran off under both profiles, so the
/// write after the web was allowed. Under governed it must be denied, and the
/// startup line must say the mode came from the profile.
#[tokio::test]
async fn a_policy_file_with_no_mode_is_enforce_under_governed() {
    let path = policy_file("governed", no_mode_file());
    let gw = Running::start(
        "127.0.0.1",
        &[("TOKENFUSE_PROFILE", "governed"), ("TOKENFUSE_FIREWALL_CONFIG", &path)],
    );
    let out = gw.output();
    assert!(out.contains("firewall=enforce(profile)"), "{out}");
    let check = write_after_web(&gw).await;
    assert_eq!(check["decision"], "deny", "{check}");
}

/// The guard: under observe a policy file with no `mode` stays off, as it was in
/// v1.18.0. Nothing is refused.
#[tokio::test]
async fn a_policy_file_with_no_mode_stays_off_under_observe() {
    let path = policy_file("observe", no_mode_file());
    let gw = Running::start(
        "127.0.0.1",
        &[("TOKENFUSE_PROFILE", "observe"), ("TOKENFUSE_FIREWALL_CONFIG", &path)],
    );
    let out = gw.output();
    assert!(out.contains("firewall=off(file)"), "{out}");
    let check = write_after_web(&gw).await;
    assert_eq!(check["decision"], "allow", "{check}");
    assert_eq!(check["governed"], false, "{check}");
}

/// The guard: a mode the file names wins over the governed default. Shadow here
/// records what enforce would refuse and refuses nothing.
#[tokio::test]
async fn a_policy_file_that_names_shadow_is_not_overridden_under_governed() {
    let shadow = r#"{
        "mode": "shadow",
        "capabilities": { "write_file": "write" },
        "rules": [ { "name": "no-write-after-web", "when_any": ["web"], "deny": ["write"] } ]
    }"#;
    let path = policy_file("shadow", shadow);
    let gw = Running::start(
        "127.0.0.1",
        &[("TOKENFUSE_PROFILE", "governed"), ("TOKENFUSE_FIREWALL_CONFIG", &path)],
    );
    let out = gw.output();
    assert!(out.contains("firewall=shadow(file)"), "{out}");
    let check = write_after_web(&gw).await;
    assert_eq!(check["decision"], "allow", "{check}");
    assert!(check["would_block"].is_string(), "{check}");
}
