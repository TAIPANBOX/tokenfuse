//! Invariant 122 (finding F-002 of the agent-security review of 2026-10-17): the gateway holds
//! the provider key of each door in a file and sends it upstream itself. A caller's own
//! provider credential never leaves the process: it is refused unless it is a gateway
//! credential. Each test here is named by a scenario in
//! `features/the-gateway-holds-the-provider-key.feature`.

use axum::body::{Body, Bytes};
use axum::extract::State;
use axum::http::{HeaderMap, Request, StatusCode};
use axum::routing::post;
use axum::Router;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use tokenfuse_core::{Ledger, Mode, Policy};
use tokenfuse_gateway::clientkeys::ClientKeys;
use tokenfuse_gateway::events::EventExporter;
use tokenfuse_gateway::provider::{HttpProvider, Provider, UpstreamAuth, UpstreamKey};
use tokenfuse_gateway::state::AppState;
use tokenfuse_gateway::wire::Wire;
use tower::ServiceExt;

const GOOD: &str = "sk-gateway-good-0123456789";
const PROVIDER_KEY: &str = "upstream-held-by-the-gateway-0000";
const CALLER_KEY: &str = "callers-own-provider-key-1111";
const BODY: &str =
    r#"{"model":"claude-haiku-5-5","max_tokens":10,"messages":[{"role":"user","content":"hi"}]}"#;
const UPSTREAM: &str = "http://127.0.0.1:9/v1/messages";
const LISTENING: &str = "tokenfuse gateway listening";
const REFUSED_BY_CALLER: &str = "the provider key comes from the caller";

/// Variables a startup test must not inherit from the shell.
const CLEARED: &[&str] = &[
    "TOKENFUSE_UPSTREAM",
    "TOKENFUSE_UPSTREAM_KEY_FILE",
    "TOKENFUSE_UPSTREAM_AUTH",
    "TOKENFUSE_CLIENT_KEYS",
    "TOKENFUSE_ALLOW_STUB",
    "TOKENFUSE_WIRE",
    "TOKENFUSE_DATA_DIR",
    "TOKENFUSE_EVENTS_PATH",
];

type Seen = Arc<Mutex<Vec<HeaderMap>>>;

fn scratch(tag: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("tf-held-key-{}-{tag}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

/// A gateway with client keys on, one key `GOOD` billed to `billing`, and an event bus in a
/// file the test can read.
fn gateway(tag: &str, provider: HttpProvider, wire: Wire) -> (AppState, PathBuf) {
    let bus = scratch(tag).join("events.ndjson");
    let _ = std::fs::remove_file(&bus);
    let events = Arc::new(EventExporter::open(bus.to_str().unwrap()).unwrap());
    let st = AppState::new(
        Arc::new(Ledger::new()),
        Arc::new(tokenfuse_gateway::pricebook::default_price_book()),
        Arc::new(Policy {
            mode: Mode::Enforce,
            ..Default::default()
        }),
        Arc::new(provider),
        "the-gateway-holds-the-provider-key",
    )
    .with_client_keys(Arc::new(
        ClientKeys::from_spec(&format!("{GOOD}:billing")).unwrap(),
    ))
    .with_events(events)
    .with_wire(wire);
    (st, bus)
}

/// Records every request the upstream receives and answers with a fixed body.
async fn record(
    State(seen): State<Seen>,
    headers: HeaderMap,
    _body: Bytes,
) -> axum::Json<serde_json::Value> {
    seen.lock().unwrap().push(headers);
    axum::Json(serde_json::json!({"stub": "upstream"}))
}

async fn spawn_upstream() -> (String, Seen) {
    let seen: Seen = Arc::new(Mutex::new(Vec::new()));
    let router = Router::new()
        .route("/", post(record))
        .with_state(seen.clone());
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        let _ = axum::serve(listener, router).await;
    });
    (format!("http://{addr}/"), seen)
}

fn brokered(endpoint: &str, auth: UpstreamAuth) -> HttpProvider {
    let key = UpstreamKey::new(PROVIDER_KEY, auth).unwrap();
    HttpProvider::new(endpoint).with_upstream_key(key)
}

fn header_text(headers: &HeaderMap, name: &str) -> Option<String> {
    headers
        .get(name)
        .and_then(|v| v.to_str().ok())
        .map(str::to_string)
}

async fn call(st: &AppState, path: &str, headers: &[(&str, &str)]) -> (StatusCode, String) {
    let mut req = Request::post(path)
        .header("content-type", "application/json")
        .header("x-fuse-run-id", "run-held-key");
    for (name, value) in headers {
        req = req.header(*name, *value);
    }
    let resp = tokenfuse_gateway::app(st.clone())
        .oneshot(req.body(Body::from(BODY)).unwrap())
        .await
        .unwrap();
    let status = resp.status();
    let bytes = axum::body::to_bytes(resp.into_body(), 1 << 16)
        .await
        .unwrap();
    (status, String::from_utf8_lossy(&bytes).into_owned())
}

fn identity_events(bus: &Path) -> Vec<serde_json::Value> {
    std::fs::read_to_string(bus)
        .unwrap_or_default()
        .lines()
        .filter_map(|l| serde_json::from_str::<serde_json::Value>(l).ok())
        .filter(|e| e["type"] == "identity_mismatch")
        .collect()
}

#[tokio::test]
async fn a_caller_supplied_x_api_key_is_refused_when_brokered() {
    let (endpoint, seen) = spawn_upstream().await;
    let (st, bus) = gateway(
        "refused",
        brokered(&endpoint, UpstreamAuth::XApiKey),
        Wire::Anthropic,
    );
    let (status, body) = call(
        &st,
        "/v1/messages",
        &[("x-fuse-key", GOOD), ("x-api-key", CALLER_KEY)],
    )
    .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED, "{body}");
    assert!(body.contains("provider_credential_refused"), "{body}");
    assert!(
        !body.contains(CALLER_KEY),
        "the presented key is echoed back: {body}"
    );
    assert!(
        seen.lock().unwrap().is_empty(),
        "a refused call reached the upstream"
    );
    let record = std::fs::read_to_string(&bus).unwrap_or_default();
    assert!(
        !record.contains(CALLER_KEY),
        "the presented key reached the record: {record}"
    );
    let events = identity_events(&bus);
    assert_eq!(events.len(), 1, "{events:?}");
    assert_eq!(
        events[0]["data"]["reason"], "caller_sent_a_provider_key",
        "{events:?}"
    );
}

#[tokio::test]
async fn a_caller_supplied_provider_key_never_reaches_the_upstream() {
    let (endpoint, seen) = spawn_upstream().await;
    let (st, bus) = gateway(
        "canary",
        brokered(&endpoint, UpstreamAuth::XApiKey),
        Wire::Anthropic,
    );
    // A valid gateway key beside the caller's own key in Authorization: refused as a whole.
    let bearer = format!("Bearer {CALLER_KEY}");
    let (status, body) = call(
        &st,
        "/v1/messages",
        &[("x-fuse-key", GOOD), ("authorization", bearer.as_str())],
    )
    .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED, "{body}");
    assert!(
        seen.lock().unwrap().is_empty(),
        "a refused call reached the upstream"
    );
    // The gateway key alone: admitted, and the upstream sees the gateway-held key and
    // nothing of the caller's.
    let (status, body) = call(&st, "/v1/messages", &[("x-fuse-key", GOOD)]).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert!(
        !body.contains(PROVIDER_KEY),
        "the provider key reached the caller: {body}"
    );
    let got: Vec<HeaderMap> = seen.lock().unwrap().clone();
    assert_eq!(got.len(), 1, "{got:?}");
    assert_eq!(
        header_text(&got[0], "x-api-key"),
        Some(PROVIDER_KEY.to_string())
    );
    assert_eq!(header_text(&got[0], "authorization"), None);
    let record = std::fs::read_to_string(&bus).unwrap_or_default();
    assert!(
        !record.contains(PROVIDER_KEY),
        "the provider key reached the record: {record}"
    );
}

#[tokio::test]
async fn a_stock_sdk_key_is_the_gateway_key_on_the_anthropic_door() {
    let (endpoint, seen) = spawn_upstream().await;
    let (st, _bus) = gateway(
        "stock",
        brokered(&endpoint, UpstreamAuth::XApiKey),
        Wire::Anthropic,
    );
    let (status, body) = call(&st, "/v1/messages", &[("x-api-key", GOOD)]).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let got: Vec<HeaderMap> = seen.lock().unwrap().clone();
    assert_eq!(got.len(), 1, "{got:?}");
    assert_eq!(
        header_text(&got[0], "x-api-key"),
        Some(PROVIDER_KEY.to_string())
    );
}

#[tokio::test]
async fn a_gateway_key_as_bearer_is_the_credential_on_the_openai_door() {
    let (endpoint, seen) = spawn_upstream().await;
    let (st, _bus) = gateway(
        "bearer",
        brokered(&endpoint, UpstreamAuth::Bearer),
        Wire::OpenAi,
    );
    let bearer = format!("Bearer {GOOD}");
    let (status, body) = call(
        &st,
        "/v1/chat/completions",
        &[("authorization", bearer.as_str())],
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let got: Vec<HeaderMap> = seen.lock().unwrap().clone();
    assert_eq!(got.len(), 1, "{got:?}");
    assert_eq!(
        header_text(&got[0], "authorization"),
        Some(format!("Bearer {PROVIDER_KEY}"))
    );
}

#[test]
fn the_default_upstream_auth_follows_the_wire() {
    assert_eq!(
        UpstreamAuth::default_for(Wire::Anthropic),
        UpstreamAuth::XApiKey
    );
    assert_eq!(
        UpstreamAuth::default_for(Wire::OpenAi),
        UpstreamAuth::Bearer
    );
}

#[tokio::test]
async fn a_brokered_provider_says_it_holds_its_key() {
    let (endpoint, _seen) = spawn_upstream().await;
    assert!(brokered(&endpoint, UpstreamAuth::XApiKey).brokers_key());
    assert!(!HttpProvider::new(endpoint).brokers_key());
}

#[test]
fn a_key_file_with_a_trailing_newline_is_read_without_it() {
    let path = scratch("newline").join("upstream.key");
    std::fs::write(&path, format!("{PROVIDER_KEY}\n")).unwrap();
    let key = UpstreamKey::from_file(&path, UpstreamAuth::XApiKey).unwrap();
    assert_eq!(key.header(), ("x-api-key", PROVIDER_KEY.to_string()));
}

#[test]
fn a_provider_key_never_appears_in_debug_output() {
    let key = UpstreamKey::new(PROVIDER_KEY, UpstreamAuth::Bearer).unwrap();
    let shown = format!("{key:?}");
    assert!(
        !shown.contains(PROVIDER_KEY),
        "the key is printed by Debug: {shown}"
    );
}

/// What one run of the real binary printed, and how it ended. A process still running at the
/// deadline was serving, so it is killed and its exit is `None`.
struct Startup {
    exit: Option<i32>,
    output: String,
}

fn free_addr() -> String {
    let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = l.local_addr().unwrap();
    drop(l);
    addr.to_string()
}

fn start(env: &[(&str, &str)]) -> Startup {
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_tokenfuse"));
    cmd.env("TOKENFUSE_PROFILE", "observe");
    for name in CLEARED {
        cmd.env_remove(*name);
    }
    cmd.env("TOKENFUSE_ADDR", free_addr());
    for (name, value) in env {
        cmd.env(*name, *value);
    }
    let mut child = cmd
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("the tokenfuse binary starts");
    let deadline = Instant::now() + Duration::from_secs(8);
    let exit = loop {
        if let Some(status) = child.try_wait().unwrap() {
            break status.code();
        }
        if Instant::now() >= deadline {
            let _ = child.kill();
            let _ = child.wait();
            break None;
        }
        std::thread::sleep(Duration::from_millis(50));
    };
    let mut output = String::new();
    if let Some(mut out) = child.stdout.take() {
        let _ = std::io::Read::read_to_string(&mut out, &mut output);
    }
    if let Some(mut err) = child.stderr.take() {
        let _ = std::io::Read::read_to_string(&mut err, &mut output);
    }
    Startup { exit, output }
}

fn key_file(tag: &str, contents: &str) -> PathBuf {
    let path = scratch(tag).join("upstream.key");
    std::fs::write(&path, contents).unwrap();
    path
}

fn path_str(path: &Path) -> &str {
    path.to_str().unwrap()
}

#[test]
fn a_brokered_gateway_says_so_at_startup_without_the_key() {
    let path = key_file("brokered", &format!("{PROVIDER_KEY}\n"));
    let run = start(&[
        ("TOKENFUSE_UPSTREAM", UPSTREAM),
        ("TOKENFUSE_UPSTREAM_KEY_FILE", path_str(&path)),
    ]);
    assert!(run.output.contains("held by the gateway"), "{}", run.output);
    assert!(
        run.output.contains("TOKENFUSE_UPSTREAM_KEY_FILE"),
        "{}",
        run.output
    );
    assert!(
        !run.output.contains(PROVIDER_KEY),
        "the provider key was printed: {}",
        run.output
    );
}

#[test]
fn an_unreadable_upstream_key_file_refuses_to_start() {
    let missing = scratch("missing").join("nothing-here.key");
    let run = start(&[
        ("TOKENFUSE_UPSTREAM", UPSTREAM),
        ("TOKENFUSE_UPSTREAM_KEY_FILE", path_str(&missing)),
    ]);
    assert_eq!(run.exit, Some(2), "{}", run.output);
    assert!(
        run.output.contains("TOKENFUSE_UPSTREAM_KEY_FILE"),
        "{}",
        run.output
    );
    assert!(
        !run.output.contains(LISTENING),
        "a refused start served anyway: {}",
        run.output
    );
}

#[test]
fn an_empty_upstream_key_file_refuses_to_start() {
    let path = key_file("empty", "");
    let run = start(&[
        ("TOKENFUSE_UPSTREAM", UPSTREAM),
        ("TOKENFUSE_UPSTREAM_KEY_FILE", path_str(&path)),
    ]);
    assert_eq!(run.exit, Some(2), "{}", run.output);
    assert!(
        run.output.contains("TOKENFUSE_UPSTREAM_KEY_FILE"),
        "{}",
        run.output
    );
    assert!(
        !run.output.contains(LISTENING),
        "a refused start served anyway: {}",
        run.output
    );
}

#[test]
fn an_unknown_upstream_auth_word_refuses_to_start() {
    let path = key_file("auth-word", &format!("{PROVIDER_KEY}\n"));
    let run = start(&[
        ("TOKENFUSE_UPSTREAM", UPSTREAM),
        ("TOKENFUSE_UPSTREAM_KEY_FILE", path_str(&path)),
        ("TOKENFUSE_UPSTREAM_AUTH", "basic"),
    ]);
    assert_eq!(run.exit, Some(2), "{}", run.output);
    assert!(
        run.output.contains("TOKENFUSE_UPSTREAM_AUTH"),
        "{}",
        run.output
    );
    assert!(run.output.contains("basic"), "{}", run.output);
    assert!(run.output.contains("bearer"), "{}", run.output);
}

#[test]
fn an_upstream_auth_without_a_key_file_refuses_to_start() {
    let run = start(&[
        ("TOKENFUSE_UPSTREAM", UPSTREAM),
        ("TOKENFUSE_UPSTREAM_AUTH", "bearer"),
    ]);
    assert_eq!(run.exit, Some(2), "{}", run.output);
    assert!(
        run.output.contains("TOKENFUSE_UPSTREAM_KEY_FILE"),
        "{}",
        run.output
    );
}

#[test]
fn an_unbrokered_gateway_says_so_at_startup() {
    let run = start(&[("TOKENFUSE_UPSTREAM", UPSTREAM)]);
    assert_eq!(
        run.exit, None,
        "an unbrokered gateway starts and serves: {}",
        run.output
    );
    assert!(run.output.contains(REFUSED_BY_CALLER), "{}", run.output);
    assert!(
        run.output.contains("TOKENFUSE_UPSTREAM_KEY_FILE"),
        "{}",
        run.output
    );
}

async fn healthz_warnings(st: &AppState) -> Vec<String> {
    let req = Request::get("/healthz?detail=1")
        .body(Body::empty())
        .unwrap();
    let resp = tokenfuse_gateway::app(st.clone())
        .oneshot(req)
        .await
        .unwrap();
    let bytes = axum::body::to_bytes(resp.into_body(), 1 << 16)
        .await
        .unwrap();
    let json: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    json["warnings"]
        .as_array()
        .unwrap()
        .iter()
        .map(|w| w.as_str().unwrap().to_string())
        .collect()
}

#[tokio::test]
async fn an_unbrokered_gateway_says_so_on_healthz() {
    let (endpoint, _seen) = spawn_upstream().await;
    let (open, _bus) = gateway(
        "healthz-open",
        HttpProvider::new(endpoint.clone()),
        Wire::Anthropic,
    );
    let warnings = healthz_warnings(&open).await;
    assert!(
        warnings.iter().any(|w| w.contains(REFUSED_BY_CALLER)),
        "{warnings:?}"
    );
    let (held, _bus) = gateway(
        "healthz-held",
        brokered(&endpoint, UpstreamAuth::XApiKey),
        Wire::Anthropic,
    );
    let warnings = healthz_warnings(&held).await;
    assert!(
        !warnings.iter().any(|w| w.contains(REFUSED_BY_CALLER)),
        "{warnings:?}"
    );
}
