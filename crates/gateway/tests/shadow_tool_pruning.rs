//! Integration test for shadow tool-pruning measurement (W2a, invariant 61).
//!
//! Follows the pattern `tests/wardryx.rs` already uses for a fake wardryx PDP
//! (a tiny stub axum server) and `tests/router.rs`'s `CapturingProvider` for a
//! fake upstream that records the exact bytes it was asked to forward, so
//! this file can assert the forwarded body is byte-identical to what the
//! client sent.
//!
//! Deviation from the letter of the brief, recorded rather than silently
//! worked around: the brief asks for the captured-tracing helper in
//! `testlog.rs` for the two tests that assert on a warn line. That module is
//! `pub(crate)` inside `tokenfuse-gateway` and is therefore invisible to this
//! file, which is compiled as its own crate against the already-built
//! library the way every file under `tests/` is. This file carries its own
//! copy of the same capture (`Captured`/`captured_log`/`log_lock`), the
//! minimum needed to read a `tracing::warn!` line back, rather than widening
//! `testlog`'s visibility for one caller outside the crate.

#![allow(clippy::await_holding_lock)]

use async_trait::async_trait;
use axum::body::{Body, Bytes};
use axum::extract::State;
use axum::http::{HeaderMap, Request, StatusCode};
use axum::routing::post;
use axum::{Json, Router as AxumRouter};
use serde_json::{json, Value};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, MutexGuard, OnceLock};
use std::time::Duration;
use tokenfuse_core::{Ledger, Mode, ModelPrice, Policy, PriceBook};
use tokenfuse_gateway::defaults::ToolsPruneMode;
use tokenfuse_gateway::provider::{
    ParsedUsage, Provider, ProviderError, ProviderResponse, UsageSlot,
};
use tokenfuse_gateway::sink::{CallRecord, EventSink};
use tokenfuse_gateway::state::AppState;
use tokenfuse_gateway::wardryx::{FailMode, Wardryx, WardryxMode};
use tower::ServiceExt;

// --- local tracing capture (see this file's module doc for why it is not `crate::testlog`) ---

#[derive(Clone)]
struct Captured(Arc<Mutex<Vec<u8>>>);

impl std::io::Write for Captured {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.0.lock().unwrap().extend_from_slice(buf);
        Ok(buf.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

impl<'a> tracing_subscriber::fmt::MakeWriter<'a> for Captured {
    type Writer = Captured;
    fn make_writer(&'a self) -> Self::Writer {
        self.clone()
    }
}

fn captured_log() -> &'static Arc<Mutex<Vec<u8>>> {
    static BUF: OnceLock<Arc<Mutex<Vec<u8>>>> = OnceLock::new();
    BUF.get_or_init(|| {
        let buf = Arc::new(Mutex::new(Vec::new()));
        let subscriber = tracing_subscriber::fmt()
            .with_writer(Captured(Arc::clone(&buf)))
            .with_ansi(false)
            .with_max_level(tracing::Level::DEBUG)
            .finish();
        // Best-effort: another test binary module may already have installed
        // the process default. Either way `buf` below is what this file reads.
        let _ = tracing::subscriber::set_global_default(subscriber);
        buf
    })
}

fn log_lock() -> MutexGuard<'static, ()> {
    static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
    LOCK.get_or_init(|| Mutex::new(()))
        .lock()
        .unwrap_or_else(|e| e.into_inner())
}

fn clear_log() {
    captured_log().lock().unwrap().clear();
}

fn log_text() -> String {
    String::from_utf8_lossy(&captured_log().lock().unwrap()).to_string()
}

// --- fake wardryx PDP: /v1/decide (always allow) + /v1/filter-tools ---

#[derive(Clone)]
struct WardryxStub {
    filter_status: Arc<Mutex<u16>>,
    filter_response: Arc<Mutex<Value>>,
    filter_calls: Arc<AtomicUsize>,
    last_filter_request: Arc<Mutex<Option<Value>>>,
}

impl WardryxStub {
    fn new(filter_response: Value) -> Self {
        WardryxStub {
            filter_status: Arc::new(Mutex::new(200)),
            filter_response: Arc::new(Mutex::new(filter_response)),
            filter_calls: Arc::new(AtomicUsize::new(0)),
            last_filter_request: Arc::new(Mutex::new(None)),
        }
    }

    fn with_status(status: u16) -> Self {
        let s = WardryxStub::new(json!({}));
        *s.filter_status.lock().unwrap() = status;
        s
    }
}

async fn decide(Json(_body): Json<Value>) -> Json<Value> {
    Json(json!({"decision": "allow", "policy_version": "v1", "cacheable": true}))
}

async fn filter_tools(
    State(stub): State<WardryxStub>,
    Json(body): Json<Value>,
) -> axum::response::Response {
    stub.filter_calls.fetch_add(1, Ordering::SeqCst);
    *stub.last_filter_request.lock().unwrap() = Some(body);
    let status = *stub.filter_status.lock().unwrap();
    let payload = stub.filter_response.lock().unwrap().clone();
    (StatusCode::from_u16(status).unwrap(), Json(payload)).into_response()
}

use axum::response::IntoResponse;

fn wardryx_router(stub: WardryxStub) -> AxumRouter {
    AxumRouter::new()
        .route("/v1/decide", post(decide))
        .route("/v1/filter-tools", post(filter_tools))
        .with_state(stub)
}

async fn spawn_server(router: AxumRouter) -> String {
    let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = l.local_addr().unwrap();
    tokio::spawn(async move {
        let _ = axum::serve(l, router).await;
    });
    format!("http://{addr}")
}

// --- fake upstream: captures the exact bytes it was asked to forward (tests/router.rs's pattern) ---

#[derive(Clone, Default)]
struct CapturedBody(Arc<Mutex<Option<Bytes>>>);

struct CapturingProvider {
    captured: CapturedBody,
}

#[async_trait]
impl Provider for CapturingProvider {
    async fn send(
        &self,
        _headers: HeaderMap,
        body: Bytes,
    ) -> Result<ProviderResponse, ProviderError> {
        *self.captured.0.lock().unwrap() = Some(body);
        let usage = tokenfuse_core::Usage {
            input_tokens: 100,
            output_tokens: 50,
            ..Default::default()
        };
        let slot: UsageSlot = Arc::new(Mutex::new(Some(ParsedUsage {
            usage,
            truncated: false,
        })));
        let chunk = Bytes::from_static(br#"{"stub":true}"#);
        let stream = futures::stream::once(async move { Ok(chunk) });
        Ok(ProviderResponse {
            status: 200,
            content_type: Some("application/json".to_string()),
            body: Box::pin(stream),
            usage: slot,
        })
    }
}

#[derive(Clone, Default)]
struct RecordingSink {
    records: Arc<Mutex<Vec<CallRecord>>>,
}

impl RecordingSink {
    fn last(&self) -> CallRecord {
        self.records.lock().unwrap().last().cloned().unwrap()
    }
}

impl EventSink for RecordingSink {
    fn record(&self, rec: CallRecord) {
        self.records.lock().unwrap().push(rec);
    }
    fn flush(&self) {}
}

fn state(
    wardryx: Wardryx,
    tools_prune: ToolsPruneMode,
    captured: CapturedBody,
    sink: RecordingSink,
) -> AppState {
    let prices = PriceBook::new().with(
        "test-model",
        ModelPrice::per_mtok_usd(3.0, 15.0, 0.30, 3.75),
    );
    AppState::new(
        Arc::new(Ledger::new()),
        Arc::new(prices),
        Arc::new(Policy {
            mode: Mode::Enforce,
            ..Default::default()
        }),
        Arc::new(CapturingProvider { captured }),
        "shadow-prune-test-policy",
    )
    .with_wardryx(Arc::new(wardryx))
    .with_tools_prune(tools_prune)
    .with_sink(Arc::new(sink))
}

/// Three declared tools, Anthropic shape: `wire_transfer` is the one the
/// fake wardryx below denies.
fn anthropic_body() -> String {
    json!({
        "model": "test-model",
        "max_tokens": 100,
        "messages": [{"role": "user", "content": "hi"}],
        "tools": [
            {"name": "lookup", "description": "read only", "input_schema": {}},
            {"name": "wire_transfer", "description": "move money", "input_schema": {"type": "object"}},
            {"name": "send_email", "description": "notify", "input_schema": {}}
        ]
    })
    .to_string()
}

/// The same three tools, OpenAI shape.
fn openai_body() -> String {
    json!({
        "model": "test-model",
        "max_tokens": 100,
        "messages": [{"role": "user", "content": "hi"}],
        "tools": [
            {"type": "function", "function": {"name": "lookup", "description": "read only"}},
            {"type": "function", "function": {"name": "wire_transfer", "description": "move money", "parameters": {"type": "object"}}},
            {"type": "function", "function": {"name": "send_email", "description": "notify"}}
        ]
    })
    .to_string()
}

fn request(body: &str) -> Request<Body> {
    Request::post("/v1/messages")
        .header("x-fuse-run-id", "shadow-prune-run")
        .header("x-fuse-agent-id", "agent://shadow-prune-test/caller")
        .header("x-fuse-budget-usd", "5.0")
        .body(Body::from(body.to_string()))
        .unwrap()
}

fn deny_wire_transfer_response() -> Value {
    json!({
        "allowed": ["lookup", "send_email"],
        "denied": [{"name": "wire_transfer", "policy": "no-money-moves", "rule": "deny_tool"}],
        "policy_version": "v1"
    })
}

// --- the tests ---

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn off_makes_no_filter_call() {
    let stub = WardryxStub::new(deny_wire_transfer_response());
    let url = spawn_server(wardryx_router(stub.clone())).await;
    tokio::time::sleep(Duration::from_millis(150)).await;

    let wardryx = Wardryx::new(
        WardryxMode::Shadow,
        FailMode::Open,
        url,
        None,
        Duration::from_millis(500),
        Duration::from_secs(0), // no caching, so a real call would be visible
    );
    // TOKENFUSE_TOOLS_PRUNE unset (Off): the setting, not the wardryx mode,
    // gates the filter-tools call.
    let st = state(
        wardryx,
        ToolsPruneMode::Off,
        CapturedBody::default(),
        RecordingSink::default(),
    );
    let app = tokenfuse_gateway::app(st);

    let resp = app.oneshot(request(&anthropic_body())).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    assert_eq!(
        stub.filter_calls.load(Ordering::SeqCst),
        0,
        "off must never call /v1/filter-tools"
    );
    assert!(resp.headers().get("x-fuse-tools-would-prune").is_none());
}

async fn shadow_pruning_never_changes_the_forwarded_body_for(body: String) {
    let stub = WardryxStub::new(deny_wire_transfer_response());
    let url = spawn_server(wardryx_router(stub.clone())).await;
    tokio::time::sleep(Duration::from_millis(150)).await;

    let wardryx = Wardryx::new(
        WardryxMode::Shadow,
        FailMode::Open,
        url,
        None,
        Duration::from_millis(500),
        Duration::from_secs(0),
    );
    let captured = CapturedBody::default();
    let st = state(
        wardryx,
        ToolsPruneMode::Shadow,
        captured.clone(),
        RecordingSink::default(),
    );
    let app = tokenfuse_gateway::app(st);

    let resp = app.oneshot(request(&body)).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    assert_eq!(
        stub.filter_calls.load(Ordering::SeqCst),
        1,
        "shadow with tools declared must call filter-tools exactly once"
    );

    let sent = captured
        .0
        .lock()
        .unwrap()
        .clone()
        .expect("the provider was called");
    assert_eq!(
        sent.as_ref(),
        body.as_bytes(),
        "shadow pruning must never change the forwarded body, byte for byte"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn shadow_pruning_never_changes_the_forwarded_body_anthropic() {
    shadow_pruning_never_changes_the_forwarded_body_for(anthropic_body()).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn shadow_pruning_never_changes_the_forwarded_body_openai() {
    shadow_pruning_never_changes_the_forwarded_body_for(openai_body()).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn shadow_records_the_tools_the_policy_would_remove() {
    let stub = WardryxStub::new(deny_wire_transfer_response());
    let url = spawn_server(wardryx_router(stub.clone())).await;
    tokio::time::sleep(Duration::from_millis(150)).await;

    let wardryx = Wardryx::new(
        WardryxMode::Shadow,
        FailMode::Open,
        url,
        None,
        Duration::from_millis(500),
        Duration::from_secs(0),
    );
    let sink = RecordingSink::default();
    let st = state(
        wardryx,
        ToolsPruneMode::Shadow,
        CapturedBody::default(),
        sink.clone(),
    );
    let app = tokenfuse_gateway::app(st);

    let body = anthropic_body();
    let resp = app.oneshot(request(&body)).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    // The denied tool's element, serialized, is the second element of the
    // "tools" array in `anthropic_body()`. Mirrors
    // `estimate::CHARS_PER_TOKEN` (4), which is `pub(crate)` and so not
    // importable from this file.
    let parsed: Value = serde_json::from_str(&body).unwrap();
    let denied_el = &parsed["tools"][1];
    let denied_len = serde_json::to_string(denied_el).unwrap().len();
    let expected_tokens = (denied_len as u64) / 4;

    let rec = sink.last();
    assert_eq!(rec.tools_offered, Some(3));
    assert_eq!(rec.tools_would_prune, Some(1));
    assert_eq!(rec.pruned_schema_tokens_est, Some(expected_tokens));

    let header = resp
        .headers()
        .get("x-fuse-tools-would-prune")
        .expect("the header must be present on a successful measurement")
        .to_str()
        .unwrap()
        .to_string();
    assert_eq!(header, format!("1;est_tokens={expected_tokens}"));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_wardryx_without_the_route_is_named_once_and_measures_nothing() {
    let _serial = log_lock();
    clear_log();

    let stub = WardryxStub::with_status(404);
    let url = spawn_server(wardryx_router(stub.clone())).await;
    tokio::time::sleep(Duration::from_millis(150)).await;

    let wardryx = Wardryx::new(
        WardryxMode::Shadow,
        FailMode::Open,
        url,
        None,
        Duration::from_millis(500),
        Duration::from_secs(0), // no caching: both calls really hit the wire
    );
    let sink = RecordingSink::default();
    let st = state(
        wardryx,
        ToolsPruneMode::Shadow,
        CapturedBody::default(),
        sink.clone(),
    );
    let app = tokenfuse_gateway::app(st.clone());

    // First call.
    let resp1 = app
        .clone()
        .oneshot(request(&anthropic_body()))
        .await
        .unwrap();
    assert_eq!(resp1.status(), StatusCode::OK);
    let rec1 = sink.last();
    assert_eq!(rec1.tools_offered, None);
    assert_eq!(rec1.tools_would_prune, None);
    assert_eq!(rec1.pruned_schema_tokens_est, None);
    assert!(resp1.headers().get("x-fuse-tools-would-prune").is_none());

    // Second call, a fresh run id so nothing about the ledger interferes.
    let mut req2 = request(&anthropic_body());
    *req2.headers_mut().get_mut("x-fuse-run-id").unwrap() = "shadow-prune-run-2".parse().unwrap();
    let resp2 = app.oneshot(req2).await.unwrap();
    assert_eq!(resp2.status(), StatusCode::OK);
    let rec2 = sink.last();
    assert_eq!(rec2.tools_offered, None);
    assert_eq!(rec2.tools_would_prune, None);
    assert_eq!(rec2.pruned_schema_tokens_est, None);
    assert!(resp2.headers().get("x-fuse-tools-would-prune").is_none());

    assert_eq!(
        stub.filter_calls.load(Ordering::SeqCst),
        2,
        "both calls reached the wire"
    );

    let log = log_text();
    let warn_lines: Vec<&str> = log
        .lines()
        .filter(|l| l.contains("WARN") && l.contains("/v1/filter-tools"))
        .collect();
    assert_eq!(
        warn_lines.len(),
        1,
        "exactly one warn line naming /v1/filter-tools for the process lifetime, got:\n{log}"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_filter_outage_in_shadow_costs_only_a_warn_line() {
    let _serial = log_lock();
    clear_log();

    let stub = WardryxStub::with_status(500);
    let url = spawn_server(wardryx_router(stub.clone())).await;
    tokio::time::sleep(Duration::from_millis(150)).await;

    let wardryx = Wardryx::new(
        WardryxMode::Shadow,
        FailMode::Open,
        url,
        None,
        Duration::from_millis(500),
        Duration::from_secs(0),
    );
    let sink = RecordingSink::default();
    let st = state(
        wardryx,
        ToolsPruneMode::Shadow,
        CapturedBody::default(),
        sink.clone(),
    );
    let app = tokenfuse_gateway::app(st);

    let resp = app.oneshot(request(&anthropic_body())).await.unwrap();
    assert_eq!(
        resp.status(),
        StatusCode::OK,
        "a filter outage in shadow must never block the call"
    );

    let rec = sink.last();
    assert_eq!(rec.tools_offered, None);
    assert_eq!(rec.tools_would_prune, None);
    assert_eq!(rec.pruned_schema_tokens_est, None);
    assert!(resp.headers().get("x-fuse-tools-would-prune").is_none());

    let log = log_text();
    let warn_lines: Vec<&str> = log.lines().filter(|l| l.contains("WARN")).collect();
    assert_eq!(
        warn_lines.len(),
        1,
        "exactly one warn line for the outage, got:\n{log}"
    );
}
