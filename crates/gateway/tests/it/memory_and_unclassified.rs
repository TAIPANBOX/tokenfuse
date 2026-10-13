//! CLAUDE.md invariants 95 and 96, through the real router.
//!
//! 95: memory is untrusted context. A run whose prompt holds memory carries the
//! `memory` label, and the starter policy refuses a later dangerous call the way
//! it refuses one after a web read. 96: a tool the source map does not name is
//! named, once per process, in the log.

use axum::body::Body;
use axum::http::{Request, Response, StatusCode};
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use tokenfuse_core::taint::FirewallMode;
use tokenfuse_core::{Ledger, Mode, ModelPrice, Policy, PriceBook};
use tokenfuse_gateway::events::EventExporter;
use tokenfuse_gateway::firewall::FirewallConfig;
use tokenfuse_gateway::provider::StubProvider;
use tokenfuse_gateway::state::AppState;
use tokenfuse_gateway::wire::Wire;
use tower::ServiceExt;
use tracing::instrument::WithSubscriber;

const SEND_EMAIL: &str =
    r#"{"content":[{"type":"tool_use","id":"c9","name":"send_email","input":{}}]}"#;
const TEXT_ONLY: &str = r#"{"content":[{"type":"text","text":"done"}]}"#;

// --- local tracing capture, scoped to the requests this module makes ---

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

struct LogCapture {
    buf: Arc<Mutex<Vec<u8>>>,
    dispatch: tracing::Dispatch,
}

impl LogCapture {
    fn new() -> Self {
        let buf = Arc::new(Mutex::new(Vec::new()));
        let subscriber = tracing_subscriber::fmt()
            .with_writer(Captured(Arc::clone(&buf)))
            .with_ansi(false)
            .with_max_level(tracing::Level::DEBUG)
            .finish();
        LogCapture {
            buf,
            dispatch: tracing::Dispatch::new(subscriber),
        }
    }

    fn dispatch(&self) -> tracing::Dispatch {
        self.dispatch.clone()
    }

    /// The warnings naming an unclassified tool, one per line.
    fn named(&self, tool: &str) -> Vec<String> {
        let text = String::from_utf8_lossy(&self.buf.lock().unwrap()).to_string();
        text.lines()
            .filter(|l| l.contains("not in the source map") && l.contains(tool))
            .map(str::to_string)
            .collect()
    }
}

// --- fixtures ---

fn events(tag: &str) -> (Arc<EventExporter>, PathBuf) {
    let dir = std::env::temp_dir().join(format!("tf-memory-{}-{tag}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join("events.ndjson");
    let _ = std::fs::remove_file(&path);
    let exp = EventExporter::open(path.to_str().unwrap()).unwrap();
    (Arc::new(exp), path)
}

fn gateway_with(fw: FirewallConfig, answer: &str, tag: &str) -> (AppState, PathBuf) {
    let prices = PriceBook::new().with(
        "test-model",
        ModelPrice::per_mtok_usd(3.0, 15.0, 0.30, 3.75),
    );
    let (exp, path) = events(tag);
    let st = AppState::new(
        Arc::new(Ledger::new()),
        Arc::new(prices),
        Arc::new(Policy {
            mode: Mode::Shadow,
            ..Default::default()
        }),
        Arc::new(StubProvider {
            body_override: Some(answer.into()),
            ..StubProvider::default()
        }),
        "memory-test",
    )
    .with_wire(Wire::Anthropic)
    .with_firewall(Arc::new(fw))
    .with_events(exp);
    (st, path)
}

fn gateway(mode: FirewallMode, answer: &str, tag: &str) -> (AppState, PathBuf) {
    gateway_with(FirewallConfig::defaults(mode), answer, tag)
}

/// A conversation whose earlier turns called each named tool, then one more
/// user message, so the history carries those tool uses.
fn body_with_history(earlier: &[&str]) -> String {
    let mut messages = vec![serde_json::json!({"role":"user","content":"hi"})];
    for (i, name) in earlier.iter().enumerate() {
        let id = format!("h{i}");
        messages.push(serde_json::json!({"role":"assistant","content":[
            {"type":"tool_use","id":id,"name":name,"input":{}}]}));
        messages.push(serde_json::json!({"role":"user","content":[
            {"type":"tool_result","tool_use_id":id,"content":"ok"}]}));
    }
    messages.push(serde_json::json!({"role":"user","content":"continue"}));
    serde_json::json!({"model":"test-model","max_tokens":100,"messages":messages}).to_string()
}

async fn post(st: AppState, run: &str, body: String, headers: &[(&str, &str)]) -> Response<Body> {
    post_logged(st, run, body, headers, None).await
}

async fn post_logged(
    st: AppState,
    run: &str,
    body: String,
    headers: &[(&str, &str)],
    log: Option<&LogCapture>,
) -> Response<Body> {
    let mut req = Request::post("/v1/messages")
        .header("content-type", "application/json")
        .header("x-fuse-run-id", run)
        .header("x-fuse-agent-id", "agent://test.local/rehearsal")
        .header("x-fuse-budget-usd", "5.0");
    for (k, v) in headers {
        req = req.header(*k, *v);
    }
    let req = req.body(Body::from(body)).unwrap();
    let fut = tokenfuse_gateway::app(st).oneshot(req);
    match log {
        Some(l) => fut.with_subscriber(l.dispatch()).await.unwrap(),
        None => fut.await.unwrap(),
    }
}

fn events_of(path: &PathBuf) -> Vec<serde_json::Value> {
    let Ok(text) = std::fs::read_to_string(path) else {
        return Vec::new();
    };
    text.lines()
        .filter(|l| !l.trim().is_empty())
        .map(|l| serde_json::from_str::<serde_json::Value>(l).unwrap())
        .collect()
}

/// The labels a `taint_raised` event added on the request-history stage.
fn history_labels(path: &PathBuf) -> Vec<Vec<String>> {
    events_of(path)
        .into_iter()
        .filter(|e| e["type"] == "taint_raised" && e["data"]["stage"] == "request_history")
        .map(|e| {
            e["data"]["added"]
                .as_array()
                .map(|a| a.iter().map(|l| l.as_str().unwrap().to_string()).collect())
                .unwrap_or_default()
        })
        .collect()
}

fn taint_types(path: &PathBuf) -> Vec<String> {
    events_of(path)
        .into_iter()
        .filter_map(|e| e["type"].as_str().map(str::to_string))
        .filter(|t| t.starts_with("taint_"))
        .collect()
}

// --- invariant 95: memory is untrusted context ---

#[tokio::test]
async fn a_memory_label_declared_in_the_prompt_stops_a_later_send() {
    // Red on the unfixed tree: `memory` labelled nothing, so the send was allowed.
    let (st, _path) = gateway(FirewallMode::Enforce, SEND_EMAIL, "declared");
    let resp = post(
        st,
        "run-declared",
        body_with_history(&[]),
        &[("x-fuse-taint", "memory")],
    )
    .await;
    assert_eq!(
        resp.status(),
        StatusCode::FORBIDDEN,
        "a run whose prompt carries memory must not send"
    );
}

#[tokio::test]
async fn a_recalled_memory_is_labelled_memory_not_unclassified() {
    // The discriminating assertion is the LABEL. A send after a recall is refused
    // today too, because `recall` is unmapped and `unclassified` is denied, so
    // only the recorded label tells the mapped tool from the unmapped one.
    let (st, path) = gateway(FirewallMode::Enforce, SEND_EMAIL, "recall");
    let resp = post(st, "run-recall", body_with_history(&["recall"]), &[]).await;
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);
    let labels = history_labels(&path);
    assert_eq!(
        labels,
        vec![vec!["memory".to_string()]],
        "recall is mapped to memory and carries no unclassified label"
    );
}

#[tokio::test]
async fn why_returns_memory_as_well() {
    let (st, path) = gateway(FirewallMode::Enforce, TEXT_ONLY, "why");
    let resp = post(st, "run-why", body_with_history(&["why"]), &[]).await;
    assert_eq!(resp.status(), StatusCode::OK);
    assert_eq!(
        history_labels(&path),
        vec![vec!["memory".to_string()]],
        "why is mapped to memory"
    );
}

#[tokio::test]
async fn a_policy_file_with_no_memory_rule_still_refuses_a_memory_run() {
    // A policy file REPLACES the starter policy, capabilities included, and this
    // one names no memory rule. So it declares send_email's capability itself,
    // as an operator's file must. The floor (invariant 95) is what denies here.
    let fw = FirewallConfig::from_json(
        r#"{"mode":"enforce","sources":{"recall":["memory"]},
            "capabilities":{"send_email":"network_egress"},
            "rules":[{"name":"mine","when_any":["web"],"deny":["exec"]}]}"#,
    )
    .expect("a valid policy");
    let (st, _path) = gateway_with(fw, SEND_EMAIL, "floor");
    let resp = post(
        st,
        "run-floor",
        body_with_history(&[]),
        &[("x-fuse-taint", "memory")],
    )
    .await;
    assert_eq!(
        resp.status(),
        StatusCode::FORBIDDEN,
        "a file that writes no memory rule must not leave memory unacted-on"
    );
}

#[tokio::test]
async fn in_shadow_a_memory_label_is_recorded_and_nothing_is_refused() {
    let (st, path) = gateway(FirewallMode::Shadow, SEND_EMAIL, "shadow");
    let resp = post(
        st,
        "run-shadow",
        body_with_history(&[]),
        &[("x-fuse-taint", "memory")],
    )
    .await;
    assert_eq!(resp.status(), StatusCode::OK, "shadow refuses nothing");
    let types = taint_types(&path);
    assert!(
        types.iter().any(|t| t == "taint_raised") && types.iter().any(|t| t == "taint_shadow"),
        "the label and the would-block are both recorded: {types:?}"
    );
}

#[tokio::test]
async fn a_memory_label_on_a_text_only_answer_refuses_nothing() {
    let (st, path) = gateway(FirewallMode::Enforce, TEXT_ONLY, "text");
    let resp = post(
        st,
        "run-text",
        body_with_history(&[]),
        &[("x-fuse-taint", "memory")],
    )
    .await;
    assert_eq!(
        resp.status(),
        StatusCode::OK,
        "a label is a source, not a verdict"
    );
    assert!(
        taint_types(&path).iter().any(|t| t == "taint_raised"),
        "and the label is recorded"
    );
}

#[tokio::test]
async fn with_the_firewall_off_memory_is_not_labelled() {
    let (st, path) = gateway(FirewallMode::Off, SEND_EMAIL, "off");
    let resp = post(
        st,
        "run-off",
        body_with_history(&["recall"]),
        &[("x-fuse-taint", "memory")],
    )
    .await;
    assert_eq!(resp.status(), StatusCode::OK);
    assert!(taint_types(&path).is_empty(), "{:?}", taint_types(&path));
    assert!(resp
        .headers()
        .get_all("x-fuse-taint")
        .iter()
        .next()
        .is_none());
}

// --- invariant 96: an unclassified tool is named, once ---

#[tokio::test]
async fn an_unclassified_tool_is_named_once_in_the_log() {
    // Two calls, the same unmapped tool both times: one line, not two.
    let (st, _path) = gateway(FirewallMode::Enforce, TEXT_ONLY, "named-once");
    let log = LogCapture::new();
    let body = body_with_history(&["mystery_tool"]);
    let resp = post_logged(st.clone(), "run-named-a", body.clone(), &[], Some(&log)).await;
    assert_eq!(resp.status(), StatusCode::OK);
    let resp = post_logged(st, "run-named-b", body, &[], Some(&log)).await;
    assert_eq!(resp.status(), StatusCode::OK);
    let named = log.named("mystery_tool");
    assert_eq!(named.len(), 1, "named once per process: {named:?}");
    assert!(
        named[0].contains("TOKENFUSE_FIREWALL_CONFIG"),
        "the line says how to classify it: {}",
        named[0]
    );
}

#[tokio::test]
async fn a_classified_tool_is_not_named() {
    // `web_search` is in the starter source map, so nothing is named for it.
    let (st, _path) = gateway(FirewallMode::Enforce, TEXT_ONLY, "classified");
    let log = LogCapture::new();
    let resp = post_logged(
        st,
        "run-classified",
        body_with_history(&["web_search"]),
        &[],
        Some(&log),
    )
    .await;
    assert_eq!(resp.status(), StatusCode::OK);
    assert!(log.named("web_search").is_empty());
}

#[tokio::test]
async fn in_shadow_an_unclassified_tool_is_named_too() {
    let (st, _path) = gateway(FirewallMode::Shadow, TEXT_ONLY, "shadow-named");
    let log = LogCapture::new();
    let resp = post_logged(
        st,
        "run-shadow-named",
        body_with_history(&["mystery_tool"]),
        &[],
        Some(&log),
    )
    .await;
    assert_eq!(resp.status(), StatusCode::OK);
    assert_eq!(log.named("mystery_tool").len(), 1);
}
