//! Invariant 143: a run's label comes from what an enforcement point saw it do,
//! not from a name it reported.
//!
//! Everything here runs through the real gateway router and the real broker, over
//! sockets, because the claim is about the two of them agreeing: a label the broker
//! reports is what `/v1/messages` and the tool-call check then judge on. The
//! upstream is a stand-in for scopyx with the same answer shape. Its name in these
//! fixtures is `scopyx` because that is the deployment this was built for, and
//! nothing in the code knows that name.

use std::collections::{BTreeMap, VecDeque};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use async_trait::async_trait;
use axum::body::Bytes;
use axum::http::{HeaderMap, StatusCode};
use axum::{routing::post, Json, Router};
use serde_json::{json, Value};
use tokenfuse_core::taint::FirewallMode;
use tokenfuse_core::{Ledger, Mode, Policy, SecretVault};
use tokenfuse_gateway::clientkeys::{ClientKeys, CLIENT_KEY_HEADER};
use tokenfuse_gateway::events::EventExporter;
use tokenfuse_gateway::firewall::FirewallConfig;
use tokenfuse_gateway::mcpbroker::{app, upstream_labels_from, BrokerState, ScanMode};
use tokenfuse_gateway::provider::{Provider, ProviderError, ProviderResponse, UsageSlot};
use tokenfuse_gateway::state::AppState;
use tokenfuse_gateway::wardryx::Wardryx;
use tokenfuse_gateway::wire::Wire;

const PAGE: &str = "the text of a page somebody else wrote";
const MODEL: &str = "claude-haiku-5-5";

/// A buffered Anthropic answer asking to run a shell, `exec` in the default map.
const ASKS_FOR_A_SHELL: &str = r#"{"id":"m1","type":"message","role":"assistant","model":"claude-haiku-5-5","content":[{"type":"tool_use","id":"toolu_sh","name":"run_shell","input":{}}],"stop_reason":"tool_use","usage":{"input_tokens":10,"output_tokens":5}}"#;

/// A buffered Anthropic answer in which the provider ran its own search.
const SEARCHED: &str = r#"{"id":"m2","type":"message","role":"assistant","model":"claude-haiku-5-5","content":[{"type":"server_tool_use","id":"srvtoolu_1","name":"web_search","input":{"query":"x"}},{"type":"web_search_tool_result","tool_use_id":"srvtoolu_1","content":[]},{"type":"text","text":"found it"}],"stop_reason":"end_turn","usage":{"input_tokens":10,"output_tokens":5}}"#;

/// The same search, and a shell asked for in the same answer.
const SEARCHED_THEN_SHELL: &str = r#"{"id":"m3","type":"message","role":"assistant","model":"claude-haiku-5-5","content":[{"type":"server_tool_use","id":"srvtoolu_2","name":"web_search","input":{"query":"x"}},{"type":"web_search_tool_result","tool_use_id":"srvtoolu_2","content":[]},{"type":"tool_use","id":"toolu_sh2","name":"run_shell","input":{}}],"stop_reason":"tool_use","usage":{"input_tokens":10,"output_tokens":5}}"#;

/// A streamed answer in which the provider ran its own search.
const STREAMED_SEARCH: &str = "event: message_start\ndata: {\"type\":\"message_start\",\"message\":{\"id\":\"m4\",\"type\":\"message\",\"role\":\"assistant\",\"model\":\"claude-haiku-5-5\",\"content\":[],\"stop_reason\":null,\"usage\":{\"input_tokens\":10,\"output_tokens\":1}}}\n\n\
event: content_block_start\ndata: {\"type\":\"content_block_start\",\"index\":0,\"content_block\":{\"type\":\"server_tool_use\",\"id\":\"srvtoolu_3\",\"name\":\"web_search\",\"input\":{}}}\n\n\
event: content_block_stop\ndata: {\"type\":\"content_block_stop\",\"index\":0}\n\n\
event: content_block_start\ndata: {\"type\":\"content_block_start\",\"index\":1,\"content_block\":{\"type\":\"text\",\"text\":\"\"}}\n\n\
event: content_block_delta\ndata: {\"type\":\"content_block_delta\",\"index\":1,\"delta\":{\"type\":\"text_delta\",\"text\":\"found it\"}}\n\n\
event: content_block_stop\ndata: {\"type\":\"content_block_stop\",\"index\":1}\n\n\
event: message_delta\ndata: {\"type\":\"message_delta\",\"delta\":{\"stop_reason\":\"end_turn\",\"stop_sequence\":null},\"usage\":{\"output_tokens\":5}}\n\n\
event: message_stop\ndata: {\"type\":\"message_stop\"}\n\n";

/// The same stream, with a shell asked for after the search.
const STREAMED_SEARCH_THEN_SHELL: &str = "event: message_start\ndata: {\"type\":\"message_start\",\"message\":{\"id\":\"m5\",\"type\":\"message\",\"role\":\"assistant\",\"model\":\"claude-haiku-5-5\",\"content\":[],\"stop_reason\":null,\"usage\":{\"input_tokens\":10,\"output_tokens\":1}}}\n\n\
event: content_block_start\ndata: {\"type\":\"content_block_start\",\"index\":0,\"content_block\":{\"type\":\"server_tool_use\",\"id\":\"srvtoolu_4\",\"name\":\"web_search\",\"input\":{}}}\n\n\
event: content_block_stop\ndata: {\"type\":\"content_block_stop\",\"index\":0}\n\n\
event: content_block_start\ndata: {\"type\":\"content_block_start\",\"index\":1,\"content_block\":{\"type\":\"tool_use\",\"id\":\"toolu_sh3\",\"name\":\"run_shell\",\"input\":{}}}\n\n\
event: content_block_stop\ndata: {\"type\":\"content_block_stop\",\"index\":1}\n\n\
event: message_delta\ndata: {\"type\":\"message_delta\",\"delta\":{\"stop_reason\":\"tool_use\",\"stop_sequence\":null},\"usage\":{\"output_tokens\":5}}\n\n\
event: message_stop\ndata: {\"type\":\"message_stop\"}\n\n";

/// Answers each call with the next body in its queue, the usage read as the
/// network path reads it.
struct QueueProvider {
    bodies: Mutex<VecDeque<&'static str>>,
}

#[async_trait]
impl Provider for QueueProvider {
    async fn send(
        &self,
        _headers: HeaderMap,
        _body: Bytes,
    ) -> Result<ProviderResponse, ProviderError> {
        let body = self
            .bodies
            .lock()
            .unwrap()
            .pop_front()
            .expect("a body for every call");
        let slot: UsageSlot = Arc::new(Mutex::new(None));
        let writer = Arc::clone(&slot);
        let stream = async_stream::try_stream! {
            let mut parser = tokenfuse_gateway::provider::UsageParser::new();
            for piece in body.as_bytes().chunks(11) {
                parser.feed(piece);
                yield Bytes::copy_from_slice(piece);
            }
            *writer.lock().unwrap() = Some(parser.finish());
        };
        Ok(ProviderResponse {
            status: 200,
            content_type: Some(if body.starts_with("event:") {
                "text/event-stream".to_string()
            } else {
                "application/json".to_string()
            }),
            body: Box::pin(stream),
            usage: slot,
        })
    }
}

fn events_path(tag: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("tf-observed-act-{}-{tag}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join("events.ndjson");
    let _ = std::fs::remove_file(&path);
    path
}

/// A real gateway state answering `bodies` in order, its events written to a file.
fn gateway(firewall: FirewallConfig, bodies: &[&'static str], tag: &str) -> (AppState, PathBuf) {
    let path = events_path(tag);
    let exp = EventExporter::open(path.to_str().unwrap()).unwrap();
    let st = AppState::new(
        Arc::new(Ledger::new()),
        Arc::new(tokenfuse_gateway::pricebook::default_price_book()),
        Arc::new(Policy {
            mode: Mode::Enforce,
            ..Default::default()
        }),
        Arc::new(QueueProvider {
            bodies: Mutex::new(bodies.iter().copied().collect()),
        }),
        "observed-act-test",
    )
    .with_wire(Wire::Anthropic)
    .with_firewall(Arc::new(firewall))
    .with_events(Arc::new(exp));
    (st, path)
}

fn enforcing() -> FirewallConfig {
    FirewallConfig::defaults(FirewallMode::Enforce)
}

async fn spawn(router: Router) -> String {
    let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = l.local_addr().unwrap();
    tokio::spawn(async move {
        let _ = axum::serve(l, router).await;
    });
    format!("http://{addr}")
}

/// The stand-in for scopyx: answers every `tools/call` with `PAGE` and counts them.
async fn page_server(is_error: bool) -> (String, Arc<AtomicUsize>) {
    let hits = Arc::new(AtomicUsize::new(0));
    let counter = Arc::clone(&hits);
    let router = Router::new().route(
        "/",
        post(move |Json(req): Json<Value>| {
            let counter = Arc::clone(&counter);
            async move {
                counter.fetch_add(1, Ordering::SeqCst);
                Json(json!({
                    "jsonrpc": "2.0",
                    "id": req.get("id").cloned().unwrap_or(Value::Null),
                    "result": {
                        "isError": is_error,
                        "content": [{"type": "text", "text": PAGE}],
                    },
                }))
            }
        }),
    );
    (spawn(router).await, hits)
}

struct BrokerSetup<'a> {
    /// The default upstream, and what `scopyx` names unless `named` says otherwise.
    upstream: String,
    named: BTreeMap<String, String>,
    gateway: Option<String>,
    labels: Option<&'a str>,
    events: Option<&'a Path>,
}

async fn broker(setup: BrokerSetup<'_>) -> String {
    let upstream_labels =
        upstream_labels_from(setup.labels, &setup.upstream, &setup.named).expect("a usable spec");
    let events = match setup.events {
        Some(path) => EventExporter::open(path.to_str().unwrap()).unwrap(),
        None => tokenfuse_core::agent_event::Exporter::disabled(),
    };
    let url = spawn(app(Arc::new(BrokerState {
        chain_proof: None,
        revocations: None,
        identity_strict: tokenfuse_gateway::identitymap::StrictMode::Off,
        upstream: setup.upstream,
        named_upstreams: setup.named,
        vault: SecretVault::new(),
        scan: ScanMode::Off,
        dlp: tokenfuse_core::DlpMode::Off,
        dlp_pii: tokenfuse_core::DlpMode::Off,
        lock: None,
        drifted: Default::default(),
        wardryx: Arc::new(Wardryx::disabled()),
        keys: ClientKeys::default(),
        clients: Default::default(),
        require_proof: false,
        client: reqwest::Client::new(),
        events: Arc::new(events),
        taint_gateway: setup.gateway,
        taint_failclosed: false,
        upstream_labels,
        xaa: None,
        agent_tokens: None,
        taint_gateway_key: None,
    })))
    .await;
    tokio::time::sleep(Duration::from_millis(100)).await;
    url
}

/// A broker in front of one server classified `web`, asking `gateway`.
async fn classified_broker(upstream: &str, gateway: &str) -> String {
    broker(BrokerSetup {
        upstream: "http://127.0.0.1:1".to_string(),
        named: BTreeMap::from([("scopyx".to_string(), upstream.to_string())]),
        gateway: Some(gateway.to_string()),
        labels: Some("scopyx=web"),
        events: None,
    })
    .await
}

/// One `tools/call` through the broker, to the upstream called `scopyx`.
async fn read(broker_url: &str, run: Option<&str>, tool: &str) -> Value {
    let mut req = reqwest::Client::new()
        .post(format!("{broker_url}/"))
        .header("x-fuse-agent-id", "agent://acme.example/reader")
        .header("x-fuse-mcp-upstream", "scopyx")
        .json(&json!({
            "jsonrpc": "2.0", "id": 1, "method": "tools/call",
            "params": {"name": tool, "arguments": {"url": "https://docs.example/private/path?who=jane"}},
        }));
    if let Some(r) = run {
        req = req.header("x-fuse-run-id", r);
    }
    req.send().await.unwrap().json().await.unwrap()
}

/// The firewall's own answer to "may this run use a shell", through the real check.
async fn may_run_a_shell(gateway_url: &str, run: &str) -> Value {
    reqwest::Client::new()
        .post(format!("{gateway_url}/v1/fuse/check-tool-call"))
        .header("x-fuse-agent-id", "agent://acme.example/reader")
        .json(&json!({"run_id": run, "tool": "run_shell"}))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap()
}

/// One metered call on `run` carrying `messages`.
async fn model_call(gateway_url: &str, run: &str, messages: Value, stream: bool) -> (u16, String) {
    let resp = reqwest::Client::new()
        .post(format!("{gateway_url}/v1/messages"))
        .header("x-fuse-run-id", run)
        .header("x-fuse-budget-usd", "5")
        .header("x-fuse-agent-id", "agent://acme.example/reader")
        .json(&json!({"model": MODEL, "max_tokens": 100, "stream": stream, "messages": messages}))
        .send()
        .await
        .unwrap();
    let status = resp.status().as_u16();
    (status, resp.text().await.unwrap())
}

fn plain_conversation() -> Value {
    json!([{"role": "user", "content": "summarise that for me"}])
}

/// A conversation reporting one finished tool call under `name`.
fn conversation_reporting(name: &str) -> Value {
    json!([
        {"role": "user", "content": "look that up"},
        {"role": "assistant", "content": [{"type": "tool_use", "id": "toolu_1", "name": name, "input": {}}]},
        {"role": "user", "content": [{"type": "tool_result", "tool_use_id": "toolu_1", "content": "ok"}]},
    ])
}

fn on_bus(path: &Path, kind: &str) -> Vec<Value> {
    std::fs::read_to_string(path)
        .unwrap_or_default()
        .lines()
        .filter_map(|l| serde_json::from_str::<Value>(l).ok())
        .filter(|e| e["type"] == kind)
        .collect()
}

/// A gateway stand-in: its check allows, and its act route answers `act`.
fn stub_gateway(
    act: StatusCode,
    body: &'static str,
) -> (Router, Arc<AtomicUsize>, Arc<Mutex<Vec<String>>>) {
    let asked = Arc::new(AtomicUsize::new(0));
    let keys = Arc::new(Mutex::new(Vec::new()));
    let counter = Arc::clone(&asked);
    let seen = Arc::clone(&keys);
    let router = Router::new()
        .route(
            "/v1/fuse/check-tool-call",
            post(|| async { Json(json!({"decision": "allow", "governed": true})) }),
        )
        .route(
            "/v1/fuse/observed-act",
            post(move |headers: HeaderMap| {
                let counter = Arc::clone(&counter);
                let seen = Arc::clone(&seen);
                async move {
                    counter.fetch_add(1, Ordering::SeqCst);
                    let key = headers
                        .get(CLIENT_KEY_HEADER)
                        .and_then(|v| v.to_str().ok())
                        .unwrap_or_default()
                        .to_string();
                    seen.lock().unwrap().push(key);
                    (act, body)
                }
            }),
        );
    (router, asked, keys)
}

// ---------------------------------------------------------------------------
// The act, at the broker
// ---------------------------------------------------------------------------

/// No sleep between the answer and the check, on purpose: the claim is that the
/// label is on the run before the agent has the page, and a label that landed a
/// moment later would leave the agent a moment to act in.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_read_through_a_classified_upstream_labels_the_run_before_the_answer_returns() {
    let (st, _) = gateway(enforcing(), &[], "before");
    let gw = spawn(tokenfuse_gateway::app(st)).await;
    let (up, hits) = page_server(false).await;
    let brk = classified_broker(&up, &gw).await;

    assert_eq!(may_run_a_shell(&gw, "run-read").await["decision"], "allow");
    let out = read(&brk, Some("run-read"), "fetch_url").await;
    assert_eq!(out["result"]["content"][0]["text"], PAGE, "{out}");
    assert_eq!(hits.load(Ordering::SeqCst), 1);

    let after = may_run_a_shell(&gw, "run-read").await;
    assert_eq!(after["decision"], "deny", "{after}");
    assert_eq!(after["carrying"], json!(["web"]), "{after}");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_renamed_tool_carries_the_label_of_the_server_that_answered() {
    let mut firewall = enforcing();
    firewall
        .sources
        .insert("crm_lookup".to_string(), vec!["internal".to_string()]);
    let (st, _) = gateway(firewall, &[ASKS_FOR_A_SHELL, ASKS_FOR_A_SHELL], "renamed");
    let gw = spawn(tokenfuse_gateway::app(st)).await;
    let (up, _) = page_server(false).await;
    let brk = classified_broker(&up, &gw).await;

    // The same conversation on a run that read nothing: the name it reports is one
    // the policy trusts, so the shell goes through. Without this half the test
    // below would pass on a gateway that refuses every shell.
    let (status, body) = model_call(
        &gw,
        "run-honest",
        conversation_reporting("crm_lookup"),
        false,
    )
    .await;
    assert_eq!(status, 200, "{body}");

    let out = read(&brk, Some("run-renamed"), "crm_lookup").await;
    assert_eq!(out["result"]["content"][0]["text"], PAGE, "{out}");
    let (status, body) = model_call(
        &gw,
        "run-renamed",
        conversation_reporting("crm_lookup"),
        false,
    )
    .await;
    assert_eq!(status, 403, "{body}");
    assert!(body.contains("web"), "the label is the act's: {body}");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_conversation_that_never_mentions_the_fetch_is_judged_on_the_act() {
    let (st, _) = gateway(enforcing(), &[ASKS_FOR_A_SHELL, ASKS_FOR_A_SHELL], "hidden");
    let gw = spawn(tokenfuse_gateway::app(st)).await;
    let (up, _) = page_server(false).await;
    let brk = classified_broker(&up, &gw).await;

    let (status, body) = model_call(&gw, "run-clean", plain_conversation(), false).await;
    assert_eq!(
        status, 200,
        "a run that read nothing keeps its shell: {body}"
    );

    read(&brk, Some("run-hidden"), "fetch_url").await;
    let (status, body) = model_call(&gw, "run-hidden", plain_conversation(), false).await;
    assert_eq!(status, 403, "{body}");
}

/// The fallback the brief keeps: a fetch nothing saw still has a name.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_name_map_still_labels_what_no_enforcement_point_saw() {
    let (st, _) = gateway(enforcing(), &[ASKS_FOR_A_SHELL], "by-name");
    let gw = spawn(tokenfuse_gateway::app(st)).await;
    let (status, body) =
        model_call(&gw, "run-named", conversation_reporting("fetch_url"), false).await;
    assert_eq!(status, 403, "{body}");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_classified_upstream_refuses_a_call_that_names_no_run() {
    let (st, _) = gateway(enforcing(), &[], "no-run");
    let gw = spawn(tokenfuse_gateway::app(st)).await;
    let (up, hits) = page_server(false).await;
    let brk = classified_broker(&up, &gw).await;

    let out = read(&brk, None, "fetch_url").await;
    let msg = out["error"]["message"].as_str().unwrap_or_default();
    assert!(msg.contains("x-fuse-run-id"), "{out}");
    assert_eq!(hits.load(Ordering::SeqCst), 0, "nothing reaches the server");
}

/// Three ways of not taking a label, one answer: the page stays here.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn an_answer_is_withheld_when_the_gateway_cannot_take_the_label() {
    for (tag, status, body) in [
        ("refused", StatusCode::INTERNAL_SERVER_ERROR, "{}"),
        ("not-json", StatusCode::OK, "not json"),
        (
            "declined",
            StatusCode::OK,
            r#"{"recorded":false,"governed":true,"reason":"no"}"#,
        ),
    ] {
        let (stub, asked, _) = stub_gateway(status, body);
        let gw = spawn(stub).await;
        let (up, hits) = page_server(false).await;
        let path = events_path(&format!("withheld-{tag}"));
        let brk = broker(BrokerSetup {
            upstream: "http://127.0.0.1:1".to_string(),
            named: BTreeMap::from([("scopyx".to_string(), up.clone())]),
            gateway: Some(gw),
            labels: Some("scopyx=web"),
            events: Some(&path),
        })
        .await;

        let out = read(&brk, Some("run-withheld"), "fetch_url").await;
        assert!(out.get("result").is_none(), "{tag}: {out}");
        assert!(!out.to_string().contains(PAGE), "{tag}: {out}");
        assert_eq!(hits.load(Ordering::SeqCst), 1, "{tag}: the fetch happened");
        assert_eq!(asked.load(Ordering::SeqCst), 1, "{tag}");
        let failed = on_bus(&path, "dependency_failed");
        if tag == "declined" {
            assert!(failed.is_empty(), "the gateway answered: {failed:?}");
        } else {
            assert_eq!(failed.len(), 1, "{tag}: {failed:?}");
            assert_eq!(failed[0]["data"]["effect"], "denied_unasked", "{tag}");
        }
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_default_route_to_a_classified_server_is_labelled_too() {
    let (st, _) = gateway(enforcing(), &[], "route");
    let gw = spawn(tokenfuse_gateway::app(st)).await;
    let (up, _) = page_server(false).await;
    // Spelt with a trailing slash on one side, as two lines of a compose file can
    // be: one server, whichever way a call reaches it.
    let brk = broker(BrokerSetup {
        upstream: format!("{up}/"),
        named: BTreeMap::from([("scopyx".to_string(), up.clone())]),
        gateway: Some(gw.clone()),
        labels: Some("scopyx=web"),
        events: None,
    })
    .await;

    let out: Value = reqwest::Client::new()
        .post(format!("{brk}/"))
        .header("x-fuse-agent-id", "agent://acme.example/reader")
        .header("x-fuse-run-id", "run-default")
        .json(&json!({"jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": {"name": "fetch_url"}}))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(out["result"]["content"][0]["text"], PAGE, "{out}");
    assert_eq!(
        may_run_a_shell(&gw, "run-default").await["decision"],
        "deny"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn an_unclassified_upstream_is_not_reported() {
    let (stub, asked, _) = stub_gateway(StatusCode::OK, r#"{"recorded":true}"#);
    let gw = spawn(stub).await;
    let (up, hits) = page_server(false).await;
    let (other, _) = page_server(false).await;
    // Something is classified on this broker, and it is not this server.
    let brk = broker(BrokerSetup {
        upstream: "http://127.0.0.1:1".to_string(),
        named: BTreeMap::from([("scopyx".to_string(), up), ("elsewhere".to_string(), other)]),
        gateway: Some(gw),
        labels: Some("elsewhere=web"),
        events: None,
    })
    .await;

    let out = read(&brk, None, "lookup").await;
    assert_eq!(out["result"]["content"][0]["text"], PAGE, "{out}");
    assert_eq!(hits.load(Ordering::SeqCst), 1);
    assert_eq!(
        asked.load(Ordering::SeqCst),
        0,
        "the gateway is told nothing"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn an_act_on_another_callers_run_is_refused() {
    let (st, _) = gateway(enforcing(), &[SEARCHED_NOTHING], "foreign");
    let st = st.with_client_keys(Arc::new(
        ClientKeys::from_spec("sk-owner:owner,sk-other:other").expect("a usable key spec"),
    ));
    let gw = spawn(tokenfuse_gateway::app(st.clone())).await;

    let opened = reqwest::Client::new()
        .post(format!("{gw}/v1/messages"))
        .header(CLIENT_KEY_HEADER, "sk-owner")
        .header("x-fuse-run-id", "run-owned")
        .header("x-fuse-budget-usd", "5")
        .json(&json!({"model": MODEL, "max_tokens": 10, "messages": plain_conversation()}))
        .send()
        .await
        .unwrap();
    assert_eq!(opened.status().as_u16(), 200);

    let act = json!({"run_id": "run-owned", "labels": ["web"], "source": "mcp:scopyx"});
    let post = |key: Option<&'static str>| {
        let mut req = reqwest::Client::new()
            .post(format!("{gw}/v1/fuse/observed-act"))
            .json(&act);
        if let Some(k) = key {
            req = req.header(CLIENT_KEY_HEADER, k);
        }
        req.send()
    };
    assert_eq!(post(None).await.unwrap().status().as_u16(), 401);
    let foreign: Value = post(Some("sk-other")).await.unwrap().json().await.unwrap();
    assert_eq!(foreign["recorded"], false, "{foreign}");
    assert!(st.taint.judged_against("run-owned").is_empty());
    let own: Value = post(Some("sk-owner")).await.unwrap().json().await.unwrap();
    assert_eq!(own["recorded"], true, "{own}");
    assert!(st.taint.judged_against("run-owned").contains("web"));
}

/// A plain answer, for a call that only needs to open a run.
const SEARCHED_NOTHING: &str = r#"{"id":"m6","type":"message","role":"assistant","model":"claude-haiku-5-5","content":[{"type":"text","text":"done"}],"stop_reason":"end_turn","usage":{"input_tokens":10,"output_tokens":5}}"#;

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_firewall_that_is_off_takes_no_label_and_the_answer_still_returns() {
    let (st, _) = gateway(FirewallConfig::disabled(), &[], "off");
    let gw = spawn(tokenfuse_gateway::app(st.clone())).await;
    let (up, _) = page_server(false).await;
    let brk = classified_broker(&up, &gw).await;

    let out = read(&brk, Some("run-off"), "fetch_url").await;
    assert_eq!(out["result"]["content"][0]["text"], PAGE, "{out}");
    assert!(st.taint.judged_against("run-off").is_empty());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_record_names_the_server_and_the_stage_and_no_url() {
    let (st, path) = gateway(enforcing(), &[], "record");
    let gw = spawn(tokenfuse_gateway::app(st)).await;
    let (up, _) = page_server(false).await;
    let brk = classified_broker(&up, &gw).await;

    read(&brk, Some("run-record"), "fetch_url").await;
    read(&brk, Some("run-record"), "fetch_url").await;

    let raised = on_bus(&path, "taint_raised");
    assert_eq!(raised.len(), 1, "a label is new to a run once: {raised:?}");
    let data = &raised[0]["data"];
    assert_eq!(data["stage"], "mcp_tool_call", "{data}");
    assert_eq!(data["added"], json!(["web"]), "{data}");
    assert_eq!(data["from_tools"], json!(["mcp:scopyx"]), "{data}");
    assert_eq!(raised[0]["run_id"], "run-record");
    let all = std::fs::read_to_string(&path).unwrap();
    assert!(
        !all.contains("docs.example") && !all.contains("jane"),
        "{all}"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn an_answer_the_upstream_marked_as_an_error_still_labels_the_run() {
    let (st, _) = gateway(enforcing(), &[], "is-error");
    let gw = spawn(tokenfuse_gateway::app(st)).await;
    let (up, _) = page_server(true).await;
    let brk = classified_broker(&up, &gw).await;

    let out = read(&brk, Some("run-iserror"), "fetch_url").await;
    assert_eq!(out["result"]["isError"], true, "{out}");
    assert_eq!(
        may_run_a_shell(&gw, "run-iserror").await["decision"],
        "deny"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_new_read_after_a_clearance_labels_the_run_again() {
    let (st, _) = gateway(enforcing(), &[], "clearance");
    let gw = spawn(tokenfuse_gateway::app(st.clone())).await;
    let (up, _) = page_server(false).await;
    let brk = classified_broker(&up, &gw).await;

    read(&brk, Some("run-cleared"), "fetch_url").await;
    st.taint.clear("run-cleared", &["web".to_string()]);
    assert_eq!(
        may_run_a_shell(&gw, "run-cleared").await["decision"],
        "allow"
    );
    read(&brk, Some("run-cleared"), "fetch_url").await;
    assert_eq!(
        may_run_a_shell(&gw, "run-cleared").await["decision"],
        "deny"
    );
    // The clearance is spent, not only outvoted: what the run is judged against
    // reads the cleared set, and the new read took its entry with it.
    assert!(st.taint.judged_against("run-cleared").contains("web"));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_label_is_asked_for_under_the_callers_own_key() {
    let (stub, _, keys) = stub_gateway(StatusCode::OK, r#"{"recorded":true,"governed":true}"#);
    let gw = spawn(stub).await;
    let (up, _) = page_server(false).await;
    let brk = classified_broker(&up, &gw).await;

    let out: Value = reqwest::Client::new()
        .post(format!("{brk}/"))
        .header(CLIENT_KEY_HEADER, "sk-the-callers-own")
        .header("x-fuse-agent-id", "agent://acme.example/reader")
        .header("x-fuse-mcp-upstream", "scopyx")
        .header("x-fuse-run-id", "run-keyed")
        .json(&json!({"jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": {"name": "fetch_url"}}))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(out["result"]["content"][0]["text"], PAGE, "{out}");
    assert_eq!(
        *keys.lock().unwrap(),
        vec!["sk-the-callers-own".to_string()]
    );
}

// ---------------------------------------------------------------------------
// The act, in the provider's answer
// ---------------------------------------------------------------------------

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_search_the_provider_ran_labels_the_run() {
    let (st, path) = gateway(enforcing(), &[SEARCHED], "provider");
    let gw = spawn(tokenfuse_gateway::app(st)).await;

    let (status, body) = model_call(&gw, "run-searched", plain_conversation(), false).await;
    assert_eq!(
        status, 200,
        "nothing to refuse: it already happened: {body}"
    );
    assert!(body.contains("found it"), "{body}");
    assert_eq!(
        may_run_a_shell(&gw, "run-searched").await["decision"],
        "deny"
    );

    let raised = on_bus(&path, "taint_raised");
    assert_eq!(raised.len(), 1, "{raised:?}");
    assert_eq!(raised[0]["data"]["stage"], "model_tool_call");
    assert_eq!(raised[0]["data"]["from_tools"], json!(["web_search"]));
    assert_eq!(raised[0]["data"]["added"], json!(["web"]));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_tool_call_in_the_same_answer_as_a_provider_search_is_judged_with_its_label() {
    let (st, _) = gateway(enforcing(), &[SEARCHED_THEN_SHELL], "same-answer");
    let gw = spawn(tokenfuse_gateway::app(st)).await;

    let (status, body) = model_call(&gw, "run-both", plain_conversation(), false).await;
    assert_eq!(status, 403, "{body}");
    assert!(!body.contains("toolu_sh2"), "{body}");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_streamed_search_the_provider_ran_labels_the_run() {
    let (st, _) = gateway(enforcing(), &[STREAMED_SEARCH], "provider-stream");
    let gw = spawn(tokenfuse_gateway::app(st)).await;

    let (status, body) = model_call(&gw, "run-stream", plain_conversation(), true).await;
    assert_eq!(status, 200, "{body}");
    assert!(body.contains("found it"), "{body}");
    assert_eq!(may_run_a_shell(&gw, "run-stream").await["decision"], "deny");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_streamed_tool_call_after_a_provider_search_is_judged_with_its_label() {
    let (st, _) = gateway(enforcing(), &[STREAMED_SEARCH_THEN_SHELL], "same-stream");
    let gw = spawn(tokenfuse_gateway::app(st)).await;

    let (_, body) = model_call(&gw, "run-stream-both", plain_conversation(), true).await;
    assert!(!body.contains("toolu_sh3"), "{body}");
    assert!(body.contains("taint_blocked"), "{body}");
}
