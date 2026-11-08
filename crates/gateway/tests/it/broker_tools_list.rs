//! The MCP broker's `tools/list` shows an agent every tool except the ones its
//! policy refuses outright: named by wardryx's `deny_tool`, or left out of an
//! `allow_tool` list, both refusals no approval lifts (invariant 146).
//!
//! A tool the agent merely holds no grant for stays listed: its call is the one
//! wardryx holds for a person, and a person can only be asked about a tool the
//! agent can see. These tests drive `mcpbroker::process` directly, the way the
//! stdio transport does, against a stub upstream MCP server and a stub wardryx
//! whose `/v1/filter-tools` answer is worked out from a small policy. A warn
//! line the broker writes while answering is read back from the request's own
//! future, the capture `shadow_tool_pruning` explains in its module doc.

use std::collections::BTreeMap;
use std::sync::{Arc, Mutex, OnceLock};
use std::time::Duration;

use axum::extract::State;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::routing::post;
use axum::{Json, Router};
use serde_json::{json, Value};
use tokenfuse_core::SecretVault;
use tokenfuse_gateway::clientkeys::ClientKeys;
use tokenfuse_gateway::mcpbroker::{process, BrokerState, CallContext, ScanMode};
use tokenfuse_gateway::wardryx::{FailMode, Wardryx, WardryxMode};
use tracing::instrument::WithSubscriber;
use tracing::span::{Attributes, Id, Record};
use tracing::subscriber::Interest;
use tracing::{Event, Metadata};

const AGENT: &str = "agent://acme/triage";
const OTHER: &str = "agent://acme/billing";

/// A decision cache that never serves an answer again.
const NO_REUSE: Duration = Duration::ZERO;

/// A decision cache that outlives the test.
const REUSE: Duration = Duration::from_secs(60);

// --- a tracing capture scoped to one test's own futures ---

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

/// A dispatcher kept registered for the life of the test binary, so tracing
/// never works out a callsite's interest from one thread's default alone.
///
/// tracing-core 0.1.36 rebuilds interest from the CURRENT thread's default
/// while only one dispatcher is registered (`has_just_one`). With one test's
/// capture the only one alive, a callsite another test's thread hit first was
/// cached as never, and the capture read an empty log: CI run 42453738943 of
/// the throwaway mutation branch for this file, on its unmutated control job.
/// A second, permanent dispatcher that answers "sometimes" keeps every
/// callsite checked per event against the thread's own default. It is nobody's
/// default and receives nothing.
struct Keeper;

impl tracing::Subscriber for Keeper {
    fn register_callsite(&self, _: &'static Metadata<'static>) -> Interest {
        Interest::sometimes()
    }
    fn enabled(&self, _: &Metadata<'_>) -> bool {
        false
    }
    fn new_span(&self, _: &Attributes<'_>) -> Id {
        Id::from_u64(1)
    }
    fn record(&self, _: &Id, _: &Record<'_>) {}
    fn record_follows_from(&self, _: &Id, _: &Id) {}
    fn event(&self, _: &Event<'_>) {}
    fn enter(&self, _: &Id) {}
    fn exit(&self, _: &Id) {}
}

fn keep_interest_per_event() {
    static KEEPER: OnceLock<tracing::Dispatch> = OnceLock::new();
    let _ = KEEPER.get_or_init(|| tracing::Dispatch::new(Keeper));
}

struct LogCapture {
    buf: Arc<Mutex<Vec<u8>>>,
    dispatch: tracing::Dispatch,
}

impl LogCapture {
    fn new() -> Self {
        keep_interest_per_event();
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

    fn text(&self) -> String {
        String::from_utf8_lossy(&self.buf.lock().unwrap()).to_string()
    }
}

// --- a stub wardryx: /v1/filter-tools worked out from a policy, /v1/decide beside it ---

/// What the stub refuses one agent, and under which rule. `unknown_rule` is
/// reported under a rule `/v1/filter-tools` does not name today, and `no_rule`
/// with no rule at all: neither may be read as a refusal no approval lifts.
#[derive(Clone, Default)]
struct Policy {
    deny_tool: Vec<&'static str>,
    /// The `allow_tool` list: when it names anything, every tool it does not
    /// name is refused under `allow_tool`, as wardryx refuses it.
    allow_tool: Vec<&'static str>,
    unknown_rule: Vec<&'static str>,
    no_rule: Vec<&'static str>,
    /// Every name starting with this is refused by `deny_tool`, for the sweep.
    deny_prefix: Option<&'static str>,
    /// Every name starting with this is refused by `allow_tool`, for the sweep.
    outside_prefix: Option<&'static str>,
    /// Every name starting with this is refused under an unknown rule.
    unknown_prefix: Option<&'static str>,
    /// Every name starting with this is refused with no rule named.
    no_rule_prefix: Option<&'static str>,
    /// Tools no grant covers: `/v1/filter-tools` names none of them, and
    /// `/v1/decide` holds a call of one for a person (wardryx rule 15).
    no_grant: Vec<&'static str>,
}

/// What the stub's `/v1/filter-tools` says about one tool.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Answer {
    Allowed,
    /// Refused, under the rule named, or under none.
    Refused(Option<&'static str>),
}

impl Policy {
    fn answer(&self, name: &str) -> Answer {
        let starts = |prefix: Option<&str>| prefix.is_some_and(|p| name.starts_with(p));
        let outside = !self.allow_tool.is_empty() && !holds(&self.allow_tool, name);
        if holds(&self.deny_tool, name) || starts(self.deny_prefix) {
            Answer::Refused(Some("deny_tool"))
        } else if outside || starts(self.outside_prefix) {
            Answer::Refused(Some("allow_tool"))
        } else if holds(&self.unknown_rule, name) || starts(self.unknown_prefix) {
            Answer::Refused(Some("when_no_grant"))
        } else if holds(&self.no_rule, name) || starts(self.no_rule_prefix) {
            Answer::Refused(None)
        } else {
            Answer::Allowed
        }
    }
}

fn holds<'a>(list: &[&'a str], name: &'a str) -> bool {
    list.contains(&name)
}

fn denies_wire_transfer() -> Policy {
    Policy {
        deny_tool: vec!["wire_transfer"],
        ..Default::default()
    }
}

#[derive(Clone, Default)]
struct Pdp {
    policies: Arc<Mutex<BTreeMap<String, Policy>>>,
    /// The status `/v1/filter-tools` answers with; 0 is 200 and the policy.
    filter_status: Arc<Mutex<u16>>,
    filter_requests: Arc<Mutex<Vec<Value>>>,
}

impl Pdp {
    fn with(agent: &str, policy: Policy) -> Self {
        let pdp = Pdp::default();
        let mut policies = pdp.policies.lock().unwrap();
        policies.insert(agent.to_string(), policy);
        drop(policies);
        pdp
    }

    fn policy(&self, agent: &str) -> Policy {
        let policies = self.policies.lock().unwrap();
        policies.get(agent).cloned().unwrap_or_default()
    }

    fn answer_filter_with(&self, status: u16) {
        *self.filter_status.lock().unwrap() = status;
    }

    fn filter_calls(&self) -> usize {
        self.filter_requests.lock().unwrap().len()
    }

    async fn serve(&self) -> String {
        let router = Router::new()
            .route("/v1/filter-tools", post(filter_tools))
            .route("/v1/decide", post(decide));
        spawn(router.with_state(self.clone())).await
    }
}

async fn filter_tools(State(pdp): State<Pdp>, Json(body): Json<Value>) -> Response {
    pdp.filter_requests.lock().unwrap().push(body.clone());
    let status = *pdp.filter_status.lock().unwrap();
    if status != 0 {
        let status = StatusCode::from_u16(status).unwrap();
        let refusal = Json(json!({ "error": "the stub refuses" }));
        return (status, refusal).into_response();
    }
    let policy = pdp.policy(body["agent_id"].as_str().unwrap_or_default());
    let mut allowed = Vec::new();
    let mut denied = Vec::new();
    for name in body["tool_names"].as_array().into_iter().flatten() {
        let name = name.as_str().unwrap_or_default();
        match policy.answer(name) {
            Answer::Allowed => allowed.push(json!(name)),
            Answer::Refused(Some(rule)) => {
                let entry = json!({ "name": name, "policy": "stub", "rule": rule });
                denied.push(entry);
            }
            Answer::Refused(None) => denied.push(json!({ "name": name, "policy": "stub" })),
        }
    }
    let answer = json!({ "allowed": allowed, "denied": denied, "policy_version": "stub-v1" });
    Json(answer).into_response()
}

async fn decide(State(pdp): State<Pdp>, Json(body): Json<Value>) -> Json<Value> {
    let policy = pdp.policy(body["agent_id"].as_str().unwrap_or_default());
    let tool = body["tool_call"]["name"].as_str().unwrap_or_default();
    let refused = policy.answer(tool);
    let answer = if matches!(refused, Answer::Refused(Some("deny_tool" | "allow_tool"))) {
        json!({ "decision": "deny", "reason": "refused outright", "policy_version": "stub-v1" })
    } else if policy.no_grant.contains(&tool) {
        json!({
            "decision": "hold",
            "reason": "no grant covers this tool",
            "approval_id": "appr-7",
            "policy_version": "stub-v1"
        })
    } else {
        json!({ "decision": "allow", "policy_version": "stub-v1" })
    };
    Json(answer)
}

// --- a stub upstream MCP server whose `tools/list` answer a test sets ---

#[derive(Clone)]
struct Upstream(Arc<Mutex<Value>>);

impl Upstream {
    fn new(answer: Value) -> Self {
        Upstream(Arc::new(Mutex::new(answer)))
    }

    fn answer_list_with(&self, answer: Value) {
        *self.0.lock().unwrap() = answer;
    }

    async fn serve(&self) -> String {
        let router = Router::new().route("/", post(upstream));
        spawn(router.with_state(self.clone())).await
    }
}

async fn upstream(State(up): State<Upstream>, Json(req): Json<Value>) -> Json<Value> {
    let id = req.get("id").cloned().unwrap_or(Value::Null);
    if req["method"] == "tools/list" {
        let mut answer = up.0.lock().unwrap().clone();
        if let Some(obj) = answer.as_object_mut() {
            obj.insert("id".to_string(), id);
        }
        return Json(answer);
    }
    Json(json!({ "jsonrpc": "2.0", "id": id, "result": { "content": [] } }))
}

async fn spawn(router: Router) -> String {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        let _ = axum::serve(listener, router).await;
    });
    format!("http://{addr}")
}

// --- the broker, a listing, and what came back ---

fn hook(mode: WardryxMode, pdp: &str, cache: Duration) -> Wardryx {
    let timeout = Duration::from_secs(2);
    Wardryx::new(mode, FailMode::Closed, pdp, None, timeout, cache)
}

fn broker(upstream: &str, wardryx: Wardryx) -> BrokerState {
    BrokerState {
        upstream: upstream.to_string(),
        named_upstreams: Default::default(),
        vault: SecretVault::new(),
        scan: ScanMode::Off,
        dlp: tokenfuse_core::DlpMode::Off,
        dlp_pii: tokenfuse_core::DlpMode::Off,
        lock: None,
        drifted: Default::default(),
        wardryx: Arc::new(wardryx),
        keys: ClientKeys::default(),
        clients: Default::default(),
        require_proof: false,
        chain_proof: None,
        identity_strict: tokenfuse_gateway::identitymap::StrictMode::Off,
        revocations: None,
        client: reqwest::Client::new(),
        events: Arc::new(tokenfuse_core::agent_event::Exporter::disabled()),
        taint_gateway: None,
        taint_failclosed: false,
        xaa: None,
        agent_tokens: None,
        taint_gateway_key: None,
        upstream_labels: Default::default(),
    }
}

fn as_agent(agent: &str) -> CallContext {
    CallContext {
        agent_id: Some(agent.to_string()),
        ..Default::default()
    }
}

/// One listed tool, with a description and a schema.
fn tool(name: &str) -> Value {
    json!({ "name": name, "description": format!("the {name} tool"), "inputSchema": {} })
}

/// A `tools/list` answer naming `names`.
fn listing(names: &[&str]) -> Value {
    let tools: Vec<Value> = names.iter().copied().map(tool).collect();
    json!({ "jsonrpc": "2.0", "result": { "tools": tools } })
}

/// What the upstream sent for request id 1.
fn with_id(mut answer: Value) -> Value {
    if let Some(obj) = answer.as_object_mut() {
        obj.insert("id".to_string(), json!(1));
    }
    answer
}

async fn list(st: &BrokerState, ctx: &CallContext) -> Value {
    let req = json!({ "jsonrpc": "2.0", "id": 1, "method": "tools/list" });
    process(st, req, ctx).await
}

/// One listing, with what the broker logs while answering it captured.
async fn list_logged(st: &BrokerState, ctx: &CallContext, log: &LogCapture) -> Value {
    list(st, ctx).with_subscriber(log.dispatch()).await
}

/// The names `answer` lists, in order.
fn listed(answer: &Value) -> Vec<String> {
    let Some(tools) = answer["result"]["tools"].as_array() else {
        return Vec::new();
    };
    tools
        .iter()
        .filter_map(|t| t["name"].as_str().map(str::to_string))
        .collect()
}

// --- the scenarios ---

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_tool_the_policy_denies_by_name_is_not_listed() {
    let pdp = Pdp::with(AGENT, denies_wire_transfer());
    let pdp_url = pdp.serve().await;
    let up = Upstream::new(listing(&["lookup", "wire_transfer", "send_email"]));
    let up_url = up.serve().await;
    let st = broker(&up_url, hook(WardryxMode::Enforce, &pdp_url, NO_REUSE));

    let answer = list(&st, &as_agent(AGENT)).await;

    assert_eq!(
        listed(&answer),
        ["lookup", "send_email"],
        "a tool deny_tool names is left out, and the rest keep their order: {answer}"
    );
    let asked = pdp.filter_requests.lock().unwrap().clone();
    assert_eq!(asked.len(), 1, "one question for one listing");
    assert_eq!(asked[0]["agent_id"], AGENT);
    assert_eq!(
        asked[0]["tool_names"],
        json!(["lookup", "wire_transfer", "send_email"])
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_tool_the_agent_holds_no_grant_for_stays_listed_and_its_call_is_held() {
    let policy = Policy {
        no_grant: vec!["deploy"],
        ..Default::default()
    };
    let pdp = Pdp::with(AGENT, policy);
    let pdp_url = pdp.serve().await;
    let up = Upstream::new(listing(&["lookup", "deploy"]));
    let up_url = up.serve().await;
    let st = broker(&up_url, hook(WardryxMode::Enforce, &pdp_url, NO_REUSE));
    let ctx = as_agent(AGENT);

    let answer = list(&st, &ctx).await;

    assert_eq!(pdp.filter_calls(), 1, "the listing was asked about");
    assert_eq!(
        listed(&answer),
        ["lookup", "deploy"],
        "a tool no grant covers is shown, so its call can reach a person: {answer}"
    );
    let call = json!({
        "jsonrpc": "2.0", "id": 2, "method": "tools/call",
        "params": { "name": "deploy", "arguments": {} }
    });
    let refused = process(&st, call, &ctx).await;
    let message = refused["error"]["message"].to_string();
    assert!(
        message.contains("requires approval") && message.contains("appr-7"),
        "the call of the listed tool is held for a person, with its approval: {refused}"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_tool_outside_the_allow_tool_list_is_not_listed() {
    let policy = Policy {
        allow_tool: vec!["lookup"],
        ..Default::default()
    };
    let pdp = Pdp::with(AGENT, policy);
    let pdp_url = pdp.serve().await;
    let up = Upstream::new(listing(&["lookup", "deploy"]));
    let up_url = up.serve().await;
    let st = broker(&up_url, hook(WardryxMode::Enforce, &pdp_url, NO_REUSE));

    let answer = list(&st, &as_agent(AGENT)).await;

    assert_eq!(
        listed(&answer),
        ["lookup"],
        "a tool the allow_tool list leaves out is refused whatever is approved: {answer}"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_tool_the_allow_tool_list_names_stays_listed() {
    let policy = Policy {
        allow_tool: vec!["lookup", "deploy", "send_email"],
        ..Default::default()
    };
    let pdp = Pdp::with(AGENT, policy);
    let pdp_url = pdp.serve().await;
    let up = Upstream::new(listing(&["lookup", "deploy", "send_email", "shell"]));
    let up_url = up.serve().await;
    let st = broker(&up_url, hook(WardryxMode::Enforce, &pdp_url, NO_REUSE));

    let answer = list(&st, &as_agent(AGENT)).await;

    assert_eq!(
        listed(&answer),
        ["lookup", "deploy", "send_email"],
        "every tool the allow_tool list names stays, in order, and only the rest goes: {answer}"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_tool_the_allow_tool_list_names_with_no_grant_stays_listed_and_its_call_is_held() {
    let policy = Policy {
        allow_tool: vec!["lookup", "deploy"],
        no_grant: vec!["deploy"],
        ..Default::default()
    };
    let pdp = Pdp::with(AGENT, policy);
    let pdp_url = pdp.serve().await;
    let up = Upstream::new(listing(&["lookup", "deploy", "shell"]));
    let up_url = up.serve().await;
    let st = broker(&up_url, hook(WardryxMode::Enforce, &pdp_url, NO_REUSE));
    let ctx = as_agent(AGENT);

    let answer = list(&st, &ctx).await;

    assert_eq!(
        listed(&answer),
        ["lookup", "deploy"],
        "a listed tool no grant covers stays, the one outside the list goes: {answer}"
    );
    let call = json!({
        "jsonrpc": "2.0", "id": 2, "method": "tools/call",
        "params": { "name": "deploy", "arguments": {} }
    });
    let refused = process(&st, call, &ctx).await;
    let message = refused["error"]["message"].to_string();
    assert!(
        message.contains("requires approval") && message.contains("appr-7"),
        "the call of the listed tool is held for a person, with its approval: {refused}"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_tool_refused_under_an_unknown_rule_or_none_stays_listed() {
    let policy = Policy {
        deny_tool: vec!["wire_transfer"],
        unknown_rule: vec!["ship"],
        no_rule: vec!["audit"],
        outside_prefix: Some("out_"),
        ..Default::default()
    };
    let pdp = Pdp::with(AGENT, policy);
    let pdp_url = pdp.serve().await;
    let names = ["lookup", "ship", "audit", "wire_transfer", "out_shell"];
    let up_url = Upstream::new(listing(&names)).serve().await;
    let st = broker(&up_url, hook(WardryxMode::Enforce, &pdp_url, NO_REUSE));

    let answer = list(&st, &as_agent(AGENT)).await;

    assert_eq!(
        listed(&answer),
        ["lookup", "ship", "audit"],
        "only deny_tool and allow_tool take a tool out of the list: {answer}"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn shadow_lists_every_tool_and_says_how_many_it_would_leave_out() {
    let pdp = Pdp::with(AGENT, denies_wire_transfer());
    let pdp_url = pdp.serve().await;
    let up = Upstream::new(listing(&["lookup", "wire_transfer", "send_email"]));
    let up_url = up.serve().await;
    let st = broker(&up_url, hook(WardryxMode::Shadow, &pdp_url, NO_REUSE));

    let answer = list(&st, &as_agent(AGENT)).await;

    assert_eq!(
        answer["_tokenfuse"]["tools_would_hide"], 1,
        "shadow says how many tools enforce would leave out: {answer}"
    );
    assert_eq!(
        listed(&answer),
        ["lookup", "wire_transfer", "send_email"],
        "shadow leaves nothing out: {answer}"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn with_the_hook_off_nothing_is_asked_and_the_answer_is_the_upstreams() {
    let pdp = Pdp::with(AGENT, denies_wire_transfer());
    let pdp_url = pdp.serve().await;
    let sent = listing(&["lookup", "wire_transfer"]);
    let up_url = Upstream::new(sent.clone()).serve().await;
    let st = broker(&up_url, hook(WardryxMode::Off, &pdp_url, NO_REUSE));

    let answer = list(&st, &as_agent(AGENT)).await;

    assert_eq!(answer, with_id(sent), "off changes nothing");
    assert_eq!(pdp.filter_calls(), 0, "off asks nothing");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_listing_that_names_no_agent_asks_nothing() {
    let pdp = Pdp::with(AGENT, denies_wire_transfer());
    let pdp_url = pdp.serve().await;
    let sent = listing(&["lookup", "wire_transfer"]);
    let up_url = Upstream::new(sent.clone()).serve().await;
    let st = broker(&up_url, hook(WardryxMode::Enforce, &pdp_url, NO_REUSE));

    for ctx in [CallContext::default(), as_agent("   ")] {
        let answer = list(&st, &ctx).await;
        assert_eq!(answer, with_id(sent.clone()), "nothing is narrowed");
    }
    assert_eq!(pdp.filter_calls(), 0, "no subject, no question");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_policy_plane_that_refuses_leaves_the_list_whole_and_says_so() {
    let pdp = Pdp::with(AGENT, denies_wire_transfer());
    pdp.answer_filter_with(500);
    let pdp_url = pdp.serve().await;
    let up = Upstream::new(listing(&["lookup", "wire_transfer"]));
    let up_url = up.serve().await;
    let st = broker(&up_url, hook(WardryxMode::Enforce, &pdp_url, NO_REUSE));
    let log = LogCapture::new();

    let answer = list_logged(&st, &as_agent(AGENT), &log).await;

    assert_eq!(pdp.filter_calls(), 1, "the listing was asked about");
    assert_eq!(
        listed(&answer),
        ["lookup", "wire_transfer"],
        "with no answer nothing is hidden, and the gate still judges each call: {answer}"
    );
    let text = log.text();
    assert!(
        text.contains("filter-tools") && text.contains("500"),
        "the operator reads why the list was not narrowed: {text}"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_unreachable_policy_plane_leaves_the_list_whole_and_says_so() {
    let closed = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let pdp_url = format!("http://{}", closed.local_addr().unwrap());
    drop(closed);
    let up = Upstream::new(listing(&["lookup", "wire_transfer"]));
    let up_url = up.serve().await;
    let st = broker(&up_url, hook(WardryxMode::Enforce, &pdp_url, NO_REUSE));
    let log = LogCapture::new();

    let answer = list_logged(&st, &as_agent(AGENT), &log).await;

    assert_eq!(
        listed(&answer),
        ["lookup", "wire_transfer"],
        "an unreachable policy plane hides nothing: {answer}"
    );
    let text = log.text();
    assert!(
        text.contains("filter-tools call failed"),
        "the operator reads why the list was not narrowed: {text}"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_failed_answer_is_not_kept_so_the_next_listing_is_narrowed() {
    let pdp = Pdp::with(AGENT, denies_wire_transfer());
    pdp.answer_filter_with(500);
    let pdp_url = pdp.serve().await;
    let up = Upstream::new(listing(&["lookup", "wire_transfer"]));
    let up_url = up.serve().await;
    let st = broker(&up_url, hook(WardryxMode::Enforce, &pdp_url, REUSE));
    let ctx = as_agent(AGENT);

    let during = list(&st, &ctx).await;
    pdp.answer_filter_with(0);
    let after = list(&st, &ctx).await;

    assert_eq!(
        listed(&during),
        ["lookup", "wire_transfer"],
        "the outage hides nothing: {during}"
    );
    assert_eq!(
        listed(&after),
        ["lookup"],
        "the plane that answers again narrows the next listing: {after}"
    );
    assert_eq!(
        pdp.filter_calls(),
        2,
        "a failure is asked again and never served from the cache"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_wardryx_without_the_route_is_named_once_and_the_list_stays_whole() {
    let pdp = Pdp::with(AGENT, denies_wire_transfer());
    pdp.answer_filter_with(404);
    let pdp_url = pdp.serve().await;
    let up = Upstream::new(listing(&["lookup", "wire_transfer"]));
    let up_url = up.serve().await;
    let st = broker(&up_url, hook(WardryxMode::Enforce, &pdp_url, NO_REUSE));
    let log = LogCapture::new();
    let ctx = as_agent(AGENT);

    let first = list_logged(&st, &ctx, &log).await;
    let second = list_logged(&st, &ctx, &log).await;

    for answer in [first, second] {
        assert_eq!(
            listed(&answer),
            ["lookup", "wire_transfer"],
            "a wardryx without the route hides nothing: {answer}"
        );
    }
    let named = log.text().matches("no /v1/filter-tools route").count();
    assert_eq!(
        named, 1,
        "a wardryx that predates the route is named once, not once per listing"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_repeated_listing_is_answered_from_the_cache() {
    let pdp = Pdp::with(AGENT, denies_wire_transfer());
    let pdp_url = pdp.serve().await;
    let up = Upstream::new(listing(&["lookup", "wire_transfer"]));
    let up_url = up.serve().await;
    let st = broker(&up_url, hook(WardryxMode::Enforce, &pdp_url, REUSE));
    let ctx = as_agent(AGENT);

    let first = list(&st, &ctx).await;
    let second = list(&st, &ctx).await;

    assert_eq!(listed(&first), ["lookup"], "{first}");
    assert_eq!(
        listed(&second),
        ["lookup"],
        "the cached answer narrows the second listing too: {second}"
    );
    assert_eq!(
        pdp.filter_calls(),
        1,
        "the second listing is answered from the cache"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_cache_never_answers_for_another_agent() {
    let pdp = Pdp::with(AGENT, denies_wire_transfer());
    let pdp_url = pdp.serve().await;
    let up = Upstream::new(listing(&["lookup", "wire_transfer"]));
    let up_url = up.serve().await;
    let st = broker(&up_url, hook(WardryxMode::Enforce, &pdp_url, REUSE));

    let mine = list(&st, &as_agent(AGENT)).await;
    let theirs = list(&st, &as_agent(OTHER)).await;

    assert_eq!(listed(&mine), ["lookup"], "{mine}");
    assert_eq!(
        listed(&theirs),
        ["lookup", "wire_transfer"],
        "another agent is answered by its own policy, not by the cache: {theirs}"
    );
    assert_eq!(
        pdp.filter_calls(),
        2,
        "each agent's listing is its own question"
    );
}

/// A small deterministic generator, so a failing seed can be run again.
struct Seeded(u64);

impl Seeded {
    fn step(&mut self) -> u64 {
        self.0 ^= self.0 >> 12;
        self.0 ^= self.0 << 25;
        self.0 ^= self.0 >> 27;
        self.0.wrapping_mul(0x2545_F491_4F6C_DD1D)
    }

    fn below(&mut self, n: u64) -> u64 {
        self.step() % n
    }
}

/// One element of a generated `tools` array: a tool with a name from a small
/// pool, so names repeat, or something an upstream should never send.
fn element(rng: &mut Seeded) -> Value {
    const NAMES: [&str; 6] = ["lookup", "deny_a", "out_c", "later_d", "quiet_e", ""];
    let name = NAMES[rng.below(NAMES.len() as u64) as usize];
    match rng.below(8) {
        0 => json!(name),
        1 => json!({ "name": 7 }),
        2 => json!({ "name": null, "description": name }),
        3 => json!({ "description": "no name at all" }),
        4 => json!([name]),
        5 => json!({ "name": [name] }),
        _ => json!({ "name": name, "inputSchema": { "type": "object" } }),
    }
}

/// What the broker should answer for `tools`: every element but a tool whose
/// string name the stub refuses under `deny_tool` or `allow_tool`, in order.
fn expected(tools: &[Value]) -> Vec<Value> {
    let outright = |n: &str| n.starts_with("deny_") || n.starts_with("out_");
    tools
        .iter()
        .filter(|t| !t["name"].as_str().is_some_and(outright))
        .cloned()
        .collect()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn hostile_listings_never_panic_and_only_tools_refused_outright_leave() {
    let policy = Policy {
        deny_prefix: Some("deny_"),
        outside_prefix: Some("out_"),
        unknown_prefix: Some("later_"),
        no_rule_prefix: Some("quiet_"),
        ..Default::default()
    };
    let pdp = Pdp::with(AGENT, policy);
    let pdp_url = pdp.serve().await;
    let up = Upstream::new(Value::Null);
    let up_url = up.serve().await;
    let st = broker(&up_url, hook(WardryxMode::Enforce, &pdp_url, NO_REUSE));
    let ctx = as_agent(AGENT);

    for seed in 0..120u64 {
        let mut rng = Seeded(0x9E37_79B9_7F4A_7C15 ^ seed);
        let count = rng.below(10);
        let mut tools: Vec<Value> = (0..count).map(|_| element(&mut rng)).collect();
        // One tool under each rule that hides it, so every seed leaves both out.
        for name in ["deny_z", "out_z"] {
            let at = rng.below(tools.len() as u64 + 1) as usize;
            tools.insert(at, json!({ "name": name }));
        }
        let sent = json!({ "jsonrpc": "2.0", "result": { "tools": tools.clone() } });
        up.answer_list_with(sent);

        let answer = list(&st, &ctx).await;

        assert_eq!(
            answer["result"]["tools"],
            Value::Array(expected(&tools)),
            "seed {seed}: only a tool refused outright leaves the listing"
        );
    }

    // An answer with no tools array to narrow goes back exactly as it came.
    let shapes = [
        json!({ "jsonrpc": "2.0" }),
        json!({ "jsonrpc": "2.0", "result": null }),
        json!({ "jsonrpc": "2.0", "result": "deny_z" }),
        json!({ "jsonrpc": "2.0", "result": { "tools": { "name": "deny_z" } } }),
        json!({ "jsonrpc": "2.0", "result": { "tools": "deny_z" } }),
        json!({ "jsonrpc": "2.0", "error": { "code": -1, "message": "deny_z" } }),
        json!("deny_z"),
        json!(["deny_z"]),
    ];
    for sent in shapes {
        up.answer_list_with(sent.clone());
        let answer = list(&st, &ctx).await;
        assert_eq!(
            answer,
            with_id(sent),
            "a listing with no tools array goes back as it came"
        );
    }
}
