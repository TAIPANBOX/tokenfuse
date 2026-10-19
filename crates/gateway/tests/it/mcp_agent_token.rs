//! The agent-token door at the MCP broker (WAVE1-DESIGN 1.5): judged before
//! every other door and alone, the agent and the run principal from the token,
//! and the token relayed to the taint gateway beside the broker's own key.

use std::sync::{Arc, Mutex};
use std::time::Duration;

use axum::extract::State;
use axum::http::HeaderMap;
use axum::routing::post;
use axum::{Json, Router};
use serde_json::{json, Value};
use std::collections::BTreeSet;
use tokenfuse_delegation::testing::{agent_token, cfg, proof_for, Key, AGENT};

use tokenfuse_gateway::agenttoken::{AgentTokens, Mode, BROKER_STATIC_KEYS_VAR};
use tokenfuse_gateway::chainproof::Proving;
use tokenfuse_gateway::clientkeys::{ClientKeys, CLIENT_KEY_HEADER};
use tokenfuse_gateway::mcpbroker::{app, BrokerState, ScanMode};
use tokenfuse_gateway::mcpdoor::PROOF_HEADER;
use tokenfuse_gateway::wardryx::{Wardryx, WardryxMode};

/// The origin the broker is told it is reached at; a proof names it plus `/`.
const BROKER_ORIGIN: &str = "https://mcp.acme.example";

async fn echo(Json(req): Json<Value>) -> Json<Value> {
    let id = req.get("id").cloned().unwrap_or(Value::Null);
    Json(json!({"jsonrpc": "2.0", "id": id, "result": {"ok": true}}))
}

#[derive(Clone, Default)]
struct Seen {
    bodies: Arc<Mutex<Vec<Value>>>,
    headers: Arc<Mutex<Vec<HeaderMap>>>,
}

async fn decide(State(seen): State<Seen>, Json(body): Json<Value>) -> Json<Value> {
    seen.bodies.lock().unwrap().push(body);
    Json(json!({"decision": "allow", "policy_version": "v1"}))
}

async fn taint_check(State(seen): State<Seen>, headers: HeaderMap) -> Json<Value> {
    seen.headers.lock().unwrap().push(headers);
    Json(json!({"decision": "allow", "governed": true}))
}

async fn spawn(router: Router) -> String {
    let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = l.local_addr().unwrap();
    tokio::spawn(async move {
        let _ = axum::serve(l, router).await;
    });
    format!("http://{addr}")
}

struct Broker {
    issuer: Key,
    holder: Key,
    tokens: Mode,
    keys: &'static str,
    wardryx: Option<String>,
    taint_gateway: Option<String>,
    taint_gateway_key: Option<String>,
    /// `TOKENFUSE_MCP_AGENT_TOKENS_STATIC_KEYS`: the key ids admitted under require.
    listed: Vec<&'static str>,
}

impl Broker {
    fn new(tokens: Mode) -> Self {
        Broker {
            issuer: Key::new(),
            holder: Key::new(),
            tokens,
            keys: "",
            wardryx: None,
            taint_gateway: None,
            taint_gateway_key: None,
            listed: Vec::new(),
        }
    }

    async fn serve(&self, upstream: String) -> String {
        let wardryx = match &self.wardryx {
            Some(url) => Wardryx::new(
                WardryxMode::Enforce,
                tokenfuse_gateway::wardryx::FailMode::Open,
                url.clone(),
                None,
                Duration::from_millis(500),
                Duration::from_secs(2),
            ),
            None => Wardryx::disabled(),
        };
        let state = Arc::new(BrokerState {
            chain_proof: Some(Arc::new(Proving {
                cfg: cfg(&self.issuer),
                origins: vec![BROKER_ORIGIN.to_string()],
            })),
            revocations: None,
            identity_strict: tokenfuse_gateway::identitymap::StrictMode::Off,
            upstream,
            named_upstreams: Default::default(),
            vault: tokenfuse_core::SecretVault::new(),
            scan: ScanMode::Off,
            dlp: tokenfuse_core::DlpMode::Off,
            dlp_pii: tokenfuse_core::DlpMode::Off,
            lock: None,
            drifted: Default::default(),
            wardryx: Arc::new(wardryx),
            keys: ClientKeys::from_spec(self.keys).expect("a usable key spec"),
            clients: Default::default(),
            require_proof: false,
            client: reqwest::Client::new(),
            events: Arc::new(tokenfuse_core::agent_event::Exporter::disabled()),
            taint_gateway: self.taint_gateway.clone(),
            taint_failclosed: true,
            xaa: None,
            agent_tokens: Some(Arc::new(AgentTokens::with_static_keys(
                self.tokens,
                self.listed
                    .iter()
                    .map(|s| s.to_string())
                    .collect::<BTreeSet<_>>(),
            ))),
            taint_gateway_key: self.taint_gateway_key.clone(),
        });
        let url = spawn(app(state)).await;
        tokio::time::sleep(Duration::from_millis(100)).await;
        url
    }

    /// The agent's token and a proof that names it, for the broker's `/`.
    fn token_headers(&self, jti: &str) -> (String, Vec<(&'static str, String)>) {
        let now = tokenfuse_gateway::sink::now_millis() / 1000;
        let tok = agent_token(&self.issuer, &self.holder, now, json!({}));
        let pf = proof_for(
            &self.holder,
            now,
            "POST",
            &format!("{BROKER_ORIGIN}/"),
            jti,
            &tok,
        );
        (
            tok.clone(),
            vec![("authorization", format!("DPoP {tok}")), (PROOF_HEADER, pf)],
        )
    }
}

async fn tools_call(broker_url: &str, headers: &[(&'static str, String)]) -> reqwest::Response {
    let mut req = reqwest::Client::new().post(broker_url).json(&json!({
        "jsonrpc": "2.0", "id": 7, "method": "tools/call",
        "params": {"name": "gh_api", "arguments": {}}
    }));
    for (k, v) in headers {
        req = req.header(*k, v.as_str());
    }
    req.send().await.unwrap()
}

/// The token admits the call, the PDP is asked about the token's agent, told
/// the door was an agent token and that possession was proved.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_broker_admits_an_agent_token_and_tells_the_pdp_who_and_how() {
    let seen = Seen::default();
    let pdp = spawn(
        Router::new()
            .route("/v1/decide", post(decide))
            .with_state(seen.clone()),
    )
    .await;
    let upstream = spawn(Router::new().route("/", post(echo))).await;
    let mut b = Broker::new(Mode::Accept);
    b.wardryx = Some(pdp);
    let url = b.serve(upstream).await;
    let (_, h) = b.token_headers("pm-1");
    let resp = tools_call(&url, &h).await;
    assert_eq!(resp.status(), 200);
    let body: Value = resp.json().await.unwrap();
    assert_eq!(body["result"]["ok"], json!(true), "{body}");
    let asked = seen
        .bodies
        .lock()
        .unwrap()
        .last()
        .cloned()
        .expect("the PDP was asked");
    assert_eq!(asked["agent_id"], AGENT, "{asked}");
    assert_eq!(asked["identity_source"], "agent-token", "{asked}");
    assert_eq!(asked["attestation_method"], "dpop-key", "{asked}");
}

/// A header naming another agent than the token proves is refused, with
/// strict identity off.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_broker_refuses_a_header_naming_another_agent_than_its_token() {
    let upstream = spawn(Router::new().route("/", post(echo))).await;
    let b = Broker::new(Mode::Accept);
    let url = b.serve(upstream).await;
    let (_, mut h) = b.token_headers("pm-2");
    h.push(("x-fuse-agent-id", "agent://acme/other".to_string()));
    let resp = tools_call(&url, &h).await;
    assert_eq!(resp.status(), 403);
    let body: Value = resp.json().await.unwrap();
    assert_eq!(
        body["error"]["reason"], "agent_id_contradicts_token",
        "{body}"
    );
}

/// A token and a client key on one call: refused, never a fall-back.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_broker_refuses_an_agent_token_beside_a_client_key() {
    let upstream = spawn(Router::new().route("/", post(echo))).await;
    let mut b = Broker::new(Mode::Accept);
    b.keys = "sk-b:bkey";
    let url = b.serve(upstream).await;
    let (_, mut h) = b.token_headers("pm-3");
    h.push((CLIENT_KEY_HEADER, "sk-b".to_string()));
    let resp = tools_call(&url, &h).await;
    assert_eq!(resp.status(), 401);
}

/// `require` closes the broker's static key door and keeps the token door.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn require_refuses_the_brokers_static_key_and_admits_a_token() {
    let upstream = spawn(Router::new().route("/", post(echo))).await;
    let mut b = Broker::new(Mode::Require);
    b.keys = "sk-b:bkey";
    let url = b.serve(upstream).await;
    let resp = tools_call(&url, &[(CLIENT_KEY_HEADER, "sk-b".to_string())]).await;
    assert_eq!(resp.status(), 401, "a static key under require");
    let (_, h) = b.token_headers("pm-4");
    let resp = tools_call(&url, &h).await;
    assert_eq!(resp.status(), 200, "a token under require");
}

/// One proof, one call: the same proof again is refused at the broker.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_broker_refuses_a_replayed_agent_token_proof() {
    let upstream = spawn(Router::new().route("/", post(echo))).await;
    let b = Broker::new(Mode::Accept);
    let url = b.serve(upstream).await;
    let (_, h) = b.token_headers("pm-5");
    assert_eq!(tools_call(&url, &h).await.status(), 200);
    assert_eq!(tools_call(&url, &h).await.status(), 401);
}

/// The taint gateway is asked with the broker's own key and the caller's
/// token, so it answers about the token's runs and no others.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_broker_relays_an_agent_token_to_the_taint_gateway_with_its_own_key() {
    let seen = Seen::default();
    let gateway = spawn(
        Router::new()
            .route("/v1/fuse/check-tool-call", post(taint_check))
            .with_state(seen.clone()),
    )
    .await;
    let upstream = spawn(Router::new().route("/", post(echo))).await;
    let mut b = Broker::new(Mode::Accept);
    b.taint_gateway = Some(gateway);
    b.taint_gateway_key = Some("sk-broker".to_string());
    let url = b.serve(upstream).await;
    let (tok, mut h) = b.token_headers("pm-6");
    h.push(("x-fuse-run-id", "r-relay-1".to_string()));
    let resp = tools_call(&url, &h).await;
    assert_eq!(resp.status(), 200);
    let asked = seen
        .headers
        .lock()
        .unwrap()
        .last()
        .cloned()
        .expect("the taint gateway was asked");
    assert_eq!(
        asked.get(CLIENT_KEY_HEADER).and_then(|v| v.to_str().ok()),
        Some("sk-broker")
    );
    assert_eq!(
        asked.get("authorization").and_then(|v| v.to_str().ok()),
        Some(format!("DPoP {tok}").as_str())
    );
}

/// Under `require`, a static key the broker's list names is admitted as it is
/// under `accept` (invariant 139).
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn require_admits_an_allow_listed_brokers_static_key() {
    let upstream = spawn(Router::new().route("/", post(echo))).await;
    let mut b = Broker::new(Mode::Require);
    b.keys = "sk-b:bkey";
    b.listed = vec!["bkey"];
    let url = b.serve(upstream).await;
    let resp = tools_call(&url, &[(CLIENT_KEY_HEADER, "sk-b".to_string())]).await;
    assert_eq!(resp.status(), 200, "a listed static key under require");
}

/// An unlisted static key at the broker is refused, and the body names the
/// broker's list variable, the same body an unknown key gets.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn require_refuses_an_unlisted_brokers_static_key_naming_its_variable() {
    let upstream = spawn(Router::new().route("/", post(echo))).await;
    let mut b = Broker::new(Mode::Require);
    b.keys = "sk-b:bkey";
    b.listed = vec![];
    let url = b.serve(upstream).await;
    let resp = tools_call(&url, &[(CLIENT_KEY_HEADER, "sk-b".to_string())]).await;
    assert_eq!(resp.status(), 401);
    let body: Value = resp.json().await.unwrap();
    assert_eq!(body["error"]["type"], "agent_token_required", "{body}");
    let reason = body["error"]["reason"].as_str().unwrap_or_default();
    assert!(
        reason.contains(BROKER_STATIC_KEYS_VAR),
        "the body names the variable: {reason}"
    );
}

/// The broker's policy question carries the token that admitted the call.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_broker_sends_the_agent_token_to_the_pdp() {
    let seen = Seen::default();
    let pdp = spawn(
        Router::new()
            .route("/v1/decide", post(decide))
            .with_state(seen.clone()),
    )
    .await;
    let upstream = spawn(Router::new().route("/", post(echo))).await;
    let mut b = Broker::new(Mode::Accept);
    b.wardryx = Some(pdp);
    let url = b.serve(upstream).await;
    let (tok, h) = b.token_headers("pm-7");
    let proof = h[1].1.clone();
    let resp = tools_call(&url, &h).await;
    assert_eq!(resp.status(), 200);
    let asked = seen
        .bodies
        .lock()
        .unwrap()
        .last()
        .cloned()
        .expect("the PDP was asked");
    assert_eq!(asked["agent_token"], tok, "{asked}");
    assert_eq!(asked["agent_dpop_proof"], proof, "{asked}");
}

/// A static-key call at the broker sends the policy plane no token.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_broker_sends_no_agent_token_for_a_static_key_call() {
    let seen = Seen::default();
    let pdp = spawn(
        Router::new()
            .route("/v1/decide", post(decide))
            .with_state(seen.clone()),
    )
    .await;
    let upstream = spawn(Router::new().route("/", post(echo))).await;
    let mut b = Broker::new(Mode::Accept);
    b.keys = "sk-b:bkey";
    b.wardryx = Some(pdp);
    let url = b.serve(upstream).await;
    let resp = tools_call(
        &url,
        &[
            (CLIENT_KEY_HEADER, "sk-b".to_string()),
            ("x-fuse-agent-id", "agent://acme/keyed".to_string()),
        ],
    )
    .await;
    assert_eq!(resp.status(), 200);
    let asked = seen
        .bodies
        .lock()
        .unwrap()
        .last()
        .cloned()
        .expect("the PDP was asked");
    assert!(asked.get("agent_token").is_none(), "{asked}");
    assert!(asked.get("agent_dpop_proof").is_none(), "{asked}");
}
