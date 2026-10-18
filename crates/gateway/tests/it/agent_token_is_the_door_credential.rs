//! An agent's own token is the door credential (WAVE1-DESIGN 1.5), at the LLM
//! door, the OpenAI door and the tool-call check, through the real router.
//!
//! The token is the one vouchryx's `client_credentials` grant mints
//! (`tokenfuse_delegation::testing::agent_token`, header `typ: at+jwt`), sent
//! as `Authorization: DPoP` with a proof that names it (`ath`).

use std::sync::{Arc, Mutex, RwLock};
use std::time::Duration;

use axum::body::Body;
use axum::extract::State;
use axum::http::{HeaderMap, Request, StatusCode};
use axum::routing::post;
use axum::{Json, Router};
use http_body_util::BodyExt;
use serde_json::{json, Value};
use tokenfuse_core::taint::FirewallMode;
use tokenfuse_delegation::revocations::{FailMode, Revocation, Revocations, Snapshot};
use tokenfuse_delegation::testing::{
    agent_token, cfg, proof_at, proof_for, token, Key, AGENT, AGENT_UNIT,
};
use tokenfuse_gateway::agenttoken::{AgentTokens, Mode};
use tokenfuse_gateway::chainproof::Proving;
use tokenfuse_gateway::clientkeys::{ClientKeys, CLIENT_KEY_HEADER};
use tokenfuse_gateway::firewall::FirewallConfig;
use tokenfuse_gateway::identitymap::{IdentityMap, StrictMode};
use tokenfuse_gateway::mcpdoor::PROOF_HEADER;
use tokenfuse_gateway::sink::{CallRecord, EventSink};
use tokenfuse_gateway::state::AppState;
use tokenfuse_gateway::unitledger::UnitLedger;
use tokenfuse_gateway::wardryx::{Wardryx, WardryxMode};
use tokenfuse_gateway::wire::Wire;
use tower::ServiceExt;

use crate::common;

/// The origin every proof here is signed for, and what the door is told it
/// is reached at; equal to the fixture's audience.
const ORIGIN: &str = "https://tokenfuse.acme.example";
/// Two static keys: an ordinary caller, and the MCP broker's own.
const KEYS: &str = "sk-a:key-a,sk-broker:broker";
const MESSAGES: &str = "/v1/messages";
const CHAT: &str = "/v1/chat/completions";
const CHECK: &str = "/v1/fuse/check-tool-call";
const BODY: &str =
    r#"{"model":"test-model","max_tokens":16,"messages":[{"role":"user","content":"hi"}]}"#;

#[derive(Clone, Default)]
struct Rows(Arc<Mutex<Vec<CallRecord>>>);

impl EventSink for Rows {
    fn record(&self, rec: CallRecord) {
        self.0.lock().unwrap().push(rec);
    }
    fn flush(&self) {}
}

impl Rows {
    fn last(&self) -> CallRecord {
        self.0.lock().unwrap().last().cloned().expect("a trace row")
    }
}

struct Gate {
    st: AppState,
    issuer: Key,
    holder: Key,
    rows: Rows,
}

/// A gateway with the delegation door on against a real issuer, the agent
/// token door in `mode` (`None` is off), and `keys` as its client keys.
fn gate(wire: Wire, mode: Option<Mode>, keys: Option<&str>) -> Gate {
    let (issuer, holder) = (Key::new(), Key::new());
    let rows = Rows::default();
    let mut st = common::app_with_wire(wire)
        .with_chain_proof(
            Some(Arc::new(Proving {
                cfg: cfg(&issuer),
                origin: ORIGIN.to_string(),
            })),
            None,
        )
        .with_agent_tokens(mode.map(|m| Arc::new(AgentTokens::new(m))))
        .with_sink(Arc::new(rows.clone()));
    if let Some(spec) = keys {
        st = st.with_client_keys(Arc::new(
            ClientKeys::from_spec(spec).expect("a usable key spec"),
        ));
    }
    Gate {
        st,
        issuer,
        holder,
        rows,
    }
}

fn now() -> i64 {
    tokenfuse_gateway::sink::now_millis() / 1000
}

/// The agent's token and a proof for `path` that names it.
fn with_token(g: &Gate, path: &str, jti: &str) -> Vec<(&'static str, String)> {
    let at = now();
    let tok = agent_token(&g.issuer, &g.holder, at, json!({}));
    let pf = proof_for(&g.holder, at, "POST", &format!("{ORIGIN}{path}"), jti, &tok);
    vec![("authorization", format!("DPoP {tok}")), (PROOF_HEADER, pf)]
}

fn call(path: &str, run: &str, headers: &[(&'static str, String)]) -> Request<Body> {
    let mut b = Request::post(path)
        .header("content-type", "application/json")
        .header("x-fuse-run-id", run);
    for (k, v) in headers {
        b = b.header(*k, v.as_str());
    }
    b.body(Body::from(BODY)).unwrap()
}

fn check(run: &str, headers: &[(&'static str, String)]) -> Request<Body> {
    let mut b = Request::post(CHECK).header("content-type", "application/json");
    for (k, v) in headers {
        b = b.header(*k, v.as_str());
    }
    b.body(Body::from(
        json!({"run_id": run, "tool": "run_shell"}).to_string(),
    ))
    .unwrap()
}

async fn send(st: &AppState, req: Request<Body>) -> (StatusCode, HeaderMap, Value) {
    let resp = tokenfuse_gateway::app(st.clone())
        .oneshot(req)
        .await
        .unwrap();
    let status = resp.status();
    let headers = resp.headers().clone();
    let bytes = resp.into_body().collect().await.unwrap().to_bytes();
    let body = serde_json::from_slice(&bytes).unwrap_or(Value::Null);
    (status, headers, body)
}

fn identity(headers: &HeaderMap) -> String {
    headers
        .get("x-fuse-identity")
        .and_then(|v| v.to_str().ok())
        .unwrap_or_default()
        .to_string()
}

fn key(secret: &str) -> (&'static str, String) {
    (CLIENT_KEY_HEADER, secret.to_string())
}

/// THE ONE THIS DOOR IS FOR. No client key, an agent token: admitted, and the
/// record names the agent and the unit the token carries, under the token's
/// principal.
#[tokio::test]
async fn an_agent_token_is_admitted_and_the_record_names_its_agent_and_unit() {
    let g = gate(Wire::Anthropic, Some(Mode::Accept), Some(KEYS));
    let (status, _, body) = send(
        &g.st,
        call(MESSAGES, "r-tok-1", &with_token(&g, MESSAGES, "p-1")),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let row = g.rows.last();
    assert_eq!(row.key_id, format!("tok:{AGENT}"));
    assert_eq!(row.agent_id, AGENT);
    assert_eq!(row.unit, AGENT_UNIT);
}

/// The agent comes from the token, and a header naming another is refused
/// even with strict identity off: a token is not a claim to warn about.
#[tokio::test]
async fn a_header_naming_another_agent_beside_its_token_is_refused_whatever_the_strict_mode() {
    let g = gate(Wire::Anthropic, Some(Mode::Accept), None);
    assert_eq!(g.st.identity_strict, StrictMode::Off);
    let mut h = with_token(&g, MESSAGES, "p-2");
    h.push(("x-fuse-agent-id", "agent://acme/other".to_string()));
    let (status, headers, body) = send(&g.st, call(MESSAGES, "r-tok-2", &h)).await;
    assert_eq!(status, StatusCode::FORBIDDEN, "{body}");
    assert_eq!(identity(&headers), "blocked=agent_id_contradicts_token");
}

/// Two credentials on one request is confusion or a probe, and is refused.
#[tokio::test]
async fn an_agent_token_beside_a_client_key_is_refused() {
    let g = gate(Wire::Anthropic, Some(Mode::Accept), Some(KEYS));
    let mut h = with_token(&g, MESSAGES, "p-3");
    h.push(key("sk-a"));
    let (status, _, body) = send(&g.st, call(MESSAGES, "r-tok-3", &h)).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED, "{body}");
    assert_eq!(body["error"]["type"], "agent_token_refused");
}

/// A proof is single-use: the same token and proof a second time is refused.
#[tokio::test]
async fn a_replayed_agent_token_proof_is_refused_the_second_time() {
    let g = gate(Wire::Anthropic, Some(Mode::Accept), None);
    let h = with_token(&g, MESSAGES, "p-4");
    let (first, _, body) = send(&g.st, call(MESSAGES, "r-tok-4", &h)).await;
    assert_eq!(first, StatusCode::OK, "{body}");
    let (second, _, body) = send(&g.st, call(MESSAGES, "r-tok-4", &h)).await;
    assert_eq!(second, StatusCode::UNAUTHORIZED, "{body}");
    assert_eq!(body["error"]["type"], "agent_token_refused");
}

/// RFC 9449 4.2 at the door: a proof that does not name the token it came
/// with is refused.
#[tokio::test]
async fn a_proof_that_does_not_name_the_agent_token_is_refused_at_the_door() {
    let g = gate(Wire::Anthropic, Some(Mode::Accept), None);
    let at = now();
    let tok = agent_token(&g.issuer, &g.holder, at, json!({}));
    let pf = proof_at(&g.holder, at, "POST", &format!("{ORIGIN}{MESSAGES}"), "p-5");
    let h = [("authorization", format!("DPoP {tok}")), (PROOF_HEADER, pf)];
    let (status, _, body) = send(&g.st, call(MESSAGES, "r-tok-5", &h)).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED, "{body}");
    assert_eq!(body["error"]["type"], "agent_token_refused");
}

/// The revocation list stops an agent at this door within one poll.
#[tokio::test]
async fn a_revoked_agent_is_refused_at_the_door() {
    let mut g = gate(Wire::Anthropic, Some(Mode::Accept), None);
    let at = now();
    let mut cache = Revocations::new(60, FailMode::Closed);
    let _ = cache.install(
        Snapshot {
            revocations: vec![Revocation {
                subject: AGENT.to_string(),
                issued_before: at + 5,
                ..Default::default()
            }],
            as_of: at,
        },
        at,
    );
    g.st.revocations = Some(Arc::new(RwLock::new(cache)));
    let (status, _, body) = send(
        &g.st,
        call(MESSAGES, "r-tok-6", &with_token(&g, MESSAGES, "p-6")),
    )
    .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED, "{body}");
    assert_eq!(body["error"]["type"], "agent_token_refused");
}

/// `require` refuses a static key and admits a token.
#[tokio::test]
async fn require_refuses_a_static_key_and_admits_an_agent_token() {
    let g = gate(Wire::Anthropic, Some(Mode::Require), Some(KEYS));
    let (status, headers, body) = send(&g.st, call(MESSAGES, "r-req-1", &[key("sk-a")])).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED, "{body}");
    assert_eq!(body["error"]["type"], "agent_token_required");
    assert!(
        headers
            .get("www-authenticate")
            .and_then(|v| v.to_str().ok())
            .is_some_and(|v| v.starts_with("DPoP")),
        "the refusal names the scheme the caller needs"
    );
    let (status, _, body) = send(
        &g.st,
        call(MESSAGES, "r-req-2", &with_token(&g, MESSAGES, "p-7")),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
}

/// `accept` keeps every static key working beside tokens, as two principals.
#[tokio::test]
async fn accept_keeps_static_keys_working_beside_agent_tokens() {
    let g = gate(Wire::Anthropic, Some(Mode::Accept), Some(KEYS));
    let (status, _, body) = send(&g.st, call(MESSAGES, "r-acc-key", &[key("sk-a")])).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(g.rows.last().key_id, "key-a");
    let (status, _, body) = send(
        &g.st,
        call(MESSAGES, "r-acc-tok", &with_token(&g, MESSAGES, "p-8")),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(g.rows.last().key_id, format!("tok:{AGENT}"));
}

/// With the door off an agent token opens nothing: the client key door
/// answers exactly as before.
#[tokio::test]
async fn with_agent_tokens_off_an_agent_token_is_not_a_door_credential() {
    let g = gate(Wire::Anthropic, None, Some(KEYS));
    let (status, _, body) = send(
        &g.st,
        call(MESSAGES, "r-off-1", &with_token(&g, MESSAGES, "p-9")),
    )
    .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED, "{body}");
    assert_eq!(body["error"]["type"], "unauthorized");
}

/// The run belongs to the token's principal: a static key naming it is
/// refused (invariant 120 with a token principal).
#[tokio::test]
async fn a_run_an_agent_token_opened_is_refused_to_a_static_key() {
    let g = gate(Wire::Anthropic, Some(Mode::Accept), Some(KEYS));
    let (status, _, body) = send(
        &g.st,
        call(MESSAGES, "r-own", &with_token(&g, MESSAGES, "p-10")),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let (status, headers, body) = send(&g.st, call(MESSAGES, "r-own", &[key("sk-a")])).await;
    assert_eq!(status, StatusCode::FORBIDDEN, "{body}");
    assert_eq!(identity(&headers), "blocked=run_owned_elsewhere");
}

/// The OpenAI door takes the token with a proof for its own path.
#[tokio::test]
async fn the_openai_door_admits_an_agent_token_proved_for_its_own_path() {
    let g = gate(Wire::OpenAi, Some(Mode::Accept), Some(KEYS));
    let (status, _, body) = send(&g.st, call(CHAT, "r-oai-1", &with_token(&g, CHAT, "p-11"))).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(g.rows.last().key_id, format!("tok:{AGENT}"));
}

/// The unit is the token's; an identity map that binds the agent to another
/// unit contradicts it, and the call is refused.
#[tokio::test]
async fn an_identity_map_binding_the_agent_to_another_unit_is_refused() {
    let g = gate(Wire::Anthropic, Some(Mode::Accept), Some(KEYS));
    let path =
        std::env::temp_dir().join(format!("tf-agent-token-it-map-{}.json", std::process::id()));
    std::fs::write(
        &path,
        r#"{"units":[{"id":"finance"},{"id":"ops"}],
            "keys":[{"key_id":"key-a","unit":"finance","agents":["agent://acme/*"]}]}"#,
    )
    .unwrap();
    let map = IdentityMap::from_path(&path).expect("the map loads");
    let _ = std::fs::remove_file(&path);
    let st = g.st.clone().with_identity(
        Arc::new(map),
        StrictMode::Off,
        Arc::new(UnitLedger::default()),
    );
    let (status, headers, body) = send(
        &st,
        call(MESSAGES, "r-map-1", &with_token(&g, MESSAGES, "p-12")),
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN, "{body}");
    assert_eq!(identity(&headers), "blocked=unit_contradicts_map");
}

/// With the door on, a delegation proof at the chain door is single-use too.
#[tokio::test]
async fn with_agent_tokens_on_a_delegation_proof_is_single_use_too() {
    let g = gate(Wire::Anthropic, Some(Mode::Accept), Some(KEYS));
    let at = now();
    let tok = token(&g.issuer, &g.holder, at, json!({}));
    let pf = proof_at(
        &g.holder,
        at,
        "POST",
        &format!("{ORIGIN}{MESSAGES}"),
        "pd-1",
    );
    let h = [
        key("sk-a"),
        ("authorization", format!("DPoP {tok}")),
        (PROOF_HEADER, pf),
    ];
    let (first, _, body) = send(&g.st, call(MESSAGES, "r-chain-1", &h)).await;
    assert_eq!(first, StatusCode::OK, "{body}");
    let (second, _, body) = send(&g.st, call(MESSAGES, "r-chain-1", &h)).await;
    assert_eq!(second, StatusCode::UNAUTHORIZED, "{body}");
    assert_eq!(body["error"]["type"], "delegation_refused");
}

fn with_firewall(g: Gate) -> Gate {
    Gate {
        st: g
            .st
            .with_firewall(Arc::new(FirewallConfig::defaults(FirewallMode::Enforce))),
        ..g
    }
}

/// The tool-call check takes the token with its own proof, and answers the
/// agent about its own run.
#[tokio::test]
async fn the_tool_check_answers_an_agent_token_about_its_own_run() {
    let g = with_firewall(gate(Wire::Anthropic, Some(Mode::Accept), Some(KEYS)));
    let (status, _, body) = send(
        &g.st,
        call(MESSAGES, "r-chk-1", &with_token(&g, MESSAGES, "p-13")),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let (status, _, body) = send(&g.st, check("r-chk-1", &with_token(&g, CHECK, "p-14"))).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["decision"], "allow", "its own run: {body}");
    let (status, _, body) = send(&g.st, check("r-chk-1", &[key("sk-a")])).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["decision"], "deny", "another principal's run: {body}");
    assert!(body.get("carrying").is_none(), "{body}");
}

/// The MCP broker relays the token beside its own key; the check answers it
/// about the token's runs, the broker's key alone about nothing, and any
/// other key beside a token is refused.
#[tokio::test]
async fn the_tool_check_answers_a_relayed_agent_token_about_its_runs_only() {
    let g = with_firewall(gate(Wire::Anthropic, Some(Mode::Accept), Some(KEYS)));
    let (status, _, body) = send(
        &g.st,
        call(MESSAGES, "r-rel-1", &with_token(&g, MESSAGES, "p-15")),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let tok = agent_token(&g.issuer, &g.holder, now(), json!({}));
    let relayed = [key("sk-broker"), ("authorization", format!("DPoP {tok}"))];
    let (status, _, body) = send(&g.st, check("r-rel-1", &relayed)).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(
        body["decision"], "allow",
        "the relayed token's own run: {body}"
    );
    let (_, _, body) = send(&g.st, check("r-rel-1", &[key("sk-broker")])).await;
    assert_eq!(
        body["decision"], "deny",
        "the broker's key alone owns nothing: {body}"
    );
    let beside_another = [key("sk-a"), ("authorization", format!("DPoP {tok}"))];
    let (status, _, body) = send(&g.st, check("r-rel-1", &beside_another)).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED, "{body}");
}

#[derive(Clone, Default)]
struct Pdp {
    asked: Arc<Mutex<Vec<Value>>>,
}

async fn decide(State(pdp): State<Pdp>, Json(body): Json<Value>) -> Json<Value> {
    pdp.asked.lock().unwrap().push(body);
    Json(json!({"decision": "allow", "policy_version": "v1"}))
}

async fn spawn_pdp(pdp: Pdp) -> String {
    let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = l.local_addr().unwrap();
    let router = Router::new()
        .route("/v1/decide", post(decide))
        .with_state(pdp);
    tokio::spawn(async move {
        let _ = axum::serve(l, router).await;
    });
    format!("http://{addr}")
}

fn with_pdp(g: Gate, url: &str) -> Gate {
    Gate {
        st: g.st.with_wardryx(Arc::new(Wardryx::new(
            WardryxMode::Enforce,
            tokenfuse_gateway::wardryx::FailMode::Open,
            url.to_string(),
            None,
            Duration::from_millis(500),
            Duration::from_secs(2),
        ))),
        ..g
    }
}

/// The policy plane is told how the door knew the agent, and the token's
/// proof of possession is what attests it.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_policy_plane_is_told_how_the_door_knew_the_agent() {
    let pdp = Pdp::default();
    let url = spawn_pdp(pdp.clone()).await;
    tokio::time::sleep(Duration::from_millis(100)).await;

    let g = with_pdp(gate(Wire::Anthropic, Some(Mode::Accept), Some(KEYS)), &url);
    let (status, _, body) = send(
        &g.st,
        call(MESSAGES, "r-pdp-1", &with_token(&g, MESSAGES, "p-16")),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let asked = pdp
        .asked
        .lock()
        .unwrap()
        .last()
        .cloned()
        .expect("the PDP was asked");
    assert_eq!(asked["identity_source"], "agent-token", "{asked}");
    assert_eq!(asked["agent_id"], AGENT, "{asked}");
    assert_eq!(asked["attestation_method"], "dpop-key", "{asked}");

    let agent_header = ("x-fuse-agent-id", "agent://acme/keyed".to_string());
    let (status, _, body) = send(
        &g.st,
        call(MESSAGES, "r-pdp-2", &[key("sk-a"), agent_header.clone()]),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let asked = pdp.asked.lock().unwrap().last().cloned().expect("asked");
    assert_eq!(asked["identity_source"], "client-key", "{asked}");

    let open = with_pdp(gate(Wire::Anthropic, Some(Mode::Accept), None), &url);
    let (status, _, body) = send(&open.st, call(MESSAGES, "r-pdp-3", &[agent_header])).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let asked = pdp.asked.lock().unwrap().last().cloned().expect("asked");
    assert_eq!(asked["identity_source"], "none", "{asked}");
}
