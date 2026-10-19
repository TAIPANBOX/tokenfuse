//! `TOKENFUSE_AGENT_TOKENS_STATIC_KEYS` at the LLM door (invariant 138), and the
//! agent token forwarded to the policy decision point (invariant 140), through
//! the real router. The startup refusals are in `static_key_allow_list_startup`.

use std::sync::{Arc, Mutex};
use std::time::Duration;

use axum::body::Body;
use axum::extract::State;
use axum::http::{HeaderMap, Request, StatusCode};
use axum::routing::post;
use axum::{Json, Router};
use http_body_util::BodyExt;
use serde_json::{json, Value};
use tokenfuse_delegation::testing::{agent_token, cfg, proof_for, Key, AGENT};
use tokenfuse_gateway::agenttoken::{AgentTokens, Mode, STATIC_KEYS_VAR};
use tokenfuse_gateway::chainproof::Proving;
use tokenfuse_gateway::clientkeys::{ClientKeys, CLIENT_KEY_HEADER};
use tokenfuse_gateway::mcpdoor::PROOF_HEADER;
use tokenfuse_gateway::sink::{CallRecord, EventSink};
use tokenfuse_gateway::state::AppState;
use tokenfuse_gateway::wardryx::{Wardryx, WardryxMode};
use tokenfuse_gateway::wire::Wire;
use tower::ServiceExt;

use crate::common;

const ORIGIN: &str = "https://tokenfuse.acme.example";
/// Three static keys: key-a (listed in most tests), key-b (configured, never
/// listed), and the broker's own.
const KEYS: &str = "sk-a:key-a,sk-b:key-b,sk-broker:broker";
const MESSAGES: &str = "/v1/messages";
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

/// A gateway with the delegation door on, the agent-token door in `mode`, the
/// client keys `KEYS`, and `listed` as the static-key allow-list.
fn gate(mode: Mode, listed: &[&str]) -> Gate {
    let (issuer, holder) = (Key::new(), Key::new());
    let rows = Rows::default();
    let allow = listed.iter().map(|s| s.to_string()).collect();
    let st = common::app_with_wire(Wire::Anthropic)
        .with_chain_proof(
            Some(Arc::new(Proving {
                cfg: cfg(&issuer),
                origin: ORIGIN.to_string(),
            })),
            None,
        )
        .with_agent_tokens(Some(Arc::new(AgentTokens::with_static_keys(mode, allow))))
        .with_client_keys(Arc::new(
            ClientKeys::from_spec(KEYS).expect("a usable key spec"),
        ))
        .with_sink(Arc::new(rows.clone()));
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

/// The agent's token and a proof for `path` that names it, as `(header, value)`.
fn token_headers(g: &Gate, path: &str, jti: &str) -> (String, Vec<(&'static str, String)>) {
    let at = now();
    let tok = agent_token(&g.issuer, &g.holder, at, json!({}));
    let pf = proof_for(&g.holder, at, "POST", &format!("{ORIGIN}{path}"), jti, &tok);
    (
        tok.clone(),
        vec![("authorization", format!("DPoP {tok}")), (PROOF_HEADER, pf)],
    )
}

fn call(run: &str, headers: &[(&'static str, String)]) -> Request<Body> {
    let mut b = Request::post(MESSAGES)
        .header("content-type", "application/json")
        .header("x-fuse-run-id", run);
    for (k, v) in headers {
        b = b.header(*k, v.as_str());
    }
    b.body(Body::from(BODY)).unwrap()
}

fn key(secret: &str) -> (&'static str, String) {
    (CLIENT_KEY_HEADER, secret.to_string())
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

/// Under `require`, a static key on the list is admitted exactly as `accept`
/// admits one, and its records file it under the key.
#[tokio::test]
async fn require_admits_an_allow_listed_static_key_as_accept_does() {
    let g = gate(Mode::Require, &["key-a"]);
    let (status, _, body) = send(&g.st, call("r-list-1", &[key("sk-a")])).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(g.rows.last().key_id, "key-a", "the record files it under the key");
}

/// An unlisted key and an unknown key are refused with the same body, and the
/// body names the list variable, so a caller learns no more from which one it
/// held.
#[tokio::test]
async fn require_refuses_an_unlisted_static_key_and_an_unknown_one_the_same_way() {
    let g = gate(Mode::Require, &["key-a"]);
    let (status, headers, unlisted) = send(&g.st, call("r-list-2", &[key("sk-b")])).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED, "{unlisted}");
    assert_eq!(unlisted["error"]["type"], "agent_token_required", "{unlisted}");
    assert!(
        headers
            .get("www-authenticate")
            .and_then(|v| v.to_str().ok())
            .is_some_and(|v| v.starts_with("DPoP")),
        "the refusal names the scheme the caller needs"
    );
    let (status, _, unknown) = send(&g.st, call("r-list-3", &[key("sk-zzz")])).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED, "{unknown}");
    assert_eq!(unlisted, unknown, "the two refusals must not tell a caller apart");
    let reason = unlisted["error"]["reason"].as_str().unwrap_or_default();
    assert!(
        reason.contains(STATIC_KEYS_VAR),
        "the body names the variable a caller can ask about: {reason}"
    );
}

/// Under `require` with no list, every static key is refused as it always was.
#[tokio::test]
async fn require_with_no_list_refuses_every_static_key_as_before() {
    let g = gate(Mode::Require, &[]);
    let (status, _, body) = send(&g.st, call("r-list-4", &[key("sk-a")])).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED, "{body}");
    assert_eq!(body["error"]["type"], "agent_token_required", "{body}");
}

/// A token beside a listed key is two credentials, and is refused: the list
/// admits a key, never a key that rides along with a token.
#[tokio::test]
async fn a_token_beside_a_listed_key_is_still_refused_under_require() {
    let g = gate(Mode::Require, &["key-a"]);
    let (_, mut h) = token_headers(&g, MESSAGES, "p-list-1");
    h.push(key("sk-a"));
    let (status, _, body) = send(&g.st, call("r-list-5", &h)).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED, "{body}");
    assert_eq!(body["error"]["type"], "agent_token_refused", "{body}");
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

fn last_asked(pdp: &Pdp) -> Value {
    pdp.asked
        .lock()
        .unwrap()
        .last()
        .cloned()
        .expect("the PDP was asked")
}

/// A call an agent token admitted carries the token to the policy plane,
/// exactly as presented, and not the proof that came with it.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_policy_plane_is_sent_the_agent_token_when_a_token_admitted_the_call() {
    let pdp = Pdp::default();
    let url = spawn_pdp(pdp.clone()).await;
    tokio::time::sleep(Duration::from_millis(100)).await;
    let g = with_pdp(gate(Mode::Accept, &[]), &url);
    let (tok, h) = token_headers(&g, MESSAGES, "p-pdp-1");
    let (status, _, body) = send(&g.st, call("r-pdp-tok", &h)).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let asked = last_asked(&pdp);
    assert_eq!(asked["agent_token"], tok, "{asked}");
    assert_eq!(asked["agent_id"], AGENT, "{asked}");
    assert!(
        !asked.to_string().contains(&h[1].1),
        "the proof of possession is never sent to the policy plane"
    );
}

/// A call a static key admitted sends no token: the field is absent, not null.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_static_key_call_is_never_sent_an_agent_token() {
    let pdp = Pdp::default();
    let url = spawn_pdp(pdp.clone()).await;
    tokio::time::sleep(Duration::from_millis(100)).await;
    let g = with_pdp(gate(Mode::Accept, &[]), &url);
    let (status, _, body) = send(
        &g.st,
        call(
            "r-pdp-key",
            &[key("sk-a"), ("x-fuse-agent-id", "agent://acme/keyed".to_string())],
        ),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let asked = last_asked(&pdp);
    assert!(
        asked.get("agent_token").is_none(),
        "a static-key call sends no token: {asked}"
    );
}

/// A token over the size cap still admits the call; only the forwarding of it
/// is withheld, so a policy that needs the token denies rather than trusting a
/// request the gateway could not verify for the plane.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_oversized_agent_token_is_admitted_but_not_forwarded() {
    let pdp = Pdp::default();
    let url = spawn_pdp(pdp.clone()).await;
    tokio::time::sleep(Duration::from_millis(100)).await;
    let g = with_pdp(gate(Mode::Accept, &[]), &url);
    let at = now();
    let big = agent_token(
        &g.issuer,
        &g.holder,
        at,
        json!({ "pad": "x".repeat(5000) }),
    );
    assert!(big.len() > tokenfuse_gateway::agenttoken::TOKEN_FOR_PDP_CAP_BYTES);
    let pf = proof_for(
        &g.holder,
        at,
        "POST",
        &format!("{ORIGIN}{MESSAGES}"),
        "p-pdp-big",
        &big,
    );
    let h = [("authorization", format!("DPoP {big}")), (PROOF_HEADER, pf)];
    let (status, _, body) = send(&g.st, call("r-pdp-big", &h)).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let asked = last_asked(&pdp);
    assert!(asked.get("agent_token").is_none(), "{asked}");
    assert_eq!(asked["identity_source"], "agent-token", "{asked}");
}
