//! A person's delegation beside the agent's own token (CLAUDE.md invariant
//! 147), at the LLM and OpenAI doors, through the real router.
//!
//! Under `TOKENFUSE_AGENT_TOKENS=require` the agent's token is the door
//! credential and acts for nobody, so until this a call acting for a person
//! was refused there. The delegation now rides in `x-fuse-delegation` with its
//! own proof in `x-fuse-delegation-dpop`, held to the agent token's key and
//! agent, and the policy plane hears the person's chain as proven.

use std::sync::{Arc, Mutex, RwLock};
use std::time::Duration;

use axum::body::Body;
use axum::extract::State;
use axum::http::{Request, StatusCode};
use axum::routing::post;
use axum::{Json, Router};
use http_body_util::BodyExt;
use serde_json::{json, Value};
use tokenfuse_delegation::revocations::{FailMode, Revocation, Revocations, Snapshot};
use tokenfuse_delegation::testing::{agent_token, cfg, proof_at, proof_for, token, Key, AGENT};
use tokenfuse_gateway::agenttoken::{AgentTokens, Mode};
use tokenfuse_gateway::chainproof::{Proving, DELEGATION_HEADER, DELEGATION_PROOF_HEADER};
use tokenfuse_gateway::clientkeys::{ClientKeys, CLIENT_KEY_HEADER};
use tokenfuse_gateway::mcpdoor::PROOF_HEADER;
use tokenfuse_gateway::state::AppState;
use tokenfuse_gateway::wardryx::{Wardryx, WardryxMode};
use tokenfuse_gateway::wire::Wire;
use tower::ServiceExt;

use crate::common;

/// The origin every proof here is signed for; equal to the fixture's audience.
const ORIGIN: &str = "https://tokenfuse.acme.example";
const KEYS: &str = "sk-a:key-a";
const MESSAGES: &str = "/v1/messages";
const CHAT: &str = "/v1/chat/completions";
const BODY: &str =
    r#"{"model":"test-model","max_tokens":16,"messages":[{"role":"user","content":"hi"}]}"#;
/// The chain the fixture's delegation proves, root first, the agent last.
const CHAIN: [&str; 3] = [
    "user://acme/alice",
    "agent://acme/runbook",
    "agent://acme/triage",
];

struct Gate {
    st: AppState,
    issuer: Key,
    holder: Key,
}

/// A gateway with the delegation door on against a real issuer and the agent
/// token door in `mode`, and `keys` as its client keys.
fn gate(wire: Wire, mode: Mode, keys: Option<&str>) -> Gate {
    let (issuer, holder) = (Key::new(), Key::new());
    let mut st = common::app_with_wire(wire)
        .with_chain_proof(
            Some(Arc::new(Proving {
                cfg: cfg(&issuer),
                origins: vec![ORIGIN.to_string()],
            })),
            None,
        )
        .with_agent_tokens(Some(Arc::new(AgentTokens::new(mode))));
    if let Some(spec) = keys {
        st = st.with_client_keys(Arc::new(
            ClientKeys::from_spec(spec).expect("a usable key spec"),
        ));
    }
    Gate { st, issuer, holder }
}

fn now() -> i64 {
    tokenfuse_gateway::sink::now_millis() / 1000
}

/// The agent's own token and its proof for `path`.
fn agent(g: &Gate, path: &str, jti: &str) -> Vec<(&'static str, String)> {
    let at = now();
    let tok = agent_token(&g.issuer, &g.holder, at, json!({}));
    let pf = proof_for(&g.holder, at, "POST", &format!("{ORIGIN}{path}"), jti, &tok);
    vec![("authorization", format!("DPoP {tok}")), (PROOF_HEADER, pf)]
}

/// The person's delegation bound to `holder`, and its own proof for `path`
/// signed by `holder` and naming it. The chain is [`CHAIN`]: RFC 8693 nests
/// `act` current-first, so the agent token's agent is the OUTER actor. `over`
/// replaces claims, `act` included.
fn delegation(
    g: &Gate,
    holder: &Key,
    path: &str,
    jti: &str,
    over: Value,
) -> Vec<(&'static str, String)> {
    let at = now();
    let mut claims = json!({"act": {"sub": CHAIN[2], "act": {"sub": CHAIN[1]}}});
    if let Value::Object(o) = over {
        for (k, v) in o {
            claims[k] = v;
        }
    }
    let tok = token(&g.issuer, holder, at, claims);
    let pf = proof_for(holder, at, "POST", &format!("{ORIGIN}{path}"), jti, &tok);
    vec![(DELEGATION_HEADER, tok), (DELEGATION_PROOF_HEADER, pf)]
}

/// The agent's token, then the person's delegation beside it, both bound to
/// the agent's key.
fn beside(g: &Gate, path: &str, jti: &str) -> Vec<(&'static str, String)> {
    let mut h = agent(g, path, &format!("{jti}-agent"));
    h.extend(delegation(
        g,
        &g.holder,
        path,
        &format!("{jti}-deleg"),
        json!({}),
    ));
    h
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

async fn send(st: &AppState, req: Request<Body>) -> (StatusCode, Value) {
    let resp = tokenfuse_gateway::app(st.clone())
        .oneshot(req)
        .await
        .unwrap();
    let status = resp.status();
    let bytes = resp.into_body().collect().await.unwrap().to_bytes();
    (
        status,
        serde_json::from_slice(&bytes).unwrap_or(Value::Null),
    )
}

#[derive(Clone, Default)]
struct Pdp {
    asked: Arc<Mutex<Vec<Value>>>,
}

impl Pdp {
    fn last(&self) -> Value {
        self.asked
            .lock()
            .unwrap()
            .last()
            .cloned()
            .expect("the PDP was asked")
    }
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
    tokio::time::sleep(Duration::from_millis(100)).await;
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

fn assert_refused(status: StatusCode, body: &Value) {
    assert_eq!(status, StatusCode::UNAUTHORIZED, "{body}");
    assert_eq!(body["error"]["type"], "delegation_refused", "{body}");
}

/// THE ONE THIS IS FOR. Under `require`, the agent's token admits the call and
/// the person's delegation beside it reaches the policy plane as a proven
/// chain, so `require_root_principal`, `max_chain_depth` and
/// `deny_if_chain_unproven` judge the person and not a claim. Without the
/// delegation, the same agent's chain stays unproven, as before.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn under_require_a_persons_delegation_beside_the_agent_token_reaches_the_pdp_proven() {
    let pdp = Pdp::default();
    let url = spawn_pdp(pdp.clone()).await;
    let g = with_pdp(gate(Wire::Anthropic, Mode::Require, None), &url);

    let (status, body) = send(
        &g.st,
        call(MESSAGES, "r-alone", &agent(&g, MESSAGES, "p-1")),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let asked = pdp.last();
    assert_eq!(asked["chain_proven"], json!(false), "{asked}");

    let (status, body) = send(
        &g.st,
        call(MESSAGES, "r-beside", &beside(&g, MESSAGES, "p-2")),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let asked = pdp.last();
    assert_eq!(asked["chain_proven"], json!(true), "{asked}");
    assert_eq!(asked["on_behalf_of"], json!(CHAIN), "{asked}");
    assert_eq!(asked["agent_id"], AGENT, "{asked}");
    assert_eq!(asked["identity_source"], "agent-token", "{asked}");
}

/// The OpenAI door shares the LLM door's `handle`, and takes the delegation
/// with proofs made for its own path.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_openai_door_takes_a_persons_delegation_beside_the_agent_token() {
    let pdp = Pdp::default();
    let url = spawn_pdp(pdp.clone()).await;
    let g = with_pdp(gate(Wire::OpenAi, Mode::Require, None), &url);
    let (status, body) = send(&g.st, call(CHAT, "r-oai", &beside(&g, CHAT, "p-3"))).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let asked = pdp.last();
    assert_eq!(asked["chain_proven"], json!(true), "{asked}");
    assert_eq!(asked["on_behalf_of"], json!(CHAIN), "{asked}");
}

/// The must-not-fire case: a delegation is still not a door credential, so
/// under `require` one in `Authorization` with no agent token is refused, as
/// before.
#[tokio::test]
async fn under_require_a_delegation_alone_is_still_not_a_door_credential() {
    let g = gate(Wire::Anthropic, Mode::Require, None);
    let at = now();
    let tok = token(&g.issuer, &g.holder, at, json!({}));
    let pf = proof_at(&g.holder, at, "POST", &format!("{ORIGIN}{MESSAGES}"), "p-4");
    let h = [("authorization", format!("DPoP {tok}")), (PROOF_HEADER, pf)];
    let (status, body) = send(&g.st, call(MESSAGES, "r-deleg-alone", &h)).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED, "{body}");
    assert_eq!(body["error"]["type"], "agent_token_required", "{body}");
}

/// A delegation bound to another key than the agent token was issued to
/// another holder, and is refused even though its own proof verifies.
#[tokio::test]
async fn a_delegation_bound_to_another_key_is_refused_beside_the_agent_token() {
    let g = gate(Wire::Anthropic, Mode::Require, None);
    let other = Key::new();
    let mut h = agent(&g, MESSAGES, "p-5-agent");
    h.extend(delegation(&g, &other, MESSAGES, "p-5-deleg", json!({})));
    let (status, body) = send(&g.st, call(MESSAGES, "r-other-key", &h)).await;
    assert_refused(status, &body);
}

/// A delegation that authorises another agent cannot be borrowed by this one.
#[tokio::test]
async fn a_delegation_that_authorises_another_agent_is_refused_beside_the_agent_token() {
    let g = gate(Wire::Anthropic, Mode::Require, None);
    let mut h = agent(&g, MESSAGES, "p-6-agent");
    h.extend(delegation(
        &g,
        &g.holder,
        MESSAGES,
        "p-6-deleg",
        json!({"act": {"sub": "agent://acme/other"}}),
    ));
    let (status, body) = send(&g.st, call(MESSAGES, "r-other-agent", &h)).await;
    assert_refused(status, &body);
}

/// Withdrawing the person at vouchryx stops the agent acting for them here,
/// while the agent's own token is untouched.
#[tokio::test]
async fn a_revoked_person_stops_the_agent_acting_for_them() {
    let mut g = gate(Wire::Anthropic, Mode::Require, None);
    let at = now();
    let mut cache = Revocations::new(60, FailMode::Closed);
    let _ = cache.install(
        Snapshot {
            revocations: vec![Revocation {
                subject: CHAIN[0].to_string(),
                issued_before: at + 5,
                ..Default::default()
            }],
            as_of: at,
        },
        at,
    );
    g.st.revocations = Some(Arc::new(RwLock::new(cache)));
    let (status, body) = send(
        &g.st,
        call(MESSAGES, "r-rev-agent", &agent(&g, MESSAGES, "p-7")),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::OK,
        "the agent itself is not revoked: {body}"
    );
    let (status, body) = send(&g.st, call(MESSAGES, "r-rev", &beside(&g, MESSAGES, "p-8"))).await;
    assert_refused(status, &body);
}

/// The second header is read only beside an agent token: beside a static key
/// it has nothing to be held to, and is refused rather than quietly dropped.
#[tokio::test]
async fn a_delegation_header_beside_a_static_key_is_refused() {
    let g = gate(Wire::Anthropic, Mode::Accept, Some(KEYS));
    let mut h = vec![(CLIENT_KEY_HEADER, "sk-a".to_string())];
    h.extend(delegation(&g, &g.holder, MESSAGES, "p-9", json!({})));
    let (status, body) = send(&g.st, call(MESSAGES, "r-static", &h)).await;
    assert_refused(status, &body);
}
