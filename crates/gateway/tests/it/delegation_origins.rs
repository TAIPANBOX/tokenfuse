//! The delegation door takes a LIST of public origins (CLAUDE.md invariant 141).
//!
//! A gateway is reached at a public name by its clients and at another name by the
//! containers beside it. A proof is accepted when its `htu` names one configured
//! origin at the route's own path. The `Host` header is never consulted.
//!
//! Driven through the real router, on the OpenAI door and on the agent-token door.

use crate::common;

use std::sync::Arc;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use tokenfuse_delegation::testing::{agent_token, cfg, proof_at, proof_for, token, Key};
use tokenfuse_gateway::agenttoken::{AgentTokens, Mode};
use tokenfuse_gateway::chainproof::Proving;
use tokenfuse_gateway::mcpdoor::PROOF_HEADER;
use tokenfuse_gateway::state::AppState;
use tokenfuse_gateway::wire::Wire;
use tower::ServiceExt;

/// The public name clients call the gateway at.
const ORIGIN: &str = "https://tokenfuse.acme.example";
/// The name the containers beside the gateway call it at.
const INTERNAL: &str = "http://tokenfuse-gateway:4100";

fn body() -> &'static str {
    r#"{"model":"test-model","max_tokens":16,"messages":[{"role":"user","content":"hi"}]}"#
}

fn now() -> i64 {
    tokenfuse_gateway::sink::now_millis() / 1000
}

/// A gateway on the OpenAI door whose delegation door is configured with `origins`.
fn gateway(origins: &[&str]) -> (AppState, Key, Key) {
    let (issuer, holder) = (Key::new(), Key::new());
    let proving = Proving {
        cfg: cfg(&issuer),
        origins: origins.iter().map(|o| o.to_string()).collect(),
    };
    let st = common::app_with_wire(Wire::OpenAi).with_chain_proof(Some(Arc::new(proving)), None);
    (st, issuer, holder)
}

/// POST one chat completion with `headers`, answering with its status.
async fn post(st: AppState, headers: Vec<(&'static str, String)>) -> StatusCode {
    let mut b = Request::builder()
        .method("POST")
        .uri("/v1/chat/completions")
        .header("content-type", "application/json")
        .header("x-fuse-run-id", "r-origins-1");
    for (k, v) in headers {
        b = b.header(k, v);
    }
    let req = b.body(Body::from(body())).unwrap();
    tokenfuse_gateway::app(st)
        .oneshot(req)
        .await
        .unwrap()
        .status()
}

/// A delegation token from `issuer` for `holder`, and a proof naming `htu`.
fn delegated(issuer: &Key, holder: &Key, htu: &str, jti: &str) -> Vec<(&'static str, String)> {
    let at = now();
    let tok = token(issuer, holder, at, serde_json::json!({"exp": at + 300}));
    let pf = proof_at(holder, at, "POST", htu, jti);
    vec![("authorization", format!("DPoP {tok}")), (PROOF_HEADER, pf)]
}

/// THE FEATURE. A proof addressed to the second configured origin is accepted on the
/// OpenAI door. Red before the fix: the door verified the proof against one origin.
#[tokio::test]
async fn a_proof_addressed_to_a_second_configured_origin_is_accepted_on_the_openai_door() {
    let (st, issuer, holder) = gateway(&[ORIGIN, INTERNAL]);
    let h = delegated(
        &issuer,
        &holder,
        &format!("{INTERNAL}/v1/chat/completions"),
        "origins-internal-1",
    );
    assert_eq!(
        post(st, h).await,
        StatusCode::OK,
        "a proof addressed to a configured origin was refused"
    );
}

/// The first origin spelled with its default port names the same origin. Red before
/// the fix: the proof's htu and the configured origin were compared as bare strings.
#[tokio::test]
async fn the_first_origin_spelled_with_its_default_port_is_the_same_origin() {
    let (st, issuer, holder) = gateway(&[ORIGIN]);
    let h = delegated(
        &issuer,
        &holder,
        "https://tokenfuse.acme.example:443/v1/chat/completions",
        "origins-default-port-1",
    );
    assert_eq!(post(st, h).await, StatusCode::OK);
}

/// A Host header naming a configured origin admits no htu that is not one.
#[tokio::test]
async fn a_host_header_naming_a_configured_origin_does_not_admit_an_htu_that_is_not_one() {
    let (st, issuer, holder) = gateway(&[ORIGIN, INTERNAL]);
    let mut h = delegated(
        &issuer,
        &holder,
        "https://evil.example/v1/chat/completions",
        "origins-host-1",
    );
    h.push(("host", "tokenfuse-gateway:4100".to_string()));
    assert_eq!(post(st, h).await, StatusCode::UNAUTHORIZED);
}

/// An origin nobody listed is refused.
#[tokio::test]
async fn a_proof_naming_an_unlisted_origin_is_refused() {
    let (st, issuer, holder) = gateway(&[ORIGIN, INTERNAL]);
    let h = delegated(
        &issuer,
        &holder,
        "https://other.example/v1/chat/completions",
        "origins-unlisted-1",
    );
    assert_eq!(post(st, h).await, StatusCode::UNAUTHORIZED);
}

/// User information in the htu is refused.
#[tokio::test]
async fn a_proof_with_user_information_in_its_htu_is_refused() {
    let (st, issuer, holder) = gateway(&[ORIGIN]);
    let h = delegated(
        &issuer,
        &holder,
        "https://user@tokenfuse.acme.example/v1/chat/completions",
        "origins-userinfo-1",
    );
    assert_eq!(post(st, h).await, StatusCode::UNAUTHORIZED);
}

/// A fragment is refused. Red before the fix: the verifier trimmed it and admitted.
#[tokio::test]
async fn a_proof_with_a_fragment_in_its_htu_is_refused() {
    let (st, issuer, holder) = gateway(&[ORIGIN]);
    let h = delegated(
        &issuer,
        &holder,
        &format!("{ORIGIN}/v1/chat/completions#frag"),
        "origins-fragment-1",
    );
    assert_eq!(post(st, h).await, StatusCode::UNAUTHORIZED);
}

/// A configured origin with a path in front of the route is refused.
#[tokio::test]
async fn a_configured_origin_at_a_path_in_front_of_the_route_is_refused() {
    let (st, issuer, holder) = gateway(&[ORIGIN, INTERNAL]);
    let h = delegated(
        &issuer,
        &holder,
        &format!("{INTERNAL}/prefix/v1/chat/completions"),
        "origins-prefix-1",
    );
    assert_eq!(post(st, h).await, StatusCode::UNAUTHORIZED);
}

/// The agent-token door takes a proof addressed to the second configured origin.
#[tokio::test]
async fn an_agent_token_proof_addressed_to_a_second_configured_origin_is_accepted() {
    let (issuer, holder) = (Key::new(), Key::new());
    let proving = Proving {
        cfg: cfg(&issuer),
        origins: vec![ORIGIN.to_string(), INTERNAL.to_string()],
    };
    let st = common::app_with_wire(Wire::OpenAi)
        .with_chain_proof(Some(Arc::new(proving)), None)
        .with_agent_tokens(Some(Arc::new(AgentTokens::new(Mode::Accept))));
    let at = now();
    let tok = agent_token(&issuer, &holder, at, serde_json::json!({}));
    let pf = proof_for(
        &holder,
        at,
        "POST",
        &format!("{INTERNAL}/v1/chat/completions"),
        "origins-agent-1",
        &tok,
    );
    let h = vec![("authorization", format!("DPoP {tok}")), (PROOF_HEADER, pf)];
    assert_eq!(
        post(st, h).await,
        StatusCode::OK,
        "an agent proof addressed to a configured origin was refused"
    );
}
