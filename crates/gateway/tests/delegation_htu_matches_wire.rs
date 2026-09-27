//! Each wire door's own path is what a DPoP delegation proof's `htu` is
//! checked against, not a literal shared by both doors.
//!
//! `proxy::handle` is the one enforcement path both `/v1/messages`
//! (Anthropic) and `/v1/chat/completions` (OpenAI) are served through
//! (invariant 55, W2a's own doc on `handle`), and it used to build the URL a
//! delegation proof is verified against from a hard-coded `"/v1/messages"`
//! regardless of which door the request actually arrived on. A caller on the
//! OpenAI door whose proof correctly named `/v1/chat/completions` was
//! refused, and a proof naming `/v1/messages` (the wrong door) was wrongly
//! accepted there instead. This was read from the source, not run, before
//! this file existed (the finding this file closes).
//!
//! Every test here drives real HTTP through `tokenfuse_gateway::app`, the
//! same router `main.rs` serves - the same style `wire_door.rs` already
//! uses for this pair of doors.

mod common;

use std::sync::Arc;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use tokenfuse_delegation::testing::{cfg, proof_at, token, Key};
use tokenfuse_gateway::chainproof::Proving;
use tokenfuse_gateway::wire::Wire;
use tower::ServiceExt;

/// The origin the fixture's proofs are signed for, and what `Proving::origin`
/// is configured with below - matching `tokenfuse_delegation::testing::AUD`,
/// which `cfg()` sets as the token's `aud`.
const ORIGIN: &str = "https://tokenfuse.acme.example";

fn openai_body() -> &'static str {
    r#"{"model":"test-model","max_tokens":16,"messages":[{"role":"user","content":"hi"}]}"#
}

fn anthropic_body() -> &'static str {
    r#"{"model":"test-model","max_tokens":16,"messages":[{"role":"user","content":"hi"}]}"#
}

/// A gateway serving `wire`, with the delegation door on against a real
/// issuer, mirroring `proxy::tests::firewall_state_proving` for the
/// integration-test crate (no direct access to that private helper here).
fn proving_state(wire: Wire) -> (tokenfuse_gateway::state::AppState, Key, Key) {
    let (issuer, holder) = (Key::new(), Key::new());
    let st = common::app_with_wire(wire).with_chain_proof(
        Some(Arc::new(Proving {
            cfg: cfg(&issuer),
            origin: ORIGIN.to_string(),
        })),
        None,
    );
    (st, issuer, holder)
}

async fn send(
    state: tokenfuse_gateway::state::AppState,
    path: &str,
    tok: &str,
    dpop: &str,
    body: &str,
) -> axum::http::StatusCode {
    let app = tokenfuse_gateway::app(state);
    let resp = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(path)
                .header("content-type", "application/json")
                .header("x-fuse-run-id", "r-htu-1")
                .header("authorization", format!("DPoP {tok}"))
                .header(tokenfuse_gateway::mcpdoor::PROOF_HEADER, dpop)
                .body(Body::from(body.to_string()))
                .unwrap(),
        )
        .await
        .unwrap();
    resp.status()
}

/// THE ONE THIS FILE EXISTS FOR. A proof naming the real OpenAI path must be
/// accepted on the OpenAI door. Red before the fix: the door built its
/// verification URL from a literal `/v1/messages` no matter which wire it
/// served, so a correct proof for `/v1/chat/completions` was refused.
#[tokio::test]
async fn a_proof_naming_the_real_openai_path_is_accepted_on_the_openai_door() {
    let (st, issuer, holder) = proving_state(Wire::OpenAi);
    let now = tokenfuse_gateway::sink::now_millis() / 1000;
    let tok = token(&issuer, &holder, now, serde_json::json!({"exp": now + 300}));
    let dpop = proof_at(
        &holder,
        now,
        "POST",
        &format!("{ORIGIN}/v1/chat/completions"),
        "p-openai-correct",
    );
    let status = send(st, "/v1/chat/completions", &tok, &dpop, openai_body()).await;
    assert_eq!(
        status,
        StatusCode::OK,
        "a proof correctly naming this door's own path was refused"
    );
}

/// The other half of the same bug: a proof naming the WRONG door's path
/// (`/v1/messages`) must be refused on the OpenAI door. Red before the fix
/// for the opposite reason from the test above: the hard-coded literal
/// happened to match this one, so it was wrongly ACCEPTED.
#[tokio::test]
async fn a_proof_naming_the_anthropic_path_is_refused_on_the_openai_door() {
    let (st, issuer, holder) = proving_state(Wire::OpenAi);
    let now = tokenfuse_gateway::sink::now_millis() / 1000;
    let tok = token(&issuer, &holder, now, serde_json::json!({"exp": now + 300}));
    let dpop = proof_at(
        &holder,
        now,
        "POST",
        &format!("{ORIGIN}/v1/messages"),
        "p-openai-wrong-door",
    );
    let status = send(st, "/v1/chat/completions", &tok, &dpop, openai_body()).await;
    assert_eq!(
        status,
        StatusCode::UNAUTHORIZED,
        "a proof naming the OTHER door's path was accepted here"
    );
}

/// Mirror/guard for the Anthropic door: a proof naming its own path is
/// accepted. This passes both before and after the fix (the old literal
/// happened to be this exact path), and it is what proves the fix did not
/// just move the bug from one door to the other.
#[tokio::test]
async fn a_proof_naming_the_real_anthropic_path_is_accepted_on_the_anthropic_door() {
    let (st, issuer, holder) = proving_state(Wire::Anthropic);
    let now = tokenfuse_gateway::sink::now_millis() / 1000;
    let tok = token(&issuer, &holder, now, serde_json::json!({"exp": now + 300}));
    let dpop = proof_at(
        &holder,
        now,
        "POST",
        &format!("{ORIGIN}/v1/messages"),
        "p-anthropic-correct",
    );
    let status = send(st, "/v1/messages", &tok, &dpop, anthropic_body()).await;
    assert_eq!(status, StatusCode::OK);
}

/// The Anthropic-door guard's other half: a proof naming the OpenAI path is
/// refused there. Also green on both sides; it is the negative control that
/// keeps the guard above from being vacuous (a door admitting every proof
/// would pass the positive guard too).
#[tokio::test]
async fn a_proof_naming_the_openai_path_is_refused_on_the_anthropic_door() {
    let (st, issuer, holder) = proving_state(Wire::Anthropic);
    let now = tokenfuse_gateway::sink::now_millis() / 1000;
    let tok = token(&issuer, &holder, now, serde_json::json!({"exp": now + 300}));
    let dpop = proof_at(
        &holder,
        now,
        "POST",
        &format!("{ORIGIN}/v1/chat/completions"),
        "p-anthropic-wrong-door",
    );
    let status = send(st, "/v1/messages", &tok, &dpop, anthropic_body()).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
}
