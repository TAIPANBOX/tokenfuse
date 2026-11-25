//! Invariant 120's delegated arm for agent tokens, through the real router.
//!
//! A parent run another agent's token opened belongs to that agent. A child
//! call admitted by an agent token may roll up into it when the person's
//! delegation beside that token (invariant 147) PROVES a chain naming the
//! parent's agent before the child's own. A claimed chain, a chain that does
//! not name the owner, a static key and a key-owned parent never are.

use std::sync::Arc;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use http_body_util::BodyExt;
use serde_json::{json, Value};
use tokenfuse_delegation::testing::{agent_token, cfg, proof_for, token, Key, AGENT};
use tokenfuse_gateway::agenttoken::{AgentTokens, Mode};
use tokenfuse_gateway::chainproof::{Proving, DELEGATION_HEADER, DELEGATION_PROOF_HEADER};
use tokenfuse_gateway::clientkeys::{ClientKeys, CLIENT_KEY_HEADER};
use tokenfuse_gateway::mcpdoor::PROOF_HEADER;
use tokenfuse_gateway::state::AppState;
use tokenfuse_gateway::wire::Wire;
use tower::ServiceExt;

use crate::common;

const ORIGIN: &str = "https://tokenfuse.acme.example";
const MESSAGES: &str = "/v1/messages";
const BODY: &str =
    r#"{"model":"test-model","max_tokens":16,"messages":[{"role":"user","content":"hi"}]}"#;
/// The agent the fixture's delegation names before the child's own.
const RUNBOOK: &str = "agent://acme/runbook";

struct Gate {
    st: AppState,
    issuer: Key,
    holder: Key,
}

fn gate(keys: Option<&str>) -> Gate {
    let (issuer, holder) = (Key::new(), Key::new());
    let mut st = common::app_with_wire(Wire::Anthropic)
        .with_chain_proof(
            Some(Arc::new(Proving {
                cfg: cfg(&issuer),
                origins: vec![ORIGIN.to_string()],
            })),
            None,
        )
        .with_agent_tokens(Some(Arc::new(AgentTokens::new(Mode::Accept))));
    if let Some(spec) = keys {
        st = st.with_client_keys(Arc::new(ClientKeys::from_spec(spec).expect("a key spec")));
    }
    Gate { st, issuer, holder }
}

fn now() -> i64 {
    tokenfuse_gateway::sink::now_millis() / 1000
}

/// An agent token naming `agent`, bound to `holder`, and its proof.
fn agent_as(g: &Gate, holder: &Key, agent: &str, jti: &str) -> Vec<(&'static str, String)> {
    let at = now();
    let tok = agent_token(
        &g.issuer,
        holder,
        at,
        json!({"sub": agent, "client_id": agent, "jti": format!("{jti}-tok")}),
    );
    let pf = proof_for(
        holder,
        at,
        "POST",
        &format!("{ORIGIN}{MESSAGES}"),
        jti,
        &tok,
    );
    vec![("authorization", format!("DPoP {tok}")), (PROOF_HEADER, pf)]
}

/// The child's agent token (the fixture's `AGENT`) and a person's delegation
/// beside it whose chain is `act`, nested current-first.
fn child(g: &Gate, jti: &str, act: Value) -> Vec<(&'static str, String)> {
    let mut h = agent_as(g, &g.holder, AGENT, &format!("{jti}-agent"));
    let at = now();
    let tok = token(
        &g.issuer,
        &g.holder,
        at,
        json!({"act": act, "jti": format!("{jti}-d")}),
    );
    let pf = proof_for(
        &g.holder,
        at,
        "POST",
        &format!("{ORIGIN}{MESSAGES}"),
        &format!("{jti}-deleg"),
        &tok,
    );
    h.push((DELEGATION_HEADER, tok));
    h.push((DELEGATION_PROOF_HEADER, pf));
    h
}

/// The chain user -> runbook -> triage (the child).
fn via_runbook() -> Value {
    json!({"sub": AGENT, "act": {"sub": RUNBOOK}})
}

fn call(run: &str, parent: Option<&str>, headers: &[(&'static str, String)]) -> Request<Body> {
    let mut b = Request::post(MESSAGES)
        .header("content-type", "application/json")
        .header("x-fuse-run-id", run);
    if let Some(p) = parent {
        b = b.header("x-fuse-parent-run-id", p);
    }
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

/// The parent run, opened by `owner`'s own token.
async fn open_parent(g: &Gate, run: &str, owner: &str) {
    let holder = Key::new();
    let (status, body) = send(
        &g.st,
        call(
            run,
            None,
            &agent_as(g, &holder, owner, &format!("{run}-open")),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "the parent opens: {body}");
}

fn refused_for_parent(status: StatusCode, body: &Value) {
    assert_eq!(status, StatusCode::FORBIDDEN, "{body}");
    assert_eq!(body["error"]["type"], "identity_mismatch", "{body}");
}

/// Red on the unfixed tree: a token-owned parent could never be rolled up into
/// by another principal, whatever the call proved.
#[tokio::test]
async fn a_proven_chain_naming_the_parent_owners_agent_rolls_up() {
    let g = gate(None);
    open_parent(&g, "parent-1", RUNBOOK).await;
    let (status, body) = send(
        &g.st,
        call("child-1", Some("parent-1"), &child(&g, "c1", via_runbook())),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let parent =
        g.st.ledger
            .snapshot("parent-1")
            .await
            .expect("the parent is open");
    assert!(
        parent.spent.0 > 0 || parent.reserved.0 > 0,
        "the child's spend rolled up: {parent:?}"
    );
}

/// Any ancestor in the proven chain counts: authority passed through it.
#[tokio::test]
async fn the_parent_owner_two_hops_up_the_chain_rolls_up() {
    let g = gate(None);
    open_parent(&g, "parent-2", RUNBOOK).await;
    let act = json!({"sub": AGENT, "act": {"sub": "agent://acme/middle", "act": {"sub": RUNBOOK}}});
    let (status, body) = send(
        &g.st,
        call("child-2", Some("parent-2"), &child(&g, "c2", act)),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
}

/// The parent the ledger holds is judged the same way when a later call omits
/// the header.
#[tokio::test]
async fn a_held_parent_is_still_delegated_when_the_header_is_omitted() {
    let g = gate(None);
    open_parent(&g, "parent-3", RUNBOOK).await;
    let (status, body) = send(
        &g.st,
        call(
            "child-3",
            Some("parent-3"),
            &child(&g, "c3a", via_runbook()),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let (status, body) = send(
        &g.st,
        call("child-3", None, &child(&g, "c3b", via_runbook())),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
}

/// Guard: the child's token alone proves no chain, so the parent stays refused.
#[tokio::test]
async fn a_claimed_chain_naming_the_parent_owner_is_refused() {
    let g = gate(None);
    open_parent(&g, "parent-4", RUNBOOK).await;
    let mut h = agent_as(&g, &g.holder, AGENT, "c4");
    h.push((
        "x-fuse-on-behalf-of",
        format!("user://acme/alice,{RUNBOOK},{AGENT}"),
    ));
    let (status, body) = send(&g.st, call("child-4", Some("parent-4"), &h)).await;
    refused_for_parent(status, &body);
}

/// Guard: a proven chain that does not name the parent's agent.
#[tokio::test]
async fn a_proven_chain_that_does_not_name_the_parent_owner_is_refused() {
    let g = gate(None);
    open_parent(&g, "parent-5", "agent://acme/elsewhere").await;
    let (status, body) = send(
        &g.st,
        call("child-5", Some("parent-5"), &child(&g, "c5", via_runbook())),
    )
    .await;
    refused_for_parent(status, &body);
}

/// Guard: a near match of the owner's agent is not the owner.
#[tokio::test]
async fn a_near_match_of_the_owners_agent_is_refused() {
    let g = gate(None);
    open_parent(&g, "parent-6", "agent://acme/runbook-ops").await;
    let (status, body) = send(
        &g.st,
        call("child-6", Some("parent-6"), &child(&g, "c6", via_runbook())),
    )
    .await;
    refused_for_parent(status, &body);
}

/// Guard: a parent a static key owns is not delegated by a chain naming an
/// agent of the same name.
#[tokio::test]
async fn a_key_owned_parent_is_not_delegated_by_a_chain() {
    let g = gate(Some("sk-runbook:runbook"));
    let open = vec![(CLIENT_KEY_HEADER, "sk-runbook".to_string())];
    let (status, body) = send(&g.st, call("parent-7", None, &open)).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let (status, body) = send(
        &g.st,
        call("child-7", Some("parent-7"), &child(&g, "c7", via_runbook())),
    )
    .await;
    refused_for_parent(status, &body);
}

/// Red until every ancestor is judged: a run that a delegation once let roll up
/// under another agent's run does not become a standing pass. A grandchild
/// opened under it without the delegation is refused.
#[tokio::test]
async fn a_grandchild_without_the_delegation_is_refused_under_the_owners_run() {
    let g = gate(None);
    open_parent(&g, "parent-9", RUNBOOK).await;
    let (status, body) = send(
        &g.st,
        call("child-9", Some("parent-9"), &child(&g, "c9", via_runbook())),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let alone = agent_as(&g, &g.holder, AGENT, "c9-alone");
    let (status, body) = send(&g.st, call("grandchild-9", Some("child-9"), &alone)).await;
    refused_for_parent(status, &body);
}

/// The held parent is judged at every call: once the delegation is gone, the
/// child's next call is refused.
#[tokio::test]
async fn a_held_parent_without_the_delegation_is_refused() {
    let g = gate(None);
    open_parent(&g, "parent-10", RUNBOOK).await;
    let (status, body) = send(
        &g.st,
        call(
            "child-10",
            Some("parent-10"),
            &child(&g, "c10", via_runbook()),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let alone = agent_as(&g, &g.holder, AGENT, "c10-alone");
    let (status, body) = send(&g.st, call("child-10", None, &alone)).await;
    refused_for_parent(status, &body);
}

/// Guard: an owner whose agent is a prefix of a chain entry is not that entry.
#[tokio::test]
async fn an_owner_that_is_a_prefix_of_a_chain_entry_is_refused() {
    let g = gate(None);
    open_parent(&g, "parent-11", "agent://acme/run").await;
    let (status, body) = send(
        &g.st,
        call(
            "child-11",
            Some("parent-11"),
            &child(&g, "c11", via_runbook()),
        ),
    )
    .await;
    refused_for_parent(status, &body);
}
