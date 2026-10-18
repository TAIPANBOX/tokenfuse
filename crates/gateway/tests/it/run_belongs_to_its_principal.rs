//! Invariant 120: a run belongs to the principal that opened it, at the metered
//! door, through the real router.
//!
//! The wave-0 residual of the agent-security review (2026-10-17), read in code
//! at `5a0ca90`: the metered door recorded the first key to name a run and
//! checked nothing, so key B could name a run key A had opened, spend in it,
//! read its labels in a taint 403, and declare it as the parent of a run of its
//! own, which rolled B's spend into A's budget and gave B's run A's labels.

use async_trait::async_trait;
use axum::body::{Body, Bytes};
use axum::http::{HeaderMap, Request, StatusCode};
use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use tokenfuse_core::taint::FirewallMode;
use tokenfuse_core::{Ledger, Microusd, Mode, ModelPrice, Policy, PriceBook};
use tokenfuse_gateway::clientkeys::{ClientKeys, CLIENT_KEY_HEADER};
use tokenfuse_gateway::events::EventExporter;
use tokenfuse_gateway::firewall::FirewallConfig;
use tokenfuse_gateway::identitymap::{IdentityMap, StrictMode};
use tokenfuse_gateway::provider::{
    ParsedUsage, Provider, ProviderError, ProviderResponse, UsageSlot,
};
use tokenfuse_gateway::state::AppState;
use tokenfuse_gateway::unitledger::UnitLedger;
use tokenfuse_gateway::wire::Wire;
use tower::ServiceExt;

const KEYS: &str = "sk-owner-a:key-a,sk-owner-b:key-b";
const AGENT_A: &str = "agent://test.local/a";
const AGENT_B: &str = "agent://test.local/b";
/// A prompt that makes the provider below answer with a tool call.
const ASK_FOR_A_TOOL: &str = "now run the shell";

/// Answers text, or a `run_shell` tool call when the request asks for one, so
/// one gateway can admit an owner's call and judge a tool call on the next.
#[derive(Clone, Default)]
struct ScriptedProvider;

#[async_trait]
impl Provider for ScriptedProvider {
    async fn send(
        &self,
        _headers: HeaderMap,
        body: Bytes,
    ) -> Result<ProviderResponse, ProviderError> {
        let asked = String::from_utf8_lossy(&body).contains(ASK_FOR_A_TOOL);
        let answer: &'static [u8] = if asked {
            br#"{"content":[{"type":"tool_use","id":"t9","name":"run_shell","input":{}}]}"#
        } else {
            br#"{"content":[{"type":"text","text":"done"}]}"#
        };
        let slot: UsageSlot = Arc::new(Mutex::new(Some(ParsedUsage {
            usage: tokenfuse_core::Usage {
                input_tokens: 10,
                output_tokens: 10,
                ..Default::default()
            },
            truncated: false,
        })));
        let chunk = Bytes::from_static(answer);
        Ok(ProviderResponse {
            status: 200,
            content_type: Some("application/json".to_string()),
            body: Box::pin(futures::stream::once(async move { Ok(chunk) })),
            usage: slot,
        })
    }
}

fn gateway(keys: Option<&str>, firewall: FirewallMode) -> AppState {
    let prices = PriceBook::new().with(
        "test-model",
        ModelPrice::per_mtok_usd(3.0, 15.0, 0.30, 3.75),
    );
    let st = AppState::new(
        Arc::new(Ledger::new()),
        Arc::new(prices),
        Arc::new(Policy {
            mode: Mode::Shadow,
            ..Default::default()
        }),
        Arc::new(ScriptedProvider),
        "run-owner-test",
    )
    .with_wire(Wire::Anthropic)
    .with_firewall(Arc::new(FirewallConfig::defaults(firewall)));
    match keys {
        Some(spec) => st.with_client_keys(Arc::new(
            ClientKeys::from_spec(spec).expect("a usable key spec"),
        )),
        None => st,
    }
}

fn scratch(name: &str) -> PathBuf {
    let d = std::env::temp_dir().join(format!("tf-run-owner-it-{}-{name}", std::process::id()));
    let _ = std::fs::remove_dir_all(&d);
    std::fs::create_dir_all(&d).unwrap();
    d
}

/// An identity map binding both keys to one unit, the coordinator key listing
/// the worker key under `may_parent`.
fn with_may_parent(st: AppState, tag: &str) -> AppState {
    let dir = scratch(tag);
    let path = dir.join("identity.json");
    std::fs::write(
        &path,
        r#"{"units":[{"id":"ops"}],
            "keys":[{"key_id":"key-a","unit":"ops","may_parent":["key-b"]},
                    {"key_id":"key-b","unit":"ops"}]}"#,
    )
    .unwrap();
    let map = IdentityMap::from_path(&path).expect("the map loads");
    st.with_identity(
        Arc::new(map),
        StrictMode::Off,
        Arc::new(UnitLedger::default()),
    )
}

struct Call<'a> {
    run: &'a str,
    key: Option<&'a str>,
    agent: &'a str,
    parent: Option<&'a str>,
    /// Put a web search in the history, so the run carries `web`.
    read_the_web: bool,
    ask_for_a_tool: bool,
}

impl<'a> Call<'a> {
    fn new(run: &'a str, key: Option<&'a str>, agent: &'a str) -> Self {
        Call {
            run,
            key,
            agent,
            parent: None,
            read_the_web: false,
            ask_for_a_tool: false,
        }
    }
}

async fn send(st: &AppState, c: Call<'_>) -> (StatusCode, String) {
    let last = if c.ask_for_a_tool {
        ASK_FOR_A_TOOL
    } else {
        "continue"
    };
    let messages = if c.read_the_web {
        serde_json::json!([
            {"role":"user","content":"hi"},
            {"role":"assistant","content":[{"type":"tool_use","id":"w1","name":"web_search","input":{}}]},
            {"role":"user","content":[{"type":"tool_result","tool_use_id":"w1","content":"ok"}]},
            {"role":"user","content":last}
        ])
    } else {
        serde_json::json!([{"role":"user","content":last}])
    };
    let body =
        serde_json::json!({"model":"test-model","max_tokens":100,"messages":messages}).to_string();
    let mut req = Request::post("/v1/messages")
        .header("content-type", "application/json")
        .header("x-fuse-run-id", c.run)
        .header("x-fuse-agent-id", c.agent)
        .header("x-fuse-budget-usd", "5.0");
    if let Some(k) = c.key {
        req = req.header(CLIENT_KEY_HEADER, k);
    }
    if let Some(p) = c.parent {
        req = req.header("x-fuse-parent-run-id", p);
    }
    let resp = tokenfuse_gateway::app(st.clone())
        .oneshot(req.body(Body::from(body)).unwrap())
        .await
        .unwrap();
    let status = resp.status();
    let bytes = axum::body::to_bytes(resp.into_body(), 1 << 20)
        .await
        .unwrap();
    (status, String::from_utf8_lossy(&bytes).into_owned())
}

fn error(body: &str) -> serde_json::Value {
    serde_json::from_str::<serde_json::Value>(body).unwrap_or_default()["error"].clone()
}

#[tokio::test]
async fn another_keys_run_is_refused_and_says_nothing_about_it() {
    let st = gateway(Some(KEYS), FirewallMode::Enforce);
    let mut a = Call::new("run-of-a", Some("sk-owner-a"), AGENT_A);
    a.read_the_web = true;
    let (status, body) = send(&st, a).await;
    assert_eq!(status, StatusCode::OK, "the owner opens its run: {body}");
    let before = st
        .ledger
        .snapshot("run-of-a")
        .await
        .expect("the run is open");

    // Today this answers `403 taint_blocked: tainted context [web]`: B learns
    // what A's run read, and B's call was reserved against A's budget first.
    let mut b = Call::new("run-of-a", Some("sk-owner-b"), AGENT_B);
    b.ask_for_a_tool = true;
    let (status, body) = send(&st, b).await;
    assert_eq!(status, StatusCode::FORBIDDEN, "{body}");
    let err = error(&body);
    assert_eq!(err["type"], "identity_mismatch", "{body}");
    assert_eq!(err["reason"], "run_owned_elsewhere", "{body}");
    assert!(
        !body.contains("web"),
        "nothing the run read is in the answer: {body}"
    );
    assert!(
        !body.contains("taint"),
        "the refusal is not a taint verdict about that run: {body}"
    );
    assert!(
        err.get("budget_usd").is_none() && err.get("spent_usd").is_none(),
        "no budget figure of another caller's run: {body}"
    );
    let after = st.ledger.snapshot("run-of-a").await.unwrap();
    assert_eq!(
        (after.steps, after.spent, after.reserved),
        (before.steps, before.spent, before.reserved),
        "B spent nothing in A's run"
    );
}

#[tokio::test]
async fn a_foreign_run_is_refused_whatever_the_modes() {
    // Shadow budget, firewall off: ownership is not a money or a taint
    // decision, so neither mode lets another key into the run.
    let st = gateway(Some(KEYS), FirewallMode::Off);
    let (status, _) = send(&st, Call::new("run-x", Some("sk-owner-a"), AGENT_A)).await;
    assert_eq!(status, StatusCode::OK);
    let (status, body) = send(&st, Call::new("run-x", Some("sk-owner-b"), AGENT_B)).await;
    assert_eq!(status, StatusCode::FORBIDDEN, "{body}");
    assert_eq!(error(&body)["reason"], "run_owned_elsewhere", "{body}");
    assert_eq!(
        st.ledger.snapshot("run-x").await.unwrap().steps,
        1,
        "only the owner's call reserved"
    );
}

#[tokio::test]
async fn the_owner_is_still_answered_on_its_own_run() {
    let st = gateway(Some(KEYS), FirewallMode::Enforce);
    for _ in 0..2 {
        let (status, body) = send(&st, Call::new("run-mine", Some("sk-owner-a"), AGENT_A)).await;
        assert_eq!(status, StatusCode::OK, "{body}");
    }
    assert_eq!(st.ledger.snapshot("run-mine").await.unwrap().steps, 2);
}

#[tokio::test]
async fn a_child_naming_another_keys_run_as_parent_is_refused_and_inherits_nothing() {
    let st = gateway(Some(KEYS), FirewallMode::Enforce);
    let mut a = Call::new("parent-of-a", Some("sk-owner-a"), AGENT_A);
    a.read_the_web = true;
    assert_eq!(send(&st, a).await.0, StatusCode::OK);
    let parent_before = st.ledger.snapshot("parent-of-a").await.unwrap();

    let mut b = Call::new("child-of-b", Some("sk-owner-b"), AGENT_B);
    b.parent = Some("parent-of-a");
    let (status, body) = send(&st, b).await;
    assert_eq!(status, StatusCode::FORBIDDEN, "{body}");
    let err = error(&body);
    assert_eq!(err["type"], "identity_mismatch", "{body}");
    assert_eq!(err["reason"], "parent_owned_elsewhere", "{body}");
    assert!(!body.contains("web"), "{body}");
    assert!(
        st.ledger.snapshot("child-of-b").await.is_none(),
        "nothing was opened under a parent the caller does not own"
    );
    assert!(
        st.inherited_taint("child-of-b").is_empty(),
        "the child inherits none of the parent's labels"
    );
    let parent_after = st.ledger.snapshot("parent-of-a").await.unwrap();
    assert_eq!(
        (parent_after.spent, parent_after.reserved),
        (parent_before.spent, parent_before.reserved),
        "nothing was spent from A's budget"
    );
}

#[tokio::test]
async fn a_child_under_its_own_keys_parent_is_admitted_and_inherits_as_before() {
    let st = gateway(Some(KEYS), FirewallMode::Enforce);
    let mut p = Call::new("parent-own", Some("sk-owner-a"), AGENT_A);
    p.read_the_web = true;
    assert_eq!(send(&st, p).await.0, StatusCode::OK);
    let mut c = Call::new("child-own", Some("sk-owner-a"), AGENT_A);
    c.parent = Some("parent-own");
    let (status, body) = send(&st, c).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert!(
        st.inherited_taint("child-own").contains("web"),
        "a child of the caller's own run inherits its labels, as before"
    );
}

#[tokio::test]
async fn the_identity_map_may_let_one_key_parent_anothers_runs() {
    let st = with_may_parent(gateway(Some(KEYS), FirewallMode::Enforce), "may-parent-yes");
    assert_eq!(
        send(
            &st,
            Call::new("coordinator-run", Some("sk-owner-a"), AGENT_A)
        )
        .await
        .0,
        StatusCode::OK
    );
    let mut w = Call::new("worker-run", Some("sk-owner-b"), AGENT_B);
    w.parent = Some("coordinator-run");
    let (status, body) = send(&st, w).await;
    assert_eq!(
        status,
        StatusCode::OK,
        "key-a lists key-b under may_parent: {body}"
    );
}

#[tokio::test]
async fn may_parent_runs_one_way_only() {
    let st = with_may_parent(
        gateway(Some(KEYS), FirewallMode::Enforce),
        "may-parent-one-way",
    );
    assert_eq!(
        send(&st, Call::new("worker-root", Some("sk-owner-b"), AGENT_B))
            .await
            .0,
        StatusCode::OK
    );
    let mut c = Call::new("coordinator-child", Some("sk-owner-a"), AGENT_A);
    c.parent = Some("worker-root");
    let (status, body) = send(&st, c).await;
    assert_eq!(
        status,
        StatusCode::FORBIDDEN,
        "key-b lists nobody, so key-a may not roll up into key-b's run: {body}"
    );
    assert_eq!(error(&body)["reason"], "parent_owned_elsewhere", "{body}");
}

#[tokio::test]
async fn a_parent_held_by_the_ledger_is_checked_when_the_header_is_omitted() {
    let st = gateway(Some(KEYS), FirewallMode::Enforce);
    // A parent nobody has called yet, opened at its Cloud budget on first
    // sight by B's child (invariant 49's exception): it has no owner, so B's
    // child is admitted under it.
    st.set_cloud_budgets(HashMap::from([(
        "late-parent".to_string(),
        Microusd::from_usd(5.0),
    )]));
    let mut b = Call::new("early-child", Some("sk-owner-b"), AGENT_B);
    b.parent = Some("late-parent");
    assert_eq!(send(&st, b).await.0, StatusCode::OK);
    // Then A opens that parent itself and owns it.
    let mut a = Call::new("late-parent", Some("sk-owner-a"), AGENT_A);
    a.read_the_web = true;
    assert_eq!(send(&st, a).await.0, StatusCode::OK);
    // B's next call omits the header; the ledger still rolls the child up into
    // A's run, so the check reads the parent the ledger holds.
    let (status, body) = send(&st, Call::new("early-child", Some("sk-owner-b"), AGENT_B)).await;
    assert_eq!(status, StatusCode::FORBIDDEN, "{body}");
    assert_eq!(error(&body)["reason"], "parent_owned_elsewhere", "{body}");
    assert!(!body.contains("web"), "{body}");
}

#[tokio::test]
async fn without_client_keys_any_caller_may_name_any_run_as_before() {
    let st = gateway(None, FirewallMode::Enforce);
    assert_eq!(
        send(&st, Call::new("shared-run", None, AGENT_A)).await.0,
        StatusCode::OK
    );
    assert_eq!(
        send(&st, Call::new("shared-run", None, AGENT_B)).await.0,
        StatusCode::OK,
        "a gateway that authenticates nobody has no owners"
    );
    let mut c = Call::new("shared-child", None, AGENT_B);
    c.parent = Some("shared-run");
    assert_eq!(send(&st, c).await.0, StatusCode::OK);
    assert_eq!(st.run_owner("shared-run"), None, "nothing is recorded");
}

#[tokio::test]
async fn a_refusal_for_another_principals_run_is_one_identity_mismatch_on_the_bus() {
    let dir = scratch("bus");
    let path = dir.join("events.ndjson");
    let exp = Arc::new(EventExporter::open(path.to_str().unwrap()).unwrap());
    let st = gateway(Some(KEYS), FirewallMode::Enforce).with_events(exp);
    assert_eq!(
        send(&st, Call::new("run-on-bus", Some("sk-owner-a"), AGENT_A))
            .await
            .0,
        StatusCode::OK
    );
    assert_eq!(
        send(&st, Call::new("run-on-bus", Some("sk-owner-b"), AGENT_B))
            .await
            .0,
        StatusCode::FORBIDDEN
    );
    let events: Vec<serde_json::Value> = std::fs::read_to_string(&path)
        .unwrap_or_default()
        .lines()
        .filter_map(|l| serde_json::from_str(l).ok())
        .filter(|e: &serde_json::Value| {
            e["type"] == "identity_mismatch" && e["data"]["reason"] == "run_owned_elsewhere"
        })
        .collect();
    assert_eq!(events.len(), 1, "one refusal, one event: {events:?}");
    let ev = &events[0];
    assert_eq!(ev["agent_id"], AGENT_B, "filed under the caller: {ev}");
    assert_eq!(ev["data"]["key_id"], "key-b", "{ev}");
    assert_eq!(ev["data"]["principal"], "key:key-b", "{ev}");
    assert_eq!(ev["data"]["run_id"], "run-on-bus", "{ev}");
    assert!(
        ev.get("run_id").is_none_or(|r| r.is_null()),
        "not filed under the run another principal owns: {ev}"
    );
    let _ = std::fs::remove_dir_all(&dir);
}
