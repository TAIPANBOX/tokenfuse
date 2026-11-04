//! `POST /v1/fuse/observed-act`: a label a run carries because of what an
//! enforcement point SAW it do (CLAUDE.md invariant 143).
//!
//! Every other way a label arrives reads a string the caller wrote. A run's tool
//! history is the caller's own `messages[]`, so `labels_for_tools` answers "has
//! this run touched an untrusted source" from a name the agent reported, and the
//! network act behind the name is invisible. An agent that renames a fetch to
//! something the source map trusts, or leaves the block out of the conversation,
//! has no web label at all.
//!
//! This is the other direction. `tokenfuse mcp-broker` forwards a `tools/call` to
//! an upstream the operator classified, the upstream answers, and the broker says
//! so here BEFORE it hands the answer back. What supplies the label is which
//! server answered, which the broker knows because it made the connection. The
//! tool name plays no part in it, and this route has no member that could carry
//! one.
//!
//! # Why it only ever adds
//!
//! Taint is monotonic, so a caller reaching this route directly can make its own
//! run more restricted and never less, which is exactly what `x-fuse-taint` has
//! always let it do. That is why a label the broker names needs no second opinion
//! here: there is nothing to gain by naming one. The classification is therefore
//! the broker's configuration and the judging stays this gateway's, one judge
//! reached from both doors (docs/07 B.7).
//!
//! # What it answers
//!
//! HTTP 200 for every question it answers, the decision in the body, for
//! `/v1/fuse/check-tool-call`'s reason. `recorded: true` is the only answer the
//! broker hands a result back on, except `governed: false`: a firewall that is off
//! labels nothing and judges nothing, and withholding a page in its name would be
//! refusing on behalf of a control the operator turned off.

use axum::response::{IntoResponse, Response};
use axum::{extract::State, http::HeaderMap, Json};
use serde::Deserialize;
use tokenfuse_core::agent_event::{taint_raised_data, EventType, TaintStage};
use tokenfuse_core::taint::{FirewallMode, Labels};

use crate::state::AppState;

/// The route this is served at, which a proof presented to it names.
pub const OBSERVED_ACT_PATH: &str = "/v1/fuse/observed-act";

/// The most labels one act may name. A classification is a short list an operator
/// wrote; anything longer is not one, and the set it would grow is held per run.
pub const MAX_LABELS: usize = 16;

/// The longest label or source this route keeps. Both reach the shared bus.
pub const MAX_NAME_CHARS: usize = 128;

/// What an enforcement point saw. Closed on purpose: a member this route does not
/// read is refused rather than dropped, so a tool name cannot arrive here and look
/// as though it mattered.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ObservedAct {
    /// The run the act belongs to. Required: taint is per run.
    #[serde(default)]
    pub run_id: String,
    /// The labels the act's output carries, as the operator classified the
    /// enforcement point that saw it.
    #[serde(default)]
    pub labels: Vec<String>,
    /// Which enforcement point saw it, `mcp:<upstream>`, for the record.
    #[serde(default)]
    pub source: String,
}

fn now_millis() -> i64 {
    crate::sink::now_millis()
}

/// Put what an enforcement point saw on the run it belongs to.
///
/// The same door as `/v1/fuse/check-tool-call`, relay included (invariant 118): a
/// client key or an agent token, and the MCP broker's relay of a token beside its
/// own key.
pub async fn observed_act(
    State(st): State<AppState>,
    headers: HeaderMap,
    Json(req): Json<ObservedAct>,
) -> Response {
    let caller = match crate::proxy::resolve_caller(&st, &headers, OBSERVED_ACT_PATH, true) {
        Ok(caller) => caller,
        Err(refused) => return refused,
    };
    answer(&st, &headers, &caller, req).into_response()
}

fn refused(reason: &str) -> Json<serde_json::Value> {
    Json(serde_json::json!({
        "recorded": false,
        "governed": true,
        "reason": reason,
    }))
}

fn answer(
    st: &AppState,
    headers: &HeaderMap,
    caller: &crate::proxy::Caller,
    req: ObservedAct,
) -> Json<serde_json::Value> {
    if st.firewall.mode == FirewallMode::Off {
        return Json(serde_json::json!({
            "recorded": false,
            "governed": false,
            "reason": "the agent firewall is off on this gateway; nothing carries a label",
        }));
    }
    if req.run_id.is_empty() || req.labels.is_empty() {
        return refused("an observed act needs a run_id and at least one label");
    }
    let too_long = |s: &str| s.chars().count() > MAX_NAME_CHARS;
    if req.labels.len() > MAX_LABELS
        || req.labels.iter().any(|l| l.is_empty() || too_long(l))
        || too_long(&req.source)
    {
        return refused("an observed act names at most 16 labels of at most 128 characters");
    }

    // Another principal's run takes nothing from this caller (invariant 118). The
    // broker's own check has already refused the call by now, so a caller meets
    // this only by coming here directly.
    let principal = caller.principal.as_str();
    let foreign = !principal.is_empty()
        && st
            .run_owner(&req.run_id)
            .is_some_and(|owner| owner != principal);
    if foreign {
        return refused("this run was opened under another client key");
    }

    let delta = st.accumulate_taint(&req.run_id, req.labels.iter().cloned().collect::<Labels>());
    let added: Vec<String> = delta.added.iter().cloned().collect();
    let carrying: Vec<String> = delta.carrying.iter().cloned().collect();
    if !added.is_empty() {
        let agent_id = caller.agent_id().unwrap_or_else(|| {
            crate::proxy::header_str(headers, "x-fuse-agent-id").unwrap_or_default()
        });
        let outcome = st.events.emit(
            EventType::TaintRaised,
            now_millis(),
            Some(&agent_id),
            Some(&req.run_id),
            None,
            // The stage says which door, and `from_tools` names the enforcement
            // point rather than the tool: the tool's name is the one thing here a
            // caller chose. No prompt at this door, and no URL ever reaches it.
            taint_raised_data(
                TaintStage::McpToolCall,
                &added,
                std::slice::from_ref(&req.source),
                &carrying,
                None,
                &[],
                "",
            ),
        );
        crate::events::log_outcome(EventType::TaintRaised, outcome);
    }
    Json(serde_json::json!({
        "recorded": true,
        "governed": true,
        "added": added,
        "carrying": carrying,
    }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::firewall::FirewallConfig;
    use axum::body::Body;
    use axum::http::{Request, StatusCode};
    use http_body_util::BodyExt;
    use std::sync::Arc;
    use tower::ServiceExt;

    async fn post(st: AppState, body: &str) -> (StatusCode, Option<serde_json::Value>) {
        let req = Request::post(OBSERVED_ACT_PATH)
            .header("content-type", "application/json")
            .header("x-fuse-agent-id", "agent://test.local/broker")
            .body(Body::from(body.to_string()))
            .unwrap();
        let resp = crate::app(st).oneshot(req).await.unwrap();
        let status = resp.status();
        let bytes = resp.into_body().collect().await.unwrap().to_bytes();
        (status, serde_json::from_slice(&bytes).ok())
    }

    /// A gateway with nothing but a firewall, for `toolcheck`'s reason: this route
    /// never reaches a provider, and a fixture that handed it one would let a
    /// future version quietly start depending on it.
    fn state_with(firewall: FirewallConfig) -> AppState {
        struct NeverCalled;
        #[async_trait::async_trait]
        impl crate::provider::Provider for NeverCalled {
            async fn send(
                &self,
                _h: axum::http::HeaderMap,
                _b: bytes::Bytes,
            ) -> Result<crate::provider::ProviderResponse, crate::provider::ProviderError>
            {
                panic!("an observed act must never reach a provider")
            }
        }
        let mut st = AppState::new(
            Arc::new(tokenfuse_core::ledger::Ledger::new()),
            Arc::new(tokenfuse_core::PriceBook::new()),
            Arc::new(tokenfuse_core::policy::Policy::default()),
            Arc::new(NeverCalled),
            "test-policy",
        );
        st.firewall = Arc::new(firewall);
        st
    }

    fn enforcing() -> AppState {
        state_with(FirewallConfig::defaults(FirewallMode::Enforce))
    }

    #[tokio::test]
    async fn an_act_puts_its_labels_on_the_run_and_says_what_it_added() {
        let st = enforcing();
        let (status, body) = post(
            st.clone(),
            r#"{"run_id":"r1","labels":["web"],"source":"mcp:scopyx"}"#,
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        let body = body.unwrap();
        assert_eq!(body["recorded"], true, "{body}");
        assert_eq!(body["added"], serde_json::json!(["web"]));
        assert!(st.taint.judged_against("r1").contains("web"));
    }

    #[tokio::test]
    async fn this_route_cannot_be_told_a_tool_name() {
        // Closed, so a name sent here is a refusal and not a member that was
        // quietly read or quietly dropped.
        let st = enforcing();
        let (status, _) = post(
            st.clone(),
            r#"{"run_id":"r2","labels":["web"],"source":"mcp:scopyx","tool":"crm_lookup"}"#,
        )
        .await;
        assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY);
        assert!(st.taint.judged_against("r2").is_empty());
    }

    #[tokio::test]
    async fn an_act_that_names_nothing_labels_nothing() {
        for body in [
            r#"{"labels":["web"]}"#,
            r#"{"run_id":"r3"}"#,
            r#"{"run_id":"r3","labels":[]}"#,
            r#"{"run_id":"r3","labels":[""]}"#,
        ] {
            let st = enforcing();
            let (status, answer) = post(st.clone(), body).await;
            assert_eq!(status, StatusCode::OK, "{body}");
            assert_eq!(answer.unwrap()["recorded"], false, "{body}");
            assert!(st.taint.judged_against("r3").is_empty(), "{body}");
        }
    }

    #[tokio::test]
    async fn hostile_acts_are_refused_and_never_grow_the_run() {
        // 200 seeded bodies either side of both bounds. The expected verdict is
        // the bounds written out again here, not read from the code under test.
        let mut state: u64 = 0x0b5e_12ed_0ac7_2026;
        let mut draw = |n: u64| {
            state = state
                .wrapping_mul(6_364_136_223_846_793_005)
                .wrapping_add(1_442_695_040_888_963_407);
            (state >> 33) % n
        };
        for case in 0..200 {
            let count = 1 + draw(24) as usize;
            let len = 1 + draw(200) as usize;
            let labels: Vec<String> = (0..count)
                .map(|i| format!("{i}{}", "x".repeat(len)))
                .collect();
            let widest = labels.iter().map(|l| l.chars().count()).max().unwrap();
            let expect = count <= 16 && widest <= 128;
            let body = serde_json::json!({"run_id": "r4", "labels": labels, "source": "mcp:s"});
            let st = enforcing();
            let (_, answer) = post(st.clone(), &body.to_string()).await;
            assert_eq!(answer.unwrap()["recorded"], expect, "case {case}");
            assert_eq!(
                !st.taint.judged_against("r4").is_empty(),
                expect,
                "case {case}"
            );
        }
    }

    #[tokio::test]
    async fn a_firewall_that_is_off_records_nothing_and_says_it_governs_nothing() {
        let st = state_with(FirewallConfig::disabled());
        let (_, body) = post(st.clone(), r#"{"run_id":"r5","labels":["web"]}"#).await;
        let body = body.unwrap();
        assert_eq!(body["recorded"], false);
        assert_eq!(body["governed"], false);
        assert!(st.taint.judged_against("r5").is_empty());
    }
}
