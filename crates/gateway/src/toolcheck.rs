//! `POST /v1/fuse/check-tool-call` — docs/07 B.7 level 2, the hard guarantee.
//!
//! Level 1 is what this gateway had: it sees `tool_use` in the model's answer
//! and replaces the response with a 403. The model REQUESTS a tool call and the
//! CLIENT executes it, so a caller that ignores the 403 runs the tool anyway,
//! and the spec has always said so in as many words. Every enforcement claim
//! this product made was therefore advisory, and B.10 listed that as a
//! limitation for seven weeks.
//!
//! This is the other side: an executor asks BEFORE it runs a tool, and acts on
//! the answer because acting on it is the whole reason it asked. The guarantee
//! is not stronger cryptography, it is a different order of operations.
//!
//! It judges and does not accumulate. A tool's OUTPUT is what carries taint,
//! and the gateway sees that in the next request's message history, so a check
//! that added labels here would be counting a tool that has not run yet.
//!
//! # The answer distinguishes three things, not two
//!
//! `allow` because nothing objected, `allow` because the firewall is OFF, and
//! `allow` because it is in shadow and a rule DID object. An SDK that folded
//! those together would report "the gateway permitted this" for a box where
//! nothing was asked, which is the `allowed_ungoverned` mistake one plane over.

use axum::{extract::State, http::HeaderMap, Json};
use serde::Deserialize;
use tokenfuse_core::agent_event::{taint_verdict_data, EventType, TaintEnforcement, TaintStage};
use tokenfuse_core::taint::{self, FirewallMode};

use crate::state::AppState;

/// Wall clock in millis, the same source every emission site here uses.
fn now_millis() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as i64)
        .unwrap_or(0)
}

/// What an executor asks about.
#[derive(Debug, Deserialize)]
pub struct CheckRequest {
    /// The run the tool would execute in. Required: taint is per run, so a
    /// check without one has nothing to be judged against, and answering
    /// `allow` to it would be answering a question nobody asked.
    #[serde(default)]
    pub run_id: String,
    /// One tool, for the common case.
    #[serde(default)]
    pub tool: Option<String>,
    /// Or several, for an executor batching a turn's calls.
    #[serde(default)]
    pub tools: Vec<String>,
    /// Which door is asking: `"mcp"` for the broker (docs/07 B.7 level 3),
    /// anything else for an SDK executor (level 2).
    ///
    /// It changes only the `stage` on the record, and it changes it because a
    /// reader needs to know whether a tool was stopped because an SDK asked
    /// politely or because it went through a door that stops things whether or
    /// not anybody asks. It never changes the DECISION: a caller that could
    /// talk itself into a different answer by naming a different door would be
    /// a caller choosing its own policy.
    #[serde(default)]
    pub via: Option<String>,
}

impl CheckRequest {
    fn tool_names(&self) -> Vec<String> {
        let mut out = self.tools.clone();
        if let Some(t) = &self.tool {
            if !t.is_empty() && !out.contains(t) {
                out.push(t.clone());
            }
        }
        out
    }
}

/// Judge a tool call an executor is about to make.
///
/// Always HTTP 200. The decision is in the body, deliberately: an executor
/// asking permission is not itself an error, a 403 here would be
/// indistinguishable from an auth failure or a proxy in the way, and a client
/// that cannot tell those apart has to choose between failing closed on a
/// network blip and failing open on a refusal.
pub async fn check_tool_call(
    State(st): State<AppState>,
    headers: HeaderMap,
    Json(req): Json<CheckRequest>,
) -> Json<serde_json::Value> {
    let agent_id = crate::proxy::header_str(&headers, "x-fuse-agent-id").unwrap_or_default();
    let unit = String::new();

    if st.firewall.mode == FirewallMode::Off {
        return Json(serde_json::json!({
            "decision": "allow",
            // Never just `allow`. Nothing was asked, and an executor recording
            // "the gateway permitted this" would be recording a governance gap
            // as a permission.
            "governed": false,
            "reason": "the agent firewall is off on this gateway; nothing judged this call",
        }));
    }

    let stage = if req.via.as_deref() == Some("mcp") {
        TaintStage::McpToolCall
    } else {
        TaintStage::ToolCallCheck
    };
    let names = req.tool_names();
    if req.run_id.is_empty() || names.is_empty() {
        return Json(serde_json::json!({
            "decision": "allow",
            "governed": false,
            "reason": "a check needs a run_id and at least one tool; taint is per run",
        }));
    }

    // The same three inputs the model-tool-call path uses, in the same order,
    // so the two doors cannot answer differently about one run.
    st.note_taint_parent(&req.run_id, "");
    let mut labels = st
        .accumulate_taint(&req.run_id, Default::default())
        .carrying;
    labels.extend(st.inherited_taint(&req.run_id));
    let requested = taint::capabilities_for_tools(&names, &st.firewall.capabilities);

    let Some(verdict) = taint::evaluate(&labels, &requested, &st.firewall.rules) else {
        return Json(serde_json::json!({
            "decision": "allow",
            "governed": true,
            "carrying": labels.iter().cloned().collect::<Vec<_>>(),
        }));
    };

    let enforcing = st.firewall.mode == FirewallMode::Enforce;
    let event = if enforcing {
        EventType::TaintBlock
    } else {
        EventType::TaintShadow
    };
    let outcome = st.events.emit(
        event,
        now_millis(),
        Some(&agent_id),
        Some(&req.run_id),
        None,
        taint_verdict_data(
            stage,
            if enforcing {
                TaintEnforcement::Enforce
            } else {
                TaintEnforcement::Shadow
            },
            &verdict,
            &names,
            // No prompt at this door: an executor asking whether it may run a
            // tool sends the tool, not the conversation. Absent rather than
            // empty, so a reader can tell "this door never sees one" from
            // "this turn had none".
            None,
            &unit,
        ),
    );
    crate::events::log_outcome(event, outcome);

    Json(serde_json::json!({
        "decision": if enforcing { "deny" } else { "allow" },
        "governed": true,
        // Present on a shadow allow and absent on a clean one, so an executor
        // that wants to be stricter than its gateway has something to read.
        "would_block": (!enforcing).then(|| verdict.reason()),
        "reason": verdict.reason(),
        "rule": verdict.rule,
        "denied": verdict.denied,
        "carrying": verdict.labels,
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

    async fn ask(st: AppState, body: &str) -> serde_json::Value {
        let req = Request::post("/v1/fuse/check-tool-call")
            .header("content-type", "application/json")
            .header("x-fuse-agent-id", "agent://test.local/executor")
            .body(Body::from(body.to_string()))
            .unwrap();
        let resp = crate::app(st).oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK, "the decision is in the body");
        let bytes = resp.into_body().collect().await.unwrap().to_bytes();
        serde_json::from_slice(&bytes).unwrap()
    }

    /// A gateway with nothing but a firewall.
    ///
    /// Built here rather than borrowed from `proxy`'s test helper on purpose:
    /// this endpoint never reaches a provider, a ledger or a price book, and a
    /// fixture that handed it those would let a future version quietly start
    /// depending on one.
    fn state_with(mode: FirewallMode) -> AppState {
        struct NeverCalled;
        #[async_trait::async_trait]
        impl crate::provider::Provider for NeverCalled {
            async fn send(
                &self,
                _h: axum::http::HeaderMap,
                _b: bytes::Bytes,
            ) -> Result<crate::provider::ProviderResponse, crate::provider::ProviderError>
            {
                panic!("check-tool-call must never reach a provider")
            }
        }
        let mut st = AppState::new(
            Arc::new(tokenfuse_core::ledger::Ledger::new()),
            Arc::new(tokenfuse_core::PriceBook::new()),
            Arc::new(tokenfuse_core::policy::Policy::default()),
            Arc::new(NeverCalled),
            "test-policy",
        );
        st.firewall = Arc::new(FirewallConfig::defaults(mode));
        st
    }

    #[tokio::test]
    async fn an_executor_can_ask_before_it_runs_the_tool() {
        // docs/07 B.7 level 2, and the reason it is the hard one: level 1 tells
        // the client after the model has already asked, and the client is free
        // to run the tool anyway. This answers before.
        let st = state_with(FirewallMode::Enforce);
        st.accumulate_taint("run-l2", ["web".to_string()].into_iter().collect());
        let a = ask(st, r#"{"run_id":"run-l2","tool":"run_shell"}"#).await;
        assert_eq!(a["decision"], "deny");
        assert_eq!(a["governed"], true);
        assert_eq!(a["rule"], "no-exec-after-untrusted");
        assert_eq!(a["denied"], serde_json::json!(["exec"]));
    }

    #[tokio::test]
    async fn the_two_doors_answer_the_same_way_about_one_run() {
        // The property that makes level 2 worth having rather than a second
        // opinion: an executor that asks first and a model whose answer is
        // judged must not be told different things about the same run and the
        // same tool, or an operator reading the trail sees a contradiction and
        // trusts neither.
        let st = state_with(FirewallMode::Enforce);
        st.accumulate_taint("run-agree", ["secrets".to_string()].into_iter().collect());

        let exec = ask(st.clone(), r#"{"run_id":"run-agree","tool":"send_email"}"#).await;
        let labels = st
            .accumulate_taint("run-agree", Default::default())
            .carrying;
        let requested =
            taint::capabilities_for_tools(&["send_email".to_string()], &st.firewall.capabilities);
        let direct = taint::evaluate(&labels, &requested, &st.firewall.rules).unwrap();

        assert_eq!(exec["decision"], "deny");
        assert_eq!(exec["rule"], direct.rule);
        assert_eq!(exec["reason"], direct.reason());
    }

    #[tokio::test]
    async fn a_clean_run_is_allowed_and_says_it_was_actually_judged() {
        let st = state_with(FirewallMode::Enforce);
        let a = ask(st, r#"{"run_id":"run-clean","tool":"run_shell"}"#).await;
        assert_eq!(a["decision"], "allow");
        assert_eq!(a["governed"], true, "judged and permitted");
    }

    #[tokio::test]
    async fn a_firewall_that_is_off_says_allow_and_ungoverned_not_just_allow() {
        // The `allowed_ungoverned` distinction, one plane over. An executor
        // that recorded "the gateway permitted this" for a box where nothing
        // was asked would file a governance gap as a permission, which is the
        // exact mistake `dependency_failed.effect` was cut to prevent.
        let st = state_with(FirewallMode::Off);
        let a = ask(st, r#"{"run_id":"run-off","tool":"run_shell"}"#).await;
        assert_eq!(a["decision"], "allow");
        assert_eq!(a["governed"], false);
        assert!(a["reason"].as_str().unwrap().contains("off"));
    }

    #[tokio::test]
    async fn shadow_allows_and_hands_back_what_it_would_have_refused() {
        // So an executor may be stricter than its gateway: the box is still
        // learning, and a client that wants to fail closed can, without
        // waiting for somebody to flip the mode.
        let st = state_with(FirewallMode::Shadow);
        st.accumulate_taint("run-l2-shadow", ["web".to_string()].into_iter().collect());
        let a = ask(st, r#"{"run_id":"run-l2-shadow","tool":"run_shell"}"#).await;
        assert_eq!(a["decision"], "allow");
        assert_eq!(a["governed"], true);
        assert!(a["would_block"]
            .as_str()
            .unwrap()
            .contains("denies capability"));
    }

    #[tokio::test]
    async fn a_check_with_no_run_is_not_answered_as_though_it_had_been_judged() {
        // Taint is per run. Answering a bare `allow` to a question with no
        // subject would be the worst shape available here: an executor gets
        // permission for a check nothing could have refused.
        let st = state_with(FirewallMode::Enforce);
        let a = ask(st.clone(), r#"{"tool":"run_shell"}"#).await;
        assert_eq!(a["decision"], "allow");
        assert_eq!(a["governed"], false);
        let b = ask(st, r#"{"run_id":"run-x"}"#).await;
        assert_eq!(
            b["governed"], false,
            "no tool is the same shape of question"
        );
    }

    #[tokio::test]
    async fn a_sub_run_is_checked_against_what_its_parent_touched() {
        // The bypass closed in `proxy.rs` has to be closed at this door too, or
        // level 2 becomes the easier way round level 1.
        let st = state_with(FirewallMode::Enforce);
        st.accumulate_taint("l2-parent", ["web".to_string()].into_iter().collect());
        st.note_taint_parent("l2-child", "l2-parent");
        let a = ask(st, r#"{"run_id":"l2-child","tool":"run_shell"}"#).await;
        assert_eq!(a["decision"], "deny");
        assert_eq!(a["carrying"], serde_json::json!(["web"]));
    }
}
