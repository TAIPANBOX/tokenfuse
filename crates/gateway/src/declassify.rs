//! `POST /v1/fuse/declassify` — docs/07 B.4 gate 1, the release valve.
//!
//! Taint is monotonic by design: once a run has touched something untrusted it
//! carries the label for the rest of its life, and since inheritance shipped on
//! 2026-08-26 a long-lived parent makes every child untrusted forever. B.10
//! names conservativeness as the price of the model and B.4 as the valve. The
//! valve was never built, so the price had no relief, and an operator whose
//! fleet is refused all day switches the firewall off, which costs them the
//! coarse model that WAS working.
//!
//! A human reviews the content and says so. The label comes off that run.
//!
//! # What keeps this from being the bypass
//!
//! Four things, and none of them is the endpoint being hard to find.
//!
//! - **`actor` must be a `user://` principal.** An `agent://` actor is refused
//!   outright: an agent clearing its own taint is precisely the shape this must
//!   not be.
//! - **`reason` is required.** A human lifting a security control without
//!   saying why is the audit hole, not the control.
//! - **`secrets` can never be cleared.** B.9 locks anti-exfiltration on in
//!   enforce mode, and clearing that label makes the rule unreachable for the
//!   run, which is disabling it by another door.
//! - **A clearance is spent by the next arrival of that label from a block
//!   nobody signed for.** They reviewed what was there, not what comes next.
//!
//! # What "what was there" means, and why it had to be said in blocks
//!
//! Taint is re-derived from the whole `messages[]` array on every request, and
//! an agent loop resends the whole conversation. So until 2026-08-26 the valve
//! did not release: clear `web` on a run, and the next turn still carried the
//! `web_search` block a person had just reviewed, that block re-supplied the
//! label, and the run was tainted again before its next action was judged. The
//! test that proved the valve worked sent a follow-up with no tool history at
//! all, a shape no agent loop produces, so it passed against the defect.
//!
//! A review is therefore about BLOCKS, by the id both wire shapes carry. The
//! same block arriving again is not an arrival; a new one is, whatever it is
//! called and however many earlier ones were signed for. `reviewed_blocks` says
//! which, and leaving it out means the ones this gateway has seen on the run,
//! which is what was on the screen the person was reading.
//!
//! And it is recorded at `high`, the band a block takes, because an estate that
//! pages when a rule fires and stays quiet when somebody switches it off has
//! its weights backwards.
//!
//! # The credential, and an honest word about it
//!
//! `TOKENFUSE_DECLASSIFY_KEY`, presented as `x-fuse-declassify-key`. When it is
//! set it is REQUIRED. When it is not, this endpoint is protected by network
//! placement exactly as `/v1/runs/{id}/kill` is, and the event says
//! `authenticated: false` so an auditor can tell the two apart. A field that
//! was always `true` would be worth nothing.
//!
//! Making the key mandatory was the other option and was rejected: `kill` sits
//! open beside this on the same router, so a bespoke credential on one endpoint
//! would be a false comfort rather than a boundary. The boundary is the
//! deployment, and this says which side of it a clearance came from.

use axum::{extract::State, http::HeaderMap, Json};
use serde::Deserialize;
use tokenfuse_core::agent_event::{taint_cleared_data, EventType};

use crate::state::AppState;

/// How much of `reason` is recorded. Shared with every other capped detail on
/// an event: an unbounded field on the bus is a line whose length a caller
/// chose.
pub const REASON_MAX_CHARS: usize = 200;

#[derive(Debug, Deserialize)]
pub struct DeclassifyRequest {
    #[serde(default)]
    pub run_id: String,
    /// The agent whose run this is. Required, and not a formality.
    ///
    /// `Exporter::emit` SKIPS an event with no `agent_id` and counts the skip,
    /// because SPEC 6.1 forbids inventing a subject. So without this the
    /// clearance would be applied and never recorded, which is the worst
    /// outcome available here: a control lifted with no trace. Found by the
    /// test rather than by reading, and it is why this field is required
    /// instead of optional.
    ///
    /// Whoever is clearing a run knows which agent it belongs to; the console
    /// shows it beside the refusal they are acting on.
    #[serde(default)]
    pub agent_id: String,
    #[serde(default)]
    pub labels: Vec<String>,
    /// Who reviewed it. A `user://` principal; anything else is refused.
    #[serde(default)]
    pub actor: String,
    /// What they concluded. Required.
    #[serde(default)]
    pub reason: String,
    /// Which tool blocks they read, by the id both wire shapes carry
    /// (Anthropic `tool_use.id`, OpenAI `tool_calls[].id`).
    ///
    /// **Absent is the normal case and it is an inference, not a shortcut.**
    /// Empty means every block this gateway has seen on the run, which is what
    /// was on the screen the person was reading: they were looking at a
    /// refusal, and the refusal is about a conversation this gateway had just
    /// carried. Requiring ids would mean the console had to fetch the
    /// conversation, which this gateway does not store, and would push the
    /// question of what a human read onto the agent framework, which is the
    /// party this endpoint exists to overrule.
    ///
    /// Naming them explicitly is honoured, for a caller that genuinely knows.
    /// An id this run never carried refuses the whole clearance rather than
    /// being skipped: it is either a mistake or an attempt to sign for a block
    /// that has not arrived yet, and a forward-dated review is the permanent
    /// exemption this valve must not hand out.
    #[serde(default)]
    pub reviewed_blocks: Vec<String>,
}

/// Let a human's review take labels off a run.
///
/// Always HTTP 200, decision in the body, for the reason
/// `/v1/fuse/check-tool-call` gives: a status code here is indistinguishable
/// from an auth failure or a proxy in the way, and a caller that cannot tell
/// those apart cannot act on either.
pub async fn declassify(
    State(st): State<AppState>,
    headers: HeaderMap,
    Json(req): Json<DeclassifyRequest>,
) -> Json<serde_json::Value> {
    let refuse = |why: &str| {
        Json(serde_json::json!({
            "cleared": [],
            "refused": [],
            "error": why,
        }))
    };

    let expected = std::env::var("TOKENFUSE_DECLASSIFY_KEY")
        .ok()
        .filter(|v| !v.trim().is_empty());
    let presented = crate::proxy::header_str(&headers, "x-fuse-declassify-key");
    let authenticated = match (&expected, &presented) {
        (Some(want), Some(got)) if want == got => true,
        // Configured and wrong, or configured and absent: refused. A key that
        // can be omitted is not a key.
        (Some(_), _) => {
            return refuse("x-fuse-declassify-key is required on this gateway and did not match")
        }
        (None, _) => false,
    };

    if req.run_id.is_empty() {
        return refuse("run_id is required: a clearance is about one run");
    }
    if req.labels.is_empty() {
        return refuse("labels is required: name what was reviewed");
    }
    if !req.agent_id.starts_with("agent://") {
        return refuse(
            "agent_id is required and must be an agent:// URI. Without a subject \
             the clearance is applied and never recorded, and SPEC 6.1 forbids \
             inventing one",
        );
    }
    if !req.actor.starts_with("user://") {
        return refuse(
            "actor must be a user:// principal. An agent clearing its own taint is \
             the thing this endpoint must not be",
        );
    }
    if req.reason.trim().is_empty() {
        return refuse(
            "reason is required: a human lifting a control without saying why is \
             the audit hole, not the control",
        );
    }

    // Read BEFORE clearing: afterwards the run's own set no longer carries
    // them, and the answer would say a half-done job was finished.
    let still_inherited = st.taint.still_inherited(&req.run_id, &req.labels);

    // Sign for the blocks, and do it BEFORE anything is cleared: a clearance
    // that took labels off and then failed to record which blocks it covered
    // would be spent by the run's very next turn, which is the defect this
    // whole change exists to close.
    let reviewed_blocks = match st.taint.mark_reviewed(&req.run_id, &req.reviewed_blocks) {
        Ok(n) => n,
        Err(unknown) => {
            return refuse(&format!(
                "reviewed_blocks names blocks this run never carried ({}). \
                 Signing for a block that has not arrived is a review of \
                 something nobody read; omit the field to cover what this \
                 gateway has actually seen on the run",
                unknown.join(", ")
            ))
        }
    };
    let (cleared, refused) = st.taint.clear(&req.run_id, &req.labels);

    if !cleared.is_empty() {
        let outcome = st.events.emit(
            EventType::TaintCleared,
            crate::sink::now_millis(),
            // The SUBJECT is the run's agent, never the actor: the actor is a
            // person, and `agent_id` is the one field this estate promises
            // holds no natural person. Who did it travels in `data.actor`,
            // which is the payload plane's side of that line.
            Some(&req.agent_id),
            Some(&req.run_id),
            None,
            taint_cleared_data(
                &cleared,
                &req.actor,
                &req.reason,
                authenticated,
                &still_inherited,
                "",
            ),
        );
        crate::events::log_outcome(EventType::TaintCleared, outcome);
    }

    Json(serde_json::json!({
        "cleared": cleared,
        "refused": refused,
        // Named rather than left for them to discover on the next call: clear a
        // child while its parent is dirty and the label returns immediately,
        // correctly, and without this line that reads as a broken feature.
        "still_inherited": still_inherited,
        "authenticated": authenticated,
        // How many tool blocks this clearance covers, which is the scope of it.
        // Zero means the run carried no identified blocks, and an operator
        // reading zero should expect the label back on the next turn: this
        // gateway had nothing to sign for, so there is nothing to hold the
        // clearance against. Same discipline as `still_inherited`, which exists
        // because a half-done job that says nothing reads as a broken feature.
        "reviewed_blocks": reviewed_blocks,
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_key_is_required_once_it_is_configured() {
        // A key that can be omitted is not a key. Asserted on the matching
        // logic rather than through the router, because the env var is process
        // state and two async tests racing on it is a flake nobody diagnoses.
        let want = Some("s3cret".to_string());
        let matches = |got: Option<&str>| matches!((&want, got), (Some(w), Some(g)) if w == g);
        assert!(matches(Some("s3cret")));
        assert!(!matches(Some("wrong")));
        assert!(!matches(None));
    }

    #[test]
    fn a_reason_longer_than_the_cap_is_cut_rather_than_carried_whole() {
        // The cap every other free-form field on an event has, and for the same
        // reason: an unbounded field on a shared bus is a line whose length the
        // caller chose. The value is a human's sentence, so cutting it loses
        // nothing an auditor needs that the run itself does not also hold.
        let long = "x".repeat(REASON_MAX_CHARS * 3);
        let d = tokenfuse_core::agent_event::taint_cleared_data(
            &["web".to_string()],
            "user://a/b",
            &long,
            true,
            &[],
            "",
        );
        let carried = d["reason"].as_str().unwrap();
        assert!(
            carried.chars().count() <= REASON_MAX_CHARS + 1,
            "{}",
            carried.len()
        );
        assert!(carried.ends_with('…'), "a cut value says it was cut");
    }

    #[test]
    fn the_event_says_whether_anybody_authenticated() {
        // A field that was always `true` would be worth nothing. An auditor
        // reading a clearance has to tell one made behind a credential from one
        // made on network placement alone.
        for authed in [true, false] {
            let d = tokenfuse_core::agent_event::taint_cleared_data(
                &["web".to_string()],
                "user://a/b",
                "reviewed",
                authed,
                &[],
                "",
            );
            assert_eq!(d["authenticated"], authed);
        }
    }
}
