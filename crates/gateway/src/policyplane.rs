//! `GET /v1/policy-plane`: did the policy plane actually answer, and did it
//! ever say no.
//!
//! WHY
//!
//! On 2026-08-04 a cloud range ran this stack against a real provider and
//! recorded, as its critical finding, that every check for "the policy plane is
//! on the data path" read environment variables. None of them asked whether a
//! verdict had ever been returned. A deployment could therefore pass every
//! check it had and be governed on paper, and the run demonstrated the
//! mechanism by accident rather than by malice: an identity header was missing,
//! a healthy PDP answered nothing, the gateway reported `wardryx unreachable`,
//! and an operator following the checks would have gone to repair a machine
//! that was fine.
//!
//! This is the invariant trailryx already carries in another form: **a check
//! that cannot fail reports zero forever.** The fact that closes it is not
//! "`TOKENFUSE_WARDRYX_MODE` is set", it is "a real allow and a real deny came
//! back inside a window", and only the gateway on the data path knows that.
//!
//! WHAT THIS ENDPOINT IS NOT
//!
//! It is not a health check and it must not be wired to one. A plane that
//! answered every call `allow` for an hour is healthy and unproven, and this
//! report says both. `allow_and_deny_seen` is a claim about EVIDENCE, and the
//! evidence for a deny normally comes from a deployment drill that sends one
//! call the policy must refuse. That is the intended shape: the check fails
//! until somebody proves the refusal works, rather than passing because nothing
//! has gone wrong yet.
//!
//! It also carries no prompt content and no run identifiers, only counts and
//! timestamps, and sits on the same unauthenticated admin surface as
//! `/v1/runs`, which the README already says not to expose.

use crate::state::AppState;
use crate::wardryx::{Verdicts, WardryxMode};
use axum::extract::{Query, State};
use axum::Json;
use serde::{Deserialize, Serialize};

/// How far back the report looks when the caller does not say. An hour is long
/// enough that a deployment drill and the check that reads it need not be in
/// the same minute, and short enough that yesterday's evidence does not answer
/// for today's deployment.
pub const DEFAULT_WINDOW_MS: i64 = 3_600_000;

#[derive(Debug, Deserialize)]
pub struct WindowParam {
    window_ms: Option<i64>,
}

/// The answer. Every field is either a configured fact or a measured one, and
/// the two are never folded together: `mode` is what somebody set, everything
/// else is what happened.
#[derive(Debug, Clone, Serialize)]
pub struct PolicyPlaneReport {
    /// `off` | `shadow` | `enforce`, as resolved at startup. `off` is also what
    /// a missing `TOKENFUSE_WARDRYX_URL` forces regardless of the mode
    /// variable, which is one of the ways a deployment believes it is governed.
    pub mode: &'static str,
    pub window_ms: i64,
    /// A real verdict, of any kind, inside the window.
    pub on_data_path: bool,
    /// A real allow AND a real deny inside the window. The one this exists for.
    pub allow_and_deny_seen: bool,
    /// A synthesized outcome inside the window because the PDP did not answer.
    /// True beside `on_data_path: false` is the fail-open case: traffic flowed
    /// and nothing examined it.
    pub falling_back: bool,
    /// Counts since this process started, with the last time of each.
    pub verdicts: Verdicts,
    /// One sentence naming what is missing, so the operator reading a failed
    /// check does not have to reconstruct it from booleans.
    pub detail: String,
}

/// Build the report. Pure in `now_millis` so a test can place a verdict at a
/// chosen instant instead of sleeping.
pub fn report(
    mode: WardryxMode,
    v: Verdicts,
    now_millis: i64,
    window_ms: i64,
) -> PolicyPlaneReport {
    // A window of zero or less would make every fact false and read as a
    // broken plane rather than a broken question.
    let window_ms = window_ms.max(1);
    let within = |last: i64| last > 0 && now_millis.saturating_sub(last) <= window_ms;

    let allow = within(v.last_allow_millis);
    let deny = within(v.last_deny_millis);
    let hold = within(v.last_hold_millis);
    let falling_back = within(v.last_unreachable_millis);
    let on_data_path = allow || deny || hold;
    let allow_and_deny_seen = allow && deny;

    let mode_str = match mode {
        WardryxMode::Off => "off",
        WardryxMode::Shadow => "shadow",
        WardryxMode::Enforce => "enforce",
    };

    let detail = match (mode, on_data_path, allow_and_deny_seen) {
        (WardryxMode::Off, _, _) => "the policy hook is off on this gateway, so no call here is \
             submitted to a policy plane. Nothing in this report can make a deployment governed \
             that is not."
            .to_string(),
        (_, false, _) if falling_back => format!(
            "the hook is {mode_str} and the PDP has answered nothing in the last {window_ms}ms; \
             {} call(s) fell back to the configured failmode instead. Traffic flowed and no \
             policy examined it.",
            v.unreachable_fallbacks
        ),
        (_, false, _) => format!(
            "the hook is {mode_str} and no verdict has come back in the last {window_ms}ms. \
             Configured is not the same fact as answering, which is the whole reason this \
             endpoint exists."
        ),
        (_, true, false) => format!(
            "the plane answered in the last {window_ms}ms (allow={}, deny={}, hold={}), and this \
             window holds no evidence that it can refuse. Send one call the policy must deny and \
             read this again.",
            v.allow, v.deny, v.hold
        ),
        (_, true, true) => format!(
            "a real allow and a real deny both came back in the last {window_ms}ms: this gateway \
             is on the data path of a plane that answers and refuses."
        ),
    };

    PolicyPlaneReport {
        mode: mode_str,
        window_ms,
        on_data_path,
        allow_and_deny_seen,
        falling_back,
        verdicts: v,
        detail,
    }
}

/// `GET /v1/policy-plane[?window_ms=N]`.
pub async fn policy_plane(
    State(st): State<AppState>,
    Query(q): Query<WindowParam>,
) -> Json<PolicyPlaneReport> {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as i64)
        .unwrap_or(0);
    Json(report(
        st.wardryx.mode,
        st.wardryx.verdicts(),
        now,
        q.window_ms.unwrap_or(DEFAULT_WINDOW_MS),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn at(now: i64, v: Verdicts) -> PolicyPlaneReport {
        report(WardryxMode::Enforce, v, now, 60_000)
    }

    /// The case the whole endpoint is for: fail-open turns an unreachable PDP
    /// into an allow, so counting that as a verdict would rebuild the fault
    /// inside the check written to catch it.
    #[test]
    fn a_failmode_fallback_is_never_evidence_of_a_verdict() {
        let r = at(
            100_000,
            Verdicts {
                unreachable_fallbacks: 9,
                last_unreachable_millis: 99_000,
                ..Default::default()
            },
        );
        assert!(!r.on_data_path);
        assert!(!r.allow_and_deny_seen);
        assert!(r.falling_back);
        assert!(
            r.detail.contains("failmode"),
            "the sentence has to name what happened instead, got: {}",
            r.detail
        );
    }

    /// An allow on its own is the normal state of a healthy day and is not
    /// evidence that anything can be refused.
    #[test]
    fn allows_alone_do_not_prove_the_plane_can_refuse() {
        let r = at(
            100_000,
            Verdicts {
                allow: 400,
                last_allow_millis: 99_500,
                ..Default::default()
            },
        );
        assert!(r.on_data_path);
        assert!(!r.allow_and_deny_seen);
    }

    #[test]
    fn a_real_allow_and_a_real_deny_in_the_window_are_the_proof() {
        let r = at(
            100_000,
            Verdicts {
                allow: 400,
                deny: 1,
                last_allow_millis: 99_500,
                last_deny_millis: 60_000,
                ..Default::default()
            },
        );
        assert!(r.on_data_path);
        assert!(r.allow_and_deny_seen);
    }

    /// The window is the half that keeps this from becoming another check that
    /// cannot fail: evidence expires.
    #[test]
    fn evidence_older_than_the_window_stops_counting() {
        let v = Verdicts {
            allow: 1,
            deny: 1,
            last_allow_millis: 10_000,
            last_deny_millis: 10_000,
            ..Default::default()
        };
        assert!(report(WardryxMode::Enforce, v, 60_000, 60_000).allow_and_deny_seen);
        assert!(!report(WardryxMode::Enforce, v, 200_000, 60_000).allow_and_deny_seen);
    }

    /// A hook that was never configured says so instead of reporting a plane
    /// that is merely quiet: the two need different actions from an operator.
    #[test]
    fn an_off_hook_says_it_is_off_rather_than_unproven() {
        let r = report(WardryxMode::Off, Verdicts::default(), 100_000, 60_000);
        assert_eq!(r.mode, "off");
        assert!(!r.allow_and_deny_seen);
        assert!(r.detail.contains("off on this gateway"), "{}", r.detail);
    }

    /// A never-seen verdict is `0`, and `0` is a real epoch instant. Reading it
    /// as "just now" would make an untouched gateway report as governed, which
    /// is the failure this endpoint exists to prevent, arriving through the
    /// back door.
    #[test]
    fn a_zero_timestamp_is_never_read_as_recent() {
        let r = report(WardryxMode::Enforce, Verdicts::default(), 500, 60_000);
        assert!(!r.on_data_path);
        assert!(!r.allow_and_deny_seen);
    }
}
