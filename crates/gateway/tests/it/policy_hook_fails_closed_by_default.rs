//! An enforcing policy hook fails closed unless an operator chose open
//! (agent-security review 2026-10-17, F-006), on the real binary.
//!
//! `wardryx::tests` proves the default through `from_vars`; nothing there
//! proves the process READS it the way a deployment configures it. Measured
//! 2026-10-17 on the bare binary: with `TOKENFUSE_WARDRYX_MODE=enforce` and no
//! failmode, a call the policy would have denied was allowed four seconds
//! after wardryx stopped, answered `x-fuse-wardryx: allow`.

use crate::common::binary::Running;

/// A port nothing listens on, standing in for a policy plane that is down.
const PDP_DOWN: &str = "http://127.0.0.1:1";

async fn a_call(gw: &Running) -> reqwest::Response {
    reqwest::Client::new()
        .post(format!("{}/v1/messages", gw.url()))
        .header("content-type", "application/json")
        .header("x-fuse-run-id", "run-pdp-down")
        .header("x-fuse-agent-id", "agent://test.local/caller")
        .body(r#"{"model":"claude-sonnet-5","max_tokens":10,"messages":[{"role":"user","content":"hi"}]}"#)
        .send()
        .await
        .expect("the gateway answers")
}

#[tokio::test]
async fn an_enforcing_gateway_with_no_failmode_refuses_while_its_pdp_is_down() {
    let gw = Running::start(
        "127.0.0.1",
        &[
            ("TOKENFUSE_WARDRYX_MODE", "enforce"),
            ("TOKENFUSE_WARDRYX_URL", PDP_DOWN),
        ],
    );
    let resp = a_call(&gw).await;
    assert_eq!(
        resp.status(),
        reqwest::StatusCode::FORBIDDEN,
        "nothing judged this call, so enforce must not let it through. Output:\n{}",
        gw.output()
    );
    assert!(
        gw.output().contains("failmode=Closed"),
        "the startup line names the failmode in effect:\n{}",
        gw.output()
    );
}

#[tokio::test]
async fn an_explicit_open_still_opens_and_is_said_at_startup() {
    let gw = Running::start(
        "127.0.0.1",
        &[
            ("TOKENFUSE_WARDRYX_MODE", "enforce"),
            ("TOKENFUSE_WARDRYX_URL", PDP_DOWN),
            ("TOKENFUSE_WARDRYX_FAILMODE", "open"),
        ],
    );
    let resp = a_call(&gw).await;
    assert_eq!(
        resp.status(),
        reqwest::StatusCode::OK,
        "an operator who chose open gets open"
    );
    assert!(
        gw.output().contains("TOKENFUSE_WARDRYX_FAILMODE=open"),
        "the choice is said once, at startup, where an operator reads it:\n{}",
        gw.output()
    );
}
