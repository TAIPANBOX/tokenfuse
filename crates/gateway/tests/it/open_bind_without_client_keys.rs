//! A gateway that authenticates nobody and listens beyond loopback says so,
//! loudly at startup and in its health detail (agent-security review
//! 2026-10-17, F-010 part), on the real binary.
//!
//! The shipped image binds `0.0.0.0:4100`. With `TOKENFUSE_CLIENT_KEYS` unset,
//! anyone who can reach that port spends through it and names any run and
//! agent they like, and until this the process said nothing about it.

use crate::common::binary::Running;

const LOUD: &str = "client authentication is OFF";

async fn get(gw: &Running, path: &str) -> String {
    reqwest::get(format!("{}{path}", gw.url()))
        .await
        .expect("the gateway answers")
        .text()
        .await
        .unwrap()
}

#[tokio::test]
async fn an_open_bind_with_no_client_keys_is_said_at_startup() {
    let gw = Running::start("0.0.0.0", &[]);
    let out = gw.output();
    assert!(out.contains(LOUD), "no warning at startup:\n{out}");
    assert!(
        out.contains("TOKENFUSE_CLIENT_KEYS"),
        "the warning names the fix:\n{out}"
    );
}

#[tokio::test]
async fn the_health_detail_says_the_gateway_is_open_to_the_network() {
    let gw = Running::start("0.0.0.0", &[]);
    let detail: serde_json::Value = serde_json::from_str(&get(&gw, "/healthz?detail=1").await)
        .expect("the health detail is JSON");
    assert_eq!(detail["status"], "ok", "{detail}");
    assert_eq!(detail["client_auth"], "off", "{detail}");
    assert_eq!(detail["bind"], "not_loopback", "{detail}");
    let warnings = detail["warnings"].as_array().expect("a warnings list");
    assert!(
        warnings.iter().any(|w| w
            .as_str()
            .unwrap_or_default()
            .contains("TOKENFUSE_CLIENT_KEYS")),
        "{detail}"
    );
}

#[tokio::test]
async fn the_plain_health_answer_is_unchanged_on_any_bind() {
    // Launchers probe `/healthz` and read `ok`; that answer does not move.
    let open = Running::start("0.0.0.0", &[]);
    assert_eq!(get(&open, "/healthz").await, "ok");
    let local = Running::start("127.0.0.1", &[]);
    assert_eq!(get(&local, "/healthz").await, "ok");
}

#[tokio::test]
async fn a_loopback_bind_with_no_client_keys_is_not_warned_about() {
    let gw = Running::start("127.0.0.1", &[]);
    assert!(!gw.output().contains(LOUD), "{}", gw.output());
}

#[tokio::test]
async fn client_keys_on_an_open_bind_are_not_warned_about() {
    let gw = Running::start("0.0.0.0", &[("TOKENFUSE_CLIENT_KEYS", "sk-live-x:agent-x")]);
    assert!(!gw.output().contains(LOUD), "{}", gw.output());
}
