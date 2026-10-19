//! The governed profile is the default, and observation is a named choice
//! (CLAUDE.md invariant 136), proved on the real binary.
//!
//! These are the tests that only the binary can show: that `serve()` reads
//! `TOKENFUSE_PROFILE` before it binds, that the defaults it hands each
//! subsystem are the ones the feature file names, and that a refusal exits 2
//! with the three ways out named. The unit tests in `defaults` pin the parser;
//! nothing there proves `main.rs` calls it.
//!
//! Every test that starts a gateway with an unset profile gets `governed`, so
//! the assertions here state the profile they mean rather than inheriting it.

use crate::common::binary::{free_port, Running};
use std::process::{Command, Stdio};
use std::thread;
use std::time::{Duration, Instant};

/// Variables that would change what these tests read, removed before a
/// refusal test starts the binary.
const CLEARED: &[&str] = &[
    "TOKENFUSE_UPSTREAM",
    "TOKENFUSE_CLIENT_KEYS",
    "TOKENFUSE_ADMIN_KEYS",
    "TOKENFUSE_ALLOW_OPEN_OBS",
    "TOKENFUSE_PROFILE",
    "TOKENFUSE_MODE",
    "TOKENFUSE_FIREWALL",
    "TOKENFUSE_FIREWALL_CONFIG",
    "TOKENFUSE_WARDRYX_MODE",
    "TOKENFUSE_WARDRYX_URL",
    "TOKENFUSE_WARDRYX_FAILMODE",
    "TOKENFUSE_AGENT_TOKENS",
    "TOKENFUSE_DECLASSIFY_KEY",
    "TOKENFUSE_MAX_RUN_BUDGET_USD",
    "TOKENFUSE_DATA_DIR",
    "RUST_LOG",
];

const CEILING: Duration = Duration::from_secs(10);

/// Starts the binary and waits for it to exit on its own. Returns the exit
/// code and everything it wrote to stderr. A process still running at the
/// ceiling is killed and the test fails: that is the gateway serving when it
/// should have refused.
fn refusal(host: &str, extra: &[(&str, &str)]) -> (Option<i32>, String) {
    let port = free_port();
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_tokenfuse"));
    for name in CLEARED {
        cmd.env_remove(name);
    }
    cmd.env("TOKENFUSE_ALLOW_STUB", "1")
        .env("TOKENFUSE_ADDR", format!("{host}:{port}"));
    for (k, v) in extra {
        cmd.env(k, v);
    }
    let mut child = cmd
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("failed to spawn the tokenfuse binary");
    let deadline = Instant::now() + CEILING;
    let status = loop {
        if let Some(s) = child.try_wait().unwrap() {
            break Some(s);
        }
        if Instant::now() >= deadline {
            break None;
        }
        thread::sleep(Duration::from_millis(20));
    };
    let Some(status) = status else {
        child.kill().ok();
        child.wait().ok();
        panic!("the gateway kept running instead of refusing to start (bind {host})");
    };
    let mut stderr = String::new();
    std::io::Read::read_to_string(&mut child.stderr.take().unwrap(), &mut stderr).ok();
    (status.code(), stderr)
}

fn body() -> serde_json::Value {
    serde_json::json!({
        "model": "claude-haiku-5-5",
        "max_tokens": 100,
        "messages": [{"role": "user", "content": "hi"}],
    })
}

/// A call whose declared run budget is one micro-dollar, far below any
/// estimate for a hundred output tokens.
async fn call_over_budget(gw: &Running) -> reqwest::StatusCode {
    reqwest::Client::new()
        .post(format!("{}/v1/messages", gw.url()))
        .header("x-fuse-run-id", "governed-budget-run")
        .header("x-fuse-budget-usd", "0.000001")
        .json(&body())
        .send()
        .await
        .expect("the gateway answers")
        .status()
}

/// RED-FIRST: before `serve()` read `TOKENFUSE_PROFILE`, an unknown value was
/// ignored and the gateway came up. Against the unfixed binary this fails with
/// "kept running".
#[tokio::test]
async fn an_unknown_profile_value_is_refused_naming_both_profiles() {
    let (code, stderr) = refusal("127.0.0.1", &[("TOKENFUSE_PROFILE", "gov")]);
    assert_eq!(code, Some(2), "stderr was: {stderr}");
    for needle in ["TOKENFUSE_PROFILE", "governed", "observe"] {
        assert!(stderr.contains(needle), "{needle} missing from: {stderr}");
    }
}

/// RED-FIRST: today the default lets a call over its budget through in shadow.
#[tokio::test]
async fn under_the_governed_profile_a_call_over_its_budget_is_refused() {
    let gw = Running::start("127.0.0.1", &[]);
    assert_eq!(
        call_over_budget(&gw).await,
        reqwest::StatusCode::PAYMENT_REQUIRED,
        "{}",
        gw.output()
    );
}

/// The guard: an operator who set a budget mode keeps it.
#[tokio::test]
async fn an_explicit_policy_mode_wins_over_the_governed_default() {
    let gw = Running::start("127.0.0.1", &[("TOKENFUSE_MODE", "shadow")]);
    assert_eq!(call_over_budget(&gw).await, reqwest::StatusCode::OK);
}

/// The guard: observe is today's default, byte for byte, and it says so.
#[tokio::test]
async fn under_the_observe_profile_a_call_over_its_budget_is_forwarded() {
    let gw = Running::start("127.0.0.1", &[("TOKENFUSE_PROFILE", "observe")]);
    assert_eq!(call_over_budget(&gw).await, reqwest::StatusCode::OK);
    assert!(gw.output().contains("enforces nothing"), "{}", gw.output());
}

/// RED-FIRST: today the hook starts in mode Off whatever the URL says.
#[tokio::test]
async fn under_the_governed_profile_the_wardryx_hook_enforces_when_a_pdp_is_named() {
    let gw = Running::start(
        "127.0.0.1",
        &[("TOKENFUSE_WARDRYX_URL", "http://127.0.0.1:9")],
    );
    let out = gw.output();
    assert!(out.contains("mode=Enforce"), "{out}");
    assert!(out.contains("failmode=Closed"), "{out}");
}

/// RED-FIRST: today the firewall starts in shadow, so a write after the web is
/// allowed at the check.
#[tokio::test]
async fn under_the_governed_profile_the_firewall_enforces_by_default() {
    let gw = Running::start("127.0.0.1", &[]);
    let client = reqwest::Client::new();
    // The run reads the web (the caller declares the label, as a framework does).
    let call = client
        .post(format!("{}/v1/messages", gw.url()))
        .header("x-fuse-run-id", "governed-firewall-run")
        .header("x-fuse-taint", "web")
        .json(&body())
        .send()
        .await
        .unwrap();
    assert_eq!(call.status(), reqwest::StatusCode::OK, "{}", gw.output());
    let check: serde_json::Value = client
        .post(format!("{}/v1/fuse/check-tool-call", gw.url()))
        .json(&serde_json::json!({
            "run_id": "governed-firewall-run",
            "tool": "write_file",
        }))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(check["decision"], "deny", "{check}");
}

/// RED-FIRST: today the five admin routes answer anyone on loopback.
#[tokio::test]
async fn under_the_governed_profile_the_admin_routes_refuse_loopback_without_a_key() {
    let gw = Running::start("127.0.0.1", &[]);
    let status = reqwest::get(format!("{}/v1/runs", gw.url()))
        .await
        .unwrap()
        .status();
    assert_eq!(status, reqwest::StatusCode::FORBIDDEN, "{}", gw.output());
}

/// The guard: the existing escape hatch still restores the old behaviour.
#[tokio::test]
async fn allow_open_obs_still_restores_the_open_admin_routes_under_governed() {
    let gw = Running::start("127.0.0.1", &[("TOKENFUSE_ALLOW_OPEN_OBS", "1")]);
    let status = reqwest::get(format!("{}/v1/runs", gw.url()))
        .await
        .unwrap()
        .status();
    assert_eq!(status, reqwest::StatusCode::OK);
}

/// RED-FIRST: today a clearance with no key is applied; the answer carries no
/// error at all.
#[tokio::test]
async fn under_the_governed_profile_declassify_refuses_without_its_key() {
    let gw = Running::start("127.0.0.1", &[]);
    let answer: serde_json::Value = reqwest::Client::new()
        .post(format!("{}/v1/fuse/declassify", gw.url()))
        .json(&serde_json::json!({
            "run_id": "governed-declassify-run",
            "agent_id": "agent://acme/a",
            "labels": ["web"],
            "actor": "user://ops/alice",
            "reason": "reviewed the page",
        }))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let error = answer["error"].as_str().unwrap_or_default();
    assert!(error.contains("TOKENFUSE_DECLASSIFY_KEY"), "{answer}");
}

/// RED-FIRST: today a wide bind with nothing authenticating starts.
#[test]
fn under_the_governed_profile_a_non_loopback_bind_without_client_auth_refuses_to_start() {
    let (code, stderr) = refusal("0.0.0.0", &[]);
    assert_eq!(code, Some(2), "stderr was: {stderr}");
    for needle in [
        "TOKENFUSE_CLIENT_KEYS",
        "TOKENFUSE_AGENT_TOKENS",
        "TOKENFUSE_PROFILE=observe",
    ] {
        assert!(stderr.contains(needle), "{needle} missing from: {stderr}");
    }
}

/// RED-FIRST: today the observe profile is not read, so nothing says it
/// enforces nothing. The warning from invariant 119 is still there.
#[tokio::test]
async fn under_the_observe_profile_a_non_loopback_bind_starts_with_the_warning() {
    let gw = Running::start("0.0.0.0", &[("TOKENFUSE_PROFILE", "observe")]);
    let out = gw.output();
    assert!(out.contains("enforces nothing"), "{out}");
    assert!(out.contains("client authentication is OFF"), "{out}");
}

/// The guard: a loopback gateway with nothing else set still starts.
#[test]
fn a_loopback_bind_under_the_governed_profile_starts_without_client_keys() {
    let gw = Running::start("127.0.0.1", &[]);
    assert!(gw.output().contains("tokenfuse gateway listening"));
}

/// RED-FIRST: today no line names the profile or the settings.
#[test]
fn the_startup_line_names_each_governed_setting_and_where_it_came_from() {
    let gw = Running::start("127.0.0.1", &[("TOKENFUSE_MODE", "warn")]);
    let out = gw.output();
    assert!(out.contains("governance profile=governed"), "{out}");
    assert!(out.contains("budget=warn(env)"), "{out}");
    assert!(out.contains("firewall=enforce(profile)"), "{out}");
}

/// RED-FIRST: today the health detail has no profile member.
#[tokio::test]
async fn the_health_detail_names_the_profile() {
    let gw = Running::start("127.0.0.1", &[]);
    let detail: serde_json::Value = reqwest::get(format!("{}/healthz?detail=1", gw.url()))
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(detail["profile"], "governed", "{detail}");
}
