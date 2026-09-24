//! W3-tokenfuse correction 2: the real `tokenfuse mcp-broker` binary is what
//! proves `main.rs` is actually wired to `xaadoor`'s startup checks. Every
//! individual refusal MESSAGE is proven once, cheaply, by `xaadoor`'s own
//! pure-function unit tests (`crates/gateway/src/xaadoor.rs`'s `mod tests`),
//! which need no process spawn; this file exists only to prove the wiring
//! itself, the one thing a unit test cannot see (same reason
//! `tests/version_and_help.rs` and `tests/admin_gate.rs` run the real
//! binary rather than calling a function).

use std::process::Command;

fn bin() -> &'static str {
    env!("CARGO_BIN_EXE_tokenfuse")
}

/// `tokenfuse mcp-broker` with a real upstream configured (so the run gets
/// past `main.rs`'s own unrelated "no upstream" early return and actually
/// reaches the XAA startup checks) and every XAA/delegation variable
/// explicitly cleared, so a pass here means "refused because of what this
/// test set", not "happened to inherit a variable from this shell".
fn run_mcp_broker(extra_env: &[(&str, &str)]) -> std::process::Output {
    let mut cmd = Command::new(bin());
    cmd.arg("mcp-broker")
        .env("TOKENFUSE_MCP_UPSTREAM", "http://127.0.0.1:1")
        .env_remove("TOKENFUSE_MCP_ACCEPT_XAA")
        .env_remove("TOKENFUSE_MCP_RESOURCE")
        .env_remove("TOKENFUSE_MCP_REQUIRE_PROOF")
        .env_remove("TOKENFUSE_DELEGATION_ISSUER")
        .env_remove("TOKENFUSE_DELEGATION_JWKS");
    for (k, v) in extra_env {
        cmd.env(k, v);
    }
    cmd.output().expect("failed to spawn the tokenfuse binary")
}

/// RED-FIRST: before `xaadoor::from_env` existed and `mcp_broker` called it,
/// `TOKENFUSE_MCP_ACCEPT_XAA` was not read anywhere in this repository, so
/// setting it to a bogus value changed nothing and the process would have
/// gone on to bind its listener (this test would time out or see exit code
/// 0/`None`, never `Some(2)`).
#[test]
fn a_bogus_accept_xaa_value_exits_2_and_names_the_variable() {
    let out = run_mcp_broker(&[("TOKENFUSE_MCP_ACCEPT_XAA", "bogus")]);
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert_eq!(out.status.code(), Some(2), "stderr was: {stderr}");
    assert!(
        stderr.contains("TOKENFUSE_MCP_ACCEPT_XAA"),
        "stderr did not name the variable: {stderr}"
    );
}

#[test]
fn accept_xaa_on_with_no_resource_exits_2_and_names_the_variable() {
    let out = run_mcp_broker(&[("TOKENFUSE_MCP_ACCEPT_XAA", "on")]);
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert_eq!(out.status.code(), Some(2), "stderr was: {stderr}");
    assert!(
        stderr.contains("TOKENFUSE_MCP_RESOURCE"),
        "stderr did not name the variable: {stderr}"
    );
}
