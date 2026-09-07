//! `TOKENFUSE_ALLOW_STUB=1` with the OpenAI wire declared and no
//! `TOKENFUSE_UPSTREAM` (CLAUDE.md task-5 finding 3, `docs/26-the-openai-door.md`).
//!
//! The built-in stub always answers a fixed, Anthropic-shaped body
//! (`provider::StubProvider`), never the OpenAI wire's `choices` shape, so a
//! deployment that declares `TOKENFUSE_WIRE=openai` while running on the stub
//! would serve every caller on `/v1/chat/completions` a body it cannot parse,
//! with nothing else in the gateway's own health signals saying so. `main.rs`
//! refuses to start in that combination rather than let it run quietly.
//!
//! Runs the real built binary (same technique as `tests/version_and_help.rs`
//! and `tests/mcp_scan_exit_code.rs`), because the decision lives in `main.rs`
//! itself and nothing in the library crate observes it.

use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

fn bin() -> &'static str {
    env!("CARGO_BIN_EXE_tokenfuse")
}

/// Polls `child` for up to `timeout` for it to exit on its own. Returns the
/// exit status if it did, `None` if it is still running when the deadline
/// passes (the caller is then responsible for killing it) - this is what
/// keeps a RED run (a refusal that does not happen) bounded instead of
/// hanging the test suite on a server that never exits.
fn wait_up_to(child: &mut Child, timeout: Duration) -> Option<std::process::ExitStatus> {
    let deadline = Instant::now() + timeout;
    loop {
        if let Some(status) = child.try_wait().expect("try_wait failed") {
            return Some(status);
        }
        if Instant::now() >= deadline {
            return None;
        }
        std::thread::sleep(Duration::from_millis(20));
    }
}

/// RED-FIRST: before this refusal existed, this combination started the
/// gateway and kept serving - `wait_up_to` times out with `status: None`,
/// and the process is killed rather than left running past the test.
///
/// The ten-second ceiling is generous on purpose: measured in this
/// sandboxed dev environment, a child that DOES exit immediately (~40ms
/// when run directly, confirmed by hand) is only observable through
/// `try_wait` from inside a `cargo test` harness process after a fixed
/// ~3.3s latency - reproduced with a plain blocking `Command::status()`
/// carrying no polling loop at all, so it is an artifact of this sandbox's
/// process supervision and not of the gateway or of this test's own logic.
/// Ten seconds comfortably clears that latency without turning a genuine
/// hang (the pre-fix behavior) into a slow pass.
#[test]
fn allow_stub_declaring_the_openai_wire_refuses_to_start() {
    let mut child = Command::new(bin())
        .env_remove("TOKENFUSE_UPSTREAM")
        .env("TOKENFUSE_ALLOW_STUB", "1")
        .env("TOKENFUSE_WIRE", "openai")
        .env("TOKENFUSE_ADDR", "127.0.0.1:0")
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("failed to spawn tokenfuse binary");

    let status = wait_up_to(&mut child, Duration::from_secs(10));
    if status.is_none() {
        child.kill().ok();
    }
    let output = child
        .wait_with_output()
        .expect("wait_with_output failed to collect the child's output");
    let stdout = String::from_utf8_lossy(&output.stdout).into_owned();
    let stderr = String::from_utf8_lossy(&output.stderr).into_owned();

    assert_eq!(
        status.and_then(|s| s.code()),
        Some(2),
        "expected the process to exit(2) within 10s; stdout: {stdout}\nstderr: {stderr}"
    );
    assert!(
        stderr.contains("TOKENFUSE_ALLOW_STUB") && stderr.contains("TOKENFUSE_WIRE"),
        "the refusal must name both variables that produced it, got: {stderr}"
    );
}

/// Negative control: the mismatch is specific to the OpenAI wire on the
/// stub. The stub's own body IS Anthropic-shaped, so `TOKENFUSE_WIRE=anthropic`
/// with `TOKENFUSE_ALLOW_STUB=1` is exactly the existing, byte-for-byte
/// unaffected offline dev loop this file's module doc already describes -
/// this must not refuse, or the refusal would be firing on a healthy
/// combination and not only the broken one.
#[test]
fn allow_stub_declaring_anthropic_is_unaffected_and_the_server_starts() {
    let mut child = Command::new(bin())
        .env_remove("TOKENFUSE_UPSTREAM")
        .env("TOKENFUSE_ALLOW_STUB", "1")
        .env("TOKENFUSE_WIRE", "anthropic")
        .env("TOKENFUSE_ADDR", "127.0.0.1:0")
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("failed to spawn tokenfuse binary");

    let status = wait_up_to(&mut child, Duration::from_millis(500));
    child.kill().ok();
    child.wait().ok();

    assert!(
        status.is_none(),
        "the process exited on its own (status: {status:?}); \
         TOKENFUSE_WIRE=anthropic with TOKENFUSE_ALLOW_STUB=1 must keep serving, unchanged"
    );
}

/// Same negative control with `TOKENFUSE_WIRE` unset entirely: with no
/// upstream URL to infer a shape from either, `Wire::from_declaration` falls
/// back to Anthropic, so this is the same unaffected case as above reached a
/// different way, and it existed before this task.
#[test]
fn allow_stub_with_no_wire_declared_is_unaffected_and_the_server_starts() {
    let mut child = Command::new(bin())
        .env_remove("TOKENFUSE_UPSTREAM")
        .env_remove("TOKENFUSE_WIRE")
        .env("TOKENFUSE_ALLOW_STUB", "1")
        .env("TOKENFUSE_ADDR", "127.0.0.1:0")
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("failed to spawn tokenfuse binary");

    let status = wait_up_to(&mut child, Duration::from_millis(500));
    child.kill().ok();
    child.wait().ok();

    assert!(
        status.is_none(),
        "the process exited on its own (status: {status:?}); with no TOKENFUSE_WIRE at all \
         the gateway must still default to Anthropic and keep serving"
    );
}
