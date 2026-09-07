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

use std::io::{BufRead, BufReader};
use std::process::{Child, Command, Stdio};
use std::sync::mpsc;
use std::thread;
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

/// The line `serve()` prints once it has actually bound and is accepting
/// connections (`main.rs`, `tracing::info!(%addr, "tokenfuse gateway
/// listening")`). Waiting for this rather than for the ABSENCE of an exit is
/// the whole point of this file's rewrite: a negative control that only
/// checks "did not exit within N ms" passes just as well when the guard
/// wrongly fires and the exit is real but slow to observe, which measured
/// ~3.3s in this sandbox (see `POSITIVE_CEILING` below) - comfortably past
/// any 500ms window a control could afford to wait. Waiting for a POSITIVE
/// signal closes that hole: a wrongly-refusing guard never prints this line
/// at all, so the wait times out and the control fails, regardless of how
/// slowly this sandbox surfaces the exit.
const LISTENING_NEEDLE: &str = "tokenfuse gateway listening";

/// Same ceiling and the same reasoning as `allow_stub_declaring_the_openai_wire_refuses_to_start`'s
/// `wait_up_to(..., Duration::from_secs(10))`: generous enough to clear this
/// sandbox's process-supervision latency without turning a genuine hang (the
/// broken-guard case this file's teeth experiment produces) into a slow pass.
const POSITIVE_CEILING: Duration = Duration::from_secs(10);

/// What a wait for `LISTENING_NEEDLE` found: whether the line appeared, and
/// every stdout line seen along the way (for the assertion message when it
/// did not - a bare "timed out" tells a reader nothing about whether the
/// process crashed, refused, or is simply slow).
struct StdoutWait {
    found: bool,
    lines: Vec<String>,
}

/// Reads `child`'s stdout (which must have been spawned with
/// `.stdout(Stdio::piped())`) on a background thread and waits up to
/// `timeout` for a line containing `needle`. Returns as soon as the needle
/// is seen; returns with `found: false` if the timeout elapses OR the
/// child's stdout closes first (the process exited without ever printing
/// it) - both are "the positive signal never arrived", which is exactly the
/// failure a wrongly-refusing guard produces.
fn wait_for_stdout_line(child: &mut Child, needle: &str, timeout: Duration) -> StdoutWait {
    let stdout = child
        .stdout
        .take()
        .expect("child must be spawned with stdout piped");
    let (tx, rx) = mpsc::channel::<String>();
    thread::spawn(move || {
        let reader = BufReader::new(stdout);
        for line in reader.lines().map_while(Result::ok) {
            if tx.send(line).is_err() {
                break;
            }
        }
        // Reader thread exits (dropping `tx`) when the child's stdout closes,
        // whether that is because it printed everything and is still running
        // or because the process exited. Either way `rx.recv_timeout` below
        // then returns `Err` once every already-sent line is drained, which
        // is what turns "the process exited early" into `found: false`
        // rather than a hang.
    });
    let deadline = Instant::now() + timeout;
    let mut lines = Vec::new();
    loop {
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            return StdoutWait {
                found: false,
                lines,
            };
        }
        match rx.recv_timeout(remaining) {
            Ok(line) => {
                let hit = line.contains(needle);
                lines.push(line);
                if hit {
                    return StdoutWait { found: true, lines };
                }
            }
            Err(_) => {
                return StdoutWait {
                    found: false,
                    lines,
                }
            }
        }
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
///
/// Waits for the POSITIVE `LISTENING_NEEDLE` signal rather than for the
/// absence of an exit: a guard that wrongly widened to fire here too would
/// still leave `status.is_none()` true inside any window short enough to
/// keep this test fast in the old form, which is exactly the control this
/// file's rewrite exists to fix (CLAUDE.md task-5 fix-round-1 finding 1).
#[test]
fn allow_stub_declaring_anthropic_is_unaffected_and_the_server_starts() {
    let mut child = Command::new(bin())
        .env_remove("TOKENFUSE_UPSTREAM")
        .env("TOKENFUSE_ALLOW_STUB", "1")
        .env("TOKENFUSE_WIRE", "anthropic")
        .env("TOKENFUSE_ADDR", "127.0.0.1:0")
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .expect("failed to spawn tokenfuse binary");

    let result = wait_for_stdout_line(&mut child, LISTENING_NEEDLE, POSITIVE_CEILING);
    child.kill().ok();
    child.wait().ok();

    assert!(
        result.found,
        "TOKENFUSE_WIRE=anthropic with TOKENFUSE_ALLOW_STUB=1 must reach \"{LISTENING_NEEDLE}\" \
         and keep serving, unchanged; stdout seen before giving up: {:?}",
        result.lines
    );
}

/// Same negative control with `TOKENFUSE_WIRE` unset entirely: with no
/// upstream URL to infer a shape from either, `Wire::from_declaration` falls
/// back to Anthropic, so this is the same unaffected case as above reached a
/// different way, and it existed before this task.
///
/// Same positive-signal rewrite as the sibling control above, same reason.
#[test]
fn allow_stub_with_no_wire_declared_is_unaffected_and_the_server_starts() {
    let mut child = Command::new(bin())
        .env_remove("TOKENFUSE_UPSTREAM")
        .env_remove("TOKENFUSE_WIRE")
        .env("TOKENFUSE_ALLOW_STUB", "1")
        .env("TOKENFUSE_ADDR", "127.0.0.1:0")
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .expect("failed to spawn tokenfuse binary");

    let result = wait_for_stdout_line(&mut child, LISTENING_NEEDLE, POSITIVE_CEILING);
    child.kill().ok();
    child.wait().ok();

    assert!(
        result.found,
        "with no TOKENFUSE_WIRE at all the gateway must still default to Anthropic, reach \
         \"{LISTENING_NEEDLE}\", and keep serving; stdout seen before giving up: {:?}",
        result.lines
    );
}
