//! CLAUDE.md invariant 98, the seam the unit tests in `defaults.rs` cannot
//! see. `defaults::*_from` proves each parser; nothing there proves that
//! `main.rs` READS the variable through the parser, before the listener
//! binds, in each process. Deleting one call leaves every unit test green.
//! These run the real binary, one per process that reads a changed switch:
//! `serve` (the LLM proxy) and `mcp-broker`.
//!
//! The same shape as `firewall_mode_startup.rs` (invariant 94): a value the
//! process cannot read exits 2 naming the variable, the value and the words
//! it accepts, and never reaches its listening line.

use std::io::{BufRead, BufReader, Read};
use std::process::{Child, Command, Stdio};
use std::sync::mpsc;
use std::thread;
use std::time::{Duration, Instant};

fn bin() -> &'static str {
    env!("CARGO_BIN_EXE_tokenfuse")
}

const GATEWAY_LISTENING: &str = "tokenfuse gateway listening";
const BROKER_LISTENING: &str = "mcp credential-broker listening";
const CEILING: Duration = Duration::from_secs(10);

fn free_addr() -> String {
    let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let a = l.local_addr().unwrap();
    drop(l);
    a.to_string()
}

/// `tokenfuse` with a stub provider (the gateway refuses to start without
/// an upstream or the stub opt-in) and nothing else from this shell.
fn gateway(extra: &[(&str, &str)]) -> Command {
    let mut cmd = Command::new(bin());
    cmd.env_remove("TOKENFUSE_UPSTREAM")
        .env_remove("TOKENFUSE_CLIENT_KEYS")
        .env_remove("TOKENFUSE_IDENTITY_MAP")
        .env("TOKENFUSE_ALLOW_STUB", "1")
        .env("TOKENFUSE_ADDR", free_addr());
    for (k, v) in extra {
        cmd.env(k, v);
    }
    cmd
}

/// `tokenfuse mcp-broker` with an upstream set, so the run gets past the
/// broker's own "no upstream" path and reaches the switches under test.
fn broker(extra: &[(&str, &str)]) -> Command {
    let mut cmd = Command::new(bin());
    cmd.arg("mcp-broker")
        .env("TOKENFUSE_MCP_UPSTREAM", "http://127.0.0.1:1")
        .env("TOKENFUSE_MCP_ADDR", free_addr())
        .env_remove("TOKENFUSE_MCP_KEYS")
        .env_remove("TOKENFUSE_MCP_CLIENT_IDS")
        .env_remove("TOKENFUSE_MCP_REQUIRE_PROOF")
        .env_remove("TOKENFUSE_MCP_REQUIRE_SECRET_SCOPES");
    for (k, v) in extra {
        cmd.env(k, v);
    }
    cmd
}

fn spawn(mut cmd: Command) -> Child {
    cmd.stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("failed to spawn the tokenfuse binary")
}

/// The exit status if the process ends before the deadline, else `None`.
fn exits_within(child: &mut Child) -> Option<std::process::ExitStatus> {
    let deadline = Instant::now() + CEILING;
    loop {
        if let Some(s) = child.try_wait().unwrap() {
            return Some(s);
        }
        if Instant::now() >= deadline {
            return None;
        }
        thread::sleep(Duration::from_millis(20));
    }
}

/// True when the process prints its listening line before the deadline.
fn listens_within(child: &mut Child, needle: &'static str) -> bool {
    let stdout = child.stdout.take().expect("stdout piped");
    let (tx, rx) = mpsc::channel::<()>();
    thread::spawn(move || {
        for line in BufReader::new(stdout).lines().map_while(Result::ok) {
            if line.contains(needle) {
                tx.send(()).ok();
            }
        }
    });
    rx.recv_timeout(CEILING).is_ok()
}

fn stderr_of(child: &mut Child) -> String {
    let mut out = String::new();
    child.stderr.take().unwrap().read_to_string(&mut out).ok();
    out
}

/// Asserts a refusal: exit 2, and the message names the variable, the value
/// and the words it accepts.
fn assert_refused(mut child: Child, name: &str, value: &str, words: &str) {
    let Some(status) = exits_within(&mut child) else {
        child.kill().ok();
        child.wait().ok();
        panic!("{name}={value}: the process kept running instead of refusing to start");
    };
    let stderr = stderr_of(&mut child);
    assert_eq!(status.code(), Some(2), "stderr was: {stderr}");
    assert!(
        stderr.contains(name),
        "stderr did not name {name}: {stderr}"
    );
    assert!(
        stderr.contains(value),
        "stderr did not name the value: {stderr}"
    );
    assert!(
        stderr.contains(words),
        "stderr did not name the words {words}: {stderr}"
    );
}

/// RED-FIRST (invariant 98): before `main.rs`'s `serve()` read
/// `TOKENFUSE_DLP_PII` through a refusing parser, `blcok` read as `off` and
/// the gateway came up listening with the PII masks off. Against the unfixed
/// binary this panics with "kept running".
#[test]
fn a_mistyped_dlp_pii_stops_the_gateway_before_it_serves() {
    let child = spawn(gateway(&[("TOKENFUSE_DLP_PII", "blcok")]));
    assert_refused(child, "TOKENFUSE_DLP_PII", "blcok", "off|shadow|mask|block");
}

#[test]
fn an_empty_dlp_pii_still_starts_the_gateway() {
    let mut child = spawn(gateway(&[("TOKENFUSE_DLP_PII", "")]));
    let seen = listens_within(&mut child, GATEWAY_LISTENING);
    child.kill().ok();
    child.wait().ok();
    assert!(
        seen,
        "an empty TOKENFUSE_DLP_PII must still start the gateway"
    );
}

/// RED-FIRST (invariant 98): before `mcp_broker()` read `TOKENFUSE_MCP_SCAN`
/// through a refusing parser, `blcok` read as `warn` and the broker served
/// with scan findings only logged. Against the unfixed binary this panics
/// with "kept running".
#[test]
fn a_mistyped_mcp_scan_stops_the_broker_before_it_serves() {
    let child = spawn(broker(&[("TOKENFUSE_MCP_SCAN", "blcok")]));
    assert_refused(child, "TOKENFUSE_MCP_SCAN", "blcok", "off|warn|block");
}

#[test]
fn an_empty_mcp_scan_still_starts_the_broker() {
    let mut child = spawn(broker(&[("TOKENFUSE_MCP_SCAN", "")]));
    let seen = listens_within(&mut child, BROKER_LISTENING);
    child.kill().ok();
    child.wait().ok();
    assert!(
        seen,
        "an empty TOKENFUSE_MCP_SCAN must still start the broker"
    );
}
