//! Seam test for CLAUDE.md invariant 94: `defaults::firewall_mode_from` and
//! `firewall::from_env` are proven by unit tests, but nothing there proves
//! `main.rs`'s `serve()` READS `TOKENFUSE_FIREWALL` through them before the
//! listener binds. Deleting that call leaves every unit test green. This file
//! runs the real binary, as `run_budget_ceiling_startup.rs` does, for the one
//! thing only the binary can show: a value the gateway cannot read exits 2
//! naming the variable, the value and the three words it accepts, and does not
//! start serving.

use std::io::{BufRead, BufReader};
use std::process::{Child, Command, Stdio};
use std::sync::mpsc;
use std::thread;
use std::time::{Duration, Instant};

fn bin() -> &'static str {
    env!("CARGO_BIN_EXE_tokenfuse")
}

const LISTENING_NEEDLE: &str = "tokenfuse gateway listening";
const CEILING: Duration = Duration::from_secs(10);

fn base_cmd(addr: &str) -> Command {
    let mut cmd = Command::new(bin());
    cmd.env("TOKENFUSE_PROFILE", "observe");
    cmd.env_remove("TOKENFUSE_UPSTREAM")
        .env_remove("TOKENFUSE_FIREWALL_CONFIG")
        .env_remove("TOKENFUSE_CLIENT_KEYS")
        .env_remove("TOKENFUSE_IDENTITY_MAP")
        .env("TOKENFUSE_ALLOW_STUB", "1")
        .env("TOKENFUSE_ADDR", addr);
    cmd
}

fn spawn_with_firewall(addr: &str, firewall: &str) -> Child {
    base_cmd(addr)
        .env("TOKENFUSE_FIREWALL", firewall)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("failed to spawn the tokenfuse binary")
}

fn free_addr() -> String {
    let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let a = l.local_addr().unwrap();
    drop(l);
    a.to_string()
}

/// True when the gateway prints its listening line before the deadline.
fn wait_for_listening(child: &mut Child) -> bool {
    let stdout = child.stdout.take().expect("stdout piped");
    let (tx, rx) = mpsc::channel::<()>();
    thread::spawn(move || {
        for line in BufReader::new(stdout).lines().map_while(Result::ok) {
            if line.contains(LISTENING_NEEDLE) {
                tx.send(()).ok();
            }
        }
    });
    rx.recv_timeout(CEILING).is_ok()
}

/// RED-FIRST: before `serve()` consulted `TOKENFUSE_FIREWALL` through the
/// parser, a misspelt value was read as no override and the gateway came up
/// listening. Against the unfixed binary this test panics with "kept serving".
#[test]
fn a_mistyped_firewall_mode_stops_the_gateway_before_it_serves() {
    let addr = free_addr();
    let mut child = spawn_with_firewall(&addr, "enfroce");
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
        panic!("TOKENFUSE_FIREWALL=enfroce: the gateway kept serving instead of refusing");
    };
    let mut stderr = String::new();
    std::io::Read::read_to_string(&mut child.stderr.take().unwrap(), &mut stderr).ok();
    assert_eq!(status.code(), Some(2), "stderr was: {stderr}");
    assert!(
        stderr.contains("TOKENFUSE_FIREWALL"),
        "stderr did not name the variable: {stderr}"
    );
    assert!(
        stderr.contains("enfroce"),
        "stderr did not name the value: {stderr}"
    );
    assert!(
        stderr.contains("off|shadow|enforce"),
        "stderr did not name the three words it accepts: {stderr}"
    );
}

/// Unset-equivalent (an empty value) is the historical behaviour: start, no
/// refusal. The guard that keeps the refusal from becoming "refuse everything".
#[test]
fn an_empty_firewall_mode_still_starts_the_gateway() {
    let addr = free_addr();
    let mut child = spawn_with_firewall(&addr, "");
    let seen = wait_for_listening(&mut child);
    child.kill().ok();
    child.wait().ok();
    assert!(seen, "an empty TOKENFUSE_FIREWALL must still start");
}
