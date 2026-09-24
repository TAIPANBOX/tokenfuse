//! Seam test for CLAUDE.md invariant 63: `defaults::cache_mode_from` is
//! proven by unit tests, but nothing proves `main.rs`'s `serve()` actually
//! CALLS it rather than, say, keeping an inline match with the old
//! `Shadow` fallback. Reverting `main.rs` to that old inline match would
//! leave every unit test in `gateway::defaults` green, since those test the
//! pure function directly and never touch the binary's own wiring.
//!
//! Runs the real built binary (same technique as `tests/stub_wire_mismatch.rs`
//! and `tests/xaa_startup.rs`), because the decision under test - what
//! `serve()` actually resolves `TOKENFUSE_CACHE` to - lives in `main.rs`
//! itself and nothing in the library crate observes it. The startup line
//! `tracing::info!(?cache_mode, "semantic cache")` is the one piece of
//! observable evidence `main.rs` exposes for this; there was nothing else
//! to assert on, so this file uses that.

use std::io::{BufRead, BufReader};
use std::process::{Child, Command, Stdio};
use std::sync::mpsc;
use std::thread;
use std::time::{Duration, Instant};

fn bin() -> &'static str {
    env!("CARGO_BIN_EXE_tokenfuse")
}

/// `tracing_subscriber::fmt()`'s default writer still emits ANSI color
/// codes even when stdout is piped (not a TTY) rather than a real terminal,
/// which splits a field like `cache_mode=Off` into `cache_mode`, an escape
/// sequence, `=`, another escape sequence, `Off`. Strips every `ESC '['
/// ... letter` CSI sequence so a plain substring match on the field can work
/// at all.
fn strip_ansi(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let mut chars = s.chars().peekable();
    while let Some(c) = chars.next() {
        if c == '\u{1b}' && chars.peek() == Some(&'[') {
            chars.next(); // consume '['
            for c2 in chars.by_ref() {
                if c2.is_ascii_alphabetic() {
                    break;
                }
            }
            continue;
        }
        out.push(c);
    }
    out
}

/// The line `serve()` logs once it has resolved `TOKENFUSE_CACHE`
/// (`main.rs`, `tracing::info!(?cache_mode, "semantic cache")`).
const CACHE_LINE_NEEDLE: &str = "semantic cache";

/// Same ceiling and reasoning as `tests/stub_wire_mismatch.rs`'s
/// `POSITIVE_CEILING`: generous enough to clear this sandbox's process
/// supervision latency without turning a genuine hang into a slow pass.
const POSITIVE_CEILING: Duration = Duration::from_secs(10);

/// What a wait for a needle found: whether it appeared, and every stdout
/// line seen along the way (for the assertion message when it did not).
struct StdoutWait {
    found_line: Option<String>,
    lines: Vec<String>,
}

/// Reads `child`'s stdout on a background thread and waits up to `timeout`
/// for a line containing `needle`, returning that whole line. Returns
/// `found_line: None` if the timeout elapses or the child's stdout closes
/// first (the process exited without ever printing it).
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
    });
    let deadline = Instant::now() + timeout;
    let mut lines = Vec::new();
    loop {
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            return StdoutWait {
                found_line: None,
                lines,
            };
        }
        match rx.recv_timeout(remaining) {
            Ok(line) => {
                let hit = line.contains(needle);
                lines.push(line.clone());
                if hit {
                    return StdoutWait {
                        found_line: Some(line),
                        lines,
                    };
                }
            }
            Err(_) => {
                return StdoutWait {
                    found_line: None,
                    lines,
                }
            }
        }
    }
}

/// Runs the real binary against the built-in stub (so it starts serving
/// rather than exiting on the `TOKENFUSE_UPSTREAM` precondition), with
/// `TOKENFUSE_CACHE` set exactly as `extra_env` says (or left unset if
/// absent from it), waits for the "semantic cache" startup line, kills the
/// process, and returns the full line plus every stdout line seen.
fn run_and_capture_cache_line(cache_value: Option<&str>) -> StdoutWait {
    let mut cmd = Command::new(bin());
    cmd.env_remove("TOKENFUSE_UPSTREAM")
        .env("TOKENFUSE_ALLOW_STUB", "1")
        .env("TOKENFUSE_ADDR", "127.0.0.1:0")
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    match cache_value {
        Some(v) => {
            cmd.env("TOKENFUSE_CACHE", v);
        }
        None => {
            cmd.env_remove("TOKENFUSE_CACHE");
        }
    }
    let mut child = cmd.spawn().expect("failed to spawn tokenfuse binary");
    let result = wait_for_stdout_line(&mut child, CACHE_LINE_NEEDLE, POSITIVE_CEILING);
    child.kill().ok();
    child.wait().ok();
    result
}

/// RED-FIRST (recorded in CLAUDE.md invariant 63 rather than re-run here on
/// every CI pass, per the same convention `tests/stub_wire_mismatch.rs`
/// follows): against `main.rs` reverted to the OLD inline match (`_ =>
/// CacheMode::Shadow` for the unset case, the pre-#319-fix default), this
/// test's assertion fails, `left: "... cache_mode=Shadow" ... right pattern
/// "cache_mode=Off"` not found - proving the seam actually depends on
/// `main.rs` calling `cache_mode_from`, not merely on the pure function
/// being correct in isolation.
#[test]
fn unset_cache_resolves_to_off_in_the_real_binary() {
    let result = run_and_capture_cache_line(None);
    let line = strip_ansi(&result.found_line.unwrap_or_else(|| {
        panic!(
            "never saw a \"{CACHE_LINE_NEEDLE}\" line; stdout seen: {:?}",
            result.lines
        )
    }));
    assert!(
        line.contains("cache_mode=Off"),
        "TOKENFUSE_CACHE unset must resolve to Off in the real binary; got: {line}"
    );
}

/// A typo value also resolves to Off in the real binary, and the process
/// warns naming the value it could not parse (`defaults::cache_mode_from`'s
/// own rule, wired through `main.rs`).
#[test]
fn a_typo_cache_value_resolves_to_off_and_warns_in_the_real_binary() {
    let mut cmd = Command::new(bin());
    cmd.env_remove("TOKENFUSE_UPSTREAM")
        .env("TOKENFUSE_ALLOW_STUB", "1")
        .env("TOKENFUSE_ADDR", "127.0.0.1:0")
        .env("TOKENFUSE_CACHE", "enforce")
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let mut child = cmd.spawn().expect("failed to spawn tokenfuse binary");
    let result = wait_for_stdout_line(&mut child, CACHE_LINE_NEEDLE, POSITIVE_CEILING);
    child.kill().ok();
    child.wait().ok();

    let line = strip_ansi(&result.found_line.clone().unwrap_or_else(|| {
        panic!(
            "never saw a \"{CACHE_LINE_NEEDLE}\" line; stdout seen: {:?}",
            result.lines
        )
    }));
    assert!(
        line.contains("cache_mode=Off"),
        "TOKENFUSE_CACHE=enforce (unrecognised) must resolve to Off; got: {line}"
    );
    // `tracing_subscriber::fmt()`'s default writer is stdout for every
    // level (this binary never routes warn/error to stderr separately, see
    // `main.rs`'s plain `.init()`), so the warn line is one of the lines
    // captured on the way to the needle above, not in the child's stderr.
    let all_stdout = strip_ansi(&result.lines.join("\n"));
    assert!(
        all_stdout.contains("TOKENFUSE_CACHE") && all_stdout.contains("enforce"),
        "the warn line must name both the variable and the value it could not \
         parse; stdout seen: {all_stdout}"
    );
}

/// Negative control: `on` reaches the binary unchanged, proving this test
/// file's needle-matching is not accidentally always true.
#[test]
fn cache_on_is_honoured_in_the_real_binary() {
    let result = run_and_capture_cache_line(Some("on"));
    let line = strip_ansi(&result.found_line.unwrap_or_else(|| {
        panic!(
            "never saw a \"{CACHE_LINE_NEEDLE}\" line; stdout seen: {:?}",
            result.lines
        )
    }));
    assert!(
        line.contains("cache_mode=On"),
        "TOKENFUSE_CACHE=on must resolve to On in the real binary; got: {line}"
    );
}
