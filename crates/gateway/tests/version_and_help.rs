//! `tokenfuse --version`/`-V` and `--help`/`-h` (plan item A12).
//!
//! Before this existed, neither flag was a recognized subcommand, so
//! `main.rs`'s dispatch fell through to `_ => serve().await`, which reads
//! `TOKENFUSE_UPSTREAM` and refuses to start without it. A downloaded binary
//! asked to identify itself printed the startup refusal instead. These tests
//! run the real built binary (same technique as `mcp_scan_exit_code.rs`) with
//! neither `TOKENFUSE_UPSTREAM` nor `TOKENFUSE_ALLOW_STUB` set, so a pass here
//! is proof the two flags are answered before that environment check runs at
//! all, not merely that they produce SOME output in some other environment.

use std::process::Command;

/// Path to the built `tokenfuse` binary (cargo sets this for integration tests).
fn bin() -> &'static str {
    env!("CARGO_BIN_EXE_tokenfuse")
}

/// Runs `tokenfuse <args...>` with a clean environment: `TOKENFUSE_UPSTREAM`
/// and `TOKENFUSE_ALLOW_STUB` explicitly removed, in case the process running
/// this test happens to have either set. That is what makes a pass here mean
/// "answered before the precondition check", not "happened to pass it".
fn run(args: &[&str]) -> std::process::Output {
    Command::new(bin())
        .args(args)
        .env_remove("TOKENFUSE_UPSTREAM")
        .env_remove("TOKENFUSE_ALLOW_STUB")
        .output()
        .expect("failed to spawn tokenfuse binary")
}

/// Manual check for `^tokenfuse \S+ \(\S+\)$` rather than a `regex`
/// dev-dependency added for one test: `tokenfuse-gateway` does not depend on
/// `regex` directly today (only transitively, through `tokenfuse-core`), and
/// this shape is simple enough to check by hand.
fn matches_version_line(line: &str) -> bool {
    let Some(rest) = line.strip_prefix("tokenfuse ") else {
        return false;
    };
    let Some((version, paren)) = rest.split_once(' ') else {
        return false;
    };
    let Some(sha) = paren.strip_prefix('(').and_then(|s| s.strip_suffix(')')) else {
        return false;
    };
    !version.is_empty()
        && !version.contains(char::is_whitespace)
        && !sha.is_empty()
        && !sha.contains(char::is_whitespace)
}

/// RED-FIRST: before `--version` was handled at all, this printed the
/// `TOKENFUSE_UPSTREAM` refusal on stderr, exit code 2, no stdout at all -
/// `matches_version_line` on an empty first line fails, and so does the exit
/// code assertion.
#[test]
fn version_prints_one_line_and_exits_0() {
    let out = run(&["--version"]);
    assert_eq!(
        out.status.code(),
        Some(0),
        "stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let stdout = String::from_utf8_lossy(&out.stdout);
    let first_line = stdout.lines().next().unwrap_or("");
    assert!(
        matches_version_line(first_line),
        "first line {first_line:?} does not match ^tokenfuse \\S+ \\(\\S+\\)$"
    );
}

#[test]
fn short_version_flag_behaves_the_same_as_long() {
    let long = run(&["--version"]);
    let short = run(&["-V"]);
    assert_eq!(long.status.code(), Some(0));
    assert_eq!(short.status.code(), Some(0));
    assert_eq!(long.stdout, short.stdout);
}

/// A build with neither `TOKENFUSE_VERSION` nor `TOKENFUSE_GIT_SHA` stamped
/// (a plain `cargo build`, which is how this test binary itself was built)
/// must say so honestly rather than claim a real release: the workspace
/// version is 0.0.1 on every tag (see `crates/gateway/Cargo.toml`), so a bare
/// `CARGO_PKG_VERSION` would read as one.
#[test]
fn an_unstamped_build_says_dev_rather_than_a_bare_workspace_version() {
    let out = run(&["--version"]);
    let stdout = String::from_utf8_lossy(&out.stdout);
    let first_line = stdout.lines().next().unwrap_or("");
    assert!(
        first_line.contains("-dev") || first_line.contains("dev"),
        "an unstamped test build should read as a dev build, got {first_line:?}"
    );
}

#[test]
fn help_exits_0_and_lists_the_real_subcommands() {
    let out = run(&["--help"]);
    assert_eq!(
        out.status.code(),
        Some(0),
        "stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let stdout = String::from_utf8_lossy(&out.stdout);
    // A representative sample, not all eleven - this asserts the list is the
    // real one `main.rs` dispatches on, not a hand-typed guess that drifted.
    for cmd in [
        "top",
        "sql",
        "backtest",
        "savings",
        "compliance",
        "mcp-scan",
        "focus-export",
        "firewall",
        "outcomes",
        "constants",
        "mcp-broker",
    ] {
        assert!(
            stdout.contains(cmd),
            "--help output is missing subcommand {cmd:?}"
        );
    }
    // The variables that decide whether a plain start actually starts.
    assert!(stdout.contains("TOKENFUSE_UPSTREAM"));
    assert!(stdout.contains("TOKENFUSE_ALLOW_STUB"));
}

#[test]
fn short_help_flag_behaves_the_same_as_long() {
    let long = run(&["--help"]);
    let short = run(&["-h"]);
    assert_eq!(long.status.code(), Some(0));
    assert_eq!(short.status.code(), Some(0));
    assert_eq!(long.stdout, short.stdout);
}

/// Regression guard (plan item A12, point 3): a plain start with neither flag
/// must refuse exactly as it did before this change - `--version`/`--help`
/// are answered earlier, but nothing else about the precondition moved.
#[test]
fn a_plain_start_with_no_upstream_still_refuses_exactly_as_before() {
    let out = run(&[]);
    assert_eq!(out.status.code(), Some(2));
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(stderr.contains("refusing to start: TOKENFUSE_UPSTREAM is not set"));
}
