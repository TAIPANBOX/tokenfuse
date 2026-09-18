//! The control plane says, at startup, whether its agent-event export is on,
//! and WHY it is off when it is off (tokenfuse#292).
//!
//! Measured 2026-09-17 on the appliance proving run: `TOKENFUSE_EVENTS_PATH`
//! pointed into a directory the process could not write to (the launchers'
//! `root:10001 2775` events directory, reached as uid 10001 with gid 999),
//! the Cloud's convenience constructor swallowed the open error and handed
//! back the disabled exporter, and the log said nothing at all. Four
//! `budget_exhausted` incidents existed and none reached the bus.
//!
//! These tests run the real `tokenfuse-cloud` binary (the technique
//! `crates/gateway/tests/version_and_help.rs` uses) with the variable pointed
//! at a file inside a directory the test makes unwritable, read its log until
//! it reports that it is listening, and then stop it. The unit under test is
//! exactly what an operator reads: the line, its level, and the words in it.
//!
//! The precondition is a non-root user: a directory's mode bits do not bind
//! root, so under root the file gets created, the export comes up enabled and
//! the first test fails with a message saying so. CI runs as `runner`, and a
//! developer machine runs as its owner; a root container is the one place
//! this measures nothing, and it says so rather than passing.

use std::io::{BufRead, BufReader};
use std::process::{Child, Command, Stdio};
use std::sync::mpsc;
use std::time::{Duration, Instant};

/// Path to the built `tokenfuse-cloud` binary (cargo sets this for a
/// package's own integration tests).
fn bin() -> &'static str {
    env!("CARGO_BIN_EXE_tokenfuse-cloud")
}

/// A unique directory per test, since the pid alone is shared by every test
/// in this binary.
fn temp_dir(tag: &str) -> std::path::PathBuf {
    let dir = std::env::temp_dir().join(format!(
        "tf-cloud-events-startup-{}-{tag}",
        std::process::id()
    ));
    std::fs::create_dir_all(&dir).expect("a temp dir");
    dir
}

/// Start the control plane with `TOKENFUSE_EVENTS_PATH` set to `events_path`
/// and collect its log until it reports that it is listening (or until a
/// generous deadline passes), then stop it. Returns every log line seen.
///
/// `PORT=0` asks the OS for a free port, and the loopback host is the
/// default; nothing here reaches the network. The subscriber the binary
/// installs writes to stdout, which is why stdout and not stderr is read.
fn startup_log(events_path: &str) -> Vec<String> {
    let mut child: Child = Command::new(bin())
        .env_remove("TOKENFUSE_CLOUD_DATA")
        .env_remove("TOKENFUSE_CLOUD_KEYS")
        .env_remove("TOKENFUSE_CLOUD_ALLOW_DEVKEY")
        .env_remove("TOKENFUSE_CLOUD_REPLAY_EVENTS")
        .env("TOKENFUSE_CLOUD_HOST", "127.0.0.1")
        .env("PORT", "0")
        .env("RUST_LOG", "info")
        .env("TOKENFUSE_EVENTS_PATH", events_path)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("failed to spawn the tokenfuse-cloud binary");

    let stdout = child.stdout.take().expect("piped stdout");
    let (tx, rx) = mpsc::channel::<String>();
    std::thread::spawn(move || {
        for line in BufReader::new(stdout).lines().map_while(Result::ok) {
            if tx.send(line).is_err() {
                break;
            }
        }
    });

    let mut lines = Vec::new();
    let deadline = Instant::now() + Duration::from_secs(20);
    loop {
        let left = deadline.saturating_duration_since(Instant::now());
        if left.is_zero() {
            break;
        }
        match rx.recv_timeout(left) {
            Ok(line) => {
                let listening = line.contains("listening on");
                lines.push(line);
                if listening {
                    break;
                }
            }
            Err(_) => break,
        }
    }
    let _ = child.kill();
    let _ = child.wait();
    lines
}

/// The line an operator reads. Matched on the words that carry the fact,
/// not on the whole sentence, so a rewording that keeps the fact keeps the
/// test.
fn the_warning_naming<'a>(lines: &'a [String], path: &str) -> Option<&'a String> {
    lines.iter().find(|l| {
        l.contains("WARN")
            && l.contains(path)
            && l.contains("TOKENFUSE_EVENTS_PATH")
            && l.to_ascii_lowercase().contains("export is off")
    })
}

/// RED-FIRST against the unfixed binary: it printed no line naming the path
/// at all (the open error was swallowed inside `Exporter::from_env`), so the
/// first assertion fails with the whole startup log in the message.
///
/// Unix only, because the fault is a Unix mode bit and so is the fixture.
#[cfg(unix)]
#[test]
fn a_control_plane_whose_events_file_cannot_be_created_says_so_at_warn_and_keeps_running() {
    use std::os::unix::fs::PermissionsExt;
    let dir = temp_dir("unwritable");
    let path = dir.join("events.ndjson");
    let path_str = path.to_str().expect("a utf-8 temp path");
    // Read and search, never write: exactly the launchers' directory as seen
    // by a process in the wrong group.
    std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o500))
        .expect("chmod 0500 on the temp dir");

    let lines = startup_log(path_str);

    // Restore before any assertion can panic, so the directory is removable.
    std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700)).ok();
    let created = path.exists();
    std::fs::remove_dir_all(&dir).ok();

    assert!(
        !created,
        "the events file was created inside a 0500 directory, so this test ran as a \
         user the mode bits do not bind (root); it measured nothing. Run it as an \
         ordinary user"
    );
    assert!(
        lines.iter().any(|l| l.contains("listening on")),
        "the control plane never reported that it was listening; an unopenable \
         events file must cost a warning and nothing else. Log:\n{}",
        lines.join("\n")
    );
    assert!(
        the_warning_naming(&lines, path_str).is_some(),
        "no line at WARN names the events path, the variable and says the export is \
         off. An operator whose TOKENFUSE_EVENTS_PATH cannot be created has to be \
         told in the log, because the only other signal is a bus that stays empty. \
         Log:\n{}",
        lines.join("\n")
    );
    assert!(
        !lines.iter().any(|l| l.contains("export enabled")),
        "the log claims the export is enabled while the file could not be created. \
         Log:\n{}",
        lines.join("\n")
    );
    let warning = the_warning_naming(&lines, path_str).expect("asserted above");
    assert!(
        warning.to_ascii_lowercase().contains("permission denied") || warning.contains("os error"),
        "the warning names the path but not the operating system's error, which is \
         what tells an operator whether to fix a mode, an owner or a typo: {warning}"
    );
    assert_eq!(
        lines
            .iter()
            .filter(|l| l.contains("WARN") && l.contains(path_str))
            .count(),
        1,
        "exactly one warning line about the path, not one per something. Log:\n{}",
        lines.join("\n")
    );
}

/// The guard, green before and after: a path the control plane CAN create is
/// reported as enabled and draws no warning. Without this the test above
/// could be passing because the harness reads no log at all.
#[test]
fn a_control_plane_with_a_writable_events_path_says_the_export_is_enabled() {
    let dir = temp_dir("writable");
    let path = dir.join("events.ndjson");
    let path_str = path.to_str().expect("a utf-8 temp path");

    let lines = startup_log(path_str);
    let created = path.exists();
    std::fs::remove_dir_all(&dir).ok();

    assert!(
        created,
        "the control plane did not create the events file it was pointed at. Log:\n{}",
        lines.join("\n")
    );
    assert!(
        lines.iter().any(|l| l.contains("export enabled")),
        "a writable path must be reported as enabled. Log:\n{}",
        lines.join("\n")
    );
    assert!(
        the_warning_naming(&lines, path_str).is_none(),
        "a writable path drew the warning meant for an unopenable one. Log:\n{}",
        lines.join("\n")
    );
}
