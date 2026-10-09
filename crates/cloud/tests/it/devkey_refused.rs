//! `TOKENFUSE_CLOUD_ALLOW_DEVKEY` is a frozen name (`compat/1.0.json`), but the
//! devkey fallback credential it used to enable was removed. A control plane
//! started with it set must refuse to start and say why in its log, instead of
//! running and answering every request with `401`.
//!
//! Like `events_export_startup`, this runs the real `tokenfuse-cloud` binary.
//! The variable is set on the child process only, never on this test process,
//! so the shared integration-test binary keeps its environment untouched.

use std::io::Read;
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

/// Path to the built `tokenfuse-cloud` binary (cargo sets this for a
/// package's own integration tests).
fn bin() -> &'static str {
    env!("CARGO_BIN_EXE_tokenfuse-cloud")
}

/// RED-FIRST against the previous binary: with the opt-in set and no keys it
/// started, listened, and accepted `Bearer devkey` as admin, so it never
/// exited and this test fails on the deadline with its log in the message.
#[test]
fn the_removed_devkey_opt_in_refuses_to_start_and_says_why() {
    let mut child = Command::new(bin())
        .env_remove("TOKENFUSE_CLOUD_DATA")
        .env_remove("TOKENFUSE_CLOUD_KEYS")
        .env_remove("TOKENFUSE_CLOUD_REPLAY_EVENTS")
        .env_remove("TOKENFUSE_EVENTS_PATH")
        .env("TOKENFUSE_CLOUD_ALLOW_DEVKEY", "1")
        .env("TOKENFUSE_CLOUD_HOST", "127.0.0.1")
        .env("PORT", "0")
        .env("RUST_LOG", "info")
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("failed to spawn the tokenfuse-cloud binary");

    let deadline = Instant::now() + Duration::from_secs(20);
    let status = loop {
        if let Some(status) = child.try_wait().expect("wait on the control plane") {
            break Some(status);
        }
        if Instant::now() >= deadline {
            break None;
        }
        std::thread::sleep(Duration::from_millis(50));
    };
    if status.is_none() {
        let _ = child.kill();
    }
    let mut log = String::new();
    if let Some(mut stdout) = child.stdout.take() {
        let _ = stdout.read_to_string(&mut log);
    }
    let _ = child.wait();

    let Some(status) = status else {
        panic!(
            "the control plane kept running with TOKENFUSE_CLOUD_ALLOW_DEVKEY=1; it must \
             refuse to start. Log:\n{log}"
        );
    };
    assert!(
        !status.success(),
        "the control plane exited 0 with TOKENFUSE_CLOUD_ALLOW_DEVKEY=1; a refusal must \
         exit non-zero so a supervisor notices. Log:\n{log}"
    );
    assert!(
        !log.contains("listening on"),
        "the control plane started listening before refusing. Log:\n{log}"
    );
    assert!(
        log.lines().any(|l| l.contains("ERROR")
            && l.contains("TOKENFUSE_CLOUD_ALLOW_DEVKEY")
            && l.to_ascii_lowercase().contains("refusing to start")),
        "no ERROR line names TOKENFUSE_CLOUD_ALLOW_DEVKEY and says it refuses to start; \
         an operator has to be told why the process stopped. Log:\n{log}"
    );
}
