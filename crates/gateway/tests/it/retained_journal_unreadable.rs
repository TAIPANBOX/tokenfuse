//! Invariant 88, D-2: a retained-reservation journal that exists but cannot be
//! read stops the gateway before the listener binds. Until this change
//! `serve()` logged an error and served anyway: without the restored
//! liability, with its id and generation counters starting from zero while new
//! retains kept being appended, so a later restart could drop records as
//! duplicate or superseded.
//!
//! The journal path is made a directory, so opening and reading it fail even
//! when the test runs as root (a 0000 file does not stop root). A missing or
//! empty journal must still start.

use std::io::{BufRead, BufReader, Read};
use std::process::{Child, Command, Stdio};
use std::sync::mpsc;
use std::thread;
use std::time::{Duration, Instant};

const LISTENING_NEEDLE: &str = "tokenfuse gateway listening";
const JOURNAL: &str = "retained-reservations.ndjson";
const CEILING: Duration = Duration::from_secs(15);

fn scratch(name: &str) -> std::path::PathBuf {
    let d = std::env::temp_dir().join(format!(
        "tf-retained-unreadable-{}-{name}",
        std::process::id()
    ));
    let _ = std::fs::remove_dir_all(&d);
    std::fs::create_dir_all(&d).unwrap();
    d
}

fn spawn(dir: &std::path::Path) -> Child {
    Command::new(env!("CARGO_BIN_EXE_tokenfuse"))
        .env("TOKENFUSE_PROFILE", "observe")
        .env_remove("TOKENFUSE_UPSTREAM")
        .env_remove("TOKENFUSE_CLOUD_URL")
        .env("TOKENFUSE_ALLOW_STUB", "1")
        .env("TOKENFUSE_ADDR", "127.0.0.1:0")
        .env("TOKENFUSE_DATA_DIR", dir)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("failed to spawn the tokenfuse binary")
}

#[test]
fn an_unreadable_journal_refuses_to_start_before_the_listener_binds() {
    let dir = scratch("dir-in-place");
    let journal = dir.join(JOURNAL);
    std::fs::create_dir(&journal).unwrap();

    let mut child = spawn(&dir);
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
    if status.is_none() {
        child.kill().ok();
        child.wait().ok();
    }
    let mut stdout = String::new();
    child
        .stdout
        .take()
        .unwrap()
        .read_to_string(&mut stdout)
        .ok();
    let mut stderr = String::new();
    child
        .stderr
        .take()
        .unwrap()
        .read_to_string(&mut stderr)
        .ok();
    let _ = std::fs::remove_dir_all(&dir);

    let Some(status) = status else {
        panic!(
            "the gateway started with an unreadable journal instead of refusing; stdout:\n{stdout}\nstderr:\n{stderr}"
        );
    };
    assert!(
        !stdout.contains(LISTENING_NEEDLE),
        "the listener bound before the refusal; stdout:\n{stdout}"
    );
    assert_eq!(status.code(), Some(2), "stderr:\n{stderr}");
    assert!(
        stderr.contains(&journal.display().to_string()),
        "the refusal must name the journal path; stderr:\n{stderr}"
    );
    assert!(
        stderr.contains("Is a directory") || stderr.contains("os error"),
        "the refusal must carry the operating system's error; stderr:\n{stderr}"
    );
}

fn starts(dir: &std::path::Path) -> bool {
    let mut child = spawn(dir);
    let stdout = child.stdout.take().unwrap();
    let (tx, rx) = mpsc::channel();
    thread::spawn(move || {
        for line in BufReader::new(stdout).lines().map_while(Result::ok) {
            if line.contains(LISTENING_NEEDLE) {
                let _ = tx.send(());
                return;
            }
        }
    });
    let seen = rx.recv_timeout(CEILING).is_ok();
    child.kill().ok();
    child.wait().ok();
    seen
}

#[test]
fn a_missing_or_empty_journal_still_starts() {
    let missing = scratch("missing");
    assert!(starts(&missing), "a missing journal must start");
    let _ = std::fs::remove_dir_all(&missing);

    let empty = scratch("empty");
    std::fs::write(empty.join(JOURNAL), b"").unwrap();
    assert!(starts(&empty), "an empty journal must start");
    let _ = std::fs::remove_dir_all(&empty);
}
