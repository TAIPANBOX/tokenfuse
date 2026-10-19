//! A malformed `TOKENFUSE_CLOUD_CORS_ORIGINS` stops the control plane before it
//! listens (CLAUDE.md invariant 131), and says which entry it could not read.
//!
//! Runs the real `tokenfuse-cloud` binary, the technique
//! `events_export_startup.rs` uses: the process either exits, which is the
//! refusal, or reports that it is listening, which means it started.

use std::io::{BufRead, BufReader};
use std::process::{Command, Stdio};
use std::sync::mpsc;
use std::time::{Duration, Instant};

fn bin() -> &'static str {
    env!("CARGO_BIN_EXE_tokenfuse-cloud")
}

/// Start the control plane with `spec` as its CORS origins. Returns the exit
/// status if it exited within the deadline, or `None` if it was still running
/// and listening (in which case it is killed).
fn start_with_cors(spec: &str) -> (Option<i32>, String) {
    let mut child = Command::new(bin())
        .env_remove("TOKENFUSE_CLOUD_DATA")
        .env_remove("TOKENFUSE_CLOUD_KEYS")
        .env("TOKENFUSE_CLOUD_HOST", "127.0.0.1")
        .env("TOKENFUSE_CLOUD_CORS_ORIGINS", spec)
        .env("PORT", "0")
        .env("RUST_LOG", "info")
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn tokenfuse-cloud");

    // The subscriber writes to stdout; collect both streams on one channel.
    let (tx, rx) = mpsc::channel::<String>();
    for stream in [
        child
            .stdout
            .take()
            .map(|s| Box::new(s) as Box<dyn std::io::Read + Send>),
        child
            .stderr
            .take()
            .map(|s| Box::new(s) as Box<dyn std::io::Read + Send>),
    ]
    .into_iter()
    .flatten()
    {
        let tx = tx.clone();
        std::thread::spawn(move || {
            for line in BufReader::new(stream).lines().map_while(Result::ok) {
                if tx.send(line).is_err() {
                    break;
                }
            }
        });
    }
    drop(tx);

    let deadline = Instant::now() + Duration::from_secs(20);
    let mut log = String::new();
    loop {
        if let Ok(Some(status)) = child.try_wait() {
            // Drain what was written before the exit.
            while let Ok(line) = rx.recv_timeout(Duration::from_millis(200)) {
                log.push_str(&line);
                log.push('\n');
            }
            return (status.code(), log);
        }
        match rx.recv_timeout(Duration::from_millis(100)) {
            Ok(line) => {
                log.push_str(&line);
                log.push('\n');
                if line.contains("listening on") {
                    let _ = child.kill();
                    let _ = child.wait();
                    return (None, log);
                }
            }
            Err(_) => {}
        }
        if Instant::now() > deadline {
            let _ = child.kill();
            let _ = child.wait();
            return (None, log);
        }
    }
}

#[test]
fn a_malformed_cors_origin_stops_the_control_plane_before_it_listens() {
    // Not an origin: no scheme, and a path. Refused, and the entry is named.
    let (code, log) = start_with_cors("dash.example.com/path");
    assert_eq!(
        code,
        Some(2),
        "a malformed TOKENFUSE_CLOUD_CORS_ORIGINS must exit 2, log:\n{log}"
    );
    assert!(
        log.contains("dash.example.com/path"),
        "the refusal names the entry it could not read, log:\n{log}"
    );
    assert!(
        !log.contains("listening on"),
        "nothing listens after a refusal, log:\n{log}"
    );
}

#[test]
fn a_wildcard_cors_origin_is_refused_not_honoured() {
    let (code, log) = start_with_cors("*");
    assert_eq!(code, Some(2), "a wildcard is not an origin, log:\n{log}");
}
