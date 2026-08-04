//! Durability across a process that was killed, not asked to stop.
//!
//! `redb_durability.rs` next door restarts a node by calling
//! `raft.shutdown()`. That is a graceful stop: destructors run, buffers flush,
//! files close. It proves budgets survive a **clean** restart, which is worth
//! knowing and is not what the word "crash" in its own comment promises.
//!
//! This one spawns the shipped binary, kills it with SIGKILL, and starts it
//! again on the same directory. Nothing in the process gets a chance to tidy
//! up, which is the only version of the question a production incident asks.
//!
//! Written after a 2026-08-04 cloud run where the same gap was found one layer
//! down: Trailryx's kill tests were `SIGKILL` on a process while the machine
//! lived, and nothing had ever taken a machine away underneath the store.

use std::io::Read;
use std::net::TcpStream;
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

fn temp_dir(tag: &str) -> PathBuf {
    std::env::temp_dir().join(format!("tf-kill-{}-{}", tag, std::process::id()))
}

/// The binary under test, as cargo built it for this test run.
fn binary() -> PathBuf {
    // CARGO_BIN_EXE_<name> is set by cargo for integration tests, and is the
    // only way to name the binary that does not guess at target directories.
    PathBuf::from(env!("CARGO_BIN_EXE_tokenfuse-cluster"))
}

struct Node(Child);

impl Node {
    fn start(port: u16, dir: &PathBuf, init: bool) -> Self {
        let mut cmd = Command::new(binary());
        cmd.arg("serve")
            .arg("--id")
            .arg("1")
            .arg("--http")
            .arg(format!("127.0.0.1:{port}"))
            .arg("--peers")
            .arg(format!("1=http://127.0.0.1:{port}"))
            .arg("--dir")
            .arg(dir)
            .stdout(Stdio::null())
            .stderr(Stdio::null());
        if init {
            cmd.arg("--init");
        }
        Node(cmd.spawn().expect("the cluster binary starts"))
    }

    /// SIGKILL. Not a shutdown, not a drop, not a signal the process can catch.
    fn kill(mut self) {
        self.0.kill().expect("the process was killed");
        self.0.wait().expect("and reaped");
    }
}

fn wait_healthy(port: u16) -> bool {
    let deadline = Instant::now() + Duration::from_secs(20);
    while Instant::now() < deadline {
        if TcpStream::connect(("127.0.0.1", port)).is_ok() {
            // Listening is not the same as ready to answer, so ask.
            if http(port, "GET", "/healthz", None).is_some() {
                return true;
            }
        }
        std::thread::sleep(Duration::from_millis(200));
    }
    false
}

/// A request spoken by hand, so this test pulls in no HTTP client the rest of
/// the crate does not already have.
fn http(port: u16, method: &str, path: &str, body: Option<&str>) -> Option<String> {
    use std::io::Write;
    let mut s = TcpStream::connect(("127.0.0.1", port)).ok()?;
    s.set_read_timeout(Some(Duration::from_secs(10))).ok()?;
    let payload = body.unwrap_or("");
    let req = format!(
        "{method} {path} HTTP/1.1\r\nHost: localhost\r\ncontent-type: application/json\r\ncontent-length: {}\r\nConnection: close\r\n\r\n{payload}",
        payload.len()
    );
    s.write_all(req.as_bytes()).ok()?;
    let mut out = String::new();
    s.read_to_string(&mut out).ok()?;
    Some(out)
}

/// Free port, taken by binding and releasing. Racy in principle and fine here:
/// the window is microseconds and the alternative is a hard-coded port that
/// collides with whatever else the machine is running.
fn free_port() -> u16 {
    let l = std::net::TcpListener::bind("127.0.0.1:0").expect("a port");
    l.local_addr().expect("its address").port()
}

#[test]
fn a_budget_survives_a_process_that_was_killed_rather_than_stopped() {
    let dir = temp_dir("survives");
    std::fs::remove_dir_all(&dir).ok();
    std::fs::create_dir_all(&dir).expect("a directory to persist into");
    let port = free_port();

    // --- round 1: write a budget, then take the process away ---
    let node = Node::start(port, &dir, true);
    assert!(
        wait_healthy(port),
        "the node never became healthy; is --dir supported?"
    );

    // Retried on the BODY, not on the status line, and this distinction is the
    // whole reason the first version of this test reported a durability
    // failure that was not one.
    //
    // `--init` is spawned behind a 300 ms delay, and `/healthz` answers before
    // it has run. A write in that window comes back **HTTP 200** carrying an
    // error object: raft has no leader yet, so nothing is stored. A test that
    // checks the status line sees success, kills the process, finds nothing on
    // the other side and blames the disk.
    let mut opened = String::new();
    let deadline = Instant::now() + Duration::from_secs(20);
    while Instant::now() < deadline {
        opened = http(
            port,
            "POST",
            "/api/write",
            Some(r#"{"Open":{"run":"r","budget_micros":1000000,"parent":null}}"#),
        )
        .expect("the open is answered");
        if opened.contains("\"accepted\":true") {
            break;
        }
        std::thread::sleep(Duration::from_millis(200));
    }
    assert!(
        opened.contains("\"accepted\":true"),
        "opening a run never succeeded; last response: {opened}"
    );

    let reserved = http(
        port,
        "POST",
        "/api/write",
        Some(r#"{"Reserve":{"run":"r","micros":600000}}"#),
    )
    .expect("the reserve is answered");
    assert!(
        reserved.contains("\"accepted\":true"),
        "the reservation should be accepted, got: {reserved}"
    );

    node.kill();
    std::thread::sleep(Duration::from_millis(300));

    // --- round 2: same directory, brand new process ---
    let node = Node::start(port, &dir, false);
    assert!(
        wait_healthy(port),
        "the node did not come back on the same directory"
    );

    // Polled rather than read once, and the delay is measured rather than
    // slept away, because the first attempt at this test failed here and the
    // reason was not durability.
    //
    // `/healthz` answers as soon as the HTTP server is up, which is before the
    // raft log has been replayed into the state machine. In that window the
    // node is listening, healthy by its own account, and answers `null` for a
    // budget that exists on its disk. A load balancer with a health check
    // pointed at `/healthz` would route to it. That is worth knowing and is a
    // separate defect from the one this file is about, so it is measured here
    // and not asserted away.
    let began = Instant::now();
    let mut read = String::new();
    let deadline = Instant::now() + Duration::from_secs(20);
    while Instant::now() < deadline {
        read = http(port, "GET", "/api/read/r", None).expect("the read is answered");
        if read.contains("1000000") {
            break;
        }
        std::thread::sleep(Duration::from_millis(200));
    }
    let recovered_after = began.elapsed();

    assert!(
        read.contains("1000000"),
        "the budget did not survive a killed process; response was: {read}"
    );
    assert!(
        read.contains("600000"),
        "the reservation did not survive a killed process; response was: {read}"
    );
    println!(
        "state was readable {} ms after /healthz first said ok",
        recovered_after.as_millis()
    );

    node.kill();
    std::fs::remove_dir_all(&dir).ok();
}
