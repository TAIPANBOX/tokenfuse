//! The real `tokenfuse` binary, started on a free port with the built-in stub
//! provider, with everything it prints kept for the test to read.
//!
//! For the tests that must see what an operator sees: a startup line, or the
//! answer of a process whose configuration came from the environment the way a
//! deployment's does. Every variable that would change what is under test is
//! removed first, so the shell running `cargo test` cannot leak into the
//! answer.

use std::io::{BufRead, BufReader, Read};
use std::process::{Child, Command, Stdio};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

/// The line the gateway prints once its listener is bound.
pub const LISTENING: &str = "tokenfuse gateway listening";
const CEILING: Duration = Duration::from_secs(15);

/// Variables a test of a startup default must not inherit from the shell.
const CLEARED: &[&str] = &[
    "TOKENFUSE_UPSTREAM",
    "TOKENFUSE_PROFILE",
    "TOKENFUSE_CLIENT_KEYS",
    "TOKENFUSE_IDENTITY_MAP",
    "TOKENFUSE_ADMIN_KEYS",
    "TOKENFUSE_ALLOW_OPEN_OBS",
    "TOKENFUSE_WARDRYX_MODE",
    "TOKENFUSE_WARDRYX_URL",
    "TOKENFUSE_WARDRYX_FAILMODE",
    "TOKENFUSE_WARDRYX_KEY",
    "TOKENFUSE_CLOUD_URL",
    "TOKENFUSE_CLOUD_KEY",
    "TOKENFUSE_FIREWALL",
    "TOKENFUSE_FIREWALL_CONFIG",
    "TOKENFUSE_EVENTS_PATH",
    "TOKENFUSE_MAX_RUN_BUDGET_USD",
    "TOKENFUSE_DATA_DIR",
    "RUST_LOG",
];

/// A port nothing is listening on at the moment of asking.
pub fn free_port() -> u16 {
    let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    l.local_addr().unwrap().port()
}

/// A started gateway. Killed when dropped.
pub struct Running {
    child: Child,
    output: Arc<Mutex<String>>,
    /// The port it listens on, reachable at `127.0.0.1` whatever host it bound.
    pub port: u16,
}

/// `tracing_subscriber::fmt()` writes ANSI colour codes even into a pipe, and
/// they split a field like `failmode=Closed` into the name, an escape, `=`,
/// another escape and the value, so a plain substring match on a field fails
/// on a line that is there. Every `ESC '[' ... letter` sequence is dropped, as
/// `cache_default_startup.rs` does for the same reason.
pub fn strip_ansi(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let mut chars = s.chars().peekable();
    while let Some(c) = chars.next() {
        if c == '\u{1b}' && chars.peek() == Some(&'[') {
            chars.next();
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

fn keep(stream: impl Read + Send + 'static, into: Arc<Mutex<String>>) {
    thread::spawn(move || {
        for line in BufReader::new(stream).lines().map_while(Result::ok) {
            let mut out = into.lock().unwrap();
            out.push_str(&strip_ansi(&line));
            out.push('\n');
        }
    });
}

impl Running {
    /// Start the gateway bound to `host` on a free port, with `extra` set on
    /// top of the stub provider, and wait for its listening line.
    pub fn start(host: &str, extra: &[(&str, &str)]) -> Running {
        let port = free_port();
        let mut cmd = Command::new(env!("CARGO_BIN_EXE_tokenfuse"));
        for name in CLEARED {
            cmd.env_remove(name);
        }
        cmd.env("TOKENFUSE_ALLOW_STUB", "1")
            .env("TOKENFUSE_ADDR", format!("{host}:{port}"));
        // Tests of other subsystems start the gateway with the observe defaults
        // every one of them was written against. The governed defaults are
        // asserted in `governed_profile.rs`, which names its profile explicitly
        // (CLAUDE.md invariant 136). A caller that names a profile here wins.
        if !extra.iter().any(|(k, _)| *k == "TOKENFUSE_PROFILE") {
            cmd.env("TOKENFUSE_PROFILE", "observe");
        }
        for (k, v) in extra {
            cmd.env(k, v);
        }
        let mut child = cmd
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .expect("failed to spawn the tokenfuse binary");
        let output = Arc::new(Mutex::new(String::new()));
        keep(child.stdout.take().unwrap(), Arc::clone(&output));
        keep(child.stderr.take().unwrap(), Arc::clone(&output));
        let mut running = Running {
            child,
            output,
            port,
        };
        let deadline = Instant::now() + CEILING;
        loop {
            if running.output().contains(LISTENING) {
                // stdout and stderr are read on two threads, so a line printed
                // to stderr before the listening line on stdout can still be in
                // flight. A startup line is what several callers assert on.
                thread::sleep(Duration::from_millis(300));
                return running;
            }
            if let Some(status) = running.child.try_wait().unwrap() {
                panic!(
                    "the gateway exited ({status}) before listening:\n{}",
                    running.output()
                );
            }
            if Instant::now() >= deadline {
                panic!(
                    "the gateway did not listen within {CEILING:?}:\n{}",
                    running.output()
                );
            }
            thread::sleep(Duration::from_millis(20));
        }
    }

    /// Everything it has printed so far, stdout and stderr together, with the
    /// colour codes taken out.
    pub fn output(&self) -> String {
        self.output.lock().unwrap().clone()
    }

    /// `http://127.0.0.1:<port>`.
    pub fn url(&self) -> String {
        format!("http://127.0.0.1:{}", self.port)
    }
}

impl Drop for Running {
    fn drop(&mut self) {
        self.child.kill().ok();
        self.child.wait().ok();
    }
}
