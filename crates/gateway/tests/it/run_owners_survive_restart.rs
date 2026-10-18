//! Invariant 120, the restart half: the principal that opened a run is still
//! its owner after the gateway restarts on the same data dir, a run-owner
//! journal that cannot be read stops the gateway before it serves, and a
//! gateway that cannot keep owners across a restart says so at startup.
//!
//! Before this change the owner map lived in memory only, so after a restart
//! the first caller to name a run owned it.

use crate::common::binary::Running;
use std::io::Read;
use std::process::{Command, Stdio};
use std::thread;
use std::time::{Duration, Instant};

const KEYS: &str = "sk-restart-a:key-a,sk-restart-b:key-b";
const JOURNAL: &str = "run-owners.ndjson";
const LISTENING: &str = "tokenfuse gateway listening";
const CALL: &str =
    r#"{"model":"claude-sonnet-5","max_tokens":32,"messages":[{"role":"user","content":"hello"}]}"#;

fn scratch(name: &str) -> std::path::PathBuf {
    let d = std::env::temp_dir().join(format!(
        "tf-run-owners-restart-{}-{name}",
        std::process::id()
    ));
    let _ = std::fs::remove_dir_all(&d);
    std::fs::create_dir_all(&d).unwrap();
    d
}

async fn call(gw: &Running, key: &str, run: &str, agent: &str) -> (u16, String) {
    let resp = reqwest::Client::new()
        .post(format!("{}/v1/messages", gw.url()))
        .header("content-type", "application/json")
        .header("x-fuse-key", key)
        .header("x-fuse-run-id", run)
        .header("x-fuse-agent-id", agent)
        .body(CALL)
        .send()
        .await
        .expect("the gateway answers");
    let status = resp.status().as_u16();
    (status, resp.text().await.unwrap_or_default())
}

#[tokio::test]
async fn run_owners_survive_a_gateway_restart() {
    let dir = scratch("survives");
    let d = dir.to_str().unwrap();
    let env = [("TOKENFUSE_CLIENT_KEYS", KEYS), ("TOKENFUSE_DATA_DIR", d)];

    let first = Running::start("127.0.0.1", &env);
    let (status, body) = call(
        &first,
        "sk-restart-a",
        "run-across-restart",
        "agent://test.local/a",
    )
    .await;
    assert_eq!(status, 200, "key A opens the run: {body}");
    let (status, body) = call(
        &first,
        "sk-restart-b",
        "run-across-restart",
        "agent://test.local/b",
    )
    .await;
    assert_eq!(status, 403, "key B is refused before the restart: {body}");
    drop(first); // SIGKILL: nothing a graceful stop would write can be what the next process reads

    let second = Running::start("127.0.0.1", &env);
    let (status, body) = call(
        &second,
        "sk-restart-b",
        "run-across-restart",
        "agent://test.local/b",
    )
    .await;
    assert_eq!(
        status, 403,
        "after the restart the run is still key A's, so key B cannot take it by naming it first: {body}"
    );
    assert!(body.contains("run_owned_elsewhere"), "{body}");
    let (status, body) = call(
        &second,
        "sk-restart-a",
        "run-across-restart",
        "agent://test.local/a",
    )
    .await;
    assert_eq!(status, 200, "and key A is still answered on it: {body}");
    assert!(
        second
            .output()
            .contains("run-owner journal replayed: 1 runs owned"),
        "the replay says what it restored:\n{}",
        second.output()
    );
    drop(second);
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn an_unreadable_run_owner_journal_refuses_to_start() {
    let dir = scratch("unreadable");
    let journal = dir.join(JOURNAL);
    std::fs::create_dir(&journal).unwrap();
    let mut child = Command::new(env!("CARGO_BIN_EXE_tokenfuse"))
        .env_remove("TOKENFUSE_UPSTREAM")
        .env_remove("TOKENFUSE_CLOUD_URL")
        .env("TOKENFUSE_ALLOW_STUB", "1")
        .env("TOKENFUSE_ADDR", "127.0.0.1:0")
        .env("TOKENFUSE_CLIENT_KEYS", KEYS)
        .env("TOKENFUSE_DATA_DIR", &dir)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("failed to spawn the tokenfuse binary");
    let deadline = Instant::now() + Duration::from_secs(15);
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
        panic!("the gateway started with an unreadable run-owner journal; stdout:\n{stdout}\nstderr:\n{stderr}");
    };
    assert!(
        !stdout.contains(LISTENING),
        "the listener bound before the refusal; stdout:\n{stdout}"
    );
    assert_eq!(status.code(), Some(2), "stderr:\n{stderr}");
    assert!(
        stderr.contains(&journal.display().to_string()),
        "the refusal names the journal; stderr:\n{stderr}"
    );
}

#[test]
fn without_a_data_dir_run_ownership_is_said_to_be_process_local() {
    let gw = Running::start("127.0.0.1", &[("TOKENFUSE_CLIENT_KEYS", KEYS)]);
    assert!(
        gw.output().contains("run ownership is process-local"),
        "a gateway that will forget its owners on restart says so:\n{}",
        gw.output()
    );
}

#[test]
fn without_client_keys_run_ownership_is_said_to_be_off() {
    let gw = Running::start("127.0.0.1", &[]);
    assert!(
        gw.output().contains("run ownership off"),
        "a gateway with no client keys says no run has an owner:\n{}",
        gw.output()
    );
}
