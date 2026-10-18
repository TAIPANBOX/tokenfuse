//! Invariant 128 over the real binary: `serve` and `mcp-broker` read the
//! checkpoint configuration at startup, have their key certified by keyryx,
//! write signed SPEC 6.5.1 records beside their stream, and write the close
//! record when stopped with SIGTERM. The unit tests in `checkpoints` prove the
//! writer and the client; only the binary can show that `main.rs` wires them.

#![cfg(unix)]

use axum::extract::{Path as AxPath, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::post;
use axum::{Json, Router};
use base64::Engine as _;
use p256::ecdsa::{signature::Verifier as _, Signature, VerifyingKey};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::io::{BufRead, BufReader};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::{mpsc, Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

const CONSUMER: &str = "tokenfuse";
const BEARER: &str = "keyryx-consumer-key";
const KEY_NAME: &str = "tokenfuse-stream";

fn b64url() -> base64::engine::GeneralPurpose {
    base64::engine::general_purpose::URL_SAFE_NO_PAD
}

fn verifying_key(jwk: &Value) -> VerifyingKey {
    let mut sec1 = vec![4u8];
    sec1.extend(b64url().decode(jwk["x"].as_str().unwrap()).unwrap());
    sec1.extend(b64url().decode(jwk["y"].as_str().unwrap()).unwrap());
    VerifyingKey::from_sec1_bytes(&sec1).unwrap()
}

#[derive(Default)]
struct Keyryx {
    now: i64,
    challenges: Mutex<Vec<String>>,
    certified: Mutex<Vec<(Value, i64, i64)>>,
}

fn authorized(h: &HeaderMap) -> bool {
    h.get("authorization").and_then(|v| v.to_str().ok()) == Some(&format!("Bearer {BEARER}"))
}

async fn challenge(State(k): State<Arc<Keyryx>>, h: HeaderMap) -> Response {
    if !authorized(&h) {
        return StatusCode::UNAUTHORIZED.into_response();
    }
    let c = format!("c{:0>42}", k.challenges.lock().unwrap().len());
    k.challenges.lock().unwrap().push(c.clone());
    Json(json!({"challenge": c, "expires_at": k.now + 60})).into_response()
}

async fn delegate(
    State(k): State<Arc<Keyryx>>,
    AxPath(name): AxPath<String>,
    h: HeaderMap,
    Json(b): Json<Value>,
) -> Response {
    let ch = b["challenge"].as_str().unwrap_or("").to_string();
    if !authorized(&h) || !k.challenges.lock().unwrap().contains(&ch) {
        return StatusCode::FORBIDDEN.into_response();
    }
    let jwk = b["jwk"].clone();
    let kid = jwk["kid"].as_str().unwrap_or("").to_string();
    let input = format!("keyryx/delegate/v1\0{name}\0{CONSUMER}\0{kid}\0{ch}");
    let proof = base64::engine::general_purpose::STANDARD
        .decode(b["proof_b64"].as_str().unwrap_or(""))
        .unwrap_or_default();
    let ok = Signature::from_slice(&proof)
        .map(|s| verifying_key(&jwk).verify(input.as_bytes(), &s).is_ok())
        .unwrap_or(false);
    if !ok {
        return StatusCode::FORBIDDEN.into_response();
    }
    let life = b["lifetime_s"].as_i64().unwrap();
    let (nb, na) = (k.now, k.now + life);
    let claims = json!({"v": 1, "iss": "keyryx", "name": name, "owner": CONSUMER, "kid": kid,
        "jwk": jwk, "not_before": nb, "not_after": na, "issued_at": k.now,
        "jti": "jti-fixed-0123456789", "roots": {"ES384": "r", "ML-DSA-65": "m"}});
    k.certified.lock().unwrap().push((jwk.clone(), nb, na));
    Json(json!({
        "statement": {"payload": b64url().encode(serde_json::to_vec(&claims).unwrap()),
                      "signatures": [{"protected": "e30", "signature": "AA"}]},
        "kid": kid, "not_before": nb, "not_after": na
    }))
    .into_response()
}

async fn keyryx() -> (String, Arc<Keyryx>) {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64
        - 5;
    let k = Arc::new(Keyryx {
        now,
        ..Default::default()
    });
    let app = Router::new()
        .route("/v1/keys/{name}/challenge", post(challenge))
        .route("/v1/keys/{name}/delegate", post(delegate))
        .with_state(Arc::clone(&k));
    let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("http://{}", l.local_addr().unwrap());
    tokio::spawn(async move {
        axum::serve(l, app).await.ok();
    });
    (url, k)
}

fn free_addr() -> String {
    let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let a = l.local_addr().unwrap().to_string();
    drop(l);
    a
}

fn temp_dir(tag: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("tf-it-ckpt-{}-{tag}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(dir.join("events")).unwrap();
    std::fs::create_dir_all(dir.join("checkpoints")).unwrap();
    std::fs::write(dir.join("credential"), format!("{BEARER}\n")).unwrap();
    dir
}

fn checkpoint_env(dir: &Path, keyryx_url: &str) -> Vec<(String, String)> {
    vec![
        (
            "TOKENFUSE_EVENTS_PATH".into(),
            dir.join("events/tokenfuse.ndjson").display().to_string(),
        ),
        (
            "TOKENFUSE_CHECKPOINTS_DIR".into(),
            dir.join("checkpoints").display().to_string(),
        ),
        ("TOKENFUSE_CHECKPOINT_KEYRYX_URL".into(), keyryx_url.into()),
        (
            "TOKENFUSE_CHECKPOINT_KEYRYX_CONSUMER".into(),
            CONSUMER.into(),
        ),
        (
            "TOKENFUSE_CHECKPOINT_KEYRYX_CREDENTIAL_FILE".into(),
            dir.join("credential").display().to_string(),
        ),
        ("TOKENFUSE_CHECKPOINT_KEY_NAME".into(), KEY_NAME.into()),
        (
            "TOKENFUSE_CHECKPOINT_KEY_LIFETIME_SECS".into(),
            "3600".into(),
        ),
    ]
}

/// The binary with exactly `env` (cleared first), its output kept, and true when
/// `needle` was printed before the deadline.
fn spawn(
    args: &[&str],
    env: &[(String, String)],
    needle: &'static str,
) -> (Child, Arc<Mutex<Vec<String>>>, bool) {
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_tokenfuse"));
    cmd.args(args)
        .env_clear()
        .env("RUST_LOG", "info")
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    for (k, v) in env {
        cmd.env(k, v);
    }
    let mut child = cmd.spawn().expect("the tokenfuse binary runs");
    let log: Arc<Mutex<Vec<String>>> = Arc::default();
    let (tx, rx) = mpsc::channel::<()>();
    let streams: [Box<dyn std::io::Read + Send>; 2] = [
        Box::new(child.stdout.take().unwrap()),
        Box::new(child.stderr.take().unwrap()),
    ];
    for s in streams {
        let (log, tx) = (Arc::clone(&log), tx.clone());
        thread::spawn(move || {
            for line in BufReader::new(s).lines().map_while(Result::ok) {
                if line.contains(needle) {
                    tx.send(()).ok();
                }
                log.lock().unwrap().push(line);
            }
        });
    }
    let up = rx.recv_timeout(Duration::from_secs(20)).is_ok();
    (child, log, up)
}

async fn terminate(child: &mut Child) -> bool {
    let started = Instant::now();
    assert!(Command::new("kill")
        .args(["-TERM", &child.id().to_string()])
        .status()
        .unwrap()
        .success());
    while started.elapsed() < Duration::from_secs(20) {
        if child.try_wait().ok().flatten().is_some() {
            return true;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    child.kill().ok();
    false
}

fn lines(b: &[u8]) -> Vec<&[u8]> {
    let mut out = vec![];
    let mut start = 0;
    for (i, c) in b.iter().enumerate() {
        if *c == b'\n' {
            out.push(&b[start..i]);
            start = i + 1;
        }
    }
    out
}

fn sha(b: &[u8]) -> String {
    format!(
        "sha256:{}",
        Sha256::digest(b)
            .iter()
            .map(|x| format!("{x:02x}"))
            .collect::<String>()
    )
}

/// Each record against the stream and the key keyryx certified: prev chained,
/// prefix the stream's first N bytes, the signature over the record's JCS form
/// without `sig`. Returns `(kind, count)` per record, panicking on a refusal.
fn verified(dir: &Path, jwk: &Value) -> Vec<(String, u64)> {
    let stream = std::fs::read(dir.join("events/tokenfuse.ndjson")).unwrap();
    let side =
        std::fs::read(dir.join("checkpoints/tokenfuse.ndjson.ckpt.ndjson")).unwrap_or_default();
    let ends: Vec<usize> = stream
        .iter()
        .enumerate()
        .filter(|(_, c)| **c == b'\n')
        .map(|(i, _)| i + 1)
        .collect();
    let mut prev = format!("sha256:{}", "0".repeat(64));
    let mut out = vec![];
    for rec in lines(&side) {
        let mut v: serde_json::Map<String, Value> = serde_json::from_slice(rec).unwrap();
        let count = v["count"].as_u64().unwrap();
        assert_eq!(v["prev"], prev.as_str(), "prev chains");
        assert_eq!(
            v["prefix"],
            sha(&stream[..ends[count as usize - 1]]).as_str(),
            "prefix"
        );
        assert_eq!(v["kid"], jwk["kid"], "signed by the certified key");
        let sig = b64url()
            .decode(v.remove("sig").unwrap().as_str().unwrap())
            .unwrap();
        let input = tokenfuse_core::jcs::canonicalize(&Value::Object(v.clone()));
        assert!(
            verifying_key(jwk)
                .verify(input.as_bytes(), &Signature::from_slice(&sig).unwrap())
                .is_ok(),
            "the signature verifies"
        );
        out.push((v["kind"].as_str().unwrap().to_string(), count));
        prev = sha(rec);
    }
    out
}

/// key.json beside the stream, so the Go verifiers can be pointed at the run.
fn keep_key(dir: &Path, k: &Keyryx) {
    let (jwk, nb, na) = k.certified.lock().unwrap()[0].clone();
    std::fs::write(
        dir.join("key.json"),
        serde_json::to_vec(&json!({"jwk": jwk, "not_before": nb, "not_after": na})).unwrap(),
    )
    .unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_gateway_signs_checkpoints_of_its_stream_and_closes_them_on_sigterm() {
    let (url, k) = keyryx().await;
    let dir = temp_dir("serve");
    let addr = free_addr();
    let mut env = checkpoint_env(&dir, &url);
    env.extend([
        ("TOKENFUSE_ADDR".to_string(), addr.clone()),
        ("TOKENFUSE_ALLOW_STUB".to_string(), "1".to_string()),
        ("TOKENFUSE_MODE".to_string(), "enforce".to_string()),
    ]);
    let (mut child, log, up) = spawn(&[], &env, "tokenfuse gateway listening");
    assert!(
        up,
        "the gateway never listened: {}",
        log.lock().unwrap().join("\n")
    );
    let http = reqwest::Client::new();
    for i in 0..70 {
        // A budget far below any call's estimate: a 402 and one breaker_tripped.
        let r = http
            .post(format!("http://{addr}/v1/messages"))
            .header("x-fuse-run-id", format!("run-{i}"))
            .header("x-fuse-agent-id", "agent://acme.example/support/bot")
            .header("x-fuse-budget-usd", "0.000001")
            .json(&json!({"model": "claude-sonnet-5", "max_tokens": 64,
                          "messages": [{"role": "user", "content": "hello"}]}))
            .send()
            .await
            .unwrap();
        assert_eq!(r.status().as_u16(), 402);
    }
    assert!(terminate(&mut child).await, "the gateway exits on SIGTERM");
    keep_key(&dir, &k);
    let all = log.lock().unwrap().join("\n");
    assert!(all.contains("signed agent-event checkpoints ON"), "{all}");
    assert!(all.contains("checkpoint key certified by keyryx"), "{all}");
    let jwk = k.certified.lock().unwrap()[0].0.clone();
    let stream = std::fs::read(dir.join("events/tokenfuse.ndjson")).unwrap();
    assert_eq!(lines(&stream).len(), 70, "one event per refused call");
    assert_eq!(
        verified(&dir, &jwk),
        vec![("checkpoint".to_string(), 64), ("close".to_string(), 70)],
        "{all}"
    );
}

async fn mcp_upstream() -> String {
    let app = Router::new().route(
        "/",
        post(|Json(b): Json<Value>| async move {
            Json(json!({"jsonrpc": "2.0", "id": b["id"], "result": {"ok": true}}))
        }),
    );
    let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("http://{}/", l.local_addr().unwrap());
    tokio::spawn(async move {
        axum::serve(l, app).await.ok();
    });
    url
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_mcp_broker_signs_its_own_stream_and_closes_it_on_sigterm() {
    let (url, k) = keyryx().await;
    let upstream = mcp_upstream().await;
    let dir = temp_dir("broker");
    let addr = free_addr();
    let mut env = checkpoint_env(&dir, &url);
    env.extend([
        ("TOKENFUSE_MCP_ADDR".to_string(), addr.clone()),
        ("TOKENFUSE_MCP_UPSTREAM".to_string(), upstream),
    ]);
    let (mut child, log, up) = spawn(&["mcp-broker"], &env, "mcp credential-broker listening");
    assert!(
        up,
        "the broker never listened: {}",
        log.lock().unwrap().join("\n")
    );
    let http = reqwest::Client::new();
    for id in 0..3 {
        let r: Value = http
            .post(format!("http://{addr}/"))
            .header("x-fuse-agent-id", "agent://acme.example/tool-user")
            .json(&json!({"jsonrpc": "2.0", "id": id, "method": "tools/call",
                          "params": {"name": "lookup", "arguments": {}}}))
            .send()
            .await
            .unwrap()
            .json()
            .await
            .unwrap();
        assert_eq!(r["result"]["ok"], true, "{r}");
    }
    assert!(terminate(&mut child).await, "the broker exits on SIGTERM");
    keep_key(&dir, &k);
    let all = log.lock().unwrap().join("\n");
    let jwk = k.certified.lock().unwrap()[0].0.clone();
    assert_eq!(
        verified(&dir, &jwk),
        vec![("close".to_string(), 3)],
        "three tool_call records, closed: {all}"
    );
}

/// The exit code within ten seconds, or `None` for a process that went on
/// running (killed, so an unfixed binary fails this rather than hanging it).
fn exit_code_within(args: &[&str], env: &[(String, String)]) -> (Option<i32>, String) {
    let mut child = Command::new(env!("CARGO_BIN_EXE_tokenfuse"))
        .args(args)
        .env_clear()
        .envs(env.iter().cloned())
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let deadline = Instant::now() + Duration::from_secs(10);
    let code = loop {
        if let Some(s) = child.try_wait().unwrap() {
            break s.code();
        }
        if Instant::now() >= deadline {
            child.kill().ok();
            child.wait().ok();
            break None;
        }
        thread::sleep(Duration::from_millis(20));
    };
    let mut err = String::new();
    if let Some(mut e) = child.stderr.take() {
        use std::io::Read as _;
        e.read_to_string(&mut err).ok();
    }
    (code, err)
}

#[test]
fn a_checkpoint_directory_with_no_keyryx_refuses_to_start_in_both_processes() {
    let dir = temp_dir("refuse");
    let env = vec![
        (
            "TOKENFUSE_EVENTS_PATH".to_string(),
            dir.join("events/tokenfuse.ndjson").display().to_string(),
        ),
        (
            "TOKENFUSE_CHECKPOINTS_DIR".to_string(),
            dir.join("checkpoints").display().to_string(),
        ),
        ("TOKENFUSE_ALLOW_STUB".to_string(), "1".to_string()),
        ("TOKENFUSE_ADDR".to_string(), free_addr()),
        ("TOKENFUSE_MCP_ADDR".to_string(), free_addr()),
        (
            "TOKENFUSE_MCP_UPSTREAM".to_string(),
            "http://127.0.0.1:9/".to_string(),
        ),
    ];
    for args in [&[][..], &["mcp-broker"][..]] {
        let (code, out) = exit_code_within(args, &env);
        assert_eq!(code, Some(2), "{args:?}: {out}");
        assert!(
            out.contains("TOKENFUSE_CHECKPOINT_KEYRYX_URL"),
            "{args:?}: {out}"
        );
    }
}
