//! Seam test for `TOKENFUSE_PRICE_BOOK` (tokenfuse#313): `pricefile`'s unit
//! tests prove the parser, but nothing there proves `main.rs`'s `serve()`
//! reads the variable, refuses a bad file, and hands the rows to the book a
//! real call is priced against. This runs the real binary, as
//! `run_budget_ceiling_startup.rs` does, against the stub provider (1000
//! input and 500 output tokens per call).

use std::io::{BufRead, BufReader};
use std::process::{Child, Command, Stdio};
use std::sync::mpsc;
use std::thread;
use std::time::{Duration, Instant};

fn bin() -> &'static str {
    env!("CARGO_BIN_EXE_tokenfuse")
}

const LISTENING_NEEDLE: &str = "tokenfuse gateway listening";
const CEILING: Duration = Duration::from_secs(10);

fn base_cmd(addr: &str) -> Command {
    let mut cmd = Command::new(bin());
    cmd.env_remove("TOKENFUSE_UPSTREAM")
        .env_remove("TOKENFUSE_PRICE_BOOK")
        .env_remove("TOKENFUSE_MAX_RUN_BUDGET_USD")
        .env_remove("TOKENFUSE_CLIENT_KEYS")
        .env_remove("TOKENFUSE_IDENTITY_MAP")
        .env("TOKENFUSE_ALLOW_STUB", "1")
        .env("TOKENFUSE_MODE", "enforce")
        .env("TOKENFUSE_ADDR", addr);
    cmd
}

fn scratch(name: &str, body: &str) -> String {
    let dir = std::env::temp_dir().join(format!("tf-pricebook-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let p = dir.join(name);
    std::fs::write(&p, body).unwrap();
    p.to_string_lossy().into_owned()
}

const SONNET_5_REGIONAL: &str = r#"{"model": "claude-sonnet-5",
    "input_per_mtok_microusd": 2200000, "output_per_mtok_microusd": 11000000,
    "cache_read_per_mtok_microusd": 220000, "cache_write_per_mtok_microusd": 2750000,
    "cache_write_1h_per_mtok_microusd": 4400000}"#;
const LOCAL_FREE: &str = r#"{"model": "my-local-model",
    "input_per_mtok_microusd": 0, "output_per_mtok_microusd": 0,
    "cache_read_per_mtok_microusd": 0, "cache_write_per_mtok_microusd": 0,
    "cache_write_1h_per_mtok_microusd": 0}"#;

/// A set but unusable file stops the process naming the variable; it never
/// starts on the built-in book while the operator believes their rates are
/// live.
#[test]
fn an_unusable_price_book_exits_2_and_names_the_variable() {
    let negative = SONNET_5_REGIONAL.replace("2200000,", "-1,");
    let typo = SONNET_5_REGIONAL.replace("\"model\"", "\"modle\"");
    let cases = [
        scratch("negative.json", &format!(r#"{{"models": [{negative}]}}"#)),
        scratch("typo.json", &format!(r#"{{"models": [{typo}]}}"#)),
        scratch("empty.json", r#"{"models": []}"#),
        scratch("garbage.json", "not json"),
        "/nonexistent/tokenfuse-prices.json".to_string(),
    ];
    for path in cases {
        let mut child = base_cmd("127.0.0.1:0")
            .env("TOKENFUSE_PRICE_BOOK", &path)
            .stdout(Stdio::null())
            .stderr(Stdio::piped())
            .spawn()
            .expect("failed to spawn the tokenfuse binary");
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
        let Some(status) = status else {
            child.kill().ok();
            child.wait().ok();
            panic!("{path}: the gateway kept serving with an unusable price book");
        };
        let mut stderr = String::new();
        std::io::Read::read_to_string(&mut child.stderr.take().unwrap(), &mut stderr).ok();
        assert_eq!(status.code(), Some(2), "{path}: stderr was: {stderr}");
        assert!(
            stderr.contains("TOKENFUSE_PRICE_BOOK"),
            "{path}: stderr did not name the variable: {stderr}"
        );
    }
}

fn spawn_serving(addr: &str, book: Option<&str>) -> Child {
    let mut cmd = base_cmd(addr);
    if let Some(p) = book {
        cmd.env("TOKENFUSE_PRICE_BOOK", p);
    }
    cmd.stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("failed to spawn the tokenfuse binary")
}

fn wait_for_listening(child: &mut Child) -> bool {
    let stdout = child.stdout.take().expect("stdout piped");
    let (tx, rx) = mpsc::channel::<()>();
    thread::spawn(move || {
        for line in BufReader::new(stdout).lines().map_while(Result::ok) {
            if line.contains(LISTENING_NEEDLE) {
                tx.send(()).ok();
            }
        }
    });
    rx.recv_timeout(CEILING).is_ok()
}

fn free_addr() -> String {
    let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let a = l.local_addr().unwrap();
    drop(l);
    a.to_string()
}

/// (status, x-fuse-price, x-fuse-cost-usd) of one call on `model`.
async fn priced(addr: &str, run: &str, model: &str) -> (u16, String, String) {
    let r = reqwest::Client::new()
        .post(format!("http://{addr}/v1/messages"))
        .header("x-fuse-run-id", run)
        .header("content-type", "application/json")
        .body(format!(
            r#"{{"model":"{model}","max_tokens":10,"messages":[{{"role":"user","content":"hi"}}]}}"#
        ))
        .send()
        .await
        .expect("the gateway must answer");
    let h = |n: &str| {
        r.headers()
            .get(n)
            .map(|v| v.to_str().unwrap().to_string())
            .unwrap_or_default()
    };
    (r.status().as_u16(), h("x-fuse-price"), h("x-fuse-cost-usd"))
}

/// The wiring end to end: without a file claude-sonnet-5 is priced at its
/// list rate (2000 + 5000 micro-USD); with a file naming the regional rate it
/// is 2200 + 5500, and a model only the file knows is priced by it.
#[tokio::test]
async fn the_binary_prices_with_the_operators_rows() {
    let addr = free_addr();
    let mut child = spawn_serving(&addr, None);
    let up = wait_for_listening(&mut child);
    let built_in = if up {
        Some(priced(&addr, "pb-built-in", "claude-sonnet-5").await)
    } else {
        None
    };
    child.kill().ok();
    child.wait().ok();
    assert!(up, "the gateway never reported listening");
    assert_eq!(
        built_in.unwrap(),
        (200, "known".to_string(), "0.007000".to_string())
    );

    let book = scratch(
        "ok.json",
        &format!(r#"{{"models": [{SONNET_5_REGIONAL}, {LOCAL_FREE}]}}"#),
    );
    let addr = free_addr();
    let mut child = spawn_serving(&addr, Some(&book));
    let up = wait_for_listening(&mut child);
    let (over, local, unknown) = if up {
        (
            Some(priced(&addr, "pb-over", "claude-sonnet-5").await),
            Some(priced(&addr, "pb-local", "my-local-model").await),
            Some(priced(&addr, "pb-unknown", "claude-sonnet-6").await),
        )
    } else {
        (None, None, None)
    };
    child.kill().ok();
    child.wait().ok();
    assert!(up, "the gateway never reported listening with a valid book");
    assert_eq!(
        over.unwrap(),
        (200, "known".to_string(), "0.007700".to_string())
    );
    assert_eq!(
        local.unwrap(),
        (200, "known".to_string(), "0.000000".to_string())
    );
    // The file cannot touch the fallback.
    assert_eq!(
        unknown.unwrap(),
        (200, "fallback".to_string(), "0.052500".to_string())
    );
}

/// `GET /v1/price-book` on the real binary.
async fn price_book(addr: &str) -> (u16, serde_json::Value) {
    let r = reqwest::Client::new()
        .get(format!("http://{addr}/v1/price-book"))
        .send()
        .await
        .expect("the gateway must answer");
    let status = r.status().as_u16();
    let body = r.json::<serde_json::Value>().await.unwrap_or_default();
    (status, body)
}

/// Invariant 86: which book a gateway prices with is readable from the
/// gateway, not only from its startup log. With the operator's file the
/// route names the row it replaced and the row it added; without one it says
/// the built-in book is the whole book; and a model the book has no row for
/// is named once a call has been priced at the fallback.
#[tokio::test]
async fn the_price_book_route_names_the_operators_rows_and_the_fallback() {
    let built_in = tokenfuse_gateway::pricebook::default_price_book()
        .entries()
        .len() as u64;

    let addr = free_addr();
    let mut child = spawn_serving(&addr, None);
    let up = wait_for_listening(&mut child);
    let plain = if up {
        Some(price_book(&addr).await)
    } else {
        None
    };
    child.kill().ok();
    child.wait().ok();
    assert!(up, "the gateway never reported listening");
    let (status, plain) = plain.unwrap();
    assert_eq!(status, 200, "GET /v1/price-book: {plain}");
    assert_eq!(plain["rows"], built_in, "{plain}");
    assert_eq!(plain["built_in_rows"], built_in, "{plain}");
    assert_eq!(plain["operator_file"], false, "{plain}");
    assert_eq!(plain["overridden"], 0, "{plain}");
    assert_eq!(plain["added"], 0, "{plain}");

    let book = scratch(
        "report.json",
        &format!(r#"{{"models": [{SONNET_5_REGIONAL}, {LOCAL_FREE}]}}"#),
    );
    let addr = free_addr();
    let mut child = spawn_serving(&addr, Some(&book));
    let up = wait_for_listening(&mut child);
    let (before, after) = if up {
        let before = price_book(&addr).await;
        priced(&addr, "pb-report", "claude-sonnet-6").await;
        (Some(before), Some(price_book(&addr).await))
    } else {
        (None, None)
    };
    child.kill().ok();
    child.wait().ok();
    assert!(up, "the gateway never reported listening with a valid book");
    let (status, before) = before.unwrap();
    assert_eq!(status, 200, "{before}");
    assert_eq!(
        before["rows"],
        built_in + 1,
        "one row replaced, one added: {before}"
    );
    assert_eq!(before["built_in_rows"], built_in, "{before}");
    assert_eq!(before["operator_file"], true, "{before}");
    assert_eq!(before["overridden"], 1, "{before}");
    assert_eq!(before["added"], 1, "{before}");
    assert_eq!(
        before["overridden_models"],
        serde_json::json!(["claude-sonnet-5"]),
        "{before}"
    );
    assert_eq!(
        before["added_models"],
        serde_json::json!(["my-local-model"]),
        "{before}"
    );
    assert_eq!(
        before["fallback"]["input_per_mtok_microusd"], 15_000_000,
        "{before}"
    );
    assert_eq!(
        before["fallback"]["output_per_mtok_microusd"], 75_000_000,
        "{before}"
    );
    assert_eq!(
        before["fallback_models_seen"],
        serde_json::json!([]),
        "nothing priced at the fallback yet: {before}"
    );
    let (_, after) = after.unwrap();
    assert_eq!(
        after["fallback_models_seen"],
        serde_json::json!(["claude-sonnet-6"]),
        "the model the book has no row for is named: {after}"
    );
    assert_eq!(after["fallback_models_seen_total"], 1, "{after}");
}
