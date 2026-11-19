//! Invariant 148: the trace carries the cache and reasoning counts a call was
//! priced with, the FOCUS export carries them as `x_` columns, and
//! `--spec 1.5` writes one row per token kind under the FOCUS 1.5
//! release-candidate names, its parts summing to the call's recorded cost.
//!
//! The real path end to end: real provider bodies (Anthropic with a 1-hour
//! cache split, OpenAI with a cached prefix and a reported zero reasoning
//! count, Vertex AI's OpenAI-compatible endpoint with 560 reasoning tokens)
//! served by a local upstream to the real `HttpProvider`, through `app()`,
//! into a Parquet trace, then the real `tokenfuse` binary over that trace.

use axum::body::{to_bytes, Body};
use axum::http::{Request, StatusCode};
use serde_json::{json, Value};
use std::collections::BTreeMap;
use std::path::Path;
use std::sync::Arc;
use tokenfuse_core::{Ledger, Mode, Policy};
use tokenfuse_gateway::provider::HttpProvider;
use tokenfuse_gateway::sink::{EventSink, ParquetSink};
use tokenfuse_gateway::state::AppState;
use tokenfuse_gateway::wire::Wire;
use tower::ServiceExt;

/// Anthropic's usage with the TTL breakdown: 400 tokens written for five
/// minutes and 600 for an hour, 1000 in all, beside 300 read from the cache.
/// On claude-haiku-4-5 (1.00 / 5.00, read 0.10, write 1.25, 1-hour write
/// 2.00 per Mtok): 10 + 100 + 30 + 500 + 1200 = 1840 micro-USD.
const ANTHROPIC: &str = r#"{"id":"msg_1","type":"message","role":"assistant","model":"claude-haiku-4-5","content":[{"type":"text","text":"hi"}],"stop_reason":"end_turn","usage":{"input_tokens":10,"output_tokens":20,"cache_read_input_tokens":300,"cache_creation_input_tokens":1000,"cache_creation":{"ephemeral_5m_input_tokens":400,"ephemeral_1h_input_tokens":600}}}"#;

/// OpenAI's usage: 950 prompt tokens of which 128 were cached, and a reasoning
/// count reported as zero. On gpt-4o (2.50 / 10.00, cached 1.25): 822 x 2.50
/// + 128 x 1.25 + 120 x 10.00 = 2055 + 160 + 1200 = 3415 micro-USD.
const OPENAI: &str = r#"{"id":"chatcmpl-1","object":"chat.completion","model":"gpt-4o","choices":[{"index":0,"message":{"role":"assistant","content":"hi"},"finish_reason":"stop"}],"usage":{"prompt_tokens":950,"completion_tokens":120,"total_tokens":1070,"prompt_tokens_details":{"cached_tokens":128},"completion_tokens_details":{"reasoning_tokens":0}}}"#;

/// Vertex AI's OpenAI-compatible endpoint, measured 2026-10-07: 560 reasoning
/// tokens outside `completion_tokens` and inside the 619 billed output.
const VERTEX: &str = r#"{"id":"vertex-1","object":"chat.completion","model":"google/gemini-2.5-flash","choices":[{"index":0,"message":{"role":"assistant","content":"hi"},"finish_reason":"stop"}],"usage":{"completion_tokens":59,"completion_tokens_details":{"reasoning_tokens":560},"prompt_tokens":14,"total_tokens":633}}"#;

const AGENT: &str = "agent://acme/finops";

/// Serves one HTTP answer on a local port and returns its address.
async fn upstream(body: &'static str) -> std::net::SocketAddr {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    tokio::spawn(async move {
        let (mut socket, _) = listener.accept().await.unwrap();
        let mut request = [0u8; 8192];
        // Never parsed; drained so the client's write completes first.
        #[allow(clippy::unused_io_amount)]
        socket.read(&mut request).await.unwrap();
        let head = format!(
            "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
            body.len()
        );
        socket.write_all(head.as_bytes()).await.unwrap();
        socket.write_all(body.as_bytes()).await.unwrap();
        socket.shutdown().await.unwrap();
    });
    address
}

/// One call through the real router to an upstream answering `body`, written
/// to `sink`.
async fn call(sink: Arc<ParquetSink>, wire: Wire, run: &str, model: &str, body: &'static str) {
    let address = upstream(body).await;
    let st = AppState::new(
        Arc::new(Ledger::new()),
        Arc::new(tokenfuse_gateway::pricebook::default_price_book()),
        Arc::new(Policy {
            mode: Mode::Enforce,
            ..Default::default()
        }),
        Arc::new(HttpProvider::new(format!("http://{address}"))),
        "focus-cache-reasoning",
    )
    .with_wire(wire)
    .with_sink(sink);
    let path = match wire {
        Wire::OpenAi => "/v1/chat/completions",
        _ => "/v1/messages",
    };
    let request = Request::post(path)
        .header("content-type", "application/json")
        .header("x-fuse-run-id", run)
        .header("x-fuse-agent-id", AGENT)
        .header("x-fuse-budget-usd", "5")
        .body(Body::from(
            json!({
                "model": model,
                "max_tokens": 1000,
                "messages": [{"role": "user", "content": "hi"}],
            })
            .to_string(),
        ))
        .unwrap();
    let response = tokenfuse_gateway::app(st).oneshot(request).await.unwrap();
    assert_eq!(response.status(), StatusCode::OK, "{run}");
    let _ = to_bytes(response.into_body(), usize::MAX).await.unwrap();
}

/// RFC 4180 fields of one CSV line (quotes doubled inside quoted fields).
fn fields(line: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut cur = String::new();
    let mut quoted = false;
    let mut chars = line.chars().peekable();
    while let Some(c) = chars.next() {
        match (c, quoted) {
            ('"', true) if chars.peek() == Some(&'"') => {
                cur.push('"');
                chars.next();
            }
            ('"', _) => quoted = !quoted,
            (',', false) => out.push(std::mem::take(&mut cur)),
            _ => cur.push(c),
        }
    }
    out.push(cur);
    out
}

type Row = BTreeMap<String, String>;

/// The export of `traces` written by the real binary, as (header, rows keyed
/// by header name).
fn export(traces: &Path, out: &Path, spec: Option<&str>) -> (Vec<String>, Vec<Row>) {
    let mut args = vec![
        "focus-export".to_string(),
        "--traces".to_string(),
        traces.to_str().unwrap().to_string(),
        "--out".to_string(),
        out.to_str().unwrap().to_string(),
    ];
    if let Some(s) = spec {
        args.push("--spec".to_string());
        args.push(s.to_string());
    }
    let status = std::process::Command::new(env!("CARGO_BIN_EXE_tokenfuse"))
        .args(&args)
        .env_remove("TOKENFUSE_UPSTREAM")
        .env_remove("TOKENFUSE_PRICE_BOOK")
        .status()
        .expect("the export runs");
    assert!(status.success(), "focus-export {spec:?} exited {status}");
    let csv = std::fs::read_to_string(out).unwrap();
    let mut lines = csv.lines();
    let header = fields(lines.next().expect("a header"));
    let rows = lines
        .map(|l| {
            let v = fields(l);
            assert_eq!(v.len(), header.len(), "a row as wide as the header: {l}");
            header.iter().cloned().zip(v).collect()
        })
        .collect();
    (header, rows)
}

fn col<'a>(row: &'a Row, name: &str) -> &'a str {
    row.get(name)
        .map(String::as_str)
        .unwrap_or_else(|| panic!("the export has no {name} column: {row:?}"))
}

fn rows_of<'a>(rows: &'a [Row], run: &str) -> Vec<&'a Row> {
    rows.iter().filter(|r| col(r, "x_run_id") == run).collect()
}

/// A `BilledCost` string as whole micro-USD.
fn micro(usd: &str) -> i64 {
    let (whole, frac) = usd.split_once('.').expect("a fixed-point cost");
    assert_eq!(frac.len(), 6, "six decimals: {usd}");
    whole.parse::<i64>().unwrap() * 1_000_000 + frac.parse::<i64>().unwrap()
}

fn sku(row: &Row) -> Value {
    serde_json::from_str(col(row, "SkuPriceDetails"))
        .unwrap_or_else(|e| panic!("SkuPriceDetails is JSON ({e}): {row:?}"))
}

fn scratch(tag: &str) -> std::path::PathBuf {
    let dir = std::env::temp_dir().join(format!("tf-focus-cache-{tag}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(dir.join("traces")).unwrap();
    dir
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_export_carries_the_cache_and_reasoning_counts_each_call_was_priced_with() {
    let dir = scratch("default");
    let traces = dir.join("traces");
    let sink = Arc::new(ParquetSink::new(traces.to_str().unwrap(), 1).unwrap());
    call(
        sink.clone(),
        Wire::Anthropic,
        "run-anthropic",
        "claude-haiku-4-5",
        ANTHROPIC,
    )
    .await;
    call(sink.clone(), Wire::OpenAi, "run-openai", "gpt-4o", OPENAI).await;
    call(
        sink.clone(),
        Wire::OpenAi,
        "run-vertex",
        "google/gemini-2.5-flash",
        VERTEX,
    )
    .await;
    sink.flush();

    let (header, rows) = export(&traces, &dir.join("focus.csv"), None);
    assert_eq!(
        &header[header.len() - 4..],
        [
            "x_cache_read_tokens",
            "x_cache_write_tokens",
            "x_cache_write_1h_tokens",
            "x_reasoning_tokens"
        ],
        "appended last: {header:?}"
    );
    let one = |run: &str| -> Row {
        let r = rows_of(&rows, run);
        assert_eq!(r.len(), 1, "one row per call in the default export: {run}");
        r[0].clone()
    };

    let a = one("run-anthropic");
    assert_eq!(col(&a, "x_tokens_in"), "10");
    assert_eq!(col(&a, "x_tokens_out"), "20");
    assert_eq!(col(&a, "x_cache_read_tokens"), "300");
    assert_eq!(col(&a, "x_cache_write_tokens"), "1000");
    assert_eq!(col(&a, "x_cache_write_1h_tokens"), "600");
    assert_eq!(
        col(&a, "x_reasoning_tokens"),
        "",
        "Anthropic names no reasoning count"
    );
    assert_eq!(
        col(&a, "BilledCost"),
        "0.001840",
        "the 1-hour subset at its own rate"
    );

    let o = one("run-openai");
    assert_eq!(
        col(&o, "x_tokens_in"),
        "822",
        "the cached subset netted out (invariant 45)"
    );
    assert_eq!(col(&o, "x_cache_read_tokens"), "128");
    assert_eq!(col(&o, "x_cache_write_tokens"), "0");
    assert_eq!(col(&o, "x_cache_write_1h_tokens"), "0");
    assert_eq!(
        col(&o, "x_reasoning_tokens"),
        "0",
        "a reported zero is a zero, not a blank"
    );
    assert_eq!(col(&o, "BilledCost"), "0.003415");

    let v = one("run-vertex");
    assert_eq!(
        col(&v, "x_tokens_out"),
        "619",
        "output keeps its meaning: 59 visible + 560 reasoning (invariant 80)"
    );
    assert_eq!(col(&v, "x_reasoning_tokens"), "560");
    assert_eq!(col(&v, "x_cache_read_tokens"), "0");
    let _ = std::fs::remove_dir_all(&dir);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn spec_1_5_writes_one_row_per_token_kind_and_the_parts_sum_to_the_call() {
    let dir = scratch("spec15");
    let traces = dir.join("traces");
    let sink = Arc::new(ParquetSink::new(traces.to_str().unwrap(), 1).unwrap());
    call(
        sink.clone(),
        Wire::Anthropic,
        "run-anthropic",
        "claude-haiku-4-5",
        ANTHROPIC,
    )
    .await;
    call(sink.clone(), Wire::OpenAi, "run-openai", "gpt-4o", OPENAI).await;
    call(
        sink.clone(),
        Wire::OpenAi,
        "run-vertex",
        "google/gemini-2.5-flash",
        VERTEX,
    )
    .await;
    sink.flush();

    let (_, default_rows) = export(&traces, &dir.join("default.csv"), None);
    let (header, rows) = export(&traces, &dir.join("focus15.csv"), Some("1.5"));
    for name in [
        "ChargeCategory",
        "ConsumedQuantity",
        "ConsumedUnit",
        "SkuPriceDetails",
        "PrincipalId",
        "CredentialId",
        "RequesterDetails",
    ] {
        assert!(
            header.iter().any(|h| h == name),
            "--spec 1.5 has no {name} column: {header:?}"
        );
    }

    // Every call's parts sum to the cost the default export recorded for it.
    for run in ["run-anthropic", "run-openai", "run-vertex"] {
        let parts: i64 = rows_of(&rows, run)
            .iter()
            .map(|r| micro(col(r, "BilledCost")))
            .sum();
        let whole = micro(col(rows_of(&default_rows, run)[0], "BilledCost"));
        assert_eq!(parts, whole, "{run}: the split adds or loses nothing");
    }

    // Anthropic: four kinds, each weighed at its own rate.
    let a = rows_of(&rows, "run-anthropic");
    let kinds: Vec<(String, String, String, String)> = a
        .iter()
        .map(|r| {
            let s = sku(r);
            (
                s["TokenDirection"].as_str().unwrap_or("").to_string(),
                s["TokenCacheAction"].as_str().unwrap_or("").to_string(),
                col(r, "ConsumedQuantity").to_string(),
                col(r, "BilledCost").to_string(),
            )
        })
        .collect();
    let want = |d: &str, c: &str, q: &str, b: &str| {
        (d.to_string(), c.to_string(), q.to_string(), b.to_string())
    };
    assert_eq!(
        kinds,
        vec![
            want("Input", "Uncached", "10", "0.000010"),
            want("Input", "Read", "300", "0.000030"),
            want("Input", "Write", "1000", "0.001700"),
            want("Output", "", "20", "0.000100"),
        ]
    );
    for r in &a {
        assert_eq!(col(r, "ConsumedUnit"), "Token");
        assert_eq!(col(r, "ChargeCategory"), "Usage");
        assert_eq!(col(r, "PrincipalId"), AGENT);
        let s = sku(r);
        assert_eq!(s["ModelId"], "claude-haiku-4-5");
        assert_eq!(s["ModelDeveloper"], "Anthropic");
        assert_eq!(s["ModelFamily"], "Claude Haiku");
        assert_eq!(s["ModelVersion"], "4.5");
        let requester: Value = serde_json::from_str(col(r, "RequesterDetails"))
            .expect("RequesterDetails is a JSON array");
        assert!(requester.as_array().is_some_and(|a| a
            .iter()
            .any(|e| e["Name"] == "AgentId" && e["Value"] == AGENT)));
    }
    let write = a
        .iter()
        .find(|r| sku(r)["TokenCacheAction"] == "Write")
        .unwrap();
    assert_eq!(col(write, "x_cache_write_1h_tokens"), "600");

    // OpenAI: the cached prefix is its own row; no write row for a zero write.
    let o = rows_of(&rows, "run-openai");
    let quantities: Vec<&str> = o.iter().map(|r| col(r, "ConsumedQuantity")).collect();
    assert_eq!(quantities, ["822", "128", "120"]);
    assert_eq!(sku(o[0])["ModelDeveloper"], "OpenAI");
    assert_eq!(sku(o[0])["ModelVersion"], "4o");

    // Vertex: reasoning stays inside the output row and is named there.
    let v = rows_of(&rows, "run-vertex");
    let output = v
        .iter()
        .find(|r| sku(r)["TokenDirection"] == "Output")
        .expect("an output row");
    assert_eq!(col(output, "ConsumedQuantity"), "619");
    assert_eq!(col(output, "x_reasoning_tokens"), "560");
    assert_eq!(sku(output)["ModelId"], "google/gemini-2.5-flash");
    assert_eq!(sku(output)["ModelDeveloper"], "Google");
    assert_eq!(sku(output)["ModelFamily"], "Gemini Flash");
    assert_eq!(sku(output)["ModelVersion"], "2.5");
    for r in v.iter().filter(|r| sku(r)["TokenDirection"] == "Input") {
        assert_eq!(
            col(r, "x_reasoning_tokens"),
            "",
            "reasoning on the output row only"
        );
    }
    let _ = std::fs::remove_dir_all(&dir);
}

/// A trace segment written before the four columns existed (the twelve
/// columns of the first P3 trace) beside one the current gateway wrote: `sql`,
/// `backtest` and both export shapes read the directory, the old row with the
/// new columns NULL or blank.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_trace_written_before_the_columns_existed_still_reads_everywhere() {
    use datafusion::arrow::array::{Int64Array, StringArray, UInt32Array, UInt64Array};
    use datafusion::arrow::datatypes::{DataType, Field, Schema};
    use datafusion::arrow::record_batch::RecordBatch;
    use datafusion::parquet::arrow::ArrowWriter;

    let dir = scratch("old");
    let traces = dir.join("traces");
    let old = Arc::new(Schema::new(vec![
        Field::new("ts_millis", DataType::Int64, false),
        Field::new("run_id", DataType::Utf8, false),
        Field::new("model", DataType::Utf8, false),
        Field::new("decision", DataType::Utf8, false),
        Field::new("input_tokens", DataType::UInt64, false),
        Field::new("output_tokens", DataType::UInt64, false),
        Field::new("cost_microusd", DataType::Int64, false),
        Field::new("step", DataType::UInt32, false),
        Field::new("agent_id", DataType::Utf8, false),
        Field::new("saved_microusd", DataType::Int64, false),
        Field::new("parent_run_id", DataType::Utf8, false),
        Field::new("on_behalf_of", DataType::Utf8, false),
    ]));
    let batch = RecordBatch::try_new(
        old.clone(),
        vec![
            Arc::new(Int64Array::from(vec![0i64])),
            Arc::new(StringArray::from(vec!["run-old"])),
            Arc::new(StringArray::from(vec!["claude-haiku-4-5"])),
            Arc::new(StringArray::from(vec!["allow"])),
            Arc::new(UInt64Array::from(vec![10u64])),
            Arc::new(UInt64Array::from(vec![20u64])),
            Arc::new(Int64Array::from(vec![110i64])),
            Arc::new(UInt32Array::from(vec![1u32])),
            Arc::new(StringArray::from(vec![AGENT])),
            Arc::new(Int64Array::from(vec![0i64])),
            Arc::new(StringArray::from(vec![""])),
            Arc::new(StringArray::from(vec![""])),
        ],
    )
    .unwrap();
    {
        let file = std::fs::File::create(traces.join("calls-old.parquet")).unwrap();
        let mut w = ArrowWriter::try_new(file, old, None).unwrap();
        w.write(&batch).unwrap();
        w.close().unwrap();
    }
    let sink = Arc::new(ParquetSink::new(traces.to_str().unwrap(), 1).unwrap());
    call(
        sink.clone(),
        Wire::Anthropic,
        "run-new",
        "claude-haiku-4-5",
        ANTHROPIC,
    )
    .await;
    sink.flush();

    let sql = std::process::Command::new(env!("CARGO_BIN_EXE_tokenfuse"))
        .args([
            "sql",
            "select run_id, coalesce(cast(cache_read_tokens as varchar), 'NULL') as cr, \
             coalesce(cast(cache_write_1h_tokens as varchar), 'NULL') as w1h, \
             coalesce(cast(reasoning_tokens as varchar), 'NULL') as rt \
             from calls order by run_id",
        ])
        .env("TOKENFUSE_DATA_DIR", &traces)
        .output()
        .expect("sql runs");
    let printed = String::from_utf8_lossy(&sql.stdout);
    let line = |run: &str| {
        printed
            .lines()
            .find(|l| l.contains(run))
            .unwrap_or_else(|| {
                panic!(
                    "sql printed no row for {run}: {printed}\n{}",
                    String::from_utf8_lossy(&sql.stderr)
                )
            })
            .split('|')
            .map(|c| c.trim().to_string())
            .filter(|c| !c.is_empty())
            .collect::<Vec<_>>()
    };
    assert_eq!(line("run-old"), ["run-old", "NULL", "NULL", "NULL"]);
    assert_eq!(line("run-new"), ["run-new", "300", "600", "NULL"]);

    let backtest = std::process::Command::new(env!("CARGO_BIN_EXE_tokenfuse"))
        .args(["backtest", "--budget", "1"])
        .env("TOKENFUSE_DATA_DIR", &traces)
        .output()
        .expect("backtest runs");
    assert!(
        backtest.status.success() && !String::from_utf8_lossy(&backtest.stderr).contains("error"),
        "backtest reads the mixed directory: {}",
        String::from_utf8_lossy(&backtest.stderr)
    );

    let (_, rows) = export(&traces, &dir.join("default.csv"), None);
    let old_row = rows_of(&rows, "run-old")[0];
    for c in [
        "x_cache_read_tokens",
        "x_cache_write_tokens",
        "x_cache_write_1h_tokens",
        "x_reasoning_tokens",
    ] {
        assert_eq!(
            col(old_row, c),
            "",
            "{c} blank on a row older than the column"
        );
    }
    assert_eq!(
        col(rows_of(&rows, "run-new")[0], "x_cache_read_tokens"),
        "300"
    );

    let (_, rows) = export(&traces, &dir.join("focus15.csv"), Some("1.5"));
    let old_rows = rows_of(&rows, "run-old");
    assert_eq!(old_rows.len(), 2, "an input row and an output row");
    let input = sku(old_rows[0]);
    assert_eq!(input["TokenDirection"], "Input");
    assert!(
        input.get("TokenCacheAction").is_none(),
        "the cache state of an older row's input is unknown, so none is named: {input}"
    );
    let parts: i64 = old_rows.iter().map(|r| micro(col(r, "BilledCost"))).sum();
    assert_eq!(parts, 110, "the recorded cost, split and not changed");
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn an_unknown_spec_is_refused_and_writes_nothing() {
    let dir = scratch("bad-spec");
    let out = dir.join("x.csv");
    let output = std::process::Command::new(env!("CARGO_BIN_EXE_tokenfuse"))
        .args([
            "focus-export",
            "--traces",
            dir.join("traces").to_str().unwrap(),
            "--out",
            out.to_str().unwrap(),
            "--spec",
            "9.9",
        ])
        .output()
        .expect("the export runs");
    assert!(!output.status.success(), "an unknown --spec is refused");
    assert!(
        String::from_utf8_lossy(&output.stderr).contains("--spec"),
        "the refusal names the flag: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(!out.exists());
    let _ = std::fs::remove_dir_all(&dir);
}
