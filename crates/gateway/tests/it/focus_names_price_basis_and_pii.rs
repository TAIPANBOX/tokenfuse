//! Invariant 109: the FOCUS export names the price basis each admitted call was
//! charged at and the PII the scanner let through, the two facts a FinOps tool
//! reading only the export (costcrew, its invariant 64) could not see: the
//! basis rode the Cloud wire alone and the PII findings the trace alone.
//!
//! The real path end to end: calls through the gateway's router into a Parquet
//! trace, then the real `tokenfuse focus-export` binary over that trace.

use axum::body::Body;
use axum::http::Request;
use std::sync::Arc;
use tokenfuse_core::{DlpMode, Ledger, Mode, Policy};
use tokenfuse_gateway::provider::StubProvider;
use tokenfuse_gateway::sink::{EventSink, ParquetSink};
use tokenfuse_gateway::state::AppState;
use tower::ServiceExt;

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

async fn call(st: &AppState, run: &str, model: &str, prompt: &str) {
    let body = serde_json::json!({
        "model": model,
        "max_tokens": 10,
        "messages": [{"role": "user", "content": prompt}],
    })
    .to_string();
    let resp = tokenfuse_gateway::app(st.clone())
        .oneshot(
            Request::post("/v1/messages")
                .header("content-type", "application/json")
                .header("x-fuse-run-id", run)
                .header("x-fuse-budget-usd", "5")
                .body(Body::from(body))
                .unwrap(),
        )
        .await
        .unwrap();
    assert!(resp.status().is_success(), "{model}: {}", resp.status());
    let _ = axum::body::to_bytes(resp.into_body(), 1 << 20).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_export_names_the_price_basis_and_the_pii_let_through() {
    let dir = std::env::temp_dir().join(format!("tf-focus-basis-pii-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    let traces = dir.join("traces");
    std::fs::create_dir_all(&traces).unwrap();
    let sink = Arc::new(ParquetSink::new(traces.to_str().unwrap(), 1).unwrap());
    let st = AppState::new(
        Arc::new(Ledger::new()),
        Arc::new(tokenfuse_gateway::pricebook::default_price_book()),
        Arc::new(Policy {
            mode: Mode::Enforce,
            ..Default::default()
        }),
        Arc::new(StubProvider::default()),
        "focus-test",
    )
    .with_dlp_pii(DlpMode::Shadow)
    .with_sink(sink.clone());
    call(
        &st,
        "run-known",
        "claude-haiku-5-5",
        "My email is jane.doe@example.com and my card is 4111 1111 1111 1111.",
    )
    .await;
    call(&st, "run-fallback", "mystery-model-1", "Reply OK.").await;
    sink.flush();

    let out = dir.join("focus.csv");
    let status = std::process::Command::new(env!("CARGO_BIN_EXE_tokenfuse"))
        .env("TOKENFUSE_PROFILE", "observe")
        .args([
            "focus-export",
            "--traces",
            traces.to_str().unwrap(),
            "--out",
            out.to_str().unwrap(),
        ])
        .env_remove("TOKENFUSE_UPSTREAM")
        .status()
        .expect("the export runs");
    assert!(status.success(), "focus-export exited {status}");
    let csv = std::fs::read_to_string(&out).unwrap();
    let mut lines = csv.lines();
    let header = fields(lines.next().expect("a header"));
    let col = |name: &str| {
        header
            .iter()
            .position(|h| h == name)
            .unwrap_or_else(|| panic!("the export has no {name} column: {header:?}"))
    };
    let (basis, pii, run) = (col("x_price_basis"), col("x_pii_findings"), col("x_run_id"));
    assert_eq!(
        header.last().map(String::as_str),
        Some("x_pii_findings"),
        "appended last, after x_price_basis: {header:?}"
    );
    let rows: Vec<Vec<String>> = lines.map(fields).collect();
    let row = |id: &str| {
        rows.iter()
            .find(|r| r[run] == id)
            .unwrap_or_else(|| panic!("no row for {id}: {rows:?}"))
            .clone()
    };
    let known = row("run-known");
    assert_eq!(known[basis], "known");
    assert_eq!(known[pii], "pii_card=1,pii_email=1");
    let fallback = row("run-fallback");
    assert_eq!(fallback[basis], "fallback");
    assert_eq!(fallback[pii], "");
    assert!(
        !csv.contains("jane.doe") && !csv.contains("4111"),
        "kinds and counts only: {csv}"
    );
    let _ = std::fs::remove_dir_all(&dir);
}
