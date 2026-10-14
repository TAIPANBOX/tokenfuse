//! Invariant 106: PII the scanner finds in a prompt and lets through (shadow
//! or mask) is on the call's trace row and its Cloud record as kinds and
//! counts, never the matched text. Until 2026-10-14 a shadow finding was an
//! `x-fuse-dlp` note on the answer and nothing else, so no dashboard could
//! show what shadow mode had found.

use axum::body::Body;
use axum::http::{Request, StatusCode};
use std::sync::{Arc, Mutex};
use tokenfuse_core::{DlpMode, Ledger, Mode, Policy};
use tokenfuse_gateway::provider::StubProvider;
use tokenfuse_gateway::sink::{CallRecord, EventSink};
use tokenfuse_gateway::state::AppState;
use tower::ServiceExt;

/// Every row the gateway records, as the JSON the Cloud wire carries.
#[derive(Default, Clone)]
struct Rows(Arc<Mutex<Vec<serde_json::Value>>>);

impl EventSink for Rows {
    fn record(&self, rec: CallRecord) {
        self.0
            .lock()
            .unwrap()
            .push(serde_json::to_value(&rec).unwrap());
    }
    fn flush(&self) {}
}

async fn call(mode: DlpMode, prompt: &str) -> (StatusCode, Vec<serde_json::Value>) {
    let rows = Rows::default();
    let st = AppState::new(
        Arc::new(Ledger::new()),
        Arc::new(tokenfuse_gateway::pricebook::default_price_book()),
        Arc::new(Policy {
            mode: Mode::Enforce,
            ..Default::default()
        }),
        Arc::new(StubProvider::default()),
        "pii-test",
    )
    .with_dlp_pii(mode)
    .with_sink(Arc::new(rows.clone()));
    let body = serde_json::json!({
        "model": "claude-haiku-5-5",
        "max_tokens": 10,
        "messages": [{"role": "user", "content": prompt}],
    })
    .to_string();
    let resp = tokenfuse_gateway::app(st)
        .oneshot(
            Request::post("/v1/messages")
                .header("content-type", "application/json")
                .header("x-fuse-run-id", "run-pii")
                .header("x-fuse-budget-usd", "1")
                .body(Body::from(body))
                .unwrap(),
        )
        .await
        .unwrap();
    let status = resp.status();
    let _ = axum::body::to_bytes(resp.into_body(), 1 << 20).await;
    let rows = rows.0.lock().unwrap().clone();
    (status, rows)
}

fn allow_row(rows: &[serde_json::Value]) -> serde_json::Value {
    rows.iter()
        .find(|r| r["decision"] == "allow")
        .cloned()
        .unwrap_or_else(|| panic!("no allow row: {rows:?}"))
}

const PROMPT: &str =
    "Reply OK. My email is jane.doe@example.com and my card is 4111 1111 1111 1111.";

#[tokio::test]
async fn shadow_records_the_kinds_it_found_and_never_the_text() {
    let (status, rows) = call(DlpMode::Shadow, PROMPT).await;
    assert_eq!(status, StatusCode::OK);
    let row = allow_row(&rows);
    assert_eq!(row["pii_findings"], "pii_card=1,pii_email=1", "{row}");
    let text = serde_json::to_string(&rows).unwrap();
    assert!(
        !text.contains("jane.doe") && !text.contains("4111"),
        "the record names kinds, never the text: {text}"
    );
}

#[tokio::test]
async fn mask_records_what_it_redacted() {
    let (status, rows) = call(DlpMode::Mask, PROMPT).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(allow_row(&rows)["pii_findings"], "pii_card=1,pii_email=1");
}

#[tokio::test]
async fn nothing_found_or_the_scan_off_records_nothing() {
    let (_, rows) = call(DlpMode::Shadow, "Reply OK.").await;
    assert!(allow_row(&rows).get("pii_findings").is_none());
    let (_, rows) = call(DlpMode::Off, PROMPT).await;
    assert!(allow_row(&rows).get("pii_findings").is_none());
}
