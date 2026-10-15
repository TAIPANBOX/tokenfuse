//! Invariant 114: a secret or PII the DLP scanner finds and lets through
//! (`shadow` forwards it as written, `mask` redacts it on its way) is one
//! `dlp_shadow` on the agent-event bus per scanner, at `medium`, naming the
//! kinds and how often, never the matched text. agent-passport SPEC 6.2
//! registered the type on 2026-10-14 and trailryx maps it; until this change
//! no emit site produced it, so a shadow week was a week of answer notes and
//! nothing on the bus.

use axum::body::Body;
use axum::http::{Request, StatusCode};
use std::path::PathBuf;
use std::sync::Arc;
use tokenfuse_core::{DlpMode, Ledger, Mode, Policy};
use tokenfuse_gateway::events::EventExporter;
use tokenfuse_gateway::provider::StubProvider;
use tokenfuse_gateway::state::AppState;
use tower::ServiceExt;

const AGENT: &str = "agent://test/dlp-shadow";
const SECRET: &str = "AKIA1234567890ABCDEF";
const EMAIL: &str = "jane.doe@example.com";

fn gateway(tag: &str, dlp: DlpMode, dlp_pii: DlpMode) -> (AppState, PathBuf) {
    let dir = std::env::temp_dir().join(format!("tf-dlp-shadow-{}-{tag}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join("events.ndjson");
    let _ = std::fs::remove_file(&path);
    let exp = Arc::new(EventExporter::open(path.to_str().unwrap()).unwrap());
    let st = AppState::new(
        Arc::new(Ledger::new()),
        Arc::new(tokenfuse_gateway::pricebook::default_price_book()),
        Arc::new(Policy {
            mode: Mode::Enforce,
            ..Default::default()
        }),
        Arc::new(StubProvider::default()),
        "dlp-shadow-test",
    )
    .with_dlp(dlp)
    .with_dlp_pii(dlp_pii)
    .with_events(exp);
    (st, path)
}

async fn call(st: AppState, prompt: &str) -> StatusCode {
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
                .header("x-fuse-run-id", "run-dlp-shadow")
                .header("x-fuse-agent-id", AGENT)
                .header("x-fuse-budget-usd", "1")
                .body(Body::from(body))
                .unwrap(),
        )
        .await
        .unwrap();
    let status = resp.status();
    let _ = axum::body::to_bytes(resp.into_body(), 1 << 20).await;
    status
}

/// Every line on the bus, raw and parsed. An absent file is no events.
fn bus(path: &PathBuf) -> Vec<(String, serde_json::Value)> {
    let Ok(text) = std::fs::read_to_string(path) else {
        return Vec::new();
    };
    text.lines()
        .filter(|l| !l.trim().is_empty())
        .map(|l| (l.to_string(), serde_json::from_str(l).unwrap()))
        .collect()
}

fn of_type(events: &[(String, serde_json::Value)], t: &str) -> Vec<(String, serde_json::Value)> {
    events
        .iter()
        .filter(|(_, e)| e["type"] == t)
        .cloned()
        .collect()
}

#[tokio::test]
async fn a_secret_found_in_shadow_is_one_dlp_shadow_on_the_bus() {
    let (st, path) = gateway("secret-shadow", DlpMode::Shadow, DlpMode::Off);
    let status = call(st, &format!("Reply OK. My key is {SECRET}.")).await;
    assert_eq!(status, StatusCode::OK, "shadow forwards the prompt");

    let events = bus(&path);
    let shadow = of_type(&events, "dlp_shadow");
    assert_eq!(shadow.len(), 1, "one dlp_shadow per scanner: {events:?}");
    let (line, e) = &shadow[0];
    assert_eq!(e["severity"], "medium");
    assert_eq!(e["source"], "tokenfuse");
    assert_eq!(e["agent_id"], AGENT);
    assert_eq!(e["run_id"], "run-dlp-shadow");
    assert_eq!(e["data"]["mode"], "shadow");
    assert_eq!(
        e["data"]["counts"],
        serde_json::json!({"aws_access_key": 1})
    );
    assert_eq!(e["data"]["summary"], "1 secret(s): aws_access_key");
    assert!(e["data"]["unit"].is_null(), "no unit resolved: {e}");
    assert!(!line.contains(SECRET), "the key reached the bus: {line}");
    assert!(
        of_type(&events, "dlp_block").is_empty(),
        "nothing was refused"
    );
}

#[tokio::test]
async fn pii_masked_on_its_way_is_one_dlp_shadow_in_mask_mode() {
    let (st, path) = gateway("pii-mask", DlpMode::Off, DlpMode::Mask);
    let prompt = format!("Reply OK. Email {EMAIL}, card 4111 1111 1111 1111.");
    assert_eq!(call(st, &prompt).await, StatusCode::OK);

    let shadow = of_type(&bus(&path), "dlp_shadow");
    assert_eq!(shadow.len(), 1, "{shadow:?}");
    let (_, e) = &shadow[0];
    // The envelope's own hex (prev_hash) may hold any digits, so the data is
    // what is read for a span.
    let data = e["data"].to_string();
    assert_eq!(e["data"]["mode"], "mask");
    assert_eq!(
        e["data"]["counts"],
        serde_json::json!({"pii_card": 1, "pii_email": 1})
    );
    assert_eq!(
        e["data"]["summary"],
        "2 pii finding(s): pii_card, pii_email"
    );
    for span in ["jane.doe", "4111"] {
        assert!(
            !data.contains(span),
            "a matched span reached the bus: {data}"
        );
    }
}

#[tokio::test]
async fn each_scanner_that_let_a_finding_through_is_its_own_event_in_its_own_mode() {
    let (st, path) = gateway("both", DlpMode::Mask, DlpMode::Shadow);
    let prompt = format!("Reply OK. Key {SECRET}, email {EMAIL}.");
    assert_eq!(call(st, &prompt).await, StatusCode::OK);

    let shadow = of_type(&bus(&path), "dlp_shadow");
    let modes: Vec<(String, serde_json::Value)> = shadow
        .iter()
        .map(|(_, e)| {
            (
                e["data"]["mode"].as_str().unwrap().to_string(),
                e["data"]["counts"].clone(),
            )
        })
        .collect();
    assert_eq!(
        modes,
        vec![
            ("mask".to_string(), serde_json::json!({"aws_access_key": 1})),
            ("shadow".to_string(), serde_json::json!({"pii_email": 1})),
        ],
        "the secret scan masked, the PII scan shadowed, one event each"
    );
}

#[tokio::test]
async fn a_prompt_a_scanner_refused_writes_no_dlp_shadow() {
    // The secret scan blocks: one dlp_block, and nothing let through.
    let (st, path) = gateway("secret-block", DlpMode::Block, DlpMode::Off);
    assert_eq!(
        call(st, &format!("My key is {SECRET}.")).await,
        StatusCode::FORBIDDEN
    );
    let events = bus(&path);
    assert!(of_type(&events, "dlp_shadow").is_empty(), "{events:?}");
    assert_eq!(of_type(&events, "dlp_block").len(), 1, "{events:?}");

    // The secret scan shadows, then the PII scan blocks: the prompt never
    // reached the provider, so the secret finding was not let through either.
    let (st, path) = gateway("shadow-then-block", DlpMode::Shadow, DlpMode::Block);
    assert_eq!(
        call(st, &format!("Key {SECRET}, email {EMAIL}.")).await,
        StatusCode::FORBIDDEN
    );
    let events = bus(&path);
    assert!(
        of_type(&events, "dlp_shadow").is_empty(),
        "a finding the other scanner refused is not let through: {events:?}"
    );
}

#[tokio::test]
async fn a_prompt_with_nothing_found_writes_no_dlp_shadow() {
    let (st, path) = gateway("clean", DlpMode::Shadow, DlpMode::Shadow);
    assert_eq!(call(st, "Reply OK.").await, StatusCode::OK);
    assert!(of_type(&bus(&path), "dlp_shadow").is_empty());
}
