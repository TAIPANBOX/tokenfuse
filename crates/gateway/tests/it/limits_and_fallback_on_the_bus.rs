//! `rate_limited` and `price_fallback` on the agent-event bus (agent-passport
//! SPEC 6.2), through the real router.

use axum::body::Body;
use axum::extract::State;
use axum::http::{Request, StatusCode};
use std::path::PathBuf;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokenfuse_core::{Ledger, Mode, Policy};
use tokenfuse_gateway::clientkeys::{ClientKeys, CLIENT_KEY_HEADER};
use tokenfuse_gateway::events::EventExporter;
use tokenfuse_gateway::provider::StubProvider;
use tokenfuse_gateway::ratelimit::Limits;
use tokenfuse_gateway::state::{AppState, FallbackEvent, PRICE_FALLBACK_EVENTS_PER_MINUTE};
use tower::ServiceExt;

const AGENT: &str = "agent://test/limits-and-fallback";

fn gateway(tag: &str, limits: Option<Limits>) -> (AppState, PathBuf) {
    let dir = std::env::temp_dir().join(format!("tf-limits-fallback-{}-{tag}", std::process::id()));
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
        "limits-fallback-test",
    )
    .with_client_keys(Arc::new(
        ClientKeys::from_spec("sk-a:a").expect("a usable key spec"),
    ))
    .with_events(exp);
    let st = match limits {
        Some(l) => st.with_key_limits(l),
        None => st,
    };
    (st, path)
}

async fn call(st: AppState, model: &str, run: &str, agent: Option<&str>) -> StatusCode {
    let body = serde_json::json!({
        "model": model,
        "max_tokens": 10,
        "messages": [{"role": "user", "content": "hi"}],
    })
    .to_string();
    let mut req = Request::post("/v1/messages")
        .header("content-type", "application/json")
        .header("x-fuse-run-id", run)
        .header("x-fuse-budget-usd", "1")
        .header(CLIENT_KEY_HEADER, "sk-a");
    if let Some(a) = agent {
        req = req.header("x-fuse-agent-id", a);
    }
    let resp = tokenfuse_gateway::app(st)
        .oneshot(req.body(Body::from(body)).unwrap())
        .await
        .unwrap();
    let status = resp.status();
    let _ = axum::body::to_bytes(resp.into_body(), 1 << 20).await;
    status
}

fn of_type(path: &PathBuf, t: &str) -> Vec<serde_json::Value> {
    let Ok(text) = std::fs::read_to_string(path) else {
        return Vec::new();
    };
    text.lines()
        .filter(|l| !l.trim().is_empty())
        .map(|l| serde_json::from_str::<serde_json::Value>(l).unwrap())
        .filter(|e| e["type"] == t)
        .collect()
}

/// Four calls inside one second on a key allowed one: three are refused 429,
/// and only the first refusal is on the bus, at `medium`, with the SPEC's
/// members and the limit named `rps`.
#[tokio::test]
async fn a_caller_over_its_rate_is_one_rate_limited_event_a_minute() {
    let (st, path) = gateway(
        "rate",
        Some(Limits {
            rps: Some(1.0),
            burst: 1.0,
            concurrency: None,
        }),
    );
    // Each call names another agent: the header cannot multiply the events.
    let mut refused = 0;
    for i in 0..4 {
        let named = format!("{AGENT}-{i}");
        if call(
            st.clone(),
            "claude-haiku-5-5",
            &format!("r-{i}"),
            Some(&named),
        )
        .await
            == StatusCode::TOO_MANY_REQUESTS
        {
            refused += 1;
        }
    }
    assert_eq!(refused, 3);
    let events = of_type(&path, "rate_limited");
    assert_eq!(
        events.len(),
        1,
        "one event a minute per principal: {events:?}"
    );
    let e = &events[0];
    assert_eq!(e["severity"], "medium", "{e}");
    assert_eq!(
        e["agent_id"], "agent://unidentified.invalid/caller",
        "a static key proves no agent, so the header never files the event: {e}"
    );
    assert!(
        e["run_id"].is_null(),
        "refused before the run was claimed, so no run: {e}"
    );
    assert_eq!(e["data"]["key_id"], "a", "{e}");
    assert_eq!(
        e["data"]["principal"],
        format!("{AGENT}-1"),
        "the agent the call named: {e}"
    );
    assert_eq!(e["data"]["limit"], "rps", "{e}");
    assert_eq!(e["data"]["limit_value"], 1.0, "{e}");
    assert_eq!(e["data"]["unreported_since_last"], 0, "{e}");
    assert!(e["data"]["retry_after_secs"].as_u64().unwrap() >= 1, "{e}");
    assert!(
        !e.to_string().contains("sk-a"),
        "never the key's value: {e}"
    );
}

/// The minute is per source: refusals inside it are counted, and the first one
/// after it says how many were not written.
#[tokio::test]
async fn refusals_inside_the_minute_are_counted_and_reported_after_it() {
    let (st, _path) = gateway("minute", None);
    let t0 = Instant::now();
    assert_eq!(st.note_rate_limited("key:a", t0), Some(0));
    assert_eq!(
        st.note_rate_limited("key:a", t0 + Duration::from_secs(10)),
        None
    );
    assert_eq!(
        st.note_rate_limited("key:a", t0 + Duration::from_secs(59)),
        None
    );
    assert_eq!(
        st.note_rate_limited("key:b", t0 + Duration::from_secs(59)),
        Some(0)
    );
    assert_eq!(
        st.note_rate_limited("key:a", t0 + Duration::from_secs(61)),
        Some(2)
    );
    assert_eq!(
        st.note_rate_limited("key:a", t0 + Duration::from_secs(62)),
        None
    );
}

/// A model with no price-book row is one `price_fallback` per model per
/// process, at `low`, naming the door and the rates; a second model is its own.
#[tokio::test]
async fn a_model_with_no_price_row_is_one_price_fallback_per_model() {
    let (st, path) = gateway("fallback", None);
    assert_eq!(
        call(st.clone(), "no-such-model-1", "r-1", Some(AGENT)).await,
        StatusCode::OK
    );
    assert_eq!(
        call(st.clone(), "no-such-model-1", "r-2", Some(AGENT)).await,
        StatusCode::OK
    );
    assert_eq!(
        call(st.clone(), "no-such-model-2", "r-3", Some(AGENT)).await,
        StatusCode::OK
    );
    let events = of_type(&path, "price_fallback");
    assert_eq!(events.len(), 2, "once per model: {events:?}");
    let e = &events[0];
    assert_eq!(e["severity"], "low", "{e}");
    assert_eq!(e["agent_id"], AGENT, "{e}");
    assert_eq!(e["run_id"], "r-1", "{e}");
    assert_eq!(e["data"]["model"], "no-such-model-1", "{e}");
    assert_eq!(e["data"]["door"], "anthropic", "{e}");
    assert!(
        e["data"]["fallback_rates"]["output_per_mtok_microusd"]
            .as_i64()
            .unwrap()
            > 0,
        "{e}"
    );
    assert_eq!(events[1]["data"]["model"], "no-such-model-2");
}

/// A model the book prices writes nothing.
#[tokio::test]
async fn a_model_the_book_prices_writes_no_price_fallback() {
    let (st, path) = gateway("known", None);
    assert_eq!(
        call(st.clone(), "claude-haiku-5-5", "r-1", Some(AGENT)).await,
        StatusCode::OK
    );
    assert!(of_type(&path, "price_fallback").is_empty());
}

/// A call that names no agent writes no event and is counted on
/// `GET /v1/price-book`; the model stays unreported, so the next call that
/// names an agent writes it.
#[tokio::test]
async fn a_call_naming_no_agent_is_counted_and_the_model_stays_unreported() {
    let (st, path) = gateway("no-agent", None);
    assert_eq!(
        call(st.clone(), "no-such-model-3", "r-1", None).await,
        StatusCode::OK
    );
    assert!(of_type(&path, "price_fallback").is_empty());
    let report = tokenfuse_gateway::pricebookreport::price_book(State(st.clone())).await;
    assert_eq!(report.0.fallback_events_unreported, 1);
    assert_eq!(
        call(st.clone(), "no-such-model-3", "r-2", Some(AGENT)).await,
        StatusCode::OK
    );
    assert_eq!(of_type(&path, "price_fallback").len(), 1);
}

/// Model ids are the caller's, so the events are capped for the whole gateway:
/// past the cap a new model is not written and not marked, and the next minute
/// writes it.
#[tokio::test]
async fn price_fallback_events_are_capped_per_minute_for_the_whole_gateway() {
    let (st, _path) = gateway("cap", None);
    let t0 = Instant::now();
    for i in 0..PRICE_FALLBACK_EVENTS_PER_MINUTE {
        assert_eq!(
            st.note_price_fallback_event(&format!("m-{i}"), t0),
            FallbackEvent::Write
        );
    }
    assert_eq!(
        st.note_price_fallback_event("m-0", t0),
        FallbackEvent::AlreadyWritten
    );
    assert_eq!(
        st.note_price_fallback_event("m-over", t0),
        FallbackEvent::OverCap
    );
    assert_eq!(
        st.note_price_fallback_event("m-over", t0 + Duration::from_secs(61)),
        FallbackEvent::Write
    );
}
