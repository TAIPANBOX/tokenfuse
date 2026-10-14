//! Invariant 104: a streamed answer's tool calls are judged as a buffered
//! answer's are, on both wires, through the real router.
//!
//! Measured 2026-10-14 on a router agent through the OpenAI door: the agent
//! streamed, the run carried `suspected_injection` and `unclassified`, the
//! starter rule denies `write` after either, and the `write_file` call the
//! model streamed back reached the agent and ran. The answers below are the
//! two wires' documented event shapes with that call in them (an Anthropic
//! `tool_use` block with `input_json_delta`s; an OpenAI-compatible stream with
//! `delta.tool_calls`, the shape OpenRouter sent for that run), delivered in
//! small chunks so the gate's event splitting is what is exercised.

use async_trait::async_trait;
use axum::body::{to_bytes, Body, Bytes};
use axum::http::{HeaderMap, Request, StatusCode};
use std::collections::VecDeque;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use tokenfuse_core::taint::FirewallMode;
use tokenfuse_core::{Ledger, Mode, Policy};
use tokenfuse_gateway::events::EventExporter;
use tokenfuse_gateway::firewall::FirewallConfig;
use tokenfuse_gateway::provider::{Provider, ProviderError, ProviderResponse, UsageSlot};
use tokenfuse_gateway::state::AppState;
use tokenfuse_gateway::wire::Wire;
use tower::ServiceExt;

/// An Anthropic stream: text, then a `write_file` tool call.
const ANTHROPIC_WRITE: &str = "event: message_start\ndata: {\"type\":\"message_start\",\"message\":{\"id\":\"msg_1\",\"type\":\"message\",\"role\":\"assistant\",\"model\":\"claude-haiku-5-5\",\"content\":[],\"stop_reason\":null,\"usage\":{\"input_tokens\":120,\"output_tokens\":1}}}\n\n\
event: content_block_start\ndata: {\"type\":\"content_block_start\",\"index\":0,\"content_block\":{\"type\":\"text\",\"text\":\"\"}}\n\n\
event: content_block_delta\ndata: {\"type\":\"content_block_delta\",\"index\":0,\"delta\":{\"type\":\"text_delta\",\"text\":\"Writing it now.\"}}\n\n\
event: content_block_stop\ndata: {\"type\":\"content_block_stop\",\"index\":0}\n\n\
event: content_block_start\ndata: {\"type\":\"content_block_start\",\"index\":1,\"content_block\":{\"type\":\"tool_use\",\"id\":\"toolu_01\",\"name\":\"write_file\",\"input\":{}}}\n\n\
event: content_block_delta\ndata: {\"type\":\"content_block_delta\",\"index\":1,\"delta\":{\"type\":\"input_json_delta\",\"partial_json\":\"{\\\"path\\\": \\\"/tmp/w8-write-test.txt\\\", \"}}\n\n\
event: content_block_delta\ndata: {\"type\":\"content_block_delta\",\"index\":1,\"delta\":{\"type\":\"input_json_delta\",\"partial_json\":\"\\\"content\\\": \\\"hello-from-w8\\\"}\"}}\n\n\
event: content_block_stop\ndata: {\"type\":\"content_block_stop\",\"index\":1}\n\n\
event: message_delta\ndata: {\"type\":\"message_delta\",\"delta\":{\"stop_reason\":\"tool_use\",\"stop_sequence\":null},\"usage\":{\"output_tokens\":42}}\n\n\
event: message_stop\ndata: {\"type\":\"message_stop\"}\n\n";

/// The same answer on the OpenAI wire, as an OpenAI-compatible router sends it.
const OPENAI_WRITE: &str = "data: {\"id\":\"gen-1\",\"object\":\"chat.completion.chunk\",\"created\":1,\"model\":\"anthropic/claude-haiku-5.5\",\"choices\":[{\"index\":0,\"delta\":{\"role\":\"assistant\",\"content\":\"Writing it now.\"},\"finish_reason\":null}]}\n\n\
data: {\"id\":\"gen-1\",\"object\":\"chat.completion.chunk\",\"created\":1,\"model\":\"anthropic/claude-haiku-5.5\",\"choices\":[{\"index\":0,\"delta\":{\"tool_calls\":[{\"index\":0,\"id\":\"toolu_01\",\"type\":\"function\",\"function\":{\"name\":\"write_file\",\"arguments\":\"\"}}]},\"finish_reason\":null}]}\n\n\
data: {\"id\":\"gen-1\",\"object\":\"chat.completion.chunk\",\"created\":1,\"model\":\"anthropic/claude-haiku-5.5\",\"choices\":[{\"index\":0,\"delta\":{\"tool_calls\":[{\"index\":0,\"function\":{\"arguments\":\"{\\\"path\\\": \\\"/tmp/w8-write-test.txt\\\", \"}}]},\"finish_reason\":null}]}\n\n\
data: {\"id\":\"gen-1\",\"object\":\"chat.completion.chunk\",\"created\":1,\"model\":\"anthropic/claude-haiku-5.5\",\"choices\":[{\"index\":0,\"delta\":{\"tool_calls\":[{\"index\":0,\"function\":{\"arguments\":\"\\\"content\\\": \\\"hello-from-w8\\\"}\"}}]},\"finish_reason\":null}]}\n\n\
data: {\"id\":\"gen-1\",\"object\":\"chat.completion.chunk\",\"created\":1,\"model\":\"anthropic/claude-haiku-5.5\",\"choices\":[{\"index\":0,\"delta\":{},\"finish_reason\":\"tool_calls\"}]}\n\n\
data: {\"id\":\"gen-1\",\"object\":\"chat.completion.chunk\",\"created\":1,\"model\":\"anthropic/claude-haiku-5.5\",\"choices\":[],\"usage\":{\"prompt_tokens\":120,\"completion_tokens\":42,\"total_tokens\":162}}\n\n\
data: [DONE]\n\n";

/// An OpenAI stream asking for a web fetch, whose output is `web`.
const OPENAI_WEB_FETCH: &str = "data: {\"id\":\"gen-2\",\"object\":\"chat.completion.chunk\",\"created\":1,\"model\":\"m\",\"choices\":[{\"index\":0,\"delta\":{\"role\":\"assistant\",\"tool_calls\":[{\"index\":0,\"id\":\"c1\",\"type\":\"function\",\"function\":{\"name\":\"web_search\",\"arguments\":\"{\\\"url\\\":\\\"https://example.com\\\"}\"}}]},\"finish_reason\":null}]}\n\n\
data: {\"id\":\"gen-2\",\"object\":\"chat.completion.chunk\",\"created\":1,\"model\":\"m\",\"choices\":[{\"index\":0,\"delta\":{},\"finish_reason\":\"tool_calls\"}]}\n\n\
data: [DONE]\n\n";

/// A buffered OpenAI answer asking to run a shell, `exec` in the default map.
const OPENAI_EXEC_BUFFERED: &str = r#"{"id":"c","object":"chat.completion","choices":[{"index":0,"message":{"role":"assistant","tool_calls":[{"id":"c2","type":"function","function":{"name":"run_shell","arguments":"{}"}}]},"finish_reason":"tool_calls"}],"usage":{"prompt_tokens":10,"completion_tokens":5,"total_tokens":15}}"#;

/// Answers each call with the next body in its queue, cut into `chunk`-byte
/// pieces, the usage read as the network path reads it.
struct QueueProvider {
    bodies: Mutex<VecDeque<&'static str>>,
    chunk: usize,
}

#[async_trait]
impl Provider for QueueProvider {
    async fn send(
        &self,
        _headers: HeaderMap,
        _body: Bytes,
    ) -> Result<ProviderResponse, ProviderError> {
        let body = self
            .bodies
            .lock()
            .unwrap()
            .pop_front()
            .expect("a body for every call");
        let slot: UsageSlot = Arc::new(Mutex::new(None));
        let writer = Arc::clone(&slot);
        let chunk = self.chunk.max(1);
        let stream = async_stream::try_stream! {
            let mut parser = tokenfuse_gateway::provider::UsageParser::new();
            for piece in body.as_bytes().chunks(chunk) {
                parser.feed(piece);
                yield Bytes::copy_from_slice(piece);
            }
            *writer.lock().unwrap() = Some(parser.finish());
        };
        let streamed = body.starts_with("data:") || body.starts_with("event:");
        Ok(ProviderResponse {
            status: 200,
            content_type: Some(if streamed {
                "text/event-stream".to_string()
            } else {
                "application/json".to_string()
            }),
            body: Box::pin(stream),
            usage: slot,
        })
    }
}

fn events(tag: &str) -> (Arc<EventExporter>, PathBuf) {
    let dir = std::env::temp_dir().join(format!("tf-streamed-tools-{}-{tag}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join("events.ndjson");
    let _ = std::fs::remove_file(&path);
    let exp = EventExporter::open(path.to_str().unwrap()).unwrap();
    (Arc::new(exp), path)
}

fn gateway(
    wire: Wire,
    mode: FirewallMode,
    bodies: &[&'static str],
    tag: &str,
) -> (AppState, PathBuf) {
    let (exp, path) = events(tag);
    let st = AppState::new(
        Arc::new(Ledger::new()),
        Arc::new(tokenfuse_gateway::pricebook::default_price_book()),
        Arc::new(Policy {
            mode: Mode::Enforce,
            ..Default::default()
        }),
        Arc::new(QueueProvider {
            bodies: Mutex::new(bodies.iter().copied().collect()),
            chunk: 7,
        }),
        "streamed-tools-test",
    )
    .with_wire(wire)
    .with_firewall(Arc::new(FirewallConfig::defaults(mode)))
    .with_events(exp);
    (st, path)
}

/// One call on `run`, streamed or not, its context declared `taint` when given.
async fn post(
    st: &AppState,
    wire: Wire,
    run: &str,
    stream: bool,
    taint: Option<&str>,
) -> (StatusCode, String) {
    let (uri, model) = match wire {
        Wire::Anthropic => ("/v1/messages", "claude-haiku-5-5"),
        Wire::OpenAi => ("/v1/chat/completions", "anthropic/claude-haiku-5.5"),
    };
    let body = serde_json::json!({
        "model": model,
        "max_tokens": 100,
        "stream": stream,
        "messages": [{"role": "user", "content": "write hello-from-w8 to /tmp/w8-write-test.txt"}],
    })
    .to_string();
    let mut req = Request::post(uri)
        .header("content-type", "application/json")
        .header("x-fuse-run-id", run)
        .header("x-fuse-budget-usd", "5")
        .header("x-fuse-agent-id", "agent://test/router");
    if let Some(t) = taint {
        req = req.header("x-fuse-taint", t);
    }
    let resp = tokenfuse_gateway::app(st.clone())
        .oneshot(req.body(Body::from(body)).unwrap())
        .await
        .unwrap();
    let status = resp.status();
    let bytes = to_bytes(resp.into_body(), 1 << 20).await.unwrap();
    (status, String::from_utf8_lossy(&bytes).into_owned())
}

fn on_bus(path: &std::path::Path, kind: &str) -> Vec<serde_json::Value> {
    std::fs::read_to_string(path)
        .unwrap_or_default()
        .lines()
        .filter_map(|l| serde_json::from_str::<serde_json::Value>(l).ok())
        .filter(|e| e["type"] == kind)
        .collect()
}

async fn refused_on(wire: Wire, answer: &'static str, tag: &str) {
    let (st, bus) = gateway(wire, FirewallMode::Enforce, &[answer], tag);
    let (status, body) = post(&st, wire, "run-stream-1", true, Some("web")).await;
    assert_eq!(status, StatusCode::OK, "the stream had opened: {body}");
    assert!(
        !body.contains("write_file")
            && !body.contains("toolu_01")
            && !body.contains("w8-write-test"),
        "a tool call the run's taint denies must not reach the agent: {body}"
    );
    assert!(
        body.contains("Writing it now."),
        "text before the tool call still streams: {body}"
    );
    assert!(
        body.contains("taint_blocked"),
        "the refusal says what it is: {body}"
    );
    let blocks = on_bus(&bus, "taint_block");
    assert_eq!(blocks.len(), 1, "one taint_block on the bus");
    assert_eq!(blocks[0]["run_id"], "run-stream-1");
    assert_eq!(blocks[0]["data"]["stage"], "model_tool_call");
    assert_eq!(
        blocks[0]["data"]["tools"],
        serde_json::json!(["write_file"])
    );
}

#[tokio::test]
async fn a_streamed_anthropic_tool_call_the_taint_denies_is_refused() {
    refused_on(Wire::Anthropic, ANTHROPIC_WRITE, "a-refused").await;
}

#[tokio::test]
async fn a_streamed_openai_tool_call_the_taint_denies_is_refused() {
    refused_on(Wire::OpenAi, OPENAI_WRITE, "o-refused").await;
}

#[tokio::test]
async fn the_refusal_is_the_event_each_wires_clients_raise_on() {
    let (st, _) = gateway(
        Wire::Anthropic,
        FirewallMode::Enforce,
        &[ANTHROPIC_WRITE],
        "a-shape",
    );
    let (_, body) = post(&st, Wire::Anthropic, "run-shape-a", true, Some("web")).await;
    let last = body.trim_end().rsplit("\n\n").next().unwrap_or_default();
    assert!(last.starts_with("event: error\ndata: "), "{body}");
    let data: serde_json::Value =
        serde_json::from_str(last.trim_start_matches("event: error\ndata: "))
            .expect("one JSON event");
    assert_eq!(data["type"], "error", "{body}");
    assert_eq!(data["error"]["type"], "taint_blocked", "{body}");
    assert_eq!(data["error"]["run_id"], "run-shape-a", "{body}");
    assert_eq!(
        data["error"]["message"], "tainted context [web] denies capability [write]",
        "{body}"
    );
    assert!(body.ends_with("\n\n"), "the event is complete: {body:?}");
    assert!(
        !body.contains("message_stop"),
        "the stream ends at the refusal: {body}"
    );
    let (st, _) = gateway(
        Wire::OpenAi,
        FirewallMode::Enforce,
        &[OPENAI_WRITE],
        "o-shape",
    );
    let (_, body) = post(&st, Wire::OpenAi, "run-shape-o", true, Some("web")).await;
    let last = body.trim_end().rsplit("\n\n").next().unwrap_or_default();
    let data: serde_json::Value =
        serde_json::from_str(last.trim_start_matches("data: ")).expect("one JSON chunk");
    assert_eq!(data["error"]["code"], "taint_blocked", "{body}");
    assert!(
        !body.contains("[DONE]"),
        "the stream ends at the refusal: {body}"
    );
}

#[tokio::test]
async fn an_untainted_streamed_tool_call_is_forwarded_byte_for_byte() {
    for (wire, answer) in [
        (Wire::Anthropic, ANTHROPIC_WRITE),
        (Wire::OpenAi, OPENAI_WRITE),
    ] {
        let (st, bus) = gateway(wire, FirewallMode::Enforce, &[answer], "clean");
        let (status, body) = post(&st, wire, "run-clean", true, None).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(body, answer, "{wire:?}: nothing to refuse, nothing changed");
        assert!(on_bus(&bus, "taint_block").is_empty());
    }
}

#[tokio::test]
async fn shadow_forwards_a_denied_streamed_tool_call_and_records_it() {
    for (wire, answer) in [
        (Wire::Anthropic, ANTHROPIC_WRITE),
        (Wire::OpenAi, OPENAI_WRITE),
    ] {
        let (st, bus) = gateway(wire, FirewallMode::Shadow, &[answer], "shadow");
        let (status, body) = post(&st, wire, "run-shadow", true, Some("web")).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(body, answer, "{wire:?}: shadow changes no byte");
        let shadow = on_bus(&bus, "taint_shadow");
        assert_eq!(shadow.len(), 1, "{wire:?}: the would-block is recorded");
        assert_eq!(
            shadow[0]["data"]["tools"],
            serde_json::json!(["write_file"])
        );
    }
}

#[tokio::test]
async fn with_the_firewall_off_a_stream_is_never_held_or_changed() {
    let (st, bus) = gateway(Wire::OpenAi, FirewallMode::Off, &[OPENAI_WRITE], "off");
    let (status, body) = post(&st, Wire::OpenAi, "run-off", true, Some("web")).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body, OPENAI_WRITE);
    assert!(on_bus(&bus, "taint_block").is_empty());
}

/// A streamed tool call taints the turns after it, as a buffered one does: a
/// web fetch the model streamed makes the run `web`, and the next turn's shell
/// call is refused.
#[tokio::test]
async fn a_streamed_tool_calls_output_taints_the_next_turn() {
    let (st, _) = gateway(
        Wire::OpenAi,
        FirewallMode::Enforce,
        &[OPENAI_WEB_FETCH, OPENAI_EXEC_BUFFERED],
        "next-turn",
    );
    let (status, body) = post(&st, Wire::OpenAi, "run-next", true, None).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body, OPENAI_WEB_FETCH, "an untainted web fetch is allowed");
    let (status, body) = post(&st, Wire::OpenAi, "run-next", false, None).await;
    assert_eq!(
        status,
        StatusCode::FORBIDDEN,
        "the streamed fetch's output is web, so exec is denied next turn: {body}"
    );
    assert!(body.contains("taint_blocked"), "{body}");
}

/// The buffered path keeps its own behaviour through the shared judgement.
#[tokio::test]
async fn the_buffered_answer_is_still_refused_with_a_403() {
    let (st, bus) = gateway(
        Wire::OpenAi,
        FirewallMode::Enforce,
        &[OPENAI_EXEC_BUFFERED],
        "buffered",
    );
    let (status, body) = post(&st, Wire::OpenAi, "run-buffered", false, Some("web")).await;
    assert_eq!(status, StatusCode::FORBIDDEN, "{body}");
    assert!(body.contains("taint_blocked"), "{body}");
    assert_eq!(on_bus(&bus, "taint_block").len(), 1);
}
