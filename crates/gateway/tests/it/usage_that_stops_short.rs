//! tokenfuse#308 and #309: what a call is charged when the provider's usage stops short of its
//! final event, and when the body breaks after some of it arrived.
//!
//! Every test here drives the REAL `HttpProvider` against a `tokio` listener through the router,
//! so the bytes are read the way the network reads them, and the only thing a fixture chooses is
//! what the provider sent and whether it finished sending it.
//!
//! Anthropic's opening `message_start` carries the input count and an opening output count (one
//! token, on a real stream); the output figure the provider bills arrives in the final
//! `message_delta`. A body that stops before that event holds an input count that looks like a
//! whole answer. `@decided 2026-11-05`: such a call is charged the input side as reported and the
//! output side at the request's cap, the most the provider can bill for it, and never the opening
//! counters alone and never the estimate of a prompt the provider has already measured.
//! Invariants 43 and 47.
//!
//! Prices: `claude-sonnet` is 3 and 15 USD per Mtok, `gpt-4o` is 2.5 and 10, so 10 input tokens
//! are 30 microusd, 950 are 2375, and a cap of 1000 output tokens is 15000 and 10000.

use axum::body::{to_bytes, Body};
use axum::http::{Request, StatusCode};
use std::sync::Arc;
use tokenfuse_core::{Ledger, Microusd, Mode, Policy};
use tokenfuse_gateway::provider::HttpProvider;
use tokenfuse_gateway::wire::Wire;
use tokenfuse_gateway::{pricebook::default_price_book, state::AppState};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tower::ServiceExt;

/// A real opening event: `output_tokens` is 1 here, which is why "the output count is zero" is
/// not the question that finds a stream with no final event.
const OPENING: &str = "event: message_start\ndata: {\"type\":\"message_start\",\"message\":{\"id\":\"msg_1\",\"type\":\"message\",\"role\":\"assistant\",\"content\":[],\"model\":\"claude-sonnet\",\"stop_reason\":null,\"stop_sequence\":null,\"usage\":{\"input_tokens\":10,\"output_tokens\":1}}}\n\n";
const TEXT: &str = "event: content_block_start\ndata: {\"type\":\"content_block_start\",\"index\":0,\"content_block\":{\"type\":\"text\",\"text\":\"\"}}\n\nevent: content_block_delta\ndata: {\"type\":\"content_block_delta\",\"index\":0,\"delta\":{\"type\":\"text_delta\",\"text\":\"Hello\"}}\n\nevent: content_block_stop\ndata: {\"type\":\"content_block_stop\",\"index\":0}\n\n";
const FINAL_DELTA: &str = "event: message_delta\ndata: {\"type\":\"message_delta\",\"delta\":{\"stop_reason\":\"end_turn\",\"stop_sequence\":null},\"usage\":{\"output_tokens\":200}}\n\n";
/// A delta that says the message is not over: a running figure, not the last one.
const OPEN_DELTA: &str = "event: message_delta\ndata: {\"type\":\"message_delta\",\"delta\":{\"stop_reason\":null,\"stop_sequence\":null},\"usage\":{\"output_tokens\":40}}\n\n";
const STOP: &str = "event: message_stop\ndata: {\"type\":\"message_stop\"}\n\n";

const CONTENT_CHUNK: &str = "data: {\"id\":\"c1\",\"object\":\"chat.completion.chunk\",\"choices\":[{\"index\":0,\"delta\":{\"content\":\"Hello\"},\"finish_reason\":null}],\"usage\":null}\n\n";
const LAST_CONTENT_CHUNK: &str = "data: {\"id\":\"c1\",\"object\":\"chat.completion.chunk\",\"choices\":[{\"index\":0,\"delta\":{},\"finish_reason\":\"stop\"}],\"usage\":null}\n\n";
const USAGE_CHUNK: &str = "data: {\"id\":\"c1\",\"object\":\"chat.completion.chunk\",\"choices\":[],\"usage\":{\"prompt_tokens\":950,\"completion_tokens\":500,\"total_tokens\":1450}}\n\n";
/// A usage chunk naming the prompt and nothing about the output.
const PROMPT_ONLY_CHUNK: &str = "data: {\"id\":\"c1\",\"object\":\"chat.completion.chunk\",\"choices\":[],\"usage\":{\"prompt_tokens\":950}}\n\n";
/// A running total on a chunk whose choice is still open, the shape a server that reports usage
/// on every chunk sends.
const RUNNING_TOTAL_CHUNK: &str = "data: {\"id\":\"c1\",\"object\":\"chat.completion.chunk\",\"choices\":[{\"index\":0,\"delta\":{\"content\":\"Hello\"},\"finish_reason\":null}],\"usage\":{\"prompt_tokens\":950,\"completion_tokens\":40,\"total_tokens\":990}}\n\n";
const DONE: &str = "data: [DONE]\n\n";

const ANTHROPIC_STREAM_REQUEST: &str =
    r#"{"model":"claude-sonnet","max_tokens":1000,"stream":true}"#;
const OPENAI_STREAM_REQUEST: &str = r#"{"model":"gpt-4o","max_tokens":1000,"stream":true}"#;

/// What the provider does with the answer once the bytes are written.
#[derive(Clone, Copy, PartialEq)]
enum Ending {
    /// `Content-Length` is what was written, so the body ends cleanly.
    Clean,
    /// `Content-Length` promises one byte more, then the connection closes: a body error.
    Broken,
}

struct Settled {
    status: StatusCode,
    /// What the gateway held for the call while the body was open: the pre-flight estimate.
    reserved_while_open: Microusd,
    spent: Microusd,
    body_errored: bool,
}

/// One call through the router and the real `HttpProvider` against a listener answering
/// `status_line` with `body`.
async fn call(
    wire: Wire,
    request: &str,
    status_line: &'static str,
    body: Vec<u8>,
    ending: Ending,
) -> Settled {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    // Not awaited: after the body it drains the request until the client closes, so the close
    // is a FIN the client reads as the end of the body and never a reset of unread bytes.
    tokio::spawn(async move {
        let (mut socket, _) = listener.accept().await.unwrap();
        let mut head = [0u8; 8192];
        // A partial read is fine: nothing here parses the request.
        #[allow(clippy::unused_io_amount)]
        socket.read(&mut head).await.unwrap();
        let promised = body.len() + usize::from(ending == Ending::Broken);
        let answer = format!(
            "HTTP/1.1 {status_line}\r\nContent-Type: text/event-stream\r\nContent-Length: {promised}\r\nConnection: close\r\n\r\n"
        );
        socket.write_all(answer.as_bytes()).await.unwrap();
        socket.write_all(&body).await.unwrap();
        socket.shutdown().await.unwrap();
        let mut rest = Vec::new();
        let _ = socket.read_to_end(&mut rest).await;
    });

    let ledger = Arc::new(Ledger::new());
    let state = AppState::new(
        ledger.clone(),
        Arc::new(default_price_book()),
        Arc::new(Policy {
            mode: Mode::Enforce,
            ..Default::default()
        }),
        Arc::new(HttpProvider::new(format!("http://{address}"))),
        "usage-that-stops-short",
    )
    .with_wire(wire);
    let uri = match wire {
        Wire::Anthropic => "/v1/messages",
        Wire::OpenAi => "/v1/chat/completions",
    };
    let response = tokenfuse_gateway::app(state)
        .oneshot(
            Request::post(uri)
                .header("content-type", "application/json")
                .header("x-fuse-run-id", "short")
                .header("x-fuse-budget-usd", "10")
                .body(Body::from(request.to_string()))
                .unwrap(),
        )
        .await
        .unwrap();
    let status = response.status();
    let reserved_while_open = ledger.snapshot("short").unwrap().reserved;
    let body_errored = to_bytes(response.into_body(), usize::MAX).await.is_err();
    let snapshot = ledger.snapshot("short").unwrap();
    assert_eq!(
        snapshot.reserved,
        Microusd::ZERO,
        "whatever the provider sent, the reservation ends settled"
    );
    Settled {
        status,
        reserved_while_open,
        spent: snapshot.spent,
        body_errored,
    }
}

async fn anthropic(parts: &[&str], ending: Ending) -> Settled {
    let body = parts.concat().into_bytes();
    call(
        Wire::Anthropic,
        ANTHROPIC_STREAM_REQUEST,
        "200 OK",
        body,
        ending,
    )
    .await
}

async fn openai(parts: &[&str], ending: Ending) -> Settled {
    let body = parts.concat().into_bytes();
    call(Wire::OpenAi, OPENAI_STREAM_REQUEST, "200 OK", body, ending).await
}

// -- #308: a body that ends cleanly and never carried its final usage ------------------------

/// The issue's own bytes.
#[tokio::test]
async fn a_clean_stream_with_no_final_usage_event_charges_the_reported_input_and_the_output_cap() {
    let got = anthropic(
        &[
            "data: {\"type\":\"message_start\",\"message\":{\"usage\":{\"input_tokens\":10}}}\n\n",
            "data: {\"type\":\"message_stop\"}\n\n",
        ],
        Ending::Clean,
    )
    .await;
    assert_eq!(got.status, StatusCode::OK);
    assert!(!got.body_errored);
    assert_eq!(
        got.spent,
        Microusd(15_030),
        "10 input as reported, 1000 output at the cap: the opening counters alone are not a settlement"
    );
}

/// A real opening event carries `output_tokens: 1`, so a rule that looked for a zero output count
/// would read this stream as whole.
#[tokio::test]
async fn the_opening_output_count_is_not_the_final_one() {
    let got = anthropic(&[OPENING, TEXT, STOP], Ending::Clean).await;
    assert_eq!(
        got.spent,
        Microusd(15_030),
        "the opening output count of 1 is not what the provider bills"
    );
}

/// The control: nothing about a stream that finished moves.
#[tokio::test]
async fn a_complete_stream_settles_on_its_usage_not_the_cap() {
    let got = anthropic(&[OPENING, TEXT, FINAL_DELTA, STOP], Ending::Clean).await;
    assert_eq!(
        got.spent,
        Microusd(3_030),
        "10 input, 200 output, as reported"
    );
}

/// A delta that said the message was open, then a clean close: the close makes the last figure
/// the final one.
#[tokio::test]
async fn a_close_after_an_open_delta_makes_that_figure_the_final_one() {
    let got = anthropic(&[OPENING, TEXT, OPEN_DELTA, STOP], Ending::Clean).await;
    assert_eq!(got.spent, Microusd(630), "10 input, 40 output, as reported");
}

/// The OpenAI half: a usage object that names the prompt and nothing about the output.
#[tokio::test]
async fn an_openai_stream_whose_usage_names_no_output_charges_the_output_cap() {
    let got = openai(
        &[CONTENT_CHUNK, LAST_CONTENT_CHUNK, PROMPT_ONLY_CHUNK, DONE],
        Ending::Clean,
    )
    .await;
    assert_eq!(
        got.spent,
        Microusd(12_375),
        "950 input as reported, 1000 output at the cap"
    );
}

/// The issue's OpenAI twin in its plain form: `include_usage` on, and the usage chunk never came.
/// No count was parsed, so this was invariant 43's estimate before this change and stays it.
#[tokio::test]
async fn an_openai_stream_that_ends_without_its_usage_chunk_stays_on_the_estimate() {
    let got = call(
        Wire::OpenAi,
        r#"{"model":"gpt-4o","max_tokens":1000,"stream":true,"stream_options":{"include_usage":true}}"#,
        "200 OK",
        [CONTENT_CHUNK, LAST_CONTENT_CHUNK, DONE].concat().into_bytes(),
        Ending::Clean,
    )
    .await;
    assert!(got.reserved_while_open > Microusd::ZERO);
    assert_eq!(got.spent, got.reserved_while_open);
}

/// A running total closed by `[DONE]`: some servers put the last usage on a chunk that still
/// names an open choice, and a clean close is the provider saying nothing follows.
#[tokio::test]
async fn a_running_total_closed_by_done_is_the_final_one() {
    let got = openai(&[RUNNING_TOTAL_CHUNK, DONE], Ending::Clean).await;
    assert_eq!(
        got.spent,
        Microusd(2_775),
        "950 input, 40 output, as reported"
    );
}

/// The usage chunk is on the last line and the stream closes cleanly: the shape every
/// `include_usage` stream has.
#[tokio::test]
async fn an_openai_stream_with_its_usage_chunk_settles_on_that_usage() {
    let got = openai(
        &[CONTENT_CHUNK, LAST_CONTENT_CHUNK, USAGE_CHUNK, DONE],
        Ending::Clean,
    )
    .await;
    assert_eq!(
        got.spent,
        Microusd(7_375),
        "950 input, 500 output, as reported"
    );
}

/// `n` completions are generated and billed, so the cap multiplies as the estimate's does.
#[tokio::test]
async fn the_cap_counts_every_completion() {
    let got = call(
        Wire::OpenAi,
        r#"{"model":"gpt-4o","max_tokens":1000,"n":2,"stream":true}"#,
        "200 OK",
        [CONTENT_CHUNK, PROMPT_ONLY_CHUNK, DONE]
            .concat()
            .into_bytes(),
        Ending::Clean,
    )
    .await;
    assert_eq!(got.spent, Microusd(22_375), "950 input, 2 x 1000 output");
}

/// No `max_tokens` on the request: the output the estimate assumes for that case, 1024.
#[tokio::test]
async fn a_request_with_no_cap_is_charged_the_output_the_estimate_assumes() {
    let got = call(
        Wire::OpenAi,
        r#"{"model":"gpt-4o","stream":true}"#,
        "200 OK",
        [CONTENT_CHUNK, PROMPT_ONLY_CHUNK, DONE]
            .concat()
            .into_bytes(),
        Ending::Clean,
    )
    .await;
    assert_eq!(got.spent, Microusd(12_615), "950 input, 1024 output");
}

/// Why the input side is the reported one and not the estimate's: a prompt written to the
/// one-hour cache is billed at twice the input rate, which the estimate cannot know. A short
/// request body keeps the estimate far below what the provider already said.
#[tokio::test]
async fn the_settlement_is_never_below_what_the_provider_already_reported() {
    let opening = "event: message_start\ndata: {\"type\":\"message_start\",\"message\":{\"usage\":{\"input_tokens\":10,\"cache_creation_input_tokens\":200000,\"cache_creation\":{\"ephemeral_1h_input_tokens\":200000},\"output_tokens\":1}}}\n\n";
    let got = anthropic(&[opening, TEXT, STOP], Ending::Clean).await;
    assert!(
        got.reserved_while_open < Microusd(1_200_030),
        "the fixture has to hold an estimate below the reported figure to prove anything, got {:?}",
        got.reserved_while_open
    );
    assert_eq!(
        got.spent,
        Microusd(1_215_030),
        "10 input, 200000 one-hour cache writes at 6 USD per Mtok, 1000 output at the cap"
    );
}

/// A whole JSON answer has no later event to wait for: what it says is all it will ever say.
#[tokio::test]
async fn a_whole_json_answer_is_complete_whatever_it_reports() {
    let got = call(
        Wire::Anthropic,
        r#"{"model":"claude-sonnet","max_tokens":1000}"#,
        "200 OK",
        br#"{"usage":{"input_tokens":10}}"#.to_vec(),
        Ending::Clean,
    )
    .await;
    assert_eq!(got.spent, Microusd(30));
}

/// A refusal charges what it reported, else zero (invariant 47's money rule): the cap is an
/// assumption about a generation, and a refused call has none to assume.
#[tokio::test]
async fn a_refusal_that_stopped_short_charges_what_it_reported_and_no_cap() {
    let got = call(
        Wire::Anthropic,
        ANTHROPIC_STREAM_REQUEST,
        "429 Too Many Requests",
        [OPENING, STOP].concat().into_bytes(),
        Ending::Clean,
    )
    .await;
    assert_eq!(got.status, StatusCode::TOO_MANY_REQUESTS);
    assert_eq!(
        got.spent,
        Microusd(45),
        "10 input and 1 output as reported, no cap"
    );
}

// -- #309: a body that breaks after some of the usage arrived --------------------------------

#[tokio::test]
async fn a_break_after_the_final_usage_event_settles_on_that_usage() {
    let got = anthropic(&[OPENING, TEXT, FINAL_DELTA], Ending::Broken).await;
    assert_eq!(got.status, StatusCode::OK);
    assert!(got.body_errored, "the fixture has to break the body");
    assert_eq!(
        got.spent,
        Microusd(3_030),
        "10 input, 200 output: the provider had already said so when the body broke"
    );
}

#[tokio::test]
async fn a_break_after_only_the_opening_counters_charges_the_output_cap() {
    let got = anthropic(&[OPENING, TEXT], Ending::Broken).await;
    assert!(got.body_errored);
    assert_eq!(
        got.spent,
        Microusd(15_030),
        "the half this body carried is what #308 refuses to settle on, on the error path too"
    );
}

#[tokio::test]
async fn a_break_after_a_delta_that_is_still_open_charges_the_output_cap() {
    let got = anthropic(&[OPENING, TEXT, OPEN_DELTA], Ending::Broken).await;
    assert!(got.body_errored);
    assert_eq!(
        got.spent,
        Microusd(15_030),
        "stop_reason null says more output was coming, so 40 is a floor and not a figure"
    );
}

#[tokio::test]
async fn a_break_before_anything_priced_stays_on_the_estimate() {
    let got = anthropic(&[TEXT], Ending::Broken).await;
    assert!(got.body_errored);
    assert!(got.reserved_while_open > Microusd::ZERO);
    assert_eq!(got.spent, got.reserved_while_open, "nothing was parsed");
}

#[tokio::test]
async fn an_openai_break_after_the_usage_chunk_settles_on_that_usage() {
    let got = openai(
        &[CONTENT_CHUNK, LAST_CONTENT_CHUNK, USAGE_CHUNK],
        Ending::Broken,
    )
    .await;
    assert!(got.body_errored);
    assert_eq!(
        got.spent,
        Microusd(7_375),
        "950 input, 500 output, as reported"
    );
}

/// The regression #309 alone would have opened: a running total is not the final figure, and
/// publishing it on the error path must not settle on it.
#[tokio::test]
async fn an_openai_break_on_a_running_total_charges_the_output_cap() {
    let got = openai(&[RUNNING_TOTAL_CHUNK], Ending::Broken).await;
    assert!(got.body_errored);
    assert_eq!(
        got.spent,
        Microusd(12_375),
        "950 input as reported, 1000 output at the cap, not the 40 counted so far"
    );
}
