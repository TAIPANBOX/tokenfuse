//! The upstream LLM provider abstraction and its real HTTP implementation.
//!
//! A provider forwards a request and returns a **streaming** body plus a slot
//! that is filled with the token [`Usage`] once the stream is fully consumed.
//! Streaming is essential: the gateway passes bytes through to the caller as
//! they arrive (SSE passthrough) and only settles the real cost at end-of-stream
//! (Phase 0 spike #1). Usage is parsed out of the same bytes as they flow by.

use async_trait::async_trait;
use axum::http::HeaderMap;
use bytes::Bytes;
use futures::stream::{BoxStream, StreamExt};
use std::sync::{Arc, Mutex};
use tokenfuse_core::Usage;

/// Usage parsed from a (possibly truncated) response body, paired with
/// whether [`UsageParser::feed`] dropped bytes before they could be parsed.
///
/// `truncated = true` means `usage` may be missing fields that would have
/// arrived after the cut: Anthropic's cumulative `output_tokens` lands in the
/// FINAL `message_delta`, so a response over [`UsageParser::CAP`] can carry a
/// real-looking but silently short `usage`, or none at all, when the whole
/// usage block landed past the cut. Callers must not price `usage` when
/// `truncated` is set; see `crate::settle::settle_amount`.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct ParsedUsage {
    pub usage: Usage,
    pub truncated: bool,
}

/// Shared slot filled with the final usage once a provider stream ends.
pub type UsageSlot = Arc<Mutex<Option<ParsedUsage>>>;

/// A streaming response from the upstream.
pub struct ProviderResponse {
    pub status: u16,
    pub content_type: Option<String>,
    /// Body chunks to pass through to the caller.
    pub body: BoxStream<'static, Result<Bytes, ProviderError>>,
    /// Filled with the parsed usage once `body` is fully consumed.
    pub usage: UsageSlot,
}

#[derive(Debug, thiserror::Error)]
pub enum ProviderError {
    /// The request never left this process: it could not be built, or the
    /// connection to the provider was never established (redirects are not
    /// followed, so there is one hop).
    #[error("upstream request was not sent: {0}")]
    NotSent(String),
    /// The connection existed; the provider may have received and executed
    /// the request.
    #[error("upstream request failed: {0}")]
    Upstream(String),
}

/// An upstream that can forward a request. Implemented by the real HTTP client
/// and by test stubs.
#[async_trait]
pub trait Provider: Send + Sync {
    async fn send(
        &self,
        headers: HeaderMap,
        body: Bytes,
    ) -> Result<ProviderResponse, ProviderError>;
}

// ---------------------------------------------------------------------------
// Usage parsing (provider-format-aware, but unified)
// ---------------------------------------------------------------------------

/// One SSE body, split into events by the WHATWG event-stream grammar (invariant 55): the
/// `data` payload of every dispatched event, in order, and whether any `data` field appeared
/// at all, which is what "this body is SSE" has always meant here (a body with `data:` lines
/// that dispatch nothing is still not a JSON document).
///
/// Two departures from the browser algorithm, both on purpose, both in the direction of not
/// losing an event: a final event the body ends without a blank line for IS dispatched (at
/// end of body nothing can follow it; a provider that omits the last blank line is a shape the
/// old line parser accepted; and on the Anthropic wire that last event is the `message_delta`
/// carrying the cumulative `output_tokens`, the figure F06 lost); and an event whose data is
/// empty after the trailing LF is removed is not dispatched (the browser dispatches an empty
/// message; here it could only fail to parse, and `saw_data_field` already records that the
/// line was there).
#[derive(Debug, Default, PartialEq, Eq)]
pub(crate) struct SseEvents {
    pub(crate) events: Vec<String>,
    pub(crate) saw_data_field: bool,
}

pub(crate) fn split_sse_events(text: &str) -> SseEvents {
    let mut out = SseEvents::default();
    // The data buffer. Every appended value is followed by one LF; `dispatch` removes the
    // last one, which is why a buffer holding exactly "\n" dispatches nothing.
    let mut data = String::new();
    let mut rest = text;
    loop {
        // One line: up to the first CR or LF, with CRLF read as one terminator. Text after
        // the last terminator is a line only when it is non-empty: the grammar sees no line
        // there, and treating it as a blank line would dispatch on a phantom.
        let (line, next) = match rest.find(['\r', '\n']) {
            Some(i) => {
                let bytes = rest.as_bytes();
                let after = if bytes[i] == b'\r' && bytes.get(i + 1) == Some(&b'\n') {
                    &rest[i + 2..]
                } else {
                    &rest[i + 1..]
                };
                (&rest[..i], Some(after))
            }
            None => (rest, None),
        };
        if next.is_none() && line.is_empty() {
            break;
        }
        if line.is_empty() {
            dispatch(&mut data, &mut out.events);
        } else if line.starts_with(':') {
            // A comment. With `split_once` below this arm is defence in depth (a line
            // starting with a colon has an empty field name, which nothing reads); it is
            // kept because the grammar names it.
        } else {
            let (field, value) = match line.split_once(':') {
                Some((f, v)) => (f, v.strip_prefix(' ').unwrap_or(v)),
                None => (line, ""),
            };
            // Leading whitespace before the field name is stripped before the comparison,
            // exactly as the line parser's `trim_start` always did (no provider is known to
            // indent a field, and a test pins the tolerance). A whitespace-only line is then
            // a field line with an empty name, not a blank line, so it dispatches nothing and
            // never splits an event.
            if field.trim_start() == "data" {
                out.saw_data_field = true;
                data.push_str(value);
                data.push('\n');
            }
            // `event`, `id`, `retry` and any other field: no effect on the data buffer.
        }
        match next {
            Some(n) => rest = n,
            None => break,
        }
    }
    // The first departure: an unterminated final event is dispatched, not discarded.
    dispatch(&mut data, &mut out.events);
    out
}

/// Dispatch: remove the trailing LF the last `data` line appended; an empty buffer, before or
/// after that, dispatches nothing. The buffer is empty afterwards either way.
fn dispatch(data: &mut String, events: &mut Vec<String>) {
    if data.is_empty() {
        return;
    }
    data.pop();
    if data.is_empty() {
        return;
    }
    events.push(std::mem::take(data));
}

/// Extracts token usage from a response body, whether SSE (streaming) or a
/// single JSON object (non-streaming). It recognizes both Anthropic
/// (`message_start` / `message_delta`) and OpenAI (`usage` with
/// `prompt_tokens`) shapes.
///
/// Buffered: the body is kept up to [`CAP`](Self::CAP) and parsed once at [`finish`](Self::finish)
/// (invariant 38), as SSE events by the event-stream grammar when any `data` field appears,
/// else as one JSON document (invariant 55). An incremental SSE parser is out of scope and is
/// tracked nowhere yet.
#[derive(Default)]
pub struct UsageParser {
    buf: Vec<u8>,
    /// Set by [`feed`](Self::feed) the moment a byte is dropped because the
    /// buffered body exceeded [`CAP`](Self::CAP). Sticky for the parser's
    /// lifetime: once one byte has been dropped, everything parsed from `buf`
    /// is potentially incomplete, so later calls cannot un-set it.
    truncated: bool,
}

impl UsageParser {
    /// Upper bound on buffered bytes; beyond this we stop accumulating and
    /// mark the result [`ParsedUsage::truncated`], so the settle path falls
    /// back to the pre-flight estimate instead of trusting usage parsed from
    /// an incomplete body (see `crate::settle::settle_amount`).
    ///
    /// `pub(crate)` rather than private: `crate::settle` names this exact
    /// number in the warning it logs when a settlement falls back because of
    /// truncation, so an operator reading the log sees the real cap rather
    /// than a second constant that could drift from this one.
    pub(crate) const CAP: usize = 8 * 1024 * 1024;

    pub fn new() -> Self {
        UsageParser::default()
    }

    pub fn feed(&mut self, chunk: &[u8]) {
        if self.buf.len() >= Self::CAP {
            if !chunk.is_empty() {
                self.truncated = true;
            }
            return;
        }
        let take = (Self::CAP - self.buf.len()).min(chunk.len());
        if take < chunk.len() {
            self.truncated = true;
        }
        self.buf.extend_from_slice(&chunk[..take]);
    }

    pub fn finish(&self) -> ParsedUsage {
        let text = String::from_utf8_lossy(&self.buf);
        let mut usage = Usage::default();
        let mut netting = OpenAiNetting::default();
        let mut tool_calls = ToolCallCounter::default();

        let sse = split_sse_events(&text);
        if sse.saw_data_field {
            // Each dispatched event is one JSON document, handed once to `merge_usage` and
            // once to the tool-call counter (invariant 55). `[DONE]` is OpenAI's end
            // sentinel; an event that does not parse is skipped and its siblings are not.
            for event in &sse.events {
                if event.trim() == "[DONE]" {
                    continue;
                }
                if let Ok(v) = serde_json::from_str::<serde_json::Value>(event) {
                    merge_usage(&mut usage, &mut netting, &v);
                    tool_calls.observe_streaming(&v);
                }
            }
        } else if let Ok(v) = serde_json::from_str::<serde_json::Value>(text.trim()) {
            // Non-streaming response: the whole body is one JSON object.
            merge_usage(&mut usage, &mut netting, &v);
            tool_calls.observe_non_streaming(&v);
        }

        usage.tool_calls = tool_calls.finish();
        ParsedUsage {
            usage,
            truncated: self.truncated,
        }
    }
}

/// Accumulates the model-emitted tool-call count across a response body (I1,
/// docs/21-tool-runs.md), for both Anthropic and OpenAI shapes, streaming or
/// not - the same "inspect the JSON shape, not the endpoint" approach
/// [`merge_usage`] already uses, since this gateway is provider-agnostic.
///
/// `finish()` returns `None` only when nothing in the body ever parsed as
/// JSON at all; any response we could actually look into resolves to at
/// least `Some(0)` - "no tool calls" is a real observation, never a guess.
#[derive(Default)]
struct ToolCallCounter {
    /// At least one JSON value from the body was successfully parsed.
    seen: bool,
    /// Anthropic: `content_block_start` events announcing a `tool_use` block
    /// (streaming), or `content[]` blocks of type `tool_use` (non-streaming) -
    /// counted the same way, since each occurrence is one tool call either way.
    anthropic: u32,
    /// OpenAI non-streaming: `choices[].message.tool_calls` length, summed
    /// across choices (a request can ask for more than one).
    openai_nonstream: u32,
    /// OpenAI streaming: distinct `(choice_index, tool_call_index)` pairs
    /// seen across `choices[].delta.tool_calls[]`. Deltas repeat per
    /// tool_call index as a call's arguments stream in, so only the count of
    /// *unique* indexes is the number of tool calls - counting deltas
    /// directly would overcount. The pairing with `choice_index` matters
    /// because `n > 1` (multiple choices) is legal on this endpoint: each
    /// choice's own `tool_calls[].index` restarts from 0 independently, so
    /// two different choices both streaming a tool call at index 0 are two
    /// distinct tool calls, not one - a bare `HashSet<u64>` keyed on the
    /// tool_call index alone would collapse them into one and undercount.
    /// The choice's own `"index"` defaults to 0 when the key is absent
    /// (which is every request that didn't ask for `n > 1`), so the common
    /// single-choice case is unaffected.
    openai_stream_idx: std::collections::HashSet<(u64, u64)>,
}

impl ToolCallCounter {
    /// Anthropic's `content_block_start` events don't have a fixed shape
    /// contract, we look for the two keys we need and ignore everything else.
    fn observe_streaming(&mut self, v: &serde_json::Value) {
        self.seen = true;
        if v.get("type").and_then(|t| t.as_str()) == Some("content_block_start") {
            let is_tool_use = v
                .get("content_block")
                .and_then(|b| b.get("type"))
                .and_then(|t| t.as_str())
                == Some("tool_use");
            if is_tool_use {
                self.anthropic += 1;
            }
        }
        if let Some(choices) = v.get("choices").and_then(|c| c.as_array()) {
            for choice in choices {
                // Absent (no `n>1` requested) defaults to 0, the same
                // implicit single-choice index every OpenAI response without
                // `n` carries.
                let choice_idx = choice.get("index").and_then(|i| i.as_u64()).unwrap_or(0);
                let Some(deltas) = choice
                    .get("delta")
                    .and_then(|d| d.get("tool_calls"))
                    .and_then(|t| t.as_array())
                else {
                    continue;
                };
                for tc in deltas {
                    if let Some(idx) = tc.get("index").and_then(|i| i.as_u64()) {
                        self.openai_stream_idx.insert((choice_idx, idx));
                    }
                }
            }
        }
    }

    fn observe_non_streaming(&mut self, v: &serde_json::Value) {
        self.seen = true;
        if let Some(content) = v.get("content").and_then(|c| c.as_array()) {
            self.anthropic += content
                .iter()
                .filter(|b| b.get("type").and_then(|t| t.as_str()) == Some("tool_use"))
                .count() as u32;
        }
        if let Some(choices) = v.get("choices").and_then(|c| c.as_array()) {
            for choice in choices {
                if let Some(tc) = choice
                    .get("message")
                    .and_then(|m| m.get("tool_calls"))
                    .and_then(|t| t.as_array())
                {
                    self.openai_nonstream += tc.len() as u32;
                }
            }
        }
    }

    fn finish(self) -> Option<u32> {
        if !self.seen {
            return None;
        }
        Some(self.anthropic + self.openai_nonstream + self.openai_stream_idx.len() as u32)
    }
}

/// The two OpenAI prompt figures seen so far in ONE parse, kept apart until each object is
/// applied so that `Usage.input_tokens` is always `gross_prompt.saturating_sub(cached)`
/// whichever order they arrive in (invariant 45; F05 of the 2026-09-18 money-path review).
/// Both follow `set_if_positive`'s rule: the last non-zero value wins, because streamed
/// events arrive oldest first.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
struct OpenAiNetting {
    /// The provider's `prompt_tokens`, which INCLUDES the cached subset.
    gross_prompt: u64,
    /// `prompt_tokens_details.cached_tokens`.
    cached: u64,
}

/// OpenAI's usage object, by its own fields: any one of these makes it OpenAI's shape,
/// including `prompt_tokens_details` on its own, which until 2026-09-18 was read as
/// Anthropic's and ignored (F05). `total_tokens` marks the shape and is never priced.
fn is_openai_shape(u: &serde_json::Value) -> bool {
    [
        "prompt_tokens",
        "completion_tokens",
        "total_tokens",
        "prompt_tokens_details",
        "completion_tokens_details",
    ]
    .iter()
    .any(|k| u.get(*k).is_some())
}

fn merge_usage(usage: &mut Usage, net: &mut OpenAiNetting, v: &serde_json::Value) {
    // Anthropic message_start: { "message": { "usage": { ... } } }
    if let Some(u) = v.get("message").and_then(|m| m.get("usage")) {
        apply_anthropic(usage, u);
    }
    // Anthropic message_delta / non-stream, or OpenAI: top-level "usage".
    // Defense in depth, currently unobservable: `Value::get` already returns
    // `None` for a non-object (including `null`) to both `apply_*` below, so
    // deleting this filter changes no test in `provider`'s module (checked
    // 2026-09-07). No test can pin it for that reason; keep it anyway.
    if let Some(u) = v.get("usage").filter(|u| u.is_object()) {
        if is_openai_shape(u) {
            apply_openai(usage, net, u);
        } else {
            apply_anthropic(usage, u);
        }
    }
}

/// Last-non-zero-wins: streamed events arrive oldest-first, and the final
/// `message_delta` carries the cumulative output-token total.
fn set_if_positive(field: &mut u64, v: &serde_json::Value, key: &str) {
    if let Some(n) = v.get(key).and_then(|x| x.as_u64()) {
        if n > 0 {
            *field = n;
        }
    }
}

fn apply_anthropic(usage: &mut Usage, u: &serde_json::Value) {
    set_if_positive(&mut usage.input_tokens, u, "input_tokens");
    set_if_positive(&mut usage.output_tokens, u, "output_tokens");
    set_if_positive(&mut usage.cache_read_tokens, u, "cache_read_input_tokens");
    set_if_positive(
        &mut usage.cache_write_tokens,
        u,
        "cache_creation_input_tokens",
    );
    // The TTL breakdown beside the total: the 1-hour subset is billed at a
    // different rate and is kept apart (tokenfuse#282); the 5-minute figure
    // is the remainder and is not stored twice.
    if let Some(breakdown) = u.get("cache_creation").filter(|c| c.is_object()) {
        set_if_positive(
            &mut usage.cache_write_1h_tokens,
            breakdown,
            "ephemeral_1h_input_tokens",
        );
    }
}

/// OpenAI's usage shape, folded into the Anthropic-shaped [`Usage`].
///
/// The two vendors disagree on one thing that costs money. Anthropic's
/// `input_tokens` and `cache_read_input_tokens` are disjoint; OpenAI's
/// `prompt_tokens` INCLUDES `prompt_tokens_details.cached_tokens`. `Usage`
/// keeps the disjoint shape, because that is what [`ModelPrice::cost`]
/// prices, so the cached subset is netted out of the prompt count here. Until
/// 2026-09-14 it was not, and every cached token was priced twice: once at
/// the full input rate inside `prompt_tokens` and again at the cache-read
/// rate, +14.5 % on a 950/128 call and more with a higher hit ratio, landing
/// in the run's budget as spend nobody was billed (tokenfuse#267).
///
/// The gross prompt count and the cached subset are kept apart in [`OpenAiNetting`] across
/// every event of one parse, and `input_tokens` is always written from that state rather than
/// from whichever object is current, so an object carrying only `prompt_tokens_details` still
/// nets a `prompt_tokens` that arrived earlier OR later (F05 of the 2026-09-18 money-path
/// review: until then the netting ran only when the CURRENT object carried `prompt_tokens`, so
/// a details-only object was read as Anthropic's shape and ignored, and the second order priced
/// the cached subset twice again).
fn apply_openai(usage: &mut Usage, net: &mut OpenAiNetting, u: &serde_json::Value) {
    if let Some(p) = u.get("prompt_tokens").and_then(|x| x.as_u64()) {
        if p > 0 {
            net.gross_prompt = p;
        }
    }
    if let Some(c) = u
        .get("prompt_tokens_details")
        .and_then(|d| d.get("cached_tokens"))
        .and_then(|x| x.as_u64())
    {
        if c > 0 {
            net.cached = c;
        }
    }
    set_if_positive(&mut usage.output_tokens, u, "completion_tokens");
    // Written from the state, not from this object, so the order the two figures arrived in
    // cannot matter. `saturating_sub`: a cached count past the prompt count is the provider's
    // bug, and an input count that wraps is the ADR-8 direction reversed.
    if net.gross_prompt > 0 {
        usage.input_tokens = net.gross_prompt.saturating_sub(net.cached);
    }
    if net.cached > 0 {
        usage.cache_read_tokens = net.cached;
    }
}

// ---------------------------------------------------------------------------
// Real HTTP provider
// ---------------------------------------------------------------------------

/// Headers we forward upstream. The provider API key is passed through and
/// never stored or logged (privacy by design) — either as `Authorization`
/// (OpenAI-style bearer auth) or as `x-api-key` (Anthropic's native auth
/// header; without it Anthropic rejects the request with 401 "x-api-key
/// header is required" even though `anthropic-version` made it through).
const FORWARD_HEADERS: &[&str] = &[
    "authorization",
    "x-api-key",
    "anthropic-version",
    "anthropic-beta",
    "openai-organization",
    "openai-beta",
    "content-type",
    "accept",
];

/// Forwards requests to a real upstream endpoint and streams the response back,
/// parsing usage out of the bytes as they flow.
pub struct HttpProvider {
    client: reqwest::Client,
    endpoint: String,
}

impl HttpProvider {
    pub fn new(endpoint: impl Into<String>) -> Self {
        // A connect timeout bounds how long a stalled upstream can tie up a
        // request during the TCP+TLS handshake. We deliberately set *no* overall
        // request timeout: responses stream (SSE) and may legitimately stay open
        // for minutes, so a whole-request deadline would cut long generations.
        let connect_secs = std::env::var("TOKENFUSE_UPSTREAM_CONNECT_TIMEOUT_SECS")
            .ok()
            .and_then(|s| s.parse().ok())
            .unwrap_or(10);
        // No redirect is followed, for two reasons. The caller's x-api-key
        // (in FORWARD_HEADERS) and the whole prompt are not safe to send to a
        // second host: on a cross-host redirect reqwest strips only five
        // headers (Authorization, Cookie, cookie2, Proxy-Authorization,
        // WWW-Authenticate), and a 307 or 308 keeps the method and the body,
        // so the key and the prompt would follow it. And one hop is what
        // makes a connect error proof that no byte of the request left this
        // process (see HttpProvider::send): a followed redirect would leave a
        // connect error ambiguous between the first hop and the second. Same
        // posture as mcpclient.rs's scanner client.
        let client = reqwest::Client::builder()
            .connect_timeout(std::time::Duration::from_secs(connect_secs))
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .expect(
                "the provider HTTP client builds; reqwest::Client::new() panics on the same failure",
            );
        HttpProvider {
            client,
            endpoint: endpoint.into(),
        }
    }
}

#[async_trait]
impl Provider for HttpProvider {
    async fn send(
        &self,
        headers: HeaderMap,
        body: Bytes,
    ) -> Result<ProviderResponse, ProviderError> {
        let mut req = self.client.post(&self.endpoint).body(body.to_vec());
        for name in FORWARD_HEADERS {
            if let Some(v) = headers.get(*name) {
                req = req.header(*name, v);
            }
        }

        // Building is proof that no bytes were dispatched.
        let request = req
            .build()
            .map_err(|e| ProviderError::NotSent(e.to_string()))?;
        // Redirects are not followed, so a connect error here is the only
        // hop's handshake failing and the request never left. Anything after
        // the connection existed (a reset or EOF after the POST was written,
        // a timeout awaiting the head) may have reached the provider.
        let resp = self.client.execute(request).await.map_err(|e| {
            if e.is_connect() {
                ProviderError::NotSent(e.to_string())
            } else {
                ProviderError::Upstream(e.to_string())
            }
        })?;
        let status = resp.status().as_u16();
        let content_type = resp
            .headers()
            .get("content-type")
            .and_then(|v| v.to_str().ok())
            .map(|s| s.to_string());

        let usage: UsageSlot = Arc::new(Mutex::new(None));
        let usage_writer = Arc::clone(&usage);
        let upstream = resp.bytes_stream();

        // Pass each chunk through unchanged while tapping it for usage. On end
        // of stream, publish the parsed usage into the shared slot.
        let body = async_stream::try_stream! {
            let mut parser = UsageParser::new();
            futures::pin_mut!(upstream);
            while let Some(chunk) = upstream.next().await {
                let chunk = chunk.map_err(|e| ProviderError::Upstream(e.to_string()))?;
                parser.feed(&chunk);
                yield chunk;
            }
            *usage_writer.lock().unwrap() = Some(parser.finish());
        };

        Ok(ProviderResponse {
            status,
            content_type,
            body: Box::pin(body),
            usage,
        })
    }
}

// ---------------------------------------------------------------------------
// Deterministic stub (offline dev + tests)
// ---------------------------------------------------------------------------

/// A deterministic stand-in used for offline runs and tests. Emits a small JSON
/// body and reports fixed usage.
#[derive(Debug, Clone)]
pub struct StubProvider {
    pub input_tokens: u64,
    pub output_tokens: u64,
    /// When true, emit the body as a couple of SSE `data:` frames to exercise
    /// the streaming passthrough path.
    pub sse: bool,
    /// Override the non-streaming JSON body (e.g. to inject a tool_use for
    /// firewall tests). Ignored in SSE mode.
    pub body_override: Option<String>,
}

impl Default for StubProvider {
    fn default() -> Self {
        StubProvider {
            input_tokens: 1_000,
            output_tokens: 500,
            sse: false,
            body_override: None,
        }
    }
}

#[async_trait]
impl Provider for StubProvider {
    async fn send(
        &self,
        _headers: HeaderMap,
        _body: Bytes,
    ) -> Result<ProviderResponse, ProviderError> {
        let usage = Usage {
            input_tokens: self.input_tokens,
            output_tokens: self.output_tokens,
            ..Default::default()
        };

        let (content_type, chunks): (Option<String>, Vec<Bytes>) = if self.sse {
            (
                Some("text/event-stream".to_string()),
                vec![
                    Bytes::from(format!(
                        "event: message_start\ndata: {{\"type\":\"message_start\",\"message\":{{\"usage\":{{\"input_tokens\":{}}}}}}}\n\n",
                        self.input_tokens
                    )),
                    Bytes::from(format!(
                        "event: message_delta\ndata: {{\"type\":\"message_delta\",\"usage\":{{\"output_tokens\":{}}}}}\n\n",
                        self.output_tokens
                    )),
                    Bytes::from_static(b"data: [DONE]\n\n"),
                ],
            )
        } else {
            let body = self.body_override.clone().unwrap_or_else(|| {
                format!(
                    r#"{{"stub":true,"usage":{{"input_tokens":{},"output_tokens":{}}}}}"#,
                    self.input_tokens, self.output_tokens
                )
            });
            (
                Some("application/json".to_string()),
                vec![Bytes::from(body)],
            )
        };

        let slot: UsageSlot = Arc::new(Mutex::new(None));
        let writer = Arc::clone(&slot);
        let body = async_stream::try_stream! {
            let mut parser = UsageParser::new();
            for chunk in chunks {
                parser.feed(&chunk);
                yield chunk;
            }
            // Prefer the declared usage; fall back to what the parser saw.
            // Never truncated in practice (the stub's bodies are a few bytes),
            // but carried through honestly rather than hard-coded false.
            // "The parser saw usage" is asked the way settlement asks it
            // (`Usage::carries_priced_tokens`, invariant 43): a body with no
            // usage block still parses and carries `tool_calls: Some(0)`, and
            // comparing against `Usage::default()` read that as usage.
            let parsed = parser.finish();
            let usage = if parsed.usage.carries_priced_tokens() { parsed.usage } else { usage };
            *writer.lock().unwrap() = Some(ParsedUsage { usage, truncated: parsed.truncated });
        };

        Ok(ProviderResponse {
            status: 200,
            content_type,
            body: Box::pin(body),
            usage: slot,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pricebook::default_price_book;
    use tokenfuse_core::{Microusd, ModelPrice};

    #[test]
    fn parses_anthropic_sse_usage() {
        let mut p = UsageParser::new();
        p.feed(b"event: message_start\ndata: {\"type\":\"message_start\",\"message\":{\"usage\":{\"input_tokens\":1200,\"cache_read_input_tokens\":300}}}\n\n");
        p.feed(b"event: message_delta\ndata: {\"type\":\"message_delta\",\"usage\":{\"output_tokens\":8}}\n\n");
        p.feed(b"event: message_delta\ndata: {\"type\":\"message_delta\",\"usage\":{\"output_tokens\":842}}\n\n");
        p.feed(b"data: [DONE]\n\n");
        let u = p.finish().usage;
        assert_eq!(u.input_tokens, 1200);
        assert_eq!(u.cache_read_tokens, 300);
        // Final cumulative delta wins.
        assert_eq!(u.output_tokens, 842);
    }

    /// The Anthropic usage object names the TTL of a cache write under
    /// `cache_creation` (`ephemeral_5m_input_tokens`, `ephemeral_1h_input_tokens`)
    /// beside the total `cache_creation_input_tokens`; the parser keeps the
    /// total and the 1-hour subset (tokenfuse#282). Here the INT-2 shape:
    /// the whole write on the 1-hour TTL.
    #[test]
    fn parses_the_one_hour_cache_write_subset_from_a_message_start() {
        let mut p = UsageParser::new();
        p.feed(b"event: message_start\ndata: {\"type\":\"message_start\",\"message\":{\"usage\":{\"input_tokens\":10,\"cache_creation_input_tokens\":140373,\"cache_read_input_tokens\":0,\"cache_creation\":{\"ephemeral_5m_input_tokens\":0,\"ephemeral_1h_input_tokens\":140373}}}}\n\n");
        p.feed(b"event: message_delta\ndata: {\"type\":\"message_delta\",\"usage\":{\"output_tokens\":192}}\n\n");
        let u = p.finish().usage;
        assert_eq!(u.input_tokens, 10);
        assert_eq!(u.output_tokens, 192);
        assert_eq!(u.cache_write_tokens, 140_373);
        assert_eq!(u.cache_write_1h_tokens, 140_373);
    }

    /// A usage object without the `cache_creation` breakdown (older API
    /// versions, and the stub) is a 5-minute write in full: the subset stays
    /// zero and nothing else moves.
    #[test]
    fn a_cache_write_without_a_ttl_breakdown_is_all_five_minute() {
        let mut p = UsageParser::new();
        p.feed(br#"{"id":"msg_2","usage":{"input_tokens":40,"output_tokens":15,"cache_creation_input_tokens":500}}"#);
        let u = p.finish().usage;
        assert_eq!(u.cache_write_tokens, 500);
        assert_eq!(u.cache_write_1h_tokens, 0);
    }

    #[test]
    fn parses_openai_sse_usage() {
        let mut p = UsageParser::new();
        p.feed(b"data: {\"choices\":[{\"delta\":{\"content\":\"hi\"}}]}\n\n");
        p.feed(b"data: {\"choices\":[],\"usage\":{\"prompt_tokens\":950,\"completion_tokens\":120,\"prompt_tokens_details\":{\"cached_tokens\":128}}}\n\n");
        p.feed(b"data: [DONE]\n\n");
        let u = p.finish().usage;
        // OpenAI's `prompt_tokens` INCLUDES the cached subset; Anthropic's
        // `input_tokens` excludes it. `Usage` keeps Anthropic's disjoint
        // shape, which is what `ModelPrice::cost` prices, so the cached 128
        // are netted out of the 950 here rather than priced twice
        // (tokenfuse#267).
        assert_eq!(u.input_tokens, 822);
        assert_eq!(u.output_tokens, 120);
        assert_eq!(u.cache_read_tokens, 128);
    }

    /// tokenfuse#267, the settle-side number. `gpt-4o` at the book's rates
    /// (2.50 input / 1.25 cached USD per Mtok), a call reporting
    /// `prompt_tokens 950` with `cached_tokens 128`: the provider bills
    /// 822 x 2.50 + 128 x 1.25 per Mtok = 2055 + 160 = 2215 micro-USD, not
    /// 950 x 2.50 + 128 x 1.25 = 2375 + 160 = 2535 (every cached token at the
    /// full input rate and again at the cache-read rate).
    #[test]
    fn an_openai_cached_token_is_priced_once_not_twice() {
        let mut p = UsageParser::new();
        p.feed(br#"{"id":"chatcmpl-1","usage":{"prompt_tokens":950,"completion_tokens":0,"prompt_tokens_details":{"cached_tokens":128}}}"#);
        let u = p.finish().usage;
        let gpt_4o = ModelPrice::per_mtok_usd(2.50, 10.00, 1.25, 2.50);
        assert_eq!(
            gpt_4o.cost(&u),
            Microusd(2215),
            "822 x 2.50 + 128 x 1.25 = 2215 micro-USD; 2535 would be the cached subset priced twice"
        );
    }

    /// The cached subset on one chunk and a bare `prompt_tokens` on a later
    /// one (a provider that repeats the prompt count on every chunk and the
    /// details once): the later chunk must not reset the input to the whole
    /// prompt while the cache-read count stays, or the double charge is back
    /// under a different chunking.
    #[test]
    fn a_later_chunk_without_the_cached_subset_still_nets_it() {
        let mut p = UsageParser::new();
        p.feed(b"data: {\"choices\":[],\"usage\":{\"prompt_tokens\":950,\"prompt_tokens_details\":{\"cached_tokens\":128}}}\n\n");
        p.feed(b"data: {\"choices\":[],\"usage\":{\"prompt_tokens\":950,\"completion_tokens\":120}}\n\n");
        p.feed(b"data: [DONE]\n\n");
        let u = p.finish().usage;
        assert_eq!(u.input_tokens, 822);
        assert_eq!(u.cache_read_tokens, 128);
        assert_eq!(u.output_tokens, 120);
    }

    /// A cached count larger than the prompt count is a provider bug, not a
    /// negative input: it nets to zero rather than wrapping.
    #[test]
    fn an_openai_cached_count_past_the_prompt_count_nets_to_zero_not_wraps() {
        let mut p = UsageParser::new();
        p.feed(br#"{"id":"chatcmpl-2","usage":{"prompt_tokens":100,"completion_tokens":5,"prompt_tokens_details":{"cached_tokens":150}}}"#);
        let u = p.finish().usage;
        assert_eq!(u.input_tokens, 0);
        assert_eq!(u.cache_read_tokens, 150);
        assert_eq!(u.output_tokens, 5);
    }

    /// No `prompt_tokens_details` at all (the shape most OpenAI-compatible
    /// providers send): nothing is netted and nothing changes.
    #[test]
    fn an_openai_usage_without_cached_tokens_is_unchanged() {
        let mut p = UsageParser::new();
        p.feed(br#"{"id":"chatcmpl-3","usage":{"prompt_tokens":950,"completion_tokens":120}}"#);
        let u = p.finish().usage;
        assert_eq!(u.input_tokens, 950);
        assert_eq!(u.cache_read_tokens, 0);
        assert_eq!(u.output_tokens, 120);
    }

    #[test]
    fn parses_non_streaming_json_usage() {
        let mut p = UsageParser::new();
        p.feed(br#"{"id":"msg_1","usage":{"input_tokens":40,"output_tokens":15}}"#);
        let u = p.finish().usage;
        assert_eq!(u.input_tokens, 40);
        assert_eq!(u.output_tokens, 15);
    }

    // -- I1: tool_calls counting (docs/21-tool-runs.md) ---------------------

    #[test]
    fn counts_anthropic_non_streaming_tool_use_blocks() {
        let mut p = UsageParser::new();
        p.feed(
            br#"{"type":"message","content":[
            {"type":"text","text":"let me check"},
            {"type":"tool_use","id":"toolu_1","name":"get_weather","input":{}},
            {"type":"tool_use","id":"toolu_2","name":"get_time","input":{}}
        ],"usage":{"input_tokens":10,"output_tokens":5}}"#,
        );
        let u = p.finish().usage;
        assert_eq!(u.tool_calls, Some(2));
    }

    #[test]
    fn counts_anthropic_streaming_content_block_start_tool_use_events() {
        let mut p = UsageParser::new();
        p.feed(
            b"data: {\"type\":\"message_start\",\"message\":{\"usage\":{\"input_tokens\":10}}}\n\n",
        );
        p.feed(b"data: {\"type\":\"content_block_start\",\"index\":0,\"content_block\":{\"type\":\"text\",\"text\":\"\"}}\n\n");
        p.feed(b"data: {\"type\":\"content_block_start\",\"index\":1,\"content_block\":{\"type\":\"tool_use\",\"id\":\"toolu_1\",\"name\":\"get_weather\"}}\n\n");
        p.feed(b"data: {\"type\":\"content_block_start\",\"index\":2,\"content_block\":{\"type\":\"tool_use\",\"id\":\"toolu_2\",\"name\":\"get_time\"}}\n\n");
        p.feed(b"data: {\"type\":\"message_delta\",\"usage\":{\"output_tokens\":20}}\n\n");
        p.feed(b"data: [DONE]\n\n");
        let u = p.finish().usage;
        assert_eq!(u.tool_calls, Some(2));
    }

    #[test]
    fn counts_openai_non_streaming_tool_calls_summed_across_choices() {
        let mut p = UsageParser::new();
        p.feed(br#"{"choices":[
            {"index":0,"message":{"role":"assistant","tool_calls":[
                {"id":"call_1","type":"function","function":{"name":"get_weather","arguments":"{}"}},
                {"id":"call_2","type":"function","function":{"name":"get_time","arguments":"{}"}}
            ]},"finish_reason":"tool_calls"},
            {"index":1,"message":{"role":"assistant","tool_calls":[
                {"id":"call_3","type":"function","function":{"name":"get_weather","arguments":"{}"}}
            ]},"finish_reason":"tool_calls"}
        ],"usage":{"prompt_tokens":30,"completion_tokens":12}}"#);
        let u = p.finish().usage;
        // 2 tool calls on choice 0 + 1 on choice 1 = 3, summed across choices.
        assert_eq!(u.tool_calls, Some(3));
    }

    #[test]
    fn counts_openai_streaming_distinct_delta_indexes_not_delta_count() {
        let mut p = UsageParser::new();
        // Index 0's arguments stream across three deltas (same tool call);
        // index 1 is a second, distinct tool call. Five deltas total, two
        // distinct indexes - the count must be 2, not 5.
        p.feed(b"data: {\"choices\":[{\"index\":0,\"delta\":{\"tool_calls\":[{\"index\":0,\"id\":\"call_1\",\"type\":\"function\",\"function\":{\"name\":\"get_weather\",\"arguments\":\"\"}}]}}]}\n\n");
        p.feed(b"data: {\"choices\":[{\"index\":0,\"delta\":{\"tool_calls\":[{\"index\":0,\"function\":{\"arguments\":\"{\\\"lat\\\"\"}}]}}]}\n\n");
        p.feed(b"data: {\"choices\":[{\"index\":0,\"delta\":{\"tool_calls\":[{\"index\":0,\"function\":{\"arguments\":\":1}\"}}]}}]}\n\n");
        p.feed(b"data: {\"choices\":[{\"index\":0,\"delta\":{\"tool_calls\":[{\"index\":1,\"id\":\"call_2\",\"type\":\"function\",\"function\":{\"name\":\"get_time\",\"arguments\":\"\"}}]}}]}\n\n");
        p.feed(b"data: {\"choices\":[{\"index\":0,\"delta\":{\"tool_calls\":[{\"index\":1,\"function\":{\"arguments\":\"{}\"}}]}}]}\n\n");
        p.feed(b"data: {\"choices\":[{\"index\":0,\"delta\":{},\"finish_reason\":\"tool_calls\"}]}\n\n");
        p.feed(b"data: [DONE]\n\n");
        let u = p.finish().usage;
        assert_eq!(u.tool_calls, Some(2));
    }

    /// Regression: `n>1` (multiple choices) each stream their OWN tool_calls
    /// index restarting from 0, so index alone is not a globally unique key.
    /// Two different choices both emitting a tool call at index 0 are two
    /// distinct tool calls - counting must not collapse them into one.
    #[test]
    fn counts_openai_streaming_tool_calls_across_multiple_choices_by_choice_and_index() {
        let mut p = UsageParser::new();
        p.feed(b"data: {\"choices\":[{\"index\":0,\"delta\":{\"tool_calls\":[{\"index\":0,\"id\":\"call_1\",\"type\":\"function\",\"function\":{\"name\":\"get_weather\",\"arguments\":\"\"}}]}},{\"index\":1,\"delta\":{\"tool_calls\":[{\"index\":0,\"id\":\"call_2\",\"type\":\"function\",\"function\":{\"name\":\"get_time\",\"arguments\":\"\"}}]}}]}\n\n");
        p.feed(b"data: [DONE]\n\n");
        let u = p.finish().usage;
        assert_eq!(u.tool_calls, Some(2));
    }

    #[test]
    fn no_tool_calls_in_a_valid_body_is_zero_not_none() {
        let mut p = UsageParser::new();
        p.feed(br#"{"type":"message","content":[{"type":"text","text":"hi"}],"usage":{"input_tokens":5,"output_tokens":2}}"#);
        let u = p.finish().usage;
        assert_eq!(u.tool_calls, Some(0));
    }

    #[test]
    fn no_tool_calls_in_a_text_only_stream_is_zero_not_none() {
        let mut p = UsageParser::new();
        p.feed(b"data: {\"choices\":[{\"index\":0,\"delta\":{\"content\":\"hi\"}}]}\n\n");
        p.feed(b"data: [DONE]\n\n");
        let u = p.finish().usage;
        assert_eq!(u.tool_calls, Some(0));
    }

    #[test]
    fn unparseable_body_leaves_tool_calls_none() {
        let mut p = UsageParser::new();
        p.feed(b"not json at all, an upstream error page or a truncated body");
        let u = p.finish().usage;
        assert_eq!(u.tool_calls, None);
    }

    #[test]
    fn empty_body_leaves_tool_calls_none() {
        let p = UsageParser::new();
        let u = p.finish().usage;
        assert_eq!(u.tool_calls, None);
    }

    // -- usage-cap truncation: a dropped byte is no longer silent ----------

    /// The defect this module used to have: a response whose usage block
    /// arrives after `UsageParser::CAP` was silently parsed to
    /// `Usage::default()`, indistinguishable from a body that genuinely
    /// carried no usage. It must now come back marked `truncated`, so the
    /// settle path can tell "nothing was there" from "something was there
    /// and we cut it off" (`crate::settle::settle_amount`).
    #[test]
    fn a_body_whose_usage_block_lands_after_the_cap_is_reported_truncated() {
        let mut p = UsageParser::new();
        // Padding that fills the cap exactly and parses to nothing (no
        // `data:` prefix, not valid JSON on its own).
        let padding = vec![b'x'; UsageParser::CAP];
        p.feed(&padding);
        // The usage block: fed once the cap is already full, so none of it
        // is ever buffered. Anthropic's shape - `message_start` carries
        // input tokens, the final `message_delta` carries the cumulative
        // output tokens - is exactly what a real oversized response would
        // lose past the cut.
        p.feed(
            b"\ndata: {\"type\":\"message_start\",\"message\":{\"usage\":{\"input_tokens\":1200}}}\n\n",
        );
        p.feed(b"data: {\"type\":\"message_delta\",\"usage\":{\"output_tokens\":842}}\n\n");
        p.feed(b"data: [DONE]\n\n");

        let result = p.finish();
        assert!(
            result.truncated,
            "a body cut at the cap must say so, not parse silently"
        );
        assert_eq!(
            result.usage,
            Usage::default(),
            "the usage block landed entirely after the cap, so nothing was parsed"
        );
    }

    /// Hostile input: a chunk that fills the buffer to exactly `CAP`, not one
    /// byte more. Nothing was ever dropped, so this must not be truncated -
    /// the off-by-one this guards is `>=` vs `>` in `feed`'s cap check.
    #[test]
    fn a_chunk_that_exactly_fills_the_cap_is_not_truncated() {
        let mut p = UsageParser::new();
        let exact = vec![b'x'; UsageParser::CAP];
        p.feed(&exact);
        assert!(
            !p.finish().truncated,
            "every byte offered was buffered; nothing was cut"
        );
    }

    /// Hostile input: once the cap is exactly full (no drop), a zero-byte
    /// chunk arriving after it must not flip `truncated` on its own - it
    /// drops nothing, by definition. Guards against a naive `buf.len() >=
    /// CAP` check treating "at capacity" as "something was cut" regardless
    /// of what (if anything) the next chunk contains.
    #[test]
    fn a_zero_byte_chunk_after_the_cap_is_not_truncated_by_itself() {
        let mut p = UsageParser::new();
        let exact = vec![b'x'; UsageParser::CAP];
        p.feed(&exact);
        p.feed(b"");
        assert!(
            !p.finish().truncated,
            "an empty chunk drops nothing, even once the buffer is full"
        );
    }

    /// Hostile input: a single chunk larger than the whole cap in one call
    /// (no prior `feed`), rather than the cap being approached gradually.
    #[test]
    fn a_single_chunk_larger_than_the_cap_is_truncated() {
        let mut p = UsageParser::new();
        let oversized = vec![b'x'; UsageParser::CAP + 500];
        p.feed(&oversized);
        assert!(
            p.finish().truncated,
            "the first and only chunk already overshot the cap"
        );
    }

    // -- a null usage chunk is not a zero (docs/26-the-openai-door.md) -----

    /// With `stream_options.include_usage` set, the provider's own reference
    /// says "All other chunks will also include a `usage` field, but with a
    /// null value." This pins that a stream shaped exactly that way, `usage:
    /// null` on every chunk but the last, still settles on the last chunk's
    /// real numbers.
    ///
    /// This does NOT pin `merge_usage`'s `.filter(u.is_object())`: `Value::get`
    /// already returns `None` for a JSON `null`, so the filter's removal does
    /// not change this test's result (checked 2026-09-07, see the comment on
    /// the filter itself). What this test actually exercises is that feeding
    /// a null-usage chunk before the real one doesn't otherwise disturb
    /// `UsageParser`'s state, e.g. by tripping some other code path into
    /// treating the run as already settled at zero.
    #[test]
    fn a_stream_with_null_usage_on_every_chunk_but_the_last_still_settles_on_the_last_chunk() {
        let mut p = UsageParser::default();
        p.feed(b"data: {\"choices\":[{\"delta\":{\"content\":\"hi\"}}],\"usage\":null}\n\n");
        p.feed(
            b"data: {\"choices\":[],\"usage\":{\"prompt_tokens\":10,\"completion_tokens\":5}}\n\n",
        );
        let u = p.finish();
        assert_eq!(u.usage.input_tokens, 10);
        assert_eq!(u.usage.output_tokens, 5);
    }

    /// The final usage chunk's `choices` is always an empty array (the
    /// provider's own reference); that must read as "zero tool calls
    /// observed", never as "nothing observed at all" (`None`).
    #[test]
    fn the_final_usage_chunks_empty_choices_array_counts_no_tool_calls() {
        let mut p = UsageParser::default();
        p.feed(
            b"data: {\"choices\":[],\"usage\":{\"prompt_tokens\":1,\"completion_tokens\":1}}\n\n",
        );
        let u = p.finish();
        assert_eq!(u.usage.tool_calls, Some(0));
    }

    #[tokio::test]
    async fn stub_sse_stream_yields_frames_and_usage() {
        let stub = StubProvider {
            input_tokens: 100,
            output_tokens: 50,
            sse: true,
            body_override: None,
        };
        let resp = stub.send(HeaderMap::new(), Bytes::new()).await.unwrap();
        let collected: Vec<u8> = {
            let mut acc = Vec::new();
            let mut body = resp.body;
            while let Some(chunk) = body.next().await {
                acc.extend_from_slice(&chunk.unwrap());
            }
            acc
        };
        let text = String::from_utf8(collected).unwrap();
        assert!(text.contains("message_start"));
        assert!(text.contains("[DONE]"));
        // Usage slot is populated after the stream is drained.
        let parsed = resp.usage.lock().unwrap().unwrap();
        assert_eq!(parsed.usage.input_tokens, 100);
        assert_eq!(parsed.usage.output_tokens, 50);
        assert!(
            !parsed.truncated,
            "a few bytes of SSE never comes near the cap"
        );
    }

    #[test]
    fn forward_headers_allowlist_includes_x_api_key() {
        // Anthropic's native auth header. Without this, the OpenAI-style
        // `authorization` header is stripped through fine but Anthropic never
        // sees a key and answers 401 "x-api-key header is required" — this
        // pins the regression at the allowlist-definition level.
        assert!(FORWARD_HEADERS.contains(&"x-api-key"));
    }

    /// End-to-end proof: spin up a real HTTP upstream, send `HttpProvider` a
    /// request carrying `x-api-key`, and assert the upstream actually
    /// received it. This exercises the real header-copy loop in `send`
    /// (not just the allowlist constant), so it can't pass while the loop
    /// itself is broken.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn http_provider_forwards_x_api_key_to_upstream() {
        use axum::{routing::post, Json, Router};
        use serde_json::{json, Value};

        // Upstream stub: echoes back whichever auth-shaped headers it saw, so
        // the test can assert on what actually crossed the wire.
        async fn echo_auth_headers(headers: HeaderMap) -> Json<Value> {
            let get = |name: &str| {
                headers
                    .get(name)
                    .and_then(|v| v.to_str().ok())
                    .unwrap_or_default()
                    .to_string()
            };
            Json(json!({
                "x_api_key": get("x-api-key"),
                "authorization": get("authorization"),
            }))
        }

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let router = Router::new().route("/", post(echo_auth_headers));
        tokio::spawn(async move {
            let _ = axum::serve(listener, router).await;
        });
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;

        let provider = HttpProvider::new(format!("http://{addr}"));

        let mut headers = HeaderMap::new();
        headers.insert("x-api-key", "sk-ant-test-key".parse().unwrap());
        headers.insert("anthropic-version", "2023-06-01".parse().unwrap());

        let resp = provider
            .send(headers, Bytes::from_static(b"{}"))
            .await
            .unwrap();
        assert_eq!(resp.status, 200);

        let mut body = resp.body;
        let mut collected = Vec::new();
        while let Some(chunk) = body.next().await {
            collected.extend_from_slice(&chunk.unwrap());
        }
        let received: Value = serde_json::from_slice(&collected).unwrap();

        // The whole point of this fix: the upstream must see the key.
        assert_eq!(received["x_api_key"], "sk-ant-test-key");
        // No Authorization header was sent in this request, and none should
        // be fabricated.
        assert_eq!(received["authorization"], "");
    }

    // -- invariant 55: usage is read from SSE events, not from lines (F06) -

    #[test]
    fn a_multi_line_data_event_is_one_document() {
        let mut p = UsageParser::new();
        p.feed(b"data: {\"type\":\"message_start\",\"message\":{\"usage\":{\"input_tokens\":10}}}\n\ndata: {\"type\":\"message_delta\",\ndata: \"usage\":{\"output_tokens\":1000}}\n\nevent: message_stop\ndata: {\"type\":\"message_stop\"}\n\n");
        let u = p.finish().usage;
        assert_eq!(u.input_tokens, 10);
        assert_eq!(u.output_tokens, 1000);
        assert_eq!(
            default_price_book().cost("claude-sonnet", &u),
            Some(Microusd(15030))
        );
    }

    #[test]
    fn a_multi_line_openai_usage_event_is_one_document() {
        let mut p = UsageParser::new();
        p.feed(b"data: {\"choices\":[],\ndata: \"usage\":{\"prompt_tokens\":950,\"completion_tokens\":120,\ndata: \"prompt_tokens_details\":{\"cached_tokens\":128}}}\n\ndata: [DONE]\n\n");
        let u = p.finish().usage;
        assert_eq!(u.input_tokens, 822);
        assert_eq!(u.cache_read_tokens, 128);
        assert_eq!(u.output_tokens, 120);
        assert_eq!(u.tool_calls, Some(0));
        let gpt_4o = ModelPrice::per_mtok_usd(2.50, 10.00, 1.25, 2.50);
        assert_eq!(gpt_4o.cost(&u), Microusd(3415));
    }

    #[test]
    fn crlf_endings_frame_events_like_lf() {
        let lf = "data: {\"type\":\"message_start\",\"message\":{\"usage\":{\"input_tokens\":10}}}\n\ndata: {\"type\":\"message_delta\",\ndata: \"usage\":{\"output_tokens\":1000}}\n\nevent: message_stop\ndata: {\"type\":\"message_stop\"}\n\n";
        let crlf = lf.replace('\n', "\r\n");
        let mut p = UsageParser::new();
        p.feed(crlf.as_bytes());
        let u = p.finish().usage;
        assert_eq!(u.input_tokens, 10);
        assert_eq!(u.output_tokens, 1000);
    }

    #[test]
    fn a_cr_only_body_frames_events() {
        let mut p = UsageParser::new();
        p.feed(b"data: {\"usage\":{\"prompt_tokens\":10}}\r\rdata: {\"usage\":{\"completion_tokens\":5}}\r\rdata: [DONE]\r\r");
        let u = p.finish().usage;
        assert_eq!(u.input_tokens, 10);
        assert_eq!(u.output_tokens, 5);
    }

    #[test]
    fn a_comment_line_inside_an_event_does_not_split_it_and_one_between_events_is_not_data() {
        // (i) a comment line inside a two-line event does not split it.
        let mut p = UsageParser::new();
        p.feed(b"data: {\"type\":\"message_delta\",\n: keep-alive\ndata: \"usage\":{\"output_tokens\":1000}}\n\n");
        assert_eq!(p.finish().usage.output_tokens, 1000);

        // (ii) a comment line between events that happens to look like a usage object prices
        // nothing: a guard, green on both sides of this change.
        let mut p = UsageParser::new();
        p.feed(b"data: {\"usage\":{\"prompt_tokens\":10}}\n\n:data: {\"usage\":{\"prompt_tokens\":999}}\n\n: {\"usage\":{\"prompt_tokens\":998}}\n\n");
        assert_eq!(p.finish().usage.input_tokens, 10);
    }

    #[test]
    fn data_with_no_space_after_the_colon_is_data() {
        let mut p = UsageParser::new();
        p.feed(b"data:{\"usage\":{\"prompt_tokens\":10,\ndata:\"completion_tokens\":5}}\n\n");
        let u = p.finish().usage;
        assert_eq!(u.input_tokens, 10);
        assert_eq!(u.output_tokens, 5);
    }

    #[test]
    fn data_with_two_spaces_keeps_the_second_space() {
        let text = "data:  {\"usage\":{\"prompt_tokens\":10}}\n\n";
        assert_eq!(
            split_sse_events(text).events,
            vec![" {\"usage\":{\"prompt_tokens\":10}}".to_string()]
        );
        // Held control: the old `.trim()` swallowed any number of leading spaces too, so this
        // half is already green at da0fa34.
        let mut p = UsageParser::new();
        p.feed(text.as_bytes());
        assert_eq!(p.finish().usage.input_tokens, 10);
    }

    #[test]
    fn event_id_and_retry_lines_do_not_touch_the_data() {
        let text = "event: message_delta\nid: 7\nretry: 3000\ndata: {\"type\":\"message_delta\",\ndata: \"usage\":{\"output_tokens\":1000}}\n\n";
        let mut p = UsageParser::new();
        p.feed(text.as_bytes());
        assert_eq!(p.finish().usage.output_tokens, 1000);
        assert_eq!(
            split_sse_events(text).events,
            vec!["{\"type\":\"message_delta\",\n\"usage\":{\"output_tokens\":1000}}".to_string()]
        );
    }

    #[test]
    fn an_empty_data_event_is_not_dispatched_but_marks_the_body_sse() {
        let got = split_sse_events("data:\n\ndata: \n\n");
        assert_eq!(
            got,
            SseEvents {
                events: vec![],
                saw_data_field: true,
            }
        );
        let mut p = UsageParser::new();
        p.feed(b"data:\n\n");
        let parsed = p.finish();
        assert_eq!(parsed.usage, Usage::default());
        assert_eq!(parsed.usage.tool_calls, None);
    }

    #[test]
    fn a_body_ending_without_the_final_blank_line_still_dispatches_its_last_event() {
        // (i)
        let mut p = UsageParser::new();
        p.feed(b"data: {\"type\":\"message_start\",\"message\":{\"usage\":{\"input_tokens\":10}}}\n\ndata: {\"type\":\"message_delta\",\ndata: \"usage\":{\"output_tokens\":1000}}");
        let u = p.finish().usage;
        assert_eq!(u.input_tokens, 10);
        assert_eq!(u.output_tokens, 1000);

        // (ii) guard, green both sides.
        let mut p = UsageParser::new();
        p.feed(b"data: {\"usage\":{\"prompt_tokens\":10}}");
        assert_eq!(p.finish().usage.input_tokens, 10);
    }

    #[test]
    fn an_event_whose_joined_json_fails_is_skipped_and_its_siblings_are_not() {
        let mut p = UsageParser::new();
        p.feed(b"data: {\"usage\":{\"prompt_tokens\":10}}\n\ndata: {\"usage\":{\"completion_tokens\":\ndata: not json}\n\ndata: {\"usage\":\ndata: {\"completion_tokens\":5}}\n\n");
        let u = p.finish().usage;
        assert_eq!(u.input_tokens, 10);
        assert_eq!(u.output_tokens, 5);
        assert_eq!(u.tool_calls, Some(0));
    }

    #[test]
    fn done_as_the_whole_data_of_an_event_is_the_sentinel_and_drops_nothing_else() {
        for done in ["data: [DONE]\n\n", "data: [DONE] \n\n"] {
            let text = format!("data: {{\"type\":\"message_start\",\"message\":{{\"usage\":{{\"input_tokens\":10}}}}}}\n\ndata: {{\"type\":\"message_delta\",\ndata: \"usage\":{{\"output_tokens\":1000}}}}\n\n{done}");
            let mut p = UsageParser::new();
            p.feed(text.as_bytes());
            let u = p.finish().usage;
            assert_eq!(u.input_tokens, 10, "{done:?}");
            assert_eq!(u.output_tokens, 1000, "{done:?}");
            let events = split_sse_events(&text).events;
            assert_eq!(events.len(), 3, "{done:?}");
            assert_eq!(events[2].trim(), "[DONE]", "{done:?}");
        }
    }

    #[test]
    fn an_event_cut_by_the_cap_is_truncated_and_nothing_parsed_from_it_is_priced() {
        let head = b"data: {\"type\":\"message_start\",\ndata: \"message\":{\"usage\":{\"input_tokens\":10}}}\n\n".to_vec();
        let tail =
            b"data: {\"type\":\"message_delta\",\"usage\":{\"output_tokens\":1000}}\n\n".to_vec();
        let comment_len = UsageParser::CAP - head.len() - 2 - 20;
        let mut comment = Vec::with_capacity(comment_len + 2);
        comment.push(b':');
        comment.extend(std::iter::repeat_n(b'x', comment_len));
        comment.push(b'\n');

        let mut p = UsageParser::new();
        p.feed(&head);
        p.feed(&comment);
        p.feed(&tail);
        let parsed = p.finish();
        assert!(parsed.truncated);
        assert_eq!(parsed.usage.input_tokens, 10);
        assert_eq!(parsed.usage.output_tokens, 0);
        assert_eq!(
            crate::settle::settle_amount(
                &default_price_book(),
                "claude-sonnet",
                Some(parsed),
                Microusd(777)
            ),
            (
                Microusd(777),
                Usage::default(),
                crate::settle::CostBasis::EstimateTruncated
            )
        );
    }

    #[test]
    fn a_body_split_at_random_offsets_with_any_line_ending_parses_identically() {
        let lf = "data: {\"type\":\"message_start\",\"message\":{\"usage\":{\"input_tokens\":10,\"cache_read_input_tokens\":300}}}\n\n: ping\nevent: content_block_start\ndata: {\"type\":\"content_block_start\",\"index\":0,\"content_block\":{\"type\":\"tool_use\",\"id\":\"toolu_1\",\"name\":\"get_weather\"}}\n\ndata: {\"type\":\"message_delta\",\ndata: \"usage\":{\"output_tokens\":1000}}\n\ndata: [DONE]\n\n";
        let expected = ParsedUsage {
            usage: Usage {
                input_tokens: 10,
                output_tokens: 1000,
                cache_read_tokens: 300,
                cache_write_tokens: 0,
                cache_write_1h_tokens: 0,
                tool_calls: Some(1),
            },
            truncated: false,
        };
        let mut seed: u64 = 0x2026_0918;
        for _ in 0..200 {
            seed = seed.wrapping_mul(6364136223846793005).wrapping_add(1);
            let ending = ["\n", "\r\n", "\r"][(seed % 3) as usize];
            let body = lf.replace('\n', ending);

            let mut one_shot = UsageParser::new();
            one_shot.feed(body.as_bytes());
            let one_shot = one_shot.finish();

            let mut chunked = UsageParser::new();
            let bytes = body.as_bytes();
            let mut offset = 0;
            while offset < bytes.len() {
                seed = seed.wrapping_mul(6364136223846793005).wrapping_add(1);
                let size = 1 + ((seed >> 8) % 37) as usize;
                let end = (offset + size).min(bytes.len());
                chunked.feed(&bytes[offset..end]);
                offset = end;
            }
            let chunked = chunked.finish();
            assert_eq!(chunked, expected, "seed={seed} ending={ending:?}");
            assert_eq!(chunked, one_shot, "seed={seed} ending={ending:?}");
        }
    }

    #[test]
    fn hostile_sse_bodies_never_panic() {
        let literals: [&[u8]; 15] = [
            b"data:",
            b"data: ",
            b"data:  ",
            b"data",
            b":",
            b"event:",
            b"id:",
            b"retry:",
            b"{\"usage\":{\"prompt_tokens\":",
            b"{\"message\":{\"usage\":{\"input_tokens\":",
            b"[DONE]",
            b"\n",
            b"\r",
            b"\r\n",
            b"\n\n",
        ];
        let mut seed: u64 = 0x0918_2026;
        for case in 0..200u32 {
            seed = seed.wrapping_mul(6364136223846793005).wrapping_add(1);
            let mut body: Vec<u8> = Vec::new();
            let pieces = 1 + (seed % 40);
            for _ in 0..pieces {
                seed = seed.wrapping_mul(6364136223846793005).wrapping_add(1);
                let kind = seed % (literals.len() as u64 + 2);
                if kind == literals.len() as u64 {
                    // 0 to 300 random bytes.
                    seed = seed.wrapping_mul(6364136223846793005).wrapping_add(1);
                    let n = (seed % 301) as usize;
                    for _ in 0..n {
                        seed = seed.wrapping_mul(6364136223846793005).wrapping_add(1);
                        body.push((seed >> 16) as u8);
                    }
                } else if kind == literals.len() as u64 + 1 {
                    // A random decimal.
                    seed = seed.wrapping_mul(6364136223846793005).wrapping_add(1);
                    body.extend_from_slice((seed % 1_000_000).to_string().as_bytes());
                } else {
                    body.extend_from_slice(literals[kind as usize]);
                }
            }
            if case == 0 {
                body.push(b':');
                body.extend(std::iter::repeat_n(b'x', 1 << 20));
            }
            if case == 1 {
                body.extend_from_slice(b"data: ");
                body.extend(std::iter::repeat_n(b'{', 1 << 20));
            }

            let text = String::from_utf8_lossy(&body).into_owned();
            let events = split_sse_events(&text);
            for event in &events.events {
                assert!(!event.is_empty(), "case={case}");
                assert!(!event.contains('\r'), "case={case}");
            }

            let mut whole = UsageParser::new();
            whole.feed(&body);
            let whole = whole.finish();

            let mut piecewise = UsageParser::new();
            for byte in &body {
                piecewise.feed(std::slice::from_ref(byte));
            }
            let piecewise = piecewise.finish();

            assert_eq!(whole, piecewise, "case={case}");
        }
    }

    /// A1 (2026-09-18): leading whitespace before the field name stays tolerated, exactly as
    /// the old line parser's `trim_start` always did.
    #[test]
    fn an_indented_data_line_is_still_a_data_field() {
        let text = "  data: {\"usage\":{\"prompt_tokens\":10}}\n\n";
        let mut p = UsageParser::new();
        p.feed(text.as_bytes());
        assert_eq!(p.finish().usage.input_tokens, 10);
        assert!(split_sse_events(text).saw_data_field);
    }

    /// A1: a whitespace-only line is a field line with an empty name after the trim, not a
    /// blank line, so it dispatches nothing and never splits an event.
    #[test]
    fn a_whitespace_only_line_is_a_field_line_not_a_blank_line() {
        let text = "data: {\"usage\":{\"prompt_tokens\":\n   \ndata: 10}}\n\n";
        let mut p = UsageParser::new();
        p.feed(text.as_bytes());
        assert_eq!(p.finish().usage.input_tokens, 10);
        assert_eq!(
            split_sse_events(text).events,
            vec!["{\"usage\":{\"prompt_tokens\":\n10}}".to_string()]
        );
    }

    // -- invariant 45, amended: the OpenAI netting state holds in both orders (F05) ----

    #[test]
    fn a_cached_subset_arriving_after_the_prompt_count_is_netted() {
        let mut p = UsageParser::new();
        p.feed(b"data: {\"usage\":{\"prompt_tokens\":950}}\n\n");
        p.feed(b"data: {\"usage\":{\"completion_tokens\":0,\"prompt_tokens_details\":{\"cached_tokens\":128}}}\n\n");
        p.feed(b"data: [DONE]\n\n");
        let u = p.finish().usage;
        assert_eq!(u.input_tokens, 822);
        assert_eq!(u.cache_read_tokens, 128);
        assert_eq!(u.output_tokens, 0);
        let gpt_4o = ModelPrice::per_mtok_usd(2.50, 10.00, 1.25, 2.50);
        assert_eq!(gpt_4o.cost(&u), Microusd(2215));
    }

    #[test]
    fn a_details_only_object_is_openai_shaped_not_anthropic() {
        let mut p = UsageParser::new();
        p.feed(b"data: {\"usage\":{\"prompt_tokens\":950}}\n\n");
        p.feed(b"data: {\"usage\":{\"prompt_tokens_details\":{\"cached_tokens\":128}}}\n\n");
        p.feed(b"data: [DONE]\n\n");
        let u = p.finish().usage;
        assert_eq!(u.input_tokens, 822);
        assert_eq!(u.cache_read_tokens, 128);
        assert_eq!(u.output_tokens, 0);
    }

    #[test]
    fn the_netting_holds_across_three_events_whatever_the_final_event_carries() {
        let cases: [[&str; 3]; 2] = [
            [
                "{\"usage\":{\"prompt_tokens\":950}}",
                "{\"usage\":{\"prompt_tokens_details\":{\"cached_tokens\":128}}}",
                "{\"usage\":{\"prompt_tokens\":950,\"completion_tokens\":120,\"prompt_tokens_details\":{\"cached_tokens\":128}}}",
            ],
            [
                "{\"usage\":{\"prompt_tokens\":950}}",
                "{\"usage\":{\"prompt_tokens_details\":{\"cached_tokens\":128}}}",
                "{\"usage\":{\"completion_tokens\":120}}",
            ],
        ];
        for (i, events) in cases.iter().enumerate() {
            let mut p = UsageParser::new();
            for event in events {
                p.feed(format!("data: {event}\n\n").as_bytes());
            }
            p.feed(b"data: [DONE]\n\n");
            let u = p.finish().usage;
            assert_eq!(u.input_tokens, 822, "order {i}");
            assert_eq!(u.cache_read_tokens, 128, "order {i}");
            assert_eq!(u.output_tokens, 120, "order {i}");
        }
    }

    #[test]
    fn a_details_only_event_before_any_prompt_count_waits_for_the_prompt() {
        // (i)
        let mut p = UsageParser::new();
        p.feed(b"data: {\"usage\":{\"prompt_tokens_details\":{\"cached_tokens\":128}}}\n\n");
        p.feed(b"data: {\"usage\":{\"prompt_tokens\":950,\"completion_tokens\":120}}\n\n");
        p.feed(b"data: [DONE]\n\n");
        let u = p.finish().usage;
        assert_eq!(u.input_tokens, 822);
        assert_eq!(u.cache_read_tokens, 128);
        assert_eq!(u.output_tokens, 120);

        // (ii) no prompt count ever.
        let mut p = UsageParser::new();
        p.feed(b"data: {\"usage\":{\"prompt_tokens_details\":{\"cached_tokens\":128}}}\n\n");
        p.feed(b"data: [DONE]\n\n");
        let u = p.finish().usage;
        assert_eq!(u.input_tokens, 0);
        assert_eq!(u.cache_read_tokens, 128);
        assert_eq!(u.output_tokens, 0);
        assert!(u.carries_priced_tokens());
    }

    #[test]
    fn a_later_zero_completion_count_keeps_the_earlier_positive_one() {
        let mut p = UsageParser::new();
        p.feed(b"data: {\"usage\":{\"prompt_tokens\":950,\"completion_tokens\":120}}\n\n");
        p.feed(b"data: {\"usage\":{\"completion_tokens\":0,\"prompt_tokens_details\":{\"cached_tokens\":128}}}\n\n");
        p.feed(b"data: [DONE]\n\n");
        let u = p.finish().usage;
        assert_eq!(u.input_tokens, 822);
        assert_eq!(u.cache_read_tokens, 128);
        assert_eq!(u.output_tokens, 120);
    }

    #[test]
    fn a_body_mixing_both_vendors_shapes_is_read_per_object() {
        let mut p = UsageParser::new();
        p.feed(
            b"data: {\"type\":\"message_start\",\"message\":{\"usage\":{\"input_tokens\":10}}}\n\n",
        );
        p.feed(b"data: {\"usage\":{\"prompt_tokens\":950}}\n\n");
        p.feed(b"data: {\"usage\":{\"prompt_tokens_details\":{\"cached_tokens\":128}}}\n\n");
        p.feed(b"data: {\"type\":\"message_delta\",\"usage\":{\"output_tokens\":1000}}\n\n");
        p.feed(b"data: {\"usage\":{\"total_tokens\":73}}\n\n");
        p.feed(b"data: [DONE]\n\n");
        let u = p.finish().usage;
        assert_eq!(u.input_tokens, 822);
        assert_eq!(u.cache_read_tokens, 128);
        assert_eq!(u.output_tokens, 1000);
    }
}
