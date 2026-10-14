//! Invariant 104: a streamed answer's tool calls are judged as a buffered
//! answer's are.
//!
//! Measured 2026-10-14 on a router agent through the OpenAI door: the agent
//! streams, the run already carried `suspected_injection` and `unclassified`,
//! the starter rule denies `write` after either, and a `write_file` call the
//! model asked for reached the agent and ran (trace `allow`, nothing blocked).
//! The buffered path judges the model's tool calls (`proxy::buffered_managed`);
//! the streamed path passed every byte through, so the judgement never applied
//! to an agent that streams, which is most of them.
//!
//! [`ToolCallHold`] sits between the provider's stream and the caller. It
//! splits the bytes into server-sent events by the event-stream grammar and
//! forwards each event as soon as it is complete, until an event opens a tool
//! call: an Anthropic `content_block_start` whose block is a `tool_use`, or an
//! OpenAI chunk carrying `choices[].delta.tool_calls`. From that event on it
//! holds everything until the provider's stream ends, collecting the tool
//! names the held events carry. The caller of [`ToolCallHold::finish`] judges
//! those names exactly as the buffered path judges a complete answer
//! (`taint::tool_names_in` over the same shapes, then `taint::evaluate`) and
//! either releases the held bytes unchanged or replaces them with one error
//! event. Text that came before the first tool call has already streamed.
//!
//! Holding to the end of the provider's stream, not to the end of each tool
//! call, is deliberate: a client cannot run a tool call before its arguments
//! are complete, the usage the settlement reads arrives last on both wires,
//! and judging every name of the answer together is what the buffered path
//! does. `@claude` 2026-10-14.
//!
//! Every event is forwarded byte for byte as the provider sent it; the only
//! change to a stream is the delay on the held part and, on a refusal, the
//! replacement. A body that is not an event stream (no blank line ever) is
//! held whole and forwarded at its end.

use std::collections::BTreeMap;

/// What [`ToolCallHold::finish`] hands back.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct Held {
    /// The bytes after the last complete event, when no tool call was ever
    /// opened: safe to forward as they are.
    pub tail: Vec<u8>,
    /// Every event from the first one that opened a tool call to the end of
    /// the stream, in order, byte for byte.
    pub held: Vec<u8>,
    /// The tool names the held events carry, as `taint::tool_names_in` reads
    /// them from a buffered answer of the same shape.
    pub tools: Vec<String>,
}

/// The stream-side half of invariant 104. See the module documentation.
#[derive(Debug, Default)]
pub struct ToolCallHold {
    /// Bytes not yet part of a complete event.
    buf: Vec<u8>,
    /// Where the scan of `buf` for an event boundary resumes, and where the
    /// line being scanned began, so a long event split over many chunks is
    /// scanned once rather than from the start on every chunk.
    scan_pos: usize,
    line_start: usize,
    holding: bool,
    held: Vec<u8>,
    /// Anthropic `tool_use` blocks, as each `content_block_start` opened them.
    anthropic_blocks: Vec<serde_json::Value>,
    /// OpenAI tool calls by (choice index, tool call index): the id, and the
    /// name as its fragments arrived (a provider may split a name; OpenAI
    /// sends it whole in the first delta).
    openai_calls: BTreeMap<(u64, u64), (Option<String>, String)>,
}

impl ToolCallHold {
    pub fn new() -> Self {
        Self::default()
    }

    /// Whether a tool call has been opened and the rest is being held.
    pub fn is_holding(&self) -> bool {
        self.holding
    }

    /// Take one chunk of the provider's stream; return the bytes to forward now.
    pub fn push(&mut self, chunk: &[u8]) -> Vec<u8> {
        self.buf.extend_from_slice(chunk);
        let mut out = Vec::new();
        while let Some(end) = self.next_event_end() {
            let raw: Vec<u8> = self.buf.drain(..end).collect();
            self.scan_pos = 0;
            self.line_start = 0;
            self.route(raw, &mut out);
        }
        out
    }

    /// The provider's stream ended. An unterminated final event is read like
    /// any other (a client may still dispatch it), so a tool call in it is held
    /// and named too.
    pub fn finish(mut self) -> Held {
        let mut tail = Vec::new();
        if !self.buf.is_empty() {
            let rest = std::mem::take(&mut self.buf);
            self.route(rest, &mut tail);
        }
        let tools = self.tool_names();
        Held {
            tail,
            held: self.held,
            tools,
        }
    }

    /// One complete event: read it, then forward it or hold it.
    fn route(&mut self, raw: Vec<u8>, out: &mut Vec<u8>) {
        let text = String::from_utf8_lossy(&raw);
        let mut opens_tool = false;
        for data in crate::provider::split_sse_events(&text).events {
            if let Ok(v) = serde_json::from_str::<serde_json::Value>(&data) {
                opens_tool |= self.observe(&v);
            }
        }
        if self.holding || opens_tool {
            self.holding = true;
            self.held.extend_from_slice(&raw);
        } else {
            out.extend_from_slice(&raw);
        }
    }

    /// Record the tool calls one event's data carries, on either wire, and say
    /// whether it carried any.
    fn observe(&mut self, v: &serde_json::Value) -> bool {
        let mut carried = false;
        // Anthropic: the block opens with its name; the arguments follow as
        // `input_json_delta`s on the same index, which carry no name.
        if v.get("type").and_then(|t| t.as_str()) == Some("content_block_start") {
            if let Some(block) = v.get("content_block") {
                if block.get("type").and_then(|t| t.as_str()) == Some("tool_use") {
                    self.anthropic_blocks.push(block.clone());
                    carried = true;
                }
            }
        }
        // OpenAI: `choices[].delta.tool_calls[]`, each delta naming its call by
        // `index`; the id and the name arrive first, the arguments after.
        if let Some(choices) = v.get("choices").and_then(|c| c.as_array()) {
            for (pos, choice) in choices.iter().enumerate() {
                let ci = choice
                    .get("index")
                    .and_then(|i| i.as_u64())
                    .unwrap_or(pos as u64);
                let Some(calls) = choice
                    .get("delta")
                    .and_then(|d| d.get("tool_calls"))
                    .and_then(|t| t.as_array())
                else {
                    continue;
                };
                for (k, tc) in calls.iter().enumerate() {
                    carried = true;
                    let ti = tc.get("index").and_then(|i| i.as_u64()).unwrap_or(k as u64);
                    let entry = self.openai_calls.entry((ci, ti)).or_default();
                    if let Some(id) = tc.get("id").and_then(|i| i.as_str()) {
                        if !id.is_empty() {
                            entry.0 = Some(id.to_string());
                        }
                    }
                    if let Some(part) = tc
                        .get("function")
                        .and_then(|f| f.get("name"))
                        .and_then(|n| n.as_str())
                    {
                        entry.1.push_str(part);
                    }
                }
            }
        }
        carried
    }

    /// The names, read by the one function the buffered path reads a complete
    /// answer with, from the same two shapes rebuilt.
    fn tool_names(&self) -> Vec<String> {
        let calls: Vec<serde_json::Value> = self
            .openai_calls
            .values()
            .filter(|(_, name)| !name.is_empty())
            .map(|(id, name)| {
                serde_json::json!({"id": id, "type": "function", "function": {"name": name}})
            })
            .collect();
        let rebuilt = serde_json::json!({
            "content": self.anthropic_blocks,
            "choices": [{"message": {"tool_calls": calls}}],
        });
        tokenfuse_core::taint::tool_names_in(&rebuilt)
    }

    /// The end of the first complete event in `buf` (just past the blank line
    /// that ends it), by the event-stream grammar's line terminators: CRLF, LF
    /// or CR. A CR at the very end may be the first half of a CRLF, so the
    /// scan waits for the next byte rather than guess.
    fn next_event_end(&mut self) -> Option<usize> {
        let buf = &self.buf;
        let mut i = self.scan_pos;
        while i < buf.len() {
            let b = buf[i];
            if b != b'\n' && b != b'\r' {
                i += 1;
                continue;
            }
            let term = if b == b'\r' {
                match buf.get(i + 1) {
                    Some(b'\n') => 2,
                    Some(_) => 1,
                    None => {
                        self.scan_pos = i;
                        return None;
                    }
                }
            } else {
                1
            };
            let empty = i == self.line_start;
            i += term;
            if empty {
                return Some(i);
            }
            self.line_start = i;
        }
        self.scan_pos = i;
        None
    }
}

/// The refusal a streamed answer carries in place of a tool call the firewall
/// denied: one error event in the shape each wire's own client libraries raise
/// on mid-stream, with the fields the buffered path's `403 taint_blocked` body
/// carries. Anthropic: `event: error` with `{"type":"error","error":{...}}`.
/// OpenAI: a `data:` chunk holding `{"error":{...}}` with `message`, `code`
/// and `param` added, as the OpenAI door adds them to every refusal. The
/// stream ends after it: no `[DONE]`, no `message_stop`.
pub fn refusal_event(openai: bool, run_id: &str, reason: &str) -> Vec<u8> {
    let mut error = serde_json::json!({
        "type": "taint_blocked",
        "run_id": run_id,
        "reason": reason,
        "message": reason,
        "retryable": false,
    });
    if openai {
        if let Some(e) = error.as_object_mut() {
            e.insert("code".into(), serde_json::json!("taint_blocked"));
            e.insert("param".into(), serde_json::Value::Null);
        }
        format!("data: {}\n\n", serde_json::json!({ "error": error })).into_bytes()
    } else {
        format!(
            "event: error\ndata: {}\n\n",
            serde_json::json!({"type": "error", "error": error})
        )
        .into_bytes()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const ANTHROPIC_TOOL_STREAM: &str = "event: message_start\ndata: {\"type\":\"message_start\",\"message\":{\"id\":\"msg_1\",\"type\":\"message\",\"role\":\"assistant\",\"model\":\"claude-haiku-5-5\",\"content\":[],\"stop_reason\":null,\"usage\":{\"input_tokens\":120,\"output_tokens\":1}}}\n\n\
event: content_block_start\ndata: {\"type\":\"content_block_start\",\"index\":0,\"content_block\":{\"type\":\"text\",\"text\":\"\"}}\n\n\
event: content_block_delta\ndata: {\"type\":\"content_block_delta\",\"index\":0,\"delta\":{\"type\":\"text_delta\",\"text\":\"Writing it now.\"}}\n\n\
event: content_block_stop\ndata: {\"type\":\"content_block_stop\",\"index\":0}\n\n\
event: content_block_start\ndata: {\"type\":\"content_block_start\",\"index\":1,\"content_block\":{\"type\":\"tool_use\",\"id\":\"toolu_01\",\"name\":\"write_file\",\"input\":{}}}\n\n\
event: content_block_delta\ndata: {\"type\":\"content_block_delta\",\"index\":1,\"delta\":{\"type\":\"input_json_delta\",\"partial_json\":\"{\\\"path\\\": \\\"/tmp/w8.txt\\\"}\"}}\n\n\
event: content_block_stop\ndata: {\"type\":\"content_block_stop\",\"index\":1}\n\n\
event: message_delta\ndata: {\"type\":\"message_delta\",\"delta\":{\"stop_reason\":\"tool_use\",\"stop_sequence\":null},\"usage\":{\"output_tokens\":42}}\n\n\
event: message_stop\ndata: {\"type\":\"message_stop\"}\n\n";

    const OPENAI_TOOL_STREAM: &str = "data: {\"id\":\"gen-1\",\"object\":\"chat.completion.chunk\",\"choices\":[{\"index\":0,\"delta\":{\"role\":\"assistant\",\"content\":\"Writing it now.\"},\"finish_reason\":null}]}\n\n\
data: {\"id\":\"gen-1\",\"object\":\"chat.completion.chunk\",\"choices\":[{\"index\":0,\"delta\":{\"tool_calls\":[{\"index\":0,\"id\":\"toolu_01\",\"type\":\"function\",\"function\":{\"name\":\"write_file\",\"arguments\":\"\"}}]},\"finish_reason\":null}]}\n\n\
data: {\"id\":\"gen-1\",\"object\":\"chat.completion.chunk\",\"choices\":[{\"index\":0,\"delta\":{\"tool_calls\":[{\"index\":0,\"function\":{\"arguments\":\"{\\\"path\\\": \\\"/tmp/w8.txt\\\"}\"}}]},\"finish_reason\":null}]}\n\n\
data: {\"id\":\"gen-1\",\"object\":\"chat.completion.chunk\",\"choices\":[{\"index\":0,\"delta\":{},\"finish_reason\":\"tool_calls\"}]}\n\n\
data: {\"id\":\"gen-1\",\"object\":\"chat.completion.chunk\",\"choices\":[],\"usage\":{\"prompt_tokens\":120,\"completion_tokens\":42,\"total_tokens\":162}}\n\n\
data: [DONE]\n\n";

    const TEXT_ONLY_STREAM: &str = "data: {\"choices\":[{\"index\":0,\"delta\":{\"content\":\"hi\"},\"finish_reason\":null}]}\n\n\
data: {\"choices\":[{\"index\":0,\"delta\":{},\"finish_reason\":\"stop\"}]}\n\n\
data: [DONE]\n\n";

    fn run(input: &[u8], sizes: &[usize]) -> (Vec<u8>, Held) {
        let mut hold = ToolCallHold::new();
        let mut forwarded = Vec::new();
        let mut at = 0;
        let mut k = 0;
        while at < input.len() {
            let n = sizes[k % sizes.len()].max(1).min(input.len() - at);
            forwarded.extend(hold.push(&input[at..at + n]));
            at += n;
            k += 1;
        }
        let held = hold.finish();
        (forwarded, held)
    }

    #[test]
    fn text_before_an_anthropic_tool_call_streams_and_the_tool_call_is_held() {
        let input = ANTHROPIC_TOOL_STREAM.as_bytes();
        let (forwarded, held) = run(input, &[input.len()]);
        let fwd = String::from_utf8(forwarded.clone()).unwrap();
        assert!(fwd.contains("Writing it now."), "{fwd}");
        assert!(!fwd.contains("write_file"), "{fwd}");
        assert!(String::from_utf8_lossy(&held.held).starts_with("event: content_block_start"));
        assert_eq!(held.tools, vec!["write_file".to_string()]);
        assert!(held.tail.is_empty());
        let mut whole = forwarded;
        whole.extend(&held.held);
        assert_eq!(
            whole, input,
            "released, the stream is byte for byte the provider's"
        );
    }

    #[test]
    fn text_before_an_openai_tool_call_streams_and_the_tool_call_is_held() {
        let input = OPENAI_TOOL_STREAM.as_bytes();
        let (forwarded, held) = run(input, &[input.len()]);
        let fwd = String::from_utf8(forwarded.clone()).unwrap();
        assert!(fwd.contains("Writing it now."), "{fwd}");
        assert!(!fwd.contains("write_file"), "{fwd}");
        assert_eq!(held.tools, vec!["write_file".to_string()]);
        let mut whole = forwarded;
        whole.extend(&held.held);
        assert_eq!(whole, input);
    }

    #[test]
    fn holding_starts_at_the_first_tool_call_and_not_before() {
        let mut hold = ToolCallHold::new();
        assert!(!hold.is_holding());
        let text = "data: {\"choices\":[{\"index\":0,\"delta\":{\"content\":\"a\"}}]}\n\n";
        assert_eq!(hold.push(text.as_bytes()), text.as_bytes());
        assert!(!hold.is_holding(), "text alone is never held");
        let call = "data: {\"choices\":[{\"index\":0,\"delta\":{\"tool_calls\":[{\"index\":0,\"function\":{\"name\":\"bash\"}}]}}]}\n\n";
        assert!(hold.push(call.as_bytes()).is_empty());
        assert!(hold.is_holding());
        assert!(
            hold.push(text.as_bytes()).is_empty(),
            "after a tool call opens, even text waits, so order is kept"
        );
        let held = hold.finish();
        assert_eq!(held.held, [call.as_bytes(), text.as_bytes()].concat());
    }

    #[test]
    fn a_stream_with_no_tool_call_is_forwarded_whole_and_holds_nothing() {
        let input = TEXT_ONLY_STREAM.as_bytes();
        let (forwarded, held) = run(input, &[5]);
        assert_eq!(forwarded, input);
        assert!(held.held.is_empty() && held.tail.is_empty() && held.tools.is_empty());
    }

    #[test]
    fn an_openai_name_split_across_deltas_is_read_whole() {
        let input = "data: {\"choices\":[{\"index\":0,\"delta\":{\"tool_calls\":[{\"index\":0,\"id\":\"c1\",\"function\":{\"name\":\"write\"}}]}}]}\n\n\
data: {\"choices\":[{\"index\":0,\"delta\":{\"tool_calls\":[{\"index\":0,\"function\":{\"name\":\"_file\"}}]}}]}\n\n\
data: {\"choices\":[{\"index\":0,\"delta\":{\"tool_calls\":[{\"index\":1,\"id\":\"c2\",\"function\":{\"name\":\"bash\"}}]}}]}\n\n";
        let (_, held) = run(input.as_bytes(), &[input.len()]);
        assert_eq!(
            held.tools,
            vec!["write_file".to_string(), "bash".to_string()]
        );
    }

    #[test]
    fn a_tool_call_in_an_unterminated_final_event_is_still_held() {
        let input = "data: {\"choices\":[{\"index\":0,\"delta\":{\"content\":\"a\"}}]}\n\n\
data: {\"choices\":[{\"index\":0,\"delta\":{\"tool_calls\":[{\"index\":0,\"function\":{\"name\":\"bash\"}}]}}]}";
        let (forwarded, held) = run(input.as_bytes(), &[3]);
        assert!(!String::from_utf8_lossy(&forwarded).contains("bash"));
        assert!(
            held.tail.is_empty(),
            "the tail opened a tool call, so it is held"
        );
        assert_eq!(held.tools, vec!["bash".to_string()]);
    }

    #[test]
    fn crlf_and_cr_line_endings_split_events_the_same_way() {
        for sep in ["\r\n", "\r"] {
            let input = OPENAI_TOOL_STREAM.replace('\n', sep);
            let (forwarded, held) = run(input.as_bytes(), &[1]);
            assert!(!String::from_utf8_lossy(&forwarded).contains("write_file"));
            assert_eq!(held.tools, vec!["write_file".to_string()], "{sep:?}");
            let mut whole = forwarded;
            whole.extend(&held.held);
            whole.extend(&held.tail);
            assert_eq!(whole, input.as_bytes(), "{sep:?}");
        }
    }

    #[test]
    fn a_server_tool_use_block_is_not_a_tool_call_the_client_runs() {
        let input = "event: content_block_start\ndata: {\"type\":\"content_block_start\",\"index\":0,\"content_block\":{\"type\":\"server_tool_use\",\"id\":\"s1\",\"name\":\"web_search\",\"input\":{}}}\n\n";
        let (forwarded, held) = run(input.as_bytes(), &[input.len()]);
        assert_eq!(
            forwarded,
            input.as_bytes(),
            "the buffered path does not judge it either"
        );
        assert!(held.tools.is_empty());
    }

    /// Any chunking of the provider's bytes, on either wire, gives the same
    /// split: nothing of the tool call is forwarded early, the names are the
    /// same, and released bytes are the provider's exactly. 200 seeds.
    #[test]
    fn chunking_never_changes_what_is_held_across_a_sweep() {
        let mut seed: u64 = 0x5eed_2026_1014;
        for case in 0..200 {
            seed ^= seed << 13;
            seed ^= seed >> 7;
            seed ^= seed << 17;
            let input = if case % 2 == 0 {
                ANTHROPIC_TOOL_STREAM
            } else {
                OPENAI_TOOL_STREAM
            }
            .as_bytes();
            let sizes: Vec<usize> = (0..8)
                .map(|i| ((seed >> (i * 7)) % 23 + 1) as usize)
                .collect();
            let (forwarded, held) = run(input, &sizes);
            assert!(
                !String::from_utf8_lossy(&forwarded).contains("write_file"),
                "case {case} sizes {sizes:?}"
            );
            assert_eq!(held.tools, vec!["write_file".to_string()], "case {case}");
            let mut whole = forwarded;
            whole.extend(&held.held);
            whole.extend(&held.tail);
            assert_eq!(whole, input, "case {case} sizes {sizes:?}");
        }
    }

    /// Bytes nobody would send, cut anywhere: never a panic, and what goes in
    /// comes out, forwarded or held. 200 seeds.
    #[test]
    fn hostile_bytes_never_panic_and_are_never_lost() {
        let mut seed: u64 = 0xdead_beef_cafe;
        for case in 0..200 {
            let mut bytes = Vec::new();
            for _ in 0..(seed % 300) {
                seed ^= seed << 13;
                seed ^= seed >> 7;
                seed ^= seed << 17;
                let pick = (seed % 9) as u8;
                bytes.push(match pick {
                    0 => b'\n',
                    1 => b'\r',
                    2 => b':',
                    3 => b'{',
                    4 => 0xff,
                    _ => b'a' + pick,
                });
            }
            let (forwarded, held) = run(&bytes, &[1 + (case % 11)]);
            let mut whole = forwarded;
            whole.extend(&held.held);
            whole.extend(&held.tail);
            assert_eq!(whole, bytes, "case {case}");
        }
    }

    #[test]
    fn the_refusal_is_an_error_event_each_wires_clients_raise_on() {
        let a = String::from_utf8(refusal_event(
            false,
            "r1",
            "tainted context [web] denies capability [write]",
        ))
        .unwrap();
        assert!(a.starts_with("event: error\ndata: "), "{a}");
        assert!(a.ends_with("\n\n"));
        let data: serde_json::Value =
            serde_json::from_str(a.trim_start_matches("event: error\ndata: ").trim()).unwrap();
        assert_eq!(data["type"], "error");
        assert_eq!(data["error"]["type"], "taint_blocked");
        assert_eq!(data["error"]["run_id"], "r1");
        assert_eq!(data["error"]["retryable"], false);
        let o = String::from_utf8(refusal_event(true, "r1", "x")).unwrap();
        assert!(o.starts_with("data: {"), "{o}");
        let data: serde_json::Value =
            serde_json::from_str(o.trim_start_matches("data: ").trim()).unwrap();
        assert_eq!(data["error"]["code"], "taint_blocked");
        assert_eq!(data["error"]["message"], "x");
        assert!(data["error"]["param"].is_null());
    }
}
