//! Which wire shape a door speaks.
//!
//! The gateway serves two front doors and forwards to one upstream endpoint.
//! Everything whose answer depends on which shape a body is written in lives
//! here, so the enforcement path in `proxy.rs` is parameterised by a value
//! rather than copied per vendor. See `docs/26-the-openai-door.md`.

use serde_json::Value;

/// The request/response shape a door speaks.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Wire {
    Anthropic,
    OpenAi,
}

/// The handful of fields the enforcement path reads out of a request body,
/// whichever shape it arrived in.
#[derive(Debug, Clone)]
pub struct ParsedRequest {
    pub model: String,
    /// The caller's cap on generated tokens, if it gave one.
    pub max_tokens: Option<u64>,
    pub stream: bool,
    /// How many completions are being asked for and therefore billed. Always
    /// 1 on the Anthropic wire, which has no such parameter; `n` on OpenAI,
    /// where the provider's own reference says "you will be charged based on
    /// the number of generated tokens across all of the choices". This is a
    /// caller-controlled multiplier on the money path: a consumer that
    /// multiplies an output-token estimate by it must use saturating
    /// arithmetic, since a plain `*` wraps silently in a release build and a
    /// wrapped reservation under-charges.
    pub completions: u64,
}

impl Wire {
    /// The path this door is served on.
    pub fn route_path(self) -> &'static str {
        match self {
            Wire::Anthropic => "/v1/messages",
            Wire::OpenAi => "/v1/chat/completions",
        }
    }

    /// Which shape this process serves: what the operator declared, else what
    /// the upstream URL's path implies, else Anthropic, which is what every
    /// deployment that predates this code already is.
    pub fn from_declaration(declared: Option<&str>, upstream: Option<&str>) -> Wire {
        match declared.map(str::trim) {
            Some(d) if d.eq_ignore_ascii_case("openai") => return Wire::OpenAi,
            Some(d) if d.eq_ignore_ascii_case("anthropic") => return Wire::Anthropic,
            // An unrecognised value is not a third shape. main.rs warns about
            // it at startup; here it simply does not win.
            _ => {}
        }
        match upstream {
            Some(u) if u.contains("/chat/completions") => Wire::OpenAi,
            _ => Wire::Anthropic,
        }
    }

    /// The system prompt, wherever this wire keeps it. Used for the semantic
    /// cache's partition key, so a wire whose system prompt this cannot see is
    /// a wire where two different callers share a partition.
    pub fn system_text(self, request: &Value) -> String {
        match self {
            Wire::Anthropic => match request.get("system") {
                Some(Value::String(s)) => s.clone(),
                Some(Value::Array(blocks)) => concat_text_blocks(blocks),
                _ => String::new(),
            },
            // OpenAI has no top-level system field: the prompt is one or more
            // messages, `developer` being the o-series spelling of `system`.
            Wire::OpenAi => {
                let Some(messages) = request.get("messages").and_then(|m| m.as_array()) else {
                    return String::new();
                };
                let mut buf = String::new();
                for m in messages {
                    let role = m.get("role").and_then(|r| r.as_str()).unwrap_or("");
                    if role != "system" && role != "developer" {
                        continue;
                    }
                    let text = match m.get("content") {
                        Some(Value::String(s)) => s.clone(),
                        Some(Value::Array(parts)) => concat_text_blocks(parts),
                        _ => String::new(),
                    };
                    if !text.is_empty() {
                        buf.push_str(&text);
                        buf.push(' ');
                    }
                }
                buf.trim().to_string()
            }
        }
    }

    /// Read the fields the enforcement path needs. Never fails: a body this
    /// cannot read yields defaults that are safe to price against, and the
    /// request goes on to be judged by everything downstream.
    pub fn parse_request(self, value: &Value) -> ParsedRequest {
        let model = value
            .get("model")
            .and_then(|m| m.as_str())
            .unwrap_or("unknown")
            .to_string();
        let stream = value
            .get("stream")
            .and_then(|s| s.as_bool())
            .unwrap_or(false);
        let max_tokens = match self {
            Wire::Anthropic => value.get("max_tokens").and_then(|m| m.as_u64()),
            // `max_tokens` is deprecated here and is refused outright by the
            // o-series, so the new name wins when both are present.
            Wire::OpenAi => value
                .get("max_completion_tokens")
                .and_then(|m| m.as_u64())
                .or_else(|| value.get("max_tokens").and_then(|m| m.as_u64())),
        };
        let completions = match self {
            Wire::Anthropic => 1,
            Wire::OpenAi => value
                .get("n")
                .and_then(|n| n.as_u64())
                .filter(|n| *n >= 1)
                .unwrap_or(1),
        };
        ParsedRequest {
            model,
            max_tokens,
            stream,
            completions,
        }
    }

    /// The body to forward, when it differs from the body that arrived.
    ///
    /// OpenAI sends no usage in a streamed response unless the request asked
    /// for it, and a run settled from an estimate rather than from measured
    /// usage is the failure this gateway exists to avoid. So a streamed
    /// request that did not answer the question gets `include_usage` added.
    ///
    /// Returns `None` when nothing needs changing, including when the body is
    /// not an object we can safely rewrite: the caller then forwards what it
    /// received, which is always safe.
    ///
    /// A caller who set `include_usage` themselves is never overruled, not
    /// even when they set it to `false`.
    pub fn prepare_upstream_body(self, body: &bytes::Bytes, stream: bool) -> Option<bytes::Bytes> {
        if self != Wire::OpenAi || !stream {
            return None;
        }
        let mut value: Value = serde_json::from_slice(body).ok()?;
        let obj = value.as_object_mut()?;
        match obj.get("stream_options") {
            Some(Value::Object(o)) if o.contains_key("include_usage") => return None,
            Some(Value::Object(_)) | None => {}
            // Present and not an object: the caller sent something we do not
            // understand, and rewriting it would change their request into one
            // they did not make.
            Some(_) => return None,
        }
        let entry = obj
            .entry("stream_options")
            .or_insert_with(|| Value::Object(Default::default()));
        entry
            .as_object_mut()?
            .insert("include_usage".to_string(), Value::Bool(true));
        serde_json::to_vec(&value).ok().map(bytes::Bytes::from)
    }
}

/// Concatenates the `text` field of each text-shaped content block in a
/// content-block array (e.g. `[{"type":"text","text":"..."}]`),
/// space-separated and trimmed. Both wires use this same shape: Anthropic's
/// `system` and message `content` arrays, and OpenAI's message `content`
/// arrays. `pub(crate)` rather than private: `proxy.rs`'s `semantic_core`
/// (a message's `content` field, not the system prompt) reads the same array
/// shape and shares this rather than keeping its own copy.
pub(crate) fn concat_text_blocks(blocks: &[Value]) -> String {
    let mut buf = String::new();
    for b in blocks {
        if let Some(t) = b.get("text").and_then(|t| t.as_str()) {
            buf.push_str(t);
            buf.push(' ');
        }
    }
    buf.trim().to_string()
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn the_anthropic_door_reads_max_tokens_and_never_asks_for_more_than_one_completion() {
        let v = json!({"model": "claude-haiku-4-5", "max_tokens": 64, "stream": true});
        let p = Wire::Anthropic.parse_request(&v);
        assert_eq!(p.model, "claude-haiku-4-5");
        assert_eq!(p.max_tokens, Some(64));
        assert!(p.stream);
        assert_eq!(p.completions, 1);
    }

    #[test]
    fn the_openai_door_prefers_max_completion_tokens_over_the_deprecated_name() {
        let v = json!({"model": "gpt-4o", "max_tokens": 16, "max_completion_tokens": 4096});
        assert_eq!(Wire::OpenAi.parse_request(&v).max_tokens, Some(4096));
    }

    #[test]
    fn the_openai_door_still_reads_the_deprecated_name_when_it_is_the_only_one() {
        let v = json!({"model": "gpt-4o", "max_tokens": 16});
        assert_eq!(Wire::OpenAi.parse_request(&v).max_tokens, Some(16));
    }

    #[test]
    fn a_request_asking_for_several_completions_says_so() {
        let v = json!({"model": "gpt-4o", "n": 4});
        assert_eq!(Wire::OpenAi.parse_request(&v).completions, 4);
    }

    #[test]
    fn a_nonsense_completion_count_is_one_and_never_zero() {
        for bad in [json!(0), json!(-3), json!("4"), json!(null), json!({})] {
            let v = json!({"model": "gpt-4o", "n": bad});
            assert_eq!(
                Wire::OpenAi.parse_request(&v).completions,
                1,
                "n={bad} must fall back to one completion, never zero"
            );
        }
    }

    #[test]
    fn an_output_limit_that_is_not_a_whole_number_is_absent_rather_than_guessed() {
        for bad in [json!("4096"), json!(1.5), json!(-1), json!(null)] {
            let v = json!({"model": "gpt-4o", "max_completion_tokens": bad});
            assert_eq!(Wire::OpenAi.parse_request(&v).max_tokens, None);
        }
    }

    #[test]
    fn a_body_that_is_not_an_object_still_parses_into_safe_defaults() {
        for v in [json!([]), json!("hello"), json!(7), json!(null)] {
            let p = Wire::OpenAi.parse_request(&v);
            assert_eq!(p.model, "unknown");
            assert_eq!(p.max_tokens, None);
            assert!(!p.stream);
            assert_eq!(p.completions, 1);
        }
    }

    #[test]
    fn each_door_knows_its_own_path() {
        assert_eq!(Wire::Anthropic.route_path(), "/v1/messages");
        assert_eq!(Wire::OpenAi.route_path(), "/v1/chat/completions");
    }

    #[test]
    fn a_declared_wire_wins_over_whatever_the_upstream_url_looks_like() {
        let w = Wire::from_declaration(
            Some("openai"),
            Some("https://api.anthropic.com/v1/messages"),
        );
        assert_eq!(w, Wire::OpenAi);
    }

    #[test]
    fn an_undeclared_wire_is_read_off_the_upstream_path() {
        assert_eq!(
            Wire::from_declaration(None, Some("https://api.openai.com/v1/chat/completions")),
            Wire::OpenAi
        );
        assert_eq!(
            Wire::from_declaration(None, Some("https://api.anthropic.com/v1/messages")),
            Wire::Anthropic
        );
    }

    #[test]
    fn an_upstream_that_says_nothing_leaves_every_existing_deployment_where_it_was() {
        assert_eq!(Wire::from_declaration(None, None), Wire::Anthropic);
        assert_eq!(
            Wire::from_declaration(None, Some("http://localhost:9999/proxy")),
            Wire::Anthropic
        );
        assert_eq!(
            Wire::from_declaration(Some(""), Some("http://localhost:9999/proxy")),
            Wire::Anthropic
        );
    }

    #[test]
    fn an_unrecognised_declaration_falls_back_rather_than_inventing_a_third_shape() {
        assert_eq!(
            Wire::from_declaration(Some("gemini"), None),
            Wire::Anthropic
        );
    }

    #[test]
    fn a_declaration_is_read_without_regard_to_case() {
        assert_eq!(Wire::from_declaration(Some("OpenAI"), None), Wire::OpenAi);
        assert_eq!(Wire::from_declaration(Some("OPENAI"), None), Wire::OpenAi);
    }

    #[test]
    fn a_declaration_with_stray_whitespace_is_still_a_declaration() {
        assert_eq!(
            Wire::from_declaration(Some("  openai  "), None),
            Wire::OpenAi
        );
        assert_eq!(
            Wire::from_declaration(
                Some("\tanthropic\n"),
                Some("https://api.openai.com/v1/chat/completions")
            ),
            Wire::Anthropic
        );
    }

    #[test]
    fn an_explicit_anthropic_declaration_beats_an_upstream_url_that_looks_like_openai() {
        let w = Wire::from_declaration(
            Some("anthropic"),
            Some("https://api.openai.com/v1/chat/completions"),
        );
        assert_eq!(w, Wire::Anthropic);
    }

    // --- system_text (semantic cache partition key) ---

    #[test]
    fn the_openai_door_finds_the_system_prompt_where_that_wire_keeps_it() {
        let v = json!({"model":"gpt-4o","messages":[
            {"role":"system","content":"You are terse."},
            {"role":"user","content":"hi"}
        ]});
        assert_eq!(Wire::OpenAi.system_text(&v), "You are terse.");
    }

    #[test]
    fn the_o_series_developer_role_is_a_system_prompt_too() {
        let v = json!({"model":"o1","messages":[
            {"role":"developer","content":"Answer in one word."},
            {"role":"user","content":"hi"}
        ]});
        assert_eq!(Wire::OpenAi.system_text(&v), "Answer in one word.");
    }

    #[test]
    fn two_openai_requests_with_different_system_prompts_do_not_share_a_partition() {
        let a = json!({"model":"gpt-4o","messages":[
            {"role":"system","content":"Answer in English."},
            {"role":"user","content":"hi"}]});
        let b = json!({"model":"gpt-4o","messages":[
            {"role":"system","content":"Answer in French."},
            {"role":"user","content":"hi"}]});
        assert_ne!(
            Wire::OpenAi.system_text(&a),
            Wire::OpenAi.system_text(&b),
            "an empty system text on both is how one caller gets the other's answer"
        );
    }

    #[test]
    fn several_system_messages_are_read_in_order_and_joined() {
        let v = json!({"model":"gpt-4o","messages":[
            {"role":"system","content":"Be terse."},
            {"role":"user","content":"hi"},
            {"role":"system","content":"Be polite."}
        ]});
        assert_eq!(Wire::OpenAi.system_text(&v), "Be terse. Be polite.");
    }

    #[test]
    fn an_openai_system_message_carrying_content_parts_is_read_as_text() {
        let v = json!({"model":"gpt-4o","messages":[
            {"role":"system","content":[{"type":"text","text":"Be terse."}]},
            {"role":"user","content":"hi"}
        ]});
        assert_eq!(Wire::OpenAi.system_text(&v), "Be terse.");
    }

    #[test]
    fn the_anthropic_door_reads_the_field_it_always_read() {
        let v = json!({"model":"claude-haiku-4-5","system":"You are terse."});
        assert_eq!(Wire::Anthropic.system_text(&v), "You are terse.");
        let arr = json!({"model":"claude-haiku-4-5",
            "system":[{"type":"text","text":"You are terse."}]});
        assert_eq!(Wire::Anthropic.system_text(&arr), "You are terse.");
    }

    #[test]
    fn a_messages_array_that_is_empty_or_full_of_nonsense_is_read_without_panicking() {
        for bad in [
            json!({"model":"gpt-4o","messages":[]}),
            json!({"model":"gpt-4o","messages":["hi", 3, null, []]}),
            json!({"model":"gpt-4o","messages":{"role":"system"}}),
            json!({"model":"gpt-4o"}),
        ] {
            assert_eq!(Wire::OpenAi.system_text(&bad), "");
        }
    }

    #[test]
    fn a_body_with_no_system_prompt_anywhere_yields_an_empty_string_on_both_doors() {
        let v = json!({"model":"gpt-4o","messages":[{"role":"user","content":"hi"}]});
        assert_eq!(Wire::OpenAi.system_text(&v), "");
        assert_eq!(Wire::Anthropic.system_text(&json!({"model":"x"})), "");
    }

    // --- prepare_upstream_body (stream_options.include_usage injection) ---

    #[test]
    fn a_streamed_openai_request_is_asked_to_report_its_usage() {
        let body = bytes::Bytes::from(r#"{"model":"gpt-4o","stream":true}"#);
        let out = Wire::OpenAi.prepare_upstream_body(&body, true).unwrap();
        let v: Value = serde_json::from_slice(&out).unwrap();
        assert_eq!(v["stream_options"]["include_usage"], json!(true));
    }

    #[test]
    fn a_caller_that_already_answered_the_question_is_not_overruled() {
        for already in [json!(true), json!(false)] {
            let body = bytes::Bytes::from(
                serde_json::json!({"model":"gpt-4o","stream":true,
                    "stream_options":{"include_usage": already}})
                .to_string(),
            );
            assert!(
                Wire::OpenAi.prepare_upstream_body(&body, true).is_none(),
                "include_usage={already} was the caller's choice and stays"
            );
        }
    }

    #[test]
    fn a_stream_options_that_is_not_an_object_is_left_exactly_as_it_came() {
        for odd in [json!("yes"), json!(3), json!([]), json!(null)] {
            let body = bytes::Bytes::from(
                serde_json::json!({"model":"gpt-4o","stream":true,"stream_options": odd})
                    .to_string(),
            );
            assert!(Wire::OpenAi.prepare_upstream_body(&body, true).is_none());
        }
    }

    #[test]
    fn nothing_is_added_to_a_request_that_does_not_stream_or_to_the_other_door() {
        let body = bytes::Bytes::from(r#"{"model":"gpt-4o"}"#);
        assert!(Wire::OpenAi.prepare_upstream_body(&body, false).is_none());
        let anth = bytes::Bytes::from(r#"{"model":"claude-haiku-4-5","stream":true}"#);
        assert!(Wire::Anthropic.prepare_upstream_body(&anth, true).is_none());
    }

    #[test]
    fn a_body_that_is_not_an_object_is_left_alone_rather_than_replaced() {
        let body = bytes::Bytes::from("[1,2,3]");
        assert!(Wire::OpenAi.prepare_upstream_body(&body, true).is_none());
    }

    #[test]
    fn two_openai_requests_with_different_system_prompts_land_in_different_cache_partitions() {
        // Same shape as the pre-existing Anthropic regression test
        // (`system_text_different_array_systems_land_in_different_partitions`
        // in proxy.rs): a unit test on `system_text` alone proves the string
        // differs, but the actual failure mode this task exists to close is
        // two callers sharing a semantic-cache partition. This proves the
        // partition key itself, via the same `SemanticCache::partition_key`
        // the proxy's cache lookup calls at crates/gateway/src/proxy.rs.
        use tokenfuse_core::SemanticCache;

        let a = json!({"model":"gpt-4o","messages":[
            {"role":"system","content":"Answer in English."},
            {"role":"user","content":"hi"}]});
        let b = json!({"model":"gpt-4o","messages":[
            {"role":"system","content":"Answer in French."},
            {"role":"user","content":"hi"}]});

        let partition_a = SemanticCache::partition_key(
            "gpt-4o",
            &Wire::OpenAi.system_text(&a),
            "",
            "",
            "default",
        );
        let partition_b = SemanticCache::partition_key(
            "gpt-4o",
            &Wire::OpenAi.system_text(&b),
            "",
            "",
            "default",
        );
        assert_ne!(
            partition_a, partition_b,
            "two OpenAI callers with different system prompts must not share a cache partition"
        );
    }
}
