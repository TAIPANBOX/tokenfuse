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
}
