//! Taint tracking / agent firewall (Ring 3.1).
//!
//! Defends against prompt injection at the level of *actions*, not words: once a
//! run's context has touched an untrusted source (web, an uploaded file, an
//! unknown tool), high-privilege actions (exec, writing to prod, sending data
//! out) are denied. We do not try to detect "bad text" — we gate what a tainted
//! agent is allowed to *do*. See docs/07-taint-model.md.
//!
//! Pure logic here; the gateway maps tools → labels/capabilities, accumulates a
//! run's taint monotonically, and enforces the policy on the model's tool calls.

use serde::{Deserialize, Serialize};
use std::collections::{BTreeSet, HashMap};

/// The set of taint labels a run has accumulated (e.g. `web`, `file`, `secrets`).
pub type Labels = BTreeSet<String>;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum FirewallMode {
    #[default]
    Off,
    /// Record would-blocks without blocking.
    Shadow,
    /// Block denied actions.
    Enforce,
}

/// A rule: if the context carries any `when_any` label and the action needs any
/// `deny` capability, the action is blocked.
///
/// `name` is not decoration. Before 2026-08-26 a block produced one prose
/// sentence, so an operator could read a single refusal and could not answer
/// "which rule costs us the most false positives" over a week of them: two
/// refusals by different rules were indistinguishable strings. The name is
/// what makes the record groupable, which is what makes shadow mode worth
/// running.
#[derive(Debug, Clone)]
pub struct TaintRule {
    pub name: String,
    pub when_any: Vec<String>,
    pub deny: Vec<String>,
}

/// A refusal, in the parts a consumer can count rather than only display.
///
/// [`reason`](TaintVerdict::reason) still renders the sentence the wire
/// contract has always carried (the `x-fuse-taint` header and the 403 body),
/// so nothing an existing client parses changes; the fields exist alongside
/// it, for the record.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TaintVerdict {
    /// The rule that fired, by name.
    pub rule: String,
    /// Everything the run was carrying at that moment, sorted.
    pub labels: Vec<String>,
    /// Every capability the action wanted, sorted.
    pub requested: Vec<String>,
    /// The subset of `requested` this rule refuses, sorted.
    pub denied: Vec<String>,
}

impl TaintVerdict {
    /// The human sentence. Unchanged from before the struct existed, on
    /// purpose: it is on the wire in two places.
    pub fn reason(&self) -> String {
        format!(
            "tainted context [{}] denies capability [{}]",
            self.labels.join(", "),
            self.denied.join(", ")
        )
    }
}

/// Extract tool-call names from a request (message history) or a response,
/// across Anthropic (`tool_use`) and OpenAI (`tool_calls`) shapes.
pub fn tool_names_in(v: &serde_json::Value) -> Vec<String> {
    let mut out = Vec::new();

    // Anthropic response: top-level content array with tool_use blocks.
    push_tool_use_from_content(v.get("content"), &mut out);

    // Anthropic request: messages[].content[] tool_use; OpenAI messages[].tool_calls.
    if let Some(msgs) = v.get("messages").and_then(|m| m.as_array()) {
        for m in msgs {
            push_tool_use_from_content(m.get("content"), &mut out);
            push_openai_tool_calls(m.get("tool_calls"), &mut out);
        }
    }

    // OpenAI response: choices[].message.tool_calls.
    if let Some(choices) = v.get("choices").and_then(|c| c.as_array()) {
        for ch in choices {
            push_openai_tool_calls(
                ch.get("message").and_then(|m| m.get("tool_calls")),
                &mut out,
            );
        }
    }

    out
}

/// Tool names a request DECLARES as available (the top-level `tools[]` array),
/// as opposed to tools already invoked ([`tool_names_in`] reads `tool_use` /
/// `tool_calls`). A request-path PEP (the Wardryx enforcement hook) must gate
/// on declared tools too: a `deny_tool` policy has to fire when a forbidden
/// tool is merely offered to the model, because the proxy decides *before* the
/// model can emit the `tool_use` that would otherwise reveal the call. Anthropic
/// names a tool at `tools[].name`; OpenAI at `tools[].function.name`.
pub fn declared_tool_names_in(v: &serde_json::Value) -> Vec<String> {
    let mut out = Vec::new();
    if let Some(tools) = v.get("tools").and_then(|t| t.as_array()) {
        for t in tools {
            // Anthropic: tools[].name
            if let Some(name) = t.get("name").and_then(|n| n.as_str()) {
                out.push(name.to_string());
            }
            // OpenAI: tools[].function.name
            if let Some(name) = t
                .get("function")
                .and_then(|f| f.get("name"))
                .and_then(|n| n.as_str())
            {
                out.push(name.to_string());
            }
        }
    }
    out
}

fn push_tool_use_from_content(content: Option<&serde_json::Value>, out: &mut Vec<String>) {
    if let Some(blocks) = content.and_then(|c| c.as_array()) {
        for b in blocks {
            if b.get("type").and_then(|t| t.as_str()) == Some("tool_use") {
                if let Some(name) = b.get("name").and_then(|n| n.as_str()) {
                    out.push(name.to_string());
                }
            }
        }
    }
}

fn push_openai_tool_calls(calls: Option<&serde_json::Value>, out: &mut Vec<String>) {
    if let Some(arr) = calls.and_then(|c| c.as_array()) {
        for tc in arr {
            if let Some(name) = tc
                .get("function")
                .and_then(|f| f.get("name"))
                .and_then(|n| n.as_str())
            {
                out.push(name.to_string());
            }
        }
    }
}

/// Map tool names to the taint labels their output carries (unknown tools →
/// `unclassified`, which is treated as untrusted).
///
/// A source carries a LIST of labels, per docs/07 B.2, which has always
/// specified `labels: [...]`. The built-in map was one label per tool until
/// 2026-08-26, so a read that is both an upload and PII could only be
/// described as one of them, and whichever the operator picked, the other
/// rule could never fire.
///
/// A source mapped to an EMPTY list is not "no labels": it is a tool nobody
/// classified, and it lands in `unclassified` with the unknown ones. The other
/// reading would turn a half-finished config into a way to launder untrusted
/// output into a trusted context.
pub fn labels_for_tools(names: &[String], sources: &HashMap<String, Vec<String>>) -> Labels {
    let mut labels = Labels::new();
    for n in names {
        match sources.get(n) {
            Some(mapped) if !mapped.is_empty() => labels.extend(mapped.iter().cloned()),
            _ => {
                labels.insert("unclassified".to_string());
            }
        }
    }
    labels
}

/// Map tool names to the capabilities they exercise (tools with no mapped
/// capability are treated as harmless and omitted).
pub fn capabilities_for_tools(
    names: &[String],
    capabilities: &HashMap<String, String>,
) -> BTreeSet<String> {
    names
        .iter()
        .filter_map(|n| capabilities.get(n).cloned())
        .collect()
}

/// Evaluate the rules; return the first block, if any.
///
/// First match wins, and the order is the config's order. Deliberately not
/// "collect every rule that would fire": a refusal is one decision, and a
/// record naming three rules would invite a reader to think three things went
/// wrong. The rules that did not get a turn are recoverable from the labels
/// and capabilities the verdict carries.
pub fn evaluate(
    labels: &Labels,
    requested: &BTreeSet<String>,
    rules: &[TaintRule],
) -> Option<TaintVerdict> {
    for rule in rules {
        let label_hit = rule.when_any.iter().any(|l| labels.contains(l));
        if !label_hit {
            continue;
        }
        let denied: Vec<String> = rule
            .deny
            .iter()
            .filter(|c| requested.contains(*c))
            .cloned()
            .collect();
        if !denied.is_empty() {
            return Some(TaintVerdict {
                rule: rule.name.clone(),
                labels: labels.iter().cloned().collect(),
                requested: requested.iter().cloned().collect(),
                denied,
            });
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn sources() -> HashMap<String, Vec<String>> {
        HashMap::from([
            ("web_search".to_string(), vec!["web".to_string()]),
            ("read_upload".to_string(), vec!["file".to_string()]),
            ("vault_read".to_string(), vec!["secrets".to_string()]),
        ])
    }
    fn caps() -> HashMap<String, String> {
        HashMap::from([
            ("run_shell".to_string(), "exec".to_string()),
            ("send_email".to_string(), "network_egress".to_string()),
        ])
    }
    fn rules() -> Vec<TaintRule> {
        vec![
            TaintRule {
                name: "no-exec-after-untrusted".into(),
                when_any: vec!["web".into(), "file".into(), "unclassified".into()],
                deny: vec!["exec".into(), "network_egress".into()],
            },
            TaintRule {
                name: "anti-exfiltration".into(),
                when_any: vec!["secrets".into()],
                deny: vec!["network_egress".into()],
            },
        ]
    }

    #[test]
    fn extracts_tool_names_from_anthropic_response() {
        let resp = json!({"content":[{"type":"text","text":"hi"},{"type":"tool_use","name":"run_shell","input":{}}]});
        assert_eq!(tool_names_in(&resp), vec!["run_shell"]);
    }

    #[test]
    fn extracts_tool_names_from_openai_response() {
        let resp =
            json!({"choices":[{"message":{"tool_calls":[{"function":{"name":"send_email"}}]}}]});
        assert_eq!(tool_names_in(&resp), vec!["send_email"]);
    }

    #[test]
    fn declares_anthropic_tools() {
        let req = json!({"tools":[
            {"name":"wire_transfer","description":"move money","input_schema":{}},
            {"name":"lookup","description":"read","input_schema":{}}
        ]});
        assert_eq!(
            declared_tool_names_in(&req),
            vec!["wire_transfer", "lookup"]
        );
    }

    #[test]
    fn declares_openai_tools() {
        let req = json!({"tools":[{"type":"function","function":{"name":"shell_exec"}}]});
        assert_eq!(declared_tool_names_in(&req), vec!["shell_exec"]);
    }

    #[test]
    fn no_tools_declared_is_empty() {
        let req = json!({"messages":[{"role":"user","content":"hi"}]});
        assert!(declared_tool_names_in(&req).is_empty());
    }

    /// The bypass this function closes: a first-turn request that only DECLARES
    /// a forbidden tool (no tool_use block yet) is invisible to `tool_names_in`,
    /// so a PEP that consulted only the latter would let a `deny_tool` policy be
    /// evaded. `declared_tool_names_in` surfaces it so the PEP can deny.
    #[test]
    fn declared_tool_is_invisible_to_invoked_scan() {
        let req = json!({
            "model":"claude-haiku-4-5","max_tokens":50,
            "messages":[{"role":"user","content":"refund by wire"}],
            "tools":[{"name":"wire_transfer","description":"move money","input_schema":{}}]
        });
        assert!(tool_names_in(&req).is_empty());
        assert_eq!(declared_tool_names_in(&req), vec!["wire_transfer"]);
    }

    #[test]
    fn a_source_mapped_to_nothing_is_untrusted_not_trusted() {
        // The config half-filled: somebody added the tool name and had not
        // decided its labels yet. Reading that as "carries nothing" would make
        // an empty list the way to declassify a source.
        let src = HashMap::from([("half_done".to_string(), Vec::new())]);
        assert!(labels_for_tools(&["half_done".to_string()], &src).contains("unclassified"));
    }

    #[test]
    fn unknown_tool_is_unclassified() {
        let l = labels_for_tools(&["mystery".to_string()], &sources());
        assert!(l.contains("unclassified"));
    }

    #[test]
    fn web_context_blocks_exec() {
        let labels = labels_for_tools(&["web_search".to_string()], &sources());
        let requested = capabilities_for_tools(&["run_shell".to_string()], &caps());
        assert!(evaluate(&labels, &requested, &rules()).is_some());
    }

    #[test]
    fn trusted_context_allows_exec() {
        let labels = Labels::new(); // nothing untrusted touched
        let requested = capabilities_for_tools(&["run_shell".to_string()], &caps());
        assert!(evaluate(&labels, &requested, &rules()).is_none());
    }

    #[test]
    fn the_verdict_names_the_rule_that_fired() {
        // Red against the pre-2026-08-26 module, which returned a String: a
        // consumer could print a refusal and could not group a week of them.
        let labels = labels_for_tools(&["web_search".to_string()], &sources());
        let requested = capabilities_for_tools(&["run_shell".to_string()], &caps());
        let v = evaluate(&labels, &requested, &rules()).expect("web + exec is refused");
        assert_eq!(v.rule, "no-exec-after-untrusted");
        assert_eq!(v.labels, vec!["web"]);
        assert_eq!(v.denied, vec!["exec"]);
    }

    #[test]
    fn the_sentence_on_the_wire_is_unchanged() {
        // Two wire surfaces carry it: the `x-fuse-taint` response header and
        // the 403 body's `reason`. Structuring the verdict must not reword
        // what an existing client already parses.
        let labels = labels_for_tools(&["web_search".to_string()], &sources());
        let requested = capabilities_for_tools(&["run_shell".to_string()], &caps());
        let v = evaluate(&labels, &requested, &rules()).unwrap();
        assert_eq!(v.reason(), "tainted context [web] denies capability [exec]");
    }

    #[test]
    fn only_the_denied_capabilities_are_named_not_every_requested_one() {
        // An action asking for two things where the rule refuses one: the
        // record must not read as though both were the problem, or an
        // operator loosens the wrong rule.
        let labels = labels_for_tools(&["vault_read".to_string()], &sources());
        let requested = capabilities_for_tools(
            &["run_shell".to_string(), "send_email".to_string()],
            &caps(),
        );
        let v = evaluate(&labels, &requested, &rules()).unwrap();
        assert_eq!(v.rule, "anti-exfiltration");
        assert_eq!(v.requested, vec!["exec", "network_egress"]);
        assert_eq!(
            v.denied,
            vec!["network_egress"],
            "exec is not this rule's business"
        );
    }

    #[test]
    fn secrets_context_blocks_only_egress_not_exec() {
        let labels = labels_for_tools(&["vault_read".to_string()], &sources());
        let exec = capabilities_for_tools(&["run_shell".to_string()], &caps());
        let egress = capabilities_for_tools(&["send_email".to_string()], &caps());
        // secrets rule denies egress but not exec
        assert!(evaluate(&labels, &exec, &rules()).is_none());
        assert!(evaluate(&labels, &egress, &rules()).is_some());
    }
}
