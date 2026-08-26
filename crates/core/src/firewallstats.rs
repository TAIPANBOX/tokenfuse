//! What the agent firewall did, aggregated over its own event stream.
//!
//! The filter emits three types (`taint_raised`, `taint_shadow`,
//! `taint_block`) and this turns a pile of them into the four questions an
//! operator actually asks, which are the four `@yurii` named on 2026-08-26:
//! "на якому етапі, що було зроблено, що отримав агент, як діяв".
//!
//! - **How runs became untrusted** — which labels, carried in by which tools.
//! - **What the filter decided** — per rule, in which mode.
//! - **What the agents tried to do** — per tool, refused versus let through.
//! - **Where it acted** — per stage.
//!
//! Plus the one that makes a shadow week worth running: **if you turned
//! enforce on today**, what would break and for whom. Without that number the
//! decision at the end of the week is a guess, which is how a firewall stays
//! in shadow forever.
//!
//! Pure aggregation over already-serialized events, deliberately: it never
//! touches the enforcement path, and it reads exactly what a consumer
//! elsewhere in the estate would read off the bus, so a number here and a
//! number in the console cannot come from different definitions.

use serde::Serialize;
use std::collections::{BTreeMap, BTreeSet};

/// One event, reduced to the members this report reads.
///
/// Built from the envelope rather than taken as JSON at every call site so a
/// missing member is handled once. Anything unparseable is skipped rather than
/// guessed at: a report that invents a stage is worse than one that says it
/// read fewer events.
#[derive(Debug, Clone)]
pub struct FirewallEvent {
    pub ts: String,
    pub kind: Kind,
    pub agent_id: String,
    pub run_id: String,
    pub stage: String,
    pub mode: String,
    pub rule: String,
    pub added: Vec<String>,
    pub from_tools: Vec<String>,
    pub denied: Vec<String>,
    pub tools: Vec<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Kind {
    /// A run picked up a label it did not have.
    Raised,
    /// The filter would have refused, and did not (shadow).
    Shadow,
    /// The filter refused (enforce).
    Block,
}

impl FirewallEvent {
    /// Read one envelope. `None` for anything that is not a firewall event.
    pub fn from_envelope(v: &serde_json::Value) -> Option<FirewallEvent> {
        let kind = match v.get("type").and_then(|t| t.as_str())? {
            "taint_raised" => Kind::Raised,
            "taint_shadow" => Kind::Shadow,
            "taint_block" => Kind::Block,
            _ => return None,
        };
        let d = v.get("data").cloned().unwrap_or(serde_json::Value::Null);
        let strings = |key: &str| -> Vec<String> {
            d.get(key)
                .and_then(|x| x.as_array())
                .map(|a| {
                    a.iter()
                        .filter_map(|s| s.as_str().map(str::to_string))
                        .collect()
                })
                .unwrap_or_default()
        };
        let text = |val: Option<&serde_json::Value>| {
            val.and_then(|x| x.as_str()).unwrap_or_default().to_string()
        };
        Some(FirewallEvent {
            ts: text(v.get("ts")),
            kind,
            agent_id: text(v.get("agent_id")),
            run_id: text(v.get("run_id")),
            stage: text(d.get("stage")),
            mode: text(d.get("mode")),
            rule: text(d.get("rule")),
            added: strings("added"),
            from_tools: strings("from_tools"),
            denied: strings("denied"),
            tools: strings("tools"),
        })
    }
}

/// One taint label and how runs came to carry it.
#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct LabelRow {
    pub label: String,
    /// Distinct runs that acquired it. Runs, not events: a run reads the web
    /// once as far as taint is concerned, and counting events would make a
    /// chatty agent look like a fleet-wide problem.
    pub runs: usize,
    /// The tools that carried it in, most frequent first, with their counts.
    pub from_tools: Vec<(String, usize)>,
    /// Times the caller declared it on the request header instead.
    pub declared: usize,
    /// Runs that got it from an ANCESTOR rather than from anything they did.
    ///
    /// Counted apart from `from_tools` because the producer puts the ancestor's
    /// RUN ID in the same member a tool name would occupy, so a report that
    /// merged them printed "from p1, web_search" and invited a reader to go
    /// looking for a tool called `p1`. Found by reading the report against a
    /// live run, not by a test.
    pub inherited: usize,
}

/// One rule and what it did.
#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct RuleRow {
    pub rule: String,
    pub refused: usize,
    pub would_refuse: usize,
    pub runs: usize,
    /// Every capability this rule actually denied, sorted.
    pub denied: Vec<String>,
}

/// One tool the model asked for, and how it fared.
#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct ToolRow {
    pub tool: String,
    pub refused: usize,
    pub allowed_by_shadow: usize,
}

/// What flipping `TOKENFUSE_FIREWALL=enforce` would have changed, measured
/// over the window rather than estimated.
#[derive(Debug, Clone, Serialize, PartialEq, Eq, Default)]
pub struct IfEnforced {
    pub actions: usize,
    pub runs: usize,
    pub agents: usize,
    /// The rule responsible for the most of them, and how many.
    pub top_rule: Option<(String, usize)>,
    /// The agent that would notice most, and how many.
    pub top_agent: Option<(String, usize)>,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct FirewallStats {
    pub events_read: usize,
    pub runs_touched: usize,
    pub first_ts: Option<String>,
    pub last_ts: Option<String>,
    pub acquisitions: Vec<LabelRow>,
    pub verdicts: Vec<RuleRow>,
    pub attempts: Vec<ToolRow>,
    pub stages: Vec<(String, usize)>,
    pub if_enforced: IfEnforced,
}

/// Aggregate. Ordering is deterministic everywhere (count descending, then
/// name) so two runs over the same window produce the same bytes and a diff
/// between two windows is readable.
pub fn compute(events: &[FirewallEvent]) -> FirewallStats {
    let mut runs_touched: BTreeSet<&str> = BTreeSet::new();
    let mut stages: BTreeMap<String, usize> = BTreeMap::new();

    // acquisitions
    let mut label_runs: BTreeMap<String, BTreeSet<&str>> = BTreeMap::new();
    let mut label_tools: BTreeMap<String, BTreeMap<String, usize>> = BTreeMap::new();
    let mut label_declared: BTreeMap<String, usize> = BTreeMap::new();
    let mut label_inherited: BTreeMap<String, usize> = BTreeMap::new();

    // verdicts
    let mut rule_refused: BTreeMap<String, usize> = BTreeMap::new();
    let mut rule_would: BTreeMap<String, usize> = BTreeMap::new();
    let mut rule_runs: BTreeMap<String, BTreeSet<&str>> = BTreeMap::new();
    let mut rule_denied: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();

    // attempts
    let mut tool_refused: BTreeMap<String, usize> = BTreeMap::new();
    let mut tool_shadowed: BTreeMap<String, usize> = BTreeMap::new();

    // the projection
    let mut shadow_runs: BTreeSet<&str> = BTreeSet::new();
    let mut shadow_agents: BTreeMap<String, usize> = BTreeMap::new();
    let mut shadow_actions = 0usize;

    let mut first: Option<&str> = None;
    let mut last: Option<&str> = None;

    for e in events {
        if !e.run_id.is_empty() {
            runs_touched.insert(&e.run_id);
        }
        if !e.stage.is_empty() {
            *stages.entry(e.stage.clone()).or_default() += 1;
        }
        if !e.ts.is_empty() {
            // Lexicographic on RFC3339 in one zone is chronological, which is
            // what the exporter writes. Cheaper than parsing, and a malformed
            // stamp sorts rather than panics.
            if first.is_none_or(|f| e.ts.as_str() < f) {
                first = Some(&e.ts);
            }
            if last.is_none_or(|l| e.ts.as_str() > l) {
                last = Some(&e.ts);
            }
        }

        match e.kind {
            Kind::Raised => {
                let from_ancestor = e.stage == "parent_run";
                for label in &e.added {
                    if !e.run_id.is_empty() {
                        label_runs
                            .entry(label.clone())
                            .or_default()
                            .insert(&e.run_id);
                    }
                    if from_ancestor {
                        *label_inherited.entry(label.clone()).or_default() += 1;
                        continue;
                    }
                    if e.from_tools.is_empty() {
                        *label_declared.entry(label.clone()).or_default() += 1;
                    }
                    for t in &e.from_tools {
                        *label_tools
                            .entry(label.clone())
                            .or_default()
                            .entry(t.clone())
                            .or_default() += 1;
                    }
                }
            }
            Kind::Shadow | Kind::Block => {
                let refused = e.kind == Kind::Block;
                if !e.rule.is_empty() {
                    if refused {
                        *rule_refused.entry(e.rule.clone()).or_default() += 1;
                    } else {
                        *rule_would.entry(e.rule.clone()).or_default() += 1;
                    }
                    if !e.run_id.is_empty() {
                        rule_runs
                            .entry(e.rule.clone())
                            .or_default()
                            .insert(&e.run_id);
                    }
                    rule_denied
                        .entry(e.rule.clone())
                        .or_default()
                        .extend(e.denied.iter().cloned());
                }
                for t in &e.tools {
                    if refused {
                        *tool_refused.entry(t.clone()).or_default() += 1;
                    } else {
                        *tool_shadowed.entry(t.clone()).or_default() += 1;
                    }
                }
                if !refused {
                    shadow_actions += 1;
                    if !e.run_id.is_empty() {
                        shadow_runs.insert(&e.run_id);
                    }
                    if !e.agent_id.is_empty() {
                        *shadow_agents.entry(e.agent_id.clone()).or_default() += 1;
                    }
                }
            }
        }
    }

    let mut acquisitions: Vec<LabelRow> = label_runs
        .keys()
        .chain(label_declared.keys())
        .chain(label_inherited.keys())
        .collect::<BTreeSet<_>>()
        .into_iter()
        .map(|label| {
            let mut from_tools: Vec<(String, usize)> = label_tools
                .get(label)
                .map(|m| m.iter().map(|(k, v)| (k.clone(), *v)).collect())
                .unwrap_or_default();
            sort_by_count(&mut from_tools);
            LabelRow {
                label: label.clone(),
                runs: label_runs.get(label).map(BTreeSet::len).unwrap_or(0),
                from_tools,
                declared: label_declared.get(label).copied().unwrap_or(0),
                inherited: label_inherited.get(label).copied().unwrap_or(0),
            }
        })
        .collect();
    acquisitions.sort_by(|a, b| b.runs.cmp(&a.runs).then(a.label.cmp(&b.label)));

    let mut verdicts: Vec<RuleRow> = rule_refused
        .keys()
        .chain(rule_would.keys())
        .collect::<BTreeSet<_>>()
        .into_iter()
        .map(|rule| RuleRow {
            rule: rule.clone(),
            refused: rule_refused.get(rule).copied().unwrap_or(0),
            would_refuse: rule_would.get(rule).copied().unwrap_or(0),
            runs: rule_runs.get(rule).map(BTreeSet::len).unwrap_or(0),
            denied: rule_denied
                .get(rule)
                .map(|s| s.iter().cloned().collect())
                .unwrap_or_default(),
        })
        .collect();
    verdicts.sort_by(|a, b| {
        (b.refused + b.would_refuse)
            .cmp(&(a.refused + a.would_refuse))
            .then(a.rule.cmp(&b.rule))
    });

    let mut attempts: Vec<ToolRow> = tool_refused
        .keys()
        .chain(tool_shadowed.keys())
        .collect::<BTreeSet<_>>()
        .into_iter()
        .map(|tool| ToolRow {
            tool: tool.clone(),
            refused: tool_refused.get(tool).copied().unwrap_or(0),
            allowed_by_shadow: tool_shadowed.get(tool).copied().unwrap_or(0),
        })
        .collect();
    attempts.sort_by(|a, b| {
        (b.refused + b.allowed_by_shadow)
            .cmp(&(a.refused + a.allowed_by_shadow))
            .then(a.tool.cmp(&b.tool))
    });

    let mut stage_rows: Vec<(String, usize)> = stages.into_iter().collect();
    sort_by_count(&mut stage_rows);

    let top_rule = rule_would
        .iter()
        .max_by(|a, b| a.1.cmp(b.1).then(b.0.cmp(a.0)))
        .map(|(k, v)| (k.clone(), *v));
    let top_agent = shadow_agents
        .iter()
        .max_by(|a, b| a.1.cmp(b.1).then(b.0.cmp(a.0)))
        .map(|(k, v)| (k.clone(), *v));

    FirewallStats {
        events_read: events.len(),
        runs_touched: runs_touched.len(),
        first_ts: first.map(str::to_string),
        last_ts: last.map(str::to_string),
        acquisitions,
        verdicts,
        attempts,
        stages: stage_rows,
        if_enforced: IfEnforced {
            actions: shadow_actions,
            runs: shadow_runs.len(),
            agents: shadow_agents.len(),
            top_rule,
            top_agent,
        },
    }
}

fn sort_by_count(rows: &mut [(String, usize)]) {
    rows.sort_by(|a, b| b.1.cmp(&a.1).then(a.0.cmp(&b.0)));
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn raised(run: &str, added: &[&str], tools: &[&str]) -> FirewallEvent {
        FirewallEvent::from_envelope(&json!({
            "ts": "2026-08-26T10:00:00Z", "type": "taint_raised",
            "agent_id": "agent://a.example/one", "run_id": run,
            "data": {"stage": "request_history", "added": added, "from_tools": tools}
        }))
        .expect("a firewall event")
    }

    fn verdict(kind: &str, run: &str, agent: &str, rule: &str, tools: &[&str]) -> FirewallEvent {
        FirewallEvent::from_envelope(&json!({
            "ts": "2026-08-26T10:01:00Z", "type": kind,
            "agent_id": agent, "run_id": run,
            "data": {
                "stage": "model_tool_call",
                "mode": if kind == "taint_block" { "enforce" } else { "shadow" },
                "rule": rule, "denied": ["exec"], "tools": tools
            }
        }))
        .expect("a firewall event")
    }

    #[test]
    fn an_event_from_another_plane_is_not_read_as_a_firewall_one() {
        // The report is run against a shared bus file that carries every
        // type. Reading a `dlp_block` as a taint verdict would put another
        // subsystem's refusals in this subsystem's numbers.
        assert!(FirewallEvent::from_envelope(&json!({"type": "dlp_block"})).is_none());
        assert!(FirewallEvent::from_envelope(&json!({"type": "tool_call"})).is_none());
        assert!(FirewallEvent::from_envelope(&json!({})).is_none());
    }

    #[test]
    fn acquisitions_count_runs_not_events() {
        // A run that reads the web on forty turns became untrusted once. On
        // events, one chatty agent would read as a fleet-wide problem.
        let evs = vec![
            raised("r1", &["web"], &["web_search"]),
            raised("r1", &["web"], &["web_search"]),
            raised("r2", &["web"], &["fetch_url"]),
        ];
        let s = compute(&evs);
        assert_eq!(s.acquisitions.len(), 1);
        assert_eq!(s.acquisitions[0].label, "web");
        assert_eq!(s.acquisitions[0].runs, 2, "two runs, not three events");
        assert_eq!(
            s.acquisitions[0].from_tools,
            vec![("web_search".into(), 2), ("fetch_url".into(), 1)],
            "most frequent first, so the tool to look at is the top line"
        );
    }

    #[test]
    fn a_label_the_caller_declared_is_not_credited_to_a_tool() {
        // Otherwise the report answers "which tool should we stop calling"
        // with a tool that was never involved.
        let mut e = raised("r1", &["secrets"], &[]);
        e.stage = "request_header".into();
        let s = compute(&[e]);
        assert_eq!(s.acquisitions[0].declared, 1);
        assert!(s.acquisitions[0].from_tools.is_empty());
    }

    #[test]
    fn an_inherited_label_is_not_reported_as_a_tool_this_run_called() {
        // Found by reading the report against a live run, not by a test. The
        // producer puts the ancestor's RUN ID in the same member a tool name
        // would occupy, so the report printed "from p1, web_search" and
        // invited a reader to go looking for a tool called `p1`.
        let mut inherited = raised("child", &["web"], &["parent-run"]);
        inherited.stage = "parent_run".into();
        let evs = vec![raised("parent", &["web"], &["web_search"]), inherited];
        let s = compute(&evs);
        assert_eq!(s.acquisitions.len(), 1);
        let web = &s.acquisitions[0];
        assert_eq!(web.runs, 2, "both runs carry it");
        assert_eq!(
            web.from_tools,
            vec![("web_search".into(), 1)],
            "one tool actually carried it in; the other run inherited it"
        );
        assert_eq!(web.inherited, 1);
        assert_eq!(web.declared, 0, "and it is not a header declaration either");
    }

    #[test]
    fn the_enforce_projection_counts_only_what_shadow_let_through() {
        // The number the whole shadow week is run to produce. A block is
        // already refused, so counting it here would tell an operator that
        // turning enforcement on changes things it has already changed.
        let evs = vec![
            verdict(
                "taint_shadow",
                "r1",
                "agent://a/one",
                "no-exec-after-untrusted",
                &["run_shell"],
            ),
            verdict(
                "taint_shadow",
                "r1",
                "agent://a/one",
                "no-exec-after-untrusted",
                &["run_shell"],
            ),
            verdict(
                "taint_shadow",
                "r2",
                "agent://a/two",
                "anti-exfiltration",
                &["send_email"],
            ),
            verdict(
                "taint_block",
                "r3",
                "agent://a/three",
                "anti-exfiltration",
                &["send_email"],
            ),
        ];
        let s = compute(&evs);
        assert_eq!(
            s.if_enforced.actions, 3,
            "the three shadowed, not the block"
        );
        assert_eq!(s.if_enforced.runs, 2);
        assert_eq!(s.if_enforced.agents, 2);
        assert_eq!(
            s.if_enforced.top_rule,
            Some(("no-exec-after-untrusted".into(), 2))
        );
        assert_eq!(s.if_enforced.top_agent, Some(("agent://a/one".into(), 2)));
    }

    #[test]
    fn a_tool_row_separates_refused_from_let_through() {
        let evs = vec![
            verdict("taint_block", "r1", "a", "rule", &["run_shell"]),
            verdict("taint_shadow", "r2", "a", "rule", &["run_shell"]),
            verdict("taint_shadow", "r3", "a", "rule", &["run_shell"]),
        ];
        let s = compute(&evs);
        assert_eq!(s.attempts.len(), 1);
        assert_eq!(s.attempts[0].tool, "run_shell");
        assert_eq!(s.attempts[0].refused, 1);
        assert_eq!(s.attempts[0].allowed_by_shadow, 2);
    }

    #[test]
    fn a_rule_row_holds_both_halves_so_a_mode_change_is_arithmetic() {
        let evs = vec![
            verdict(
                "taint_block",
                "r1",
                "a",
                "anti-exfiltration",
                &["send_email"],
            ),
            verdict(
                "taint_shadow",
                "r2",
                "a",
                "anti-exfiltration",
                &["http_post"],
            ),
        ];
        let s = compute(&evs);
        assert_eq!(s.verdicts[0].refused, 1);
        assert_eq!(s.verdicts[0].would_refuse, 1);
        assert_eq!(s.verdicts[0].runs, 2);
        assert_eq!(s.verdicts[0].denied, vec!["exec"]);
    }

    #[test]
    fn the_window_is_the_events_own_first_and_last() {
        let mut a = raised("r1", &["web"], &["web_search"]);
        a.ts = "2026-08-26T09:00:00Z".into();
        let mut b = raised("r2", &["web"], &["web_search"]);
        b.ts = "2026-08-26T11:00:00Z".into();
        // Out of order on purpose: an NDJSON file appended by two writers is.
        let s = compute(&[b, a]);
        assert_eq!(s.first_ts.as_deref(), Some("2026-08-26T09:00:00Z"));
        assert_eq!(s.last_ts.as_deref(), Some("2026-08-26T11:00:00Z"));
    }

    #[test]
    fn nothing_read_is_a_report_of_zero_rather_than_a_panic() {
        // The common first run: enable shadow, read the file five minutes
        // later. Every count must be zero and every optional empty, so the
        // renderer can say "measured nothing" instead of "all clear".
        let s = compute(&[]);
        assert_eq!(s.events_read, 0);
        assert_eq!(s.runs_touched, 0);
        assert!(s.first_ts.is_none() && s.acquisitions.is_empty() && s.verdicts.is_empty());
        assert_eq!(s.if_enforced, IfEnforced::default());
    }

    #[test]
    fn ordering_is_stable_across_two_runs_over_the_same_events() {
        // A report an operator diffs week to week is useless if the row order
        // is a HashMap's. Ties break on name, so the bytes are the same.
        let evs = vec![
            verdict("taint_shadow", "r1", "a", "b-rule", &["t"]),
            verdict("taint_shadow", "r2", "a", "a-rule", &["t"]),
        ];
        let one = compute(&evs);
        let two = compute(&evs);
        assert_eq!(one, two);
        assert_eq!(one.verdicts[0].rule, "a-rule", "equal counts break on name");
    }
}
