//! `tokenfuse firewall --events <ndjson> [--run <id>] [--agent <id>] [--json]`
//!
//! What the agent firewall did, read back off its own event stream. The
//! surface that makes shadow mode worth running: the filter has been able to
//! refuse things since Ring 3.1 and, until 2026-08-26, could not tell anyone
//! afterwards what it had refused, to whom, or under which rule.
//!
//! Read-only, and it reads the SHARED bus file rather than a private one, so
//! a count here and a count in a console downstream come from the same lines.
//! It never touches the enforcement path.

use tokenfuse_core::firewallstats::{compute, FirewallEvent, FirewallStats};

#[derive(Debug, Clone, Default)]
pub struct Args {
    pub events: Option<String>,
    pub run: Option<String>,
    pub agent: Option<String>,
    pub json: bool,
}

pub fn parse_args(args: &[String]) -> Args {
    let mut out = Args::default();
    let mut it = args.iter();
    while let Some(a) = it.next() {
        match a.as_str() {
            "--events" => out.events = it.next().cloned(),
            "--run" => out.run = it.next().cloned(),
            "--agent" => out.agent = it.next().cloned(),
            "--json" => out.json = true,
            _ => {}
        }
    }
    out
}

/// Read the NDJSON stream, filter, aggregate, print.
///
/// A line that is not JSON is skipped and counted, never fatal: the events
/// file is appended to by a live gateway, so reading it while the last line is
/// half-written is the normal case, not a corruption.
pub async fn run(args: &Args) -> Result<(), String> {
    let path = args
        .events
        .clone()
        .ok_or_else(|| "missing --events <ndjson path>".to_string())?;
    let text = std::fs::read_to_string(&path)
        .map_err(|e| format!("could not read events at '{path}': {e}"))?;

    let mut unreadable = 0usize;
    let mut events: Vec<FirewallEvent> = Vec::new();
    for line in text.lines().filter(|l| !l.trim().is_empty()) {
        match serde_json::from_str::<serde_json::Value>(line) {
            Ok(v) => {
                if let Some(e) = FirewallEvent::from_envelope(&v) {
                    events.push(e);
                }
            }
            Err(_) => unreadable += 1,
        }
    }
    if let Some(r) = &args.run {
        events.retain(|e| &e.run_id == r);
    }
    if let Some(a) = &args.agent {
        events.retain(|e| e.agent_id.contains(a.as_str()));
    }

    let stats = compute(&events);
    if args.json {
        println!(
            "{}",
            serde_json::to_string_pretty(&stats).map_err(|e| e.to_string())?
        );
        return Ok(());
    }
    print!("{}", render(&stats, &path, unreadable));
    Ok(())
}

/// The human report. Separated from `run` so it is testable without a file.
pub fn render(s: &FirewallStats, path: &str, unreadable: usize) -> String {
    let mut o = String::new();
    o.push_str("AGENT FIREWALL\n");
    match (&s.first_ts, &s.last_ts) {
        (Some(a), Some(b)) => o.push_str(&format!("  window   {a} .. {b}\n")),
        // Said rather than left blank: an empty window and a quiet week look
        // identical on a report that omits the line.
        _ => o.push_str("  window   nothing in range\n"),
    }
    o.push_str(&format!(
        "  read     {} firewall event(s) from {path}, {} run(s) touched the filter\n",
        s.events_read, s.runs_touched
    ));
    if unreadable > 0 {
        o.push_str(&format!(
            "  skipped  {unreadable} line(s) that were not JSON (a live file's last line often is not)\n"
        ));
    }

    if s.events_read == 0 {
        o.push_str(
            "\n  This measured NOTHING, which is not the same as finding nothing.\n  \
             Check that the gateway ran with TOKENFUSE_FIREWALL=shadow (or enforce)\n  \
             and that TOKENFUSE_EVENTS points at this file.\n",
        );
        return o;
    }

    o.push_str("\nHOW RUNS BECAME UNTRUSTED\n");
    if s.acquisitions.is_empty() {
        o.push_str("  nothing was classified as untrusted in this window\n");
    }
    let label_w = s.acquisitions.iter().map(|a| a.label.len()).max().unwrap_or(0).clamp(12, 32);
    for a in &s.acquisitions {
        let tools = if a.from_tools.is_empty() {
            "-".to_string()
        } else {
            a.from_tools
                .iter()
                .map(|(t, n)| format!("{t} ({n})"))
                .collect::<Vec<_>>()
                .join(", ")
        };
        let declared = if a.declared > 0 {
            format!("   [declared by the caller: {}]", a.declared)
        } else {
            String::new()
        };
        o.push_str(&format!(
            "  {:<label_w$} {:>4} run(s)   from {tools}{declared}\n",
            a.label, a.runs
        ));
    }

    o.push_str("\nWHAT THE FILTER DECIDED\n");
    if s.verdicts.is_empty() {
        o.push_str("  no rule fired\n");
    }
    // Width from the data, not a guess: rule names come from an operator's
    // own file and "no-payments-after-customer-data" is a perfectly ordinary
    // one. A fixed column turned the table into ragged prose the first time a
    // real config was read.
    let rule_w = s.verdicts.iter().map(|v| v.rule.len()).max().unwrap_or(0).clamp(20, 44);
    for v in &s.verdicts {
        o.push_str(&format!(
            "  {:<rule_w$} refused {:>4}   would refuse {:>4}   over {} run(s), denying {}\n",
            v.rule,
            v.refused,
            v.would_refuse,
            v.runs,
            if v.denied.is_empty() {
                "-".to_string()
            } else {
                v.denied.join(", ")
            }
        ));
    }

    o.push_str("\nWHAT THE AGENTS TRIED TO DO\n");
    if s.attempts.is_empty() {
        o.push_str("  no tool call reached a rule\n");
    }
    let tool_w = s.attempts.iter().map(|t| t.tool.len()).max().unwrap_or(0).clamp(16, 40);
    for t in &s.attempts {
        o.push_str(&format!(
            "  {:<tool_w$} refused {:>4}   let through by shadow {:>4}\n",
            t.tool, t.refused, t.allowed_by_shadow
        ));
    }

    o.push_str("\nWHERE IT ACTED\n");
    for (stage, n) in &s.stages {
        o.push_str(&format!("  {stage:<20} {n:>5}\n"));
    }

    o.push_str("\nIF YOU TURNED ENFORCE ON OVER THIS WINDOW\n");
    if s.if_enforced.actions == 0 {
        o.push_str("  nothing would have changed: no action was let through by shadow\n");
    } else {
        o.push_str(&format!(
            "  {} action(s) would have been REFUSED, across {} run(s) and {} agent(s)\n",
            s.if_enforced.actions, s.if_enforced.runs, s.if_enforced.agents
        ));
        if let Some((rule, n)) = &s.if_enforced.top_rule {
            o.push_str(&format!("  most of it one rule:  {rule} ({n})\n"));
        }
        if let Some((agent, n)) = &s.if_enforced.top_agent {
            o.push_str(&format!("  who would notice:     {agent} ({n})\n"));
        }
    }
    o
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokenfuse_core::firewallstats::compute;

    fn ev(json: serde_json::Value) -> FirewallEvent {
        FirewallEvent::from_envelope(&json).expect("a firewall event")
    }

    #[test]
    fn an_empty_read_says_it_measured_nothing_rather_than_all_clear() {
        // The failure this whole subsystem is about, one level up: a report
        // that looks identical whether the firewall was quiet or was never
        // switched on teaches an operator that it is working.
        let out = render(&compute(&[]), "/tmp/events.ndjson", 0);
        assert!(out.contains("measured NOTHING"), "{out}");
        assert!(out.contains("TOKENFUSE_FIREWALL=shadow"), "{out}");
        assert!(!out.contains("IF YOU TURNED ENFORCE ON"), "{out}");
    }

    #[test]
    fn the_report_answers_all_four_questions() {
        // "на якому етапі, що було зроблено, що отримав агент, як діяв"
        // (@yurii 2026-08-26), each a section rather than a field somewhere.
        let evs = vec![
            ev(serde_json::json!({
                "ts": "2026-08-26T10:00:00Z", "type": "taint_raised",
                "agent_id": "agent://a/one", "run_id": "r1",
                "data": {"stage": "request_history", "added": ["web"], "from_tools": ["web_search"]}
            })),
            ev(serde_json::json!({
                "ts": "2026-08-26T10:01:00Z", "type": "taint_shadow",
                "agent_id": "agent://a/one", "run_id": "r1",
                "data": {"stage": "model_tool_call", "mode": "shadow",
                         "rule": "no-exec-after-untrusted", "denied": ["exec"],
                         "tools": ["run_shell"]}
            })),
        ];
        let out = render(&compute(&evs), "/tmp/e.ndjson", 0);
        assert!(out.contains("HOW RUNS BECAME UNTRUSTED"), "{out}");
        assert!(out.contains("web") && out.contains("web_search"), "{out}");
        assert!(out.contains("no-exec-after-untrusted"), "{out}");
        assert!(out.contains("run_shell"), "{out}");
        assert!(
            out.contains("model_tool_call") && out.contains("request_history"),
            "{out}"
        );
        assert!(out.contains("1 action(s) would have been REFUSED"), "{out}");
    }

    #[test]
    fn a_run_with_no_would_blocks_says_nothing_would_change() {
        // Not an empty section. "Turning enforcement on breaks nothing" is
        // the single most valuable sentence this report can print, and it is
        // the one an operator is waiting for.
        let evs = vec![ev(serde_json::json!({
            "ts": "2026-08-26T10:00:00Z", "type": "taint_raised",
            "agent_id": "agent://a/one", "run_id": "r1",
            "data": {"stage": "request_history", "added": ["web"], "from_tools": ["web_search"]}
        }))];
        let out = render(&compute(&evs), "/tmp/e.ndjson", 0);
        assert!(out.contains("nothing would have changed"), "{out}");
    }

    #[test]
    fn a_half_written_last_line_is_counted_not_fatal() {
        let out = render(&compute(&[]), "/tmp/e.ndjson", 3);
        assert!(out.contains("skipped  3 line(s)"), "{out}");
    }

    #[test]
    fn a_long_rule_name_does_not_ragged_the_table() {
        // Found by running the report over a real operator config, not by a
        // test: "no-payments-after-customer-data" is 31 characters and the
        // column was 28, so the counts after it stopped lining up.
        let evs = vec![
            ev(serde_json::json!({
                "ts": "2026-08-26T10:00:00Z", "type": "taint_block",
                "agent_id": "a", "run_id": "r1",
                "data": {"stage": "model_tool_call", "mode": "enforce",
                         "rule": "no-payments-after-customer-data",
                         "denied": ["financial"], "tools": ["wire_transfer"]}
            })),
            ev(serde_json::json!({
                "ts": "2026-08-26T10:00:00Z", "type": "taint_block",
                "agent_id": "a", "run_id": "r2",
                "data": {"stage": "model_tool_call", "mode": "enforce",
                         "rule": "short", "denied": ["exec"], "tools": ["bash"]}
            })),
        ];
        let out = render(&compute(&evs), "/tmp/e", 0);
        let rows: Vec<&str> = out
            .lines()
            .filter(|l| l.contains("refused") && l.contains("would refuse"))
            .collect();
        assert_eq!(rows.len(), 2);
        let col = |l: &str| l.find("refused").unwrap();
        assert_eq!(col(rows[0]), col(rows[1]), "the counts line up:\n{out}");
    }

    #[test]
    fn parse_args_reads_every_flag() {
        let a = parse_args(&[
            "--events".into(),
            "/tmp/e".into(),
            "--run".into(),
            "r1".into(),
            "--agent".into(),
            "rca".into(),
            "--json".into(),
        ]);
        assert_eq!(a.events.as_deref(), Some("/tmp/e"));
        assert_eq!(a.run.as_deref(), Some("r1"));
        assert_eq!(a.agent.as_deref(), Some("rca"));
        assert!(a.json);
    }
}
