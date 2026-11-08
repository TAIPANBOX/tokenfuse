#!/usr/bin/env python3
"""Apply one named mutant to the product code by an exact string edit.

Throwaway: lives only on the mutants branch of tokenfuse#516. Exits 2 when the
edit does not apply, so a mutant that never ran is never read as one that
survived.
"""
import sys

W = "crates/gateway/src/wardryx.rs"
B = "crates/gateway/src/mcpbroker.rs"

MUTANTS = {
    "control": [],
    # Any denied entry hides the tool, whatever its rule.
    "rule-ignored": [(W,
        ".filter(|d| d.rule.as_deref() == Some(DENY_TOOL_RULE))",
        ".filter(|d| d.rule.as_deref() != Some(\"no-such-rule\"))")],
    # Shadow narrows as enforce does.
    "shadow-narrows": [(B,
        "    if st.wardryx.mode == WardryxMode::Enforce {\n        if !hide.is_empty() {",
        "    if st.wardryx.mode != WardryxMode::Off {\n        if !hide.is_empty() {")],
    # No answer hides every listed tool.
    "outage-hides-all": [(B,
        "        ListAnswer::NoAnswer => return,",
        "        ListAnswer::NoAnswer => names.iter().cloned().collect(),")],
    # The listing never reuses a cached answer.
    "cache-bypassed": [(W,
        "        if let Some(cached) = self.filter_cache.get(agent_id, tool_names) {",
        "        if let Some(cached) = self.filter_cache.get(agent_id, tool_names).filter(|_| false) {")],
    # A failure is cached as an empty answer.
    "failure-cached": [(W,
        "        let outcome = client.filter_tools(&wire, timeout).await?;",
        "        let outcome = client.filter_tools(&wire, timeout).await.unwrap_or(FilterOutcome { allowed: Vec::new(), denied: Vec::new(), policy_version: None });")],
    # A listing with no agent is asked about as the empty agent.
    "asks-without-agent": [(B,
        "    let Some(agent) = attributed_agent(ctx) else {\n        return;\n    };\n    let names = listed_tool_names(answer);",
        "    let agent = attributed_agent(ctx).unwrap_or(\"\");\n    let names = listed_tool_names(answer);")],
    # Off asks too.
    "off-asks": [(B,
        "    if st.wardryx.mode == WardryxMode::Off {\n        return;\n    }\n    let Some(agent)",
        "    if st.wardryx.mode == WardryxMode::Off && agent_is_never_checked() {\n        return;\n    }\n    let Some(agent)"),
        (B,
        "async fn narrow_listing(",
        "fn agent_is_never_checked() -> bool {\n    std::env::var(\"NO_SUCH_VARIABLE_FOR_THE_MUTANT\").is_ok()\n}\n\nasync fn narrow_listing(")],
    # The missing route is said on every listing.
    "route-said-each-time": [(W,
        "if !self.warned_list_not_found.swap(true, Ordering::SeqCst) {",
        "if !self.warned_list_not_found.swap(false, Ordering::SeqCst) {")],
    # The filter cache forgets whose answer it holds.
    "cache-key-loses-agent": [(W,
        "        sorted.hash(&mut hasher);\n        (agent_id.to_string(), hasher.finish())",
        "        sorted.hash(&mut hasher);\n        (agent_id.len().min(0).to_string(), hasher.finish())")],
    # Enforce keeps only the denied tools.
    "keeps-the-wrong-ones": [(B,
        "    tools.retain(|t| !named_in(t, hide));",
        "    tools.retain(|t| named_in(t, hide));")],
}

name = sys.argv[1]
if name not in MUTANTS:
    sys.exit(f"unknown mutant {name!r}")
for path, old, new in MUTANTS[name]:
    text = open(path).read()
    if text.count(old) != 1:
        print(f"MUTANT DID NOT APPLY: {name}: {old!r} found {text.count(old)} times in {path}")
        sys.exit(2)
    open(path, "w").write(text.replace(old, new))
    print(f"applied {name} to {path}")
