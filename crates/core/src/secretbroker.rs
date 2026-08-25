//! Credential brokering for MCP tool calls.
//!
//! Agents (and the LLM prompt) should never hold raw secrets. Instead a tool
//! call carries **handles** like `{{secret:github_token}}`, and the broker swaps
//! in the real value from a vault *at the boundary* — just before the request
//! leaves for the MCP server. The secret is therefore never in the model's
//! context, the trace, or the agent's memory.
//!
//! This module is the pure, dependency-light core (vault + substitution); the
//! network proxy that uses it lives in the gateway (`mcpbroker`).
//!
//! ## Scoping: WHO may resolve a handle, not just whether it exists
//!
//! A secret can optionally carry a [`ScopeRule`]: which agent ids and/or
//! which tool names may resolve it (`TOKENFUSE_MCP_SECRET_SCOPES`,
//! `docs/23-mcp-broker-v2.md` section 4). [`SecretVault::resolve`] is the
//! identity-aware read path every caller (`inject_secrets` included) goes
//! through now; a secret with NO rule resolves for anyone, unconditionally,
//! exactly as this vault always behaved before scoping existed. That is the
//! back-compat guarantee: an existing `TOKENFUSE_MCP_SECRETS`-only deployment
//! sees no behaviour change until it opts into `TOKENFUSE_MCP_SECRET_SCOPES`.

use std::collections::{HashMap, HashSet};

use serde_json::Value;

/// An optional access-control rule for one named secret: which agent ids
/// and/or which tool names may resolve it. `None` on a side means that side
/// is unconstrained; a rule with BOTH sides `None` cannot be produced by
/// [`parse_scope_spec`] (an empty entry is a parse error, see there), but a
/// hand-built one is legal and simply allows everyone, the same as no rule
/// at all. A secret this type is never attached to (via
/// [`SecretVault::set_scope`]) is unscoped: resolvable by any agent, any
/// tool, unchanged from before this type existed.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ScopeRule {
    pub agents: Option<HashSet<String>>,
    pub tools: Option<HashSet<String>>,
}

impl ScopeRule {
    /// A rule naming allowed agent ids only; any tool.
    pub fn agents(ids: impl IntoIterator<Item = impl Into<String>>) -> Self {
        Self {
            agents: Some(ids.into_iter().map(Into::into).collect()),
            tools: None,
        }
    }

    /// A rule naming allowed tool names only; any agent.
    pub fn tools(names: impl IntoIterator<Item = impl Into<String>>) -> Self {
        Self {
            agents: None,
            tools: Some(names.into_iter().map(Into::into).collect()),
        }
    }

    /// A rule naming both allowed agent ids and allowed tool names; a caller
    /// must satisfy both.
    pub fn agents_and_tools(
        ids: impl IntoIterator<Item = impl Into<String>>,
        names: impl IntoIterator<Item = impl Into<String>>,
    ) -> Self {
        Self {
            agents: Some(ids.into_iter().map(Into::into).collect()),
            tools: Some(names.into_iter().map(Into::into).collect()),
        }
    }

    /// Whether `agent_id`/`tool` satisfy this rule. `agent_id: None` never
    /// satisfies an agent-constrained rule: an absent identity is not a
    /// wildcard anywhere else this gateway makes an authorization decision
    /// (`mcpbroker::attributed_agent` reads a blank header as `None` for the
    /// same reason, and `needs_identity` refuses rather than guesses). An
    /// empty `tool` never satisfies a tool-constrained rule for the same
    /// reason: `params.name` missing or non-string is not "any tool", it is
    /// "no tool named", and naming no tool cannot be in a set of names.
    fn allows(&self, agent_id: Option<&str>, tool: &str) -> bool {
        let agent_ok = match &self.agents {
            None => true,
            Some(allowed) => match agent_id {
                Some(id) => allowed.contains(id),
                None => false,
            },
        };
        let tool_ok = match &self.tools {
            None => true,
            Some(allowed) => !tool.is_empty() && allowed.contains(tool),
        };
        agent_ok && tool_ok
    }
}

/// A `TOKENFUSE_MCP_SECRET_SCOPES` spec that is set but malformed.
///
/// Unlike `ClientKeys::from_spec` (`crates/gateway/src/clientkeys.rs`), which
/// skips one bad entry and keeps the rest of the spec usable, ANY malformed
/// entry here fails the WHOLE spec. The two failures are not the same shape:
/// a dropped key-credential entry only makes one fewer credential valid, the
/// safe direction. A dropped scope entry would silently UNSCOPE the secret it
/// was meant to protect, which is the exact failure this feature exists to
/// close, so a typo has to be loud rather than quietly permissive.
#[derive(Debug, PartialEq, Eq)]
pub struct InvalidScopeSpec(pub String);

impl std::fmt::Display for InvalidScopeSpec {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "TOKENFUSE_MCP_SECRET_SCOPES is set but invalid: {}; refusing to start rather than \
             silently leaving a secret unscoped",
            self.0
        )
    }
}

impl std::error::Error for InvalidScopeSpec {}

/// Parse `TOKENFUSE_MCP_SECRET_SCOPES`:
/// `name=agents:a1|a2;tools:t1|t2,name2=agents:a3`.
///
/// Each comma-separated entry binds one secret NAME (matching a
/// `{{secret:NAME}}` handle and a `SecretVault::from_pairs` key) to an
/// OPTIONAL `agents:` clause and/or an OPTIONAL `tools:` clause, each a
/// `|`-joined set, the two clauses separated by `;` when both are present. A
/// clause that is absent means that dimension is unconstrained: `agents:a1`
/// with no `tools:` clause allows agent `a1` to use the secret with ANY tool.
/// A secret named in no entry at all is unscoped: resolvable by any agent,
/// any tool, exactly as `TOKENFUSE_MCP_SECRETS` alone has always behaved
/// (`docs/23-mcp-broker-v2.md` section 4).
///
/// A blank/whitespace-only spec is "not configured": returns an empty map,
/// the same reading `SecretVault::from_pairs` and `ClientKeys::from_spec`
/// give a blank spec. A non-blank spec is validated entry by entry, and
/// unlike `ClientKeys::from_spec`, ONE bad entry fails the whole spec: see
/// [`InvalidScopeSpec`].
pub fn parse_scope_spec(spec: &str) -> Result<HashMap<String, ScopeRule>, InvalidScopeSpec> {
    let trimmed = spec.trim();
    if trimmed.is_empty() {
        return Ok(HashMap::new());
    }
    let mut rules = HashMap::new();
    for entry in trimmed.split(',') {
        let entry = entry.trim();
        if entry.is_empty() {
            continue;
        }
        let Some((name, rule_spec)) = entry.split_once('=') else {
            return Err(InvalidScopeSpec(format!(
                "entry {entry:?} has no '=' (expected NAME=agents:a1|a2;tools:t1|t2)"
            )));
        };
        let name = name.trim();
        if name.is_empty() {
            return Err(InvalidScopeSpec(format!(
                "entry {entry:?} names no secret before '='"
            )));
        }
        if rules.contains_key(name) {
            return Err(InvalidScopeSpec(format!(
                "secret {name:?} is scoped twice; merge the two entries into one"
            )));
        }
        let rule_spec = rule_spec.trim();
        if rule_spec.is_empty() {
            return Err(InvalidScopeSpec(format!(
                "secret {name:?} names no clause after '=' (omit the whole entry to leave it \
                 unscoped, or add agents:.../tools:...)"
            )));
        }
        let mut rule = ScopeRule::default();
        let (mut saw_agents, mut saw_tools) = (false, false);
        for clause in rule_spec.split(';') {
            let clause = clause.trim();
            if clause.is_empty() {
                return Err(InvalidScopeSpec(format!(
                    "secret {name:?} has an empty clause (a stray ';')"
                )));
            }
            let Some((label, list)) = clause.split_once(':') else {
                return Err(InvalidScopeSpec(format!(
                    "secret {name:?} clause {clause:?} has no ':' (expected agents:a1|a2 or \
                     tools:t1|t2)"
                )));
            };
            let values: HashSet<String> = list
                .split('|')
                .map(str::trim)
                .filter(|v| !v.is_empty())
                .map(str::to_string)
                .collect();
            if values.is_empty() {
                return Err(InvalidScopeSpec(format!(
                    "secret {name:?} clause {clause:?} names no value after ':'"
                )));
            }
            match label.trim().to_lowercase().as_str() {
                "agents" if !saw_agents => {
                    saw_agents = true;
                    rule.agents = Some(values);
                }
                "tools" if !saw_tools => {
                    saw_tools = true;
                    rule.tools = Some(values);
                }
                "agents" | "tools" => {
                    return Err(InvalidScopeSpec(format!(
                        "secret {name:?} repeats the {label:?} clause"
                    )));
                }
                _ => {
                    return Err(InvalidScopeSpec(format!(
                        "secret {name:?} clause {clause:?} is neither 'agents' nor 'tools'"
                    )));
                }
            }
        }
        rules.insert(name.to_string(), rule);
    }
    Ok(rules)
}

/// What [`SecretVault::resolve`] found for one handle name, given who is
/// asking and for which tool.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Resolved<'a> {
    /// The secret exists and this (agent, tool) may use it: either the
    /// secret carries no [`ScopeRule`] (unscoped, resolvable by anyone,
    /// today's behaviour) or it does and this pairing satisfies it.
    Allowed(&'a str),
    /// No secret is configured under this name.
    Unknown,
    /// The secret exists, carries a [`ScopeRule`], and this (agent, tool)
    /// does not satisfy it. The caller decides what that means (this
    /// module never forwards anything); `mcpbroker::process` refuses the
    /// whole `tools/call`, see `docs/23-mcp-broker-v2.md` section 4.
    ScopeDenied,
}

/// A store of named secrets the broker can inject, and the optional
/// [`ScopeRule`]s that narrow who may resolve which.
#[derive(Debug, Default, Clone)]
pub struct SecretVault {
    secrets: HashMap<String, String>,
    scopes: HashMap<String, ScopeRule>,
}

impl SecretVault {
    pub fn new() -> Self {
        Self::default()
    }

    /// Parse `name1=value1,name2=value2`. Values must not contain `,` or `=`
    /// (fine for tokens); richer formats can build the vault directly.
    pub fn from_pairs(spec: &str) -> Self {
        let mut v = Self::new();
        for pair in spec.split(',').filter(|s| !s.trim().is_empty()) {
            if let Some((name, value)) = pair.split_once('=') {
                v.insert(name.trim(), value.trim());
            }
        }
        v
    }

    pub fn insert(&mut self, name: impl Into<String>, value: impl Into<String>) {
        self.secrets.insert(name.into(), value.into());
    }

    /// Attach a [`ScopeRule`] to `name`, narrowing who may resolve it. A
    /// secret with no rule (the default) is resolvable by anyone; calling
    /// this is what opts one in to scoping.
    pub fn set_scope(&mut self, name: impl Into<String>, rule: ScopeRule) {
        self.scopes.insert(name.into(), rule);
    }

    /// Parse and apply [`parse_scope_spec`] onto this vault in one call, for
    /// `main.rs`'s convenience wiring `TOKENFUSE_MCP_SECRET_SCOPES`.
    pub fn apply_scope_spec(&mut self, spec: &str) -> Result<(), InvalidScopeSpec> {
        for (name, rule) in parse_scope_spec(spec)? {
            self.set_scope(name, rule);
        }
        Ok(())
    }

    /// Resolve `name` for a specific caller: the requesting `agent_id`
    /// (`None` when the call carried no identity) and the `tool` being
    /// called (empty when unknown). See [`Resolved`] and this module's
    /// scoping section above.
    #[must_use]
    pub fn resolve(&self, name: &str, agent_id: Option<&str>, tool: &str) -> Resolved<'_> {
        let Some(value) = self.secrets.get(name) else {
            return Resolved::Unknown;
        };
        match self.scopes.get(name) {
            None => Resolved::Allowed(value.as_str()),
            Some(rule) if rule.allows(agent_id, tool) => Resolved::Allowed(value.as_str()),
            Some(_) => Resolved::ScopeDenied,
        }
    }

    pub fn is_empty(&self) -> bool {
        self.secrets.is_empty()
    }

    pub fn len(&self) -> usize {
        self.secrets.len()
    }

    /// How many configured secrets carry NO [`ScopeRule`] (resolvable by any
    /// agent, any tool). Read at startup so an operator sees the count even
    /// if they never open the config that would show it (`docs/23` section
    /// 4): a warning nobody has to go looking for.
    #[must_use]
    pub fn unscoped_count(&self) -> usize {
        self.unscoped_names().len()
    }

    /// The names behind [`Self::unscoped_count`], for a startup message that
    /// says WHICH secrets rather than only how many.
    #[must_use]
    pub fn unscoped_names(&self) -> Vec<&str> {
        self.secrets
            .keys()
            .filter(|name| !self.scopes.contains_key(name.as_str()))
            .map(String::as_str)
            .collect()
    }
}

/// Outcome of an injection pass.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct Injection {
    /// How many handles were replaced with real secrets.
    pub replaced: usize,
    /// Handles whose secret was not in the vault (left as-is).
    pub missing: Vec<String>,
    /// Handles whose secret EXISTS but carries a [`ScopeRule`] this call's
    /// (agent, tool) does not satisfy (left as-is, same as `missing`, but
    /// reported separately: this is a deliberate access-control decision,
    /// not an absent secret, and a caller should log and refuse
    /// differently. See `mcpbroker::process`.)
    pub refused: Vec<String>,
}

const OPEN: &str = "{{secret:";
const CLOSE: &str = "}}";

/// Replace every `{{secret:NAME}}` handle inside all string values of `v`
/// with the vault's secret, for this specific `agent_id` (`None` if the call
/// carried no identity) and `tool` (empty if unknown). A handle whose secret
/// is unscoped resolves regardless of `agent_id`/`tool`, unchanged from
/// before scoping existed. Unknown and scope-denied handles are both left
/// untouched (see [`Injection`]) and reported separately. Recurses through
/// objects and arrays.
pub fn inject_secrets(
    v: &mut Value,
    vault: &SecretVault,
    agent_id: Option<&str>,
    tool: &str,
) -> Injection {
    let mut inj = Injection::default();
    walk(v, vault, agent_id, tool, &mut inj);
    inj
}

fn walk(
    v: &mut Value,
    vault: &SecretVault,
    agent_id: Option<&str>,
    tool: &str,
    inj: &mut Injection,
) {
    match v {
        Value::String(s) => {
            if s.contains(OPEN) {
                *s = replace_handles(s, vault, agent_id, tool, inj);
            }
        }
        Value::Array(items) => {
            for it in items {
                walk(it, vault, agent_id, tool, inj);
            }
        }
        Value::Object(map) => {
            for (_, val) in map.iter_mut() {
                walk(val, vault, agent_id, tool, inj);
            }
        }
        _ => {}
    }
}

/// Replace all `{{secret:NAME}}` occurrences in a single string.
fn replace_handles(
    s: &str,
    vault: &SecretVault,
    agent_id: Option<&str>,
    tool: &str,
    inj: &mut Injection,
) -> String {
    let mut out = String::with_capacity(s.len());
    let mut rest = s;
    while let Some(start) = rest.find(OPEN) {
        out.push_str(&rest[..start]);
        let after = &rest[start + OPEN.len()..];
        match after.find(CLOSE) {
            Some(end) => {
                let name = &after[..end];
                match vault.resolve(name, agent_id, tool) {
                    Resolved::Allowed(secret) => {
                        out.push_str(secret);
                        inj.replaced += 1;
                    }
                    Resolved::Unknown => {
                        // Unknown secret: keep the handle verbatim so nothing
                        // silently becomes empty, and report it.
                        out.push_str(OPEN);
                        out.push_str(name);
                        out.push_str(CLOSE);
                        inj.missing.push(name.to_string());
                    }
                    Resolved::ScopeDenied => {
                        // Known secret, wrong caller: keep the handle
                        // verbatim (never substitute a value the caller
                        // must not have) and report it distinctly from
                        // `missing` so a caller can tell "no such secret"
                        // from "not for you".
                        out.push_str(OPEN);
                        out.push_str(name);
                        out.push_str(CLOSE);
                        inj.refused.push(name.to_string());
                    }
                }
                rest = &after[end + CLOSE.len()..];
            }
            None => {
                // Unterminated handle — emit the rest unchanged.
                out.push_str(OPEN);
                out.push_str(after);
                rest = "";
            }
        }
    }
    out.push_str(rest);
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn injects_nested_handles() {
        let vault = SecretVault::from_pairs("github_token=ghp_REAL,api=KEY123");
        let mut v = json!({
            "name": "create_issue",
            "arguments": {
                "auth": "Bearer {{secret:github_token}}",
                "headers": ["x-api-key: {{secret:api}}"],
                "title": "hello"
            }
        });
        let inj = inject_secrets(&mut v, &vault, None, "");
        assert_eq!(inj.replaced, 2);
        assert!(inj.missing.is_empty());
        assert!(inj.refused.is_empty());
        assert_eq!(v["arguments"]["auth"], "Bearer ghp_REAL");
        assert_eq!(v["arguments"]["headers"][0], "x-api-key: KEY123");
        assert_eq!(v["arguments"]["title"], "hello");
    }

    #[test]
    fn missing_handle_is_reported_and_kept() {
        let vault = SecretVault::from_pairs("a=1");
        let mut v = json!({ "x": "{{secret:nope}}" });
        let inj = inject_secrets(&mut v, &vault, None, "");
        assert_eq!(inj.replaced, 0);
        assert_eq!(inj.missing, vec!["nope".to_string()]);
        assert!(inj.refused.is_empty());
        assert_eq!(v["x"], "{{secret:nope}}");
    }

    #[test]
    fn plain_values_untouched() {
        let vault = SecretVault::from_pairs("a=1");
        let mut v = json!({ "n": 42, "s": "no handles here", "b": true });
        let inj = inject_secrets(&mut v, &vault, None, "");
        assert_eq!(inj, Injection::default());
        assert_eq!(v["s"], "no handles here");
    }

    // --- ScopeRule / SecretVault::resolve --------------------------------

    #[test]
    fn an_unscoped_secret_resolves_for_any_agent_any_tool() {
        let mut vault = SecretVault::new();
        vault.insert("gh", "ghp_REAL");
        // No `set_scope` call at all: today's behaviour, unconditional.
        for (agent, tool) in [
            (None, ""),
            (Some("agent-a"), ""),
            (Some("agent-a"), "create_issue"),
            (Some("literally-anyone"), "any_tool_at_all"),
        ] {
            assert_eq!(
                vault.resolve("gh", agent, tool),
                Resolved::Allowed("ghp_REAL"),
                "an unscoped secret must resolve for agent={agent:?} tool={tool:?}"
            );
        }
    }

    #[test]
    fn an_unknown_name_is_unknown_regardless_of_scoping() {
        let vault = SecretVault::new();
        assert_eq!(
            vault.resolve("nope", Some("agent-a"), "tool-a"),
            Resolved::Unknown
        );
    }

    #[test]
    fn an_agent_scoped_secret_allows_the_listed_agent_and_refuses_others() {
        let mut vault = SecretVault::new();
        vault.insert("gh", "ghp_REAL");
        vault.set_scope("gh", ScopeRule::agents(["agent-a", "agent-b"]));

        assert_eq!(
            vault.resolve("gh", Some("agent-a"), "any_tool"),
            Resolved::Allowed("ghp_REAL"),
            "a listed agent resolves with ANY tool: the rule names no tools clause"
        );
        assert_eq!(
            vault.resolve("gh", Some("agent-b"), "other_tool"),
            Resolved::Allowed("ghp_REAL")
        );
        assert_eq!(
            vault.resolve("gh", Some("agent-c"), "any_tool"),
            Resolved::ScopeDenied,
            "an unlisted agent must be refused, not silently allowed"
        );
    }

    #[test]
    fn an_agent_scoped_secret_refuses_an_absent_identity() {
        // The security-critical edge case: a call with NO agent id must not
        // be read as a wildcard. This is the same posture
        // `mcpbroker::needs_identity` takes for the Wardryx gate.
        let mut vault = SecretVault::new();
        vault.insert("gh", "ghp_REAL");
        vault.set_scope("gh", ScopeRule::agents(["agent-a"]));
        assert_eq!(
            vault.resolve("gh", None, "any_tool"),
            Resolved::ScopeDenied,
            "no agent id must never satisfy an agent-constrained rule"
        );
    }

    #[test]
    fn a_tool_scoped_secret_allows_the_listed_tool_and_refuses_others() {
        let mut vault = SecretVault::new();
        vault.insert("gh", "ghp_REAL");
        vault.set_scope("gh", ScopeRule::tools(["create_issue"]));

        assert_eq!(
            vault.resolve("gh", Some("any-agent"), "create_issue"),
            Resolved::Allowed("ghp_REAL"),
            "the listed tool resolves with ANY agent: the rule names no agents clause"
        );
        assert_eq!(
            vault.resolve("gh", Some("any-agent"), "delete_repo"),
            Resolved::ScopeDenied,
            "an unlisted tool must be refused"
        );
        assert_eq!(
            vault.resolve("gh", Some("any-agent"), ""),
            Resolved::ScopeDenied,
            "an unknown (empty) tool name never satisfies a tool-constrained rule"
        );
    }

    #[test]
    fn a_rule_with_both_clauses_requires_both_to_match() {
        let mut vault = SecretVault::new();
        vault.insert("gh", "ghp_REAL");
        vault.set_scope(
            "gh",
            ScopeRule::agents_and_tools(["agent-a"], ["create_issue"]),
        );

        assert_eq!(
            vault.resolve("gh", Some("agent-a"), "create_issue"),
            Resolved::Allowed("ghp_REAL")
        );
        assert_eq!(
            vault.resolve("gh", Some("agent-a"), "delete_repo"),
            Resolved::ScopeDenied,
            "right agent, wrong tool must still refuse"
        );
        assert_eq!(
            vault.resolve("gh", Some("agent-z"), "create_issue"),
            Resolved::ScopeDenied,
            "right tool, wrong agent must still refuse"
        );
    }

    #[test]
    fn unscoped_count_and_names_cover_only_secrets_with_no_rule() {
        let mut vault = SecretVault::new();
        vault.insert("scoped", "s1");
        vault.insert("also_scoped", "s2");
        vault.insert("open", "s3");
        vault.set_scope("scoped", ScopeRule::agents(["a"]));
        vault.set_scope("also_scoped", ScopeRule::tools(["t"]));

        assert_eq!(vault.unscoped_count(), 1);
        assert_eq!(vault.unscoped_names(), vec!["open"]);
    }

    // --- inject_secrets end to end (still core-level, no HTTP) ------------

    #[test]
    fn inject_secrets_refuses_a_scope_denied_handle_and_reports_it_distinctly() {
        let mut vault = SecretVault::new();
        vault.insert("gh", "ghp_REAL");
        vault.set_scope("gh", ScopeRule::agents(["agent-a"]));
        let mut v = json!({ "auth": "Bearer {{secret:gh}}" });

        let inj = inject_secrets(&mut v, &vault, Some("agent-mallory"), "any_tool");
        assert_eq!(inj.replaced, 0);
        assert!(
            inj.missing.is_empty(),
            "the secret exists, it is not missing"
        );
        assert_eq!(inj.refused, vec!["gh".to_string()]);
        assert_eq!(
            v["auth"], "Bearer {{secret:gh}}",
            "the handle must stay verbatim, never a substituted or empty value"
        );
    }

    #[test]
    fn inject_secrets_still_injects_for_the_allowed_pairing() {
        let mut vault = SecretVault::new();
        vault.insert("gh", "ghp_REAL");
        vault.set_scope("gh", ScopeRule::agents(["agent-a"]));
        let mut v = json!({ "auth": "Bearer {{secret:gh}}" });

        let inj = inject_secrets(&mut v, &vault, Some("agent-a"), "any_tool");
        assert_eq!(inj.replaced, 1);
        assert!(inj.refused.is_empty());
        assert_eq!(v["auth"], "Bearer ghp_REAL");
    }

    // --- parse_scope_spec --------------------------------------------------

    #[test]
    fn a_blank_spec_is_not_configured() {
        for spec in ["", "   ", "\n"] {
            assert_eq!(
                parse_scope_spec(spec),
                Ok(HashMap::new()),
                "blank spec {spec:?} must mean 'not configured', not an error"
            );
        }
    }

    #[test]
    fn parses_agents_and_tools_clauses() {
        let rules = parse_scope_spec("gh=agents:a1|a2;tools:t1|t2,stripe=agents:billing")
            .expect("valid spec");
        assert_eq!(rules.len(), 2);
        assert_eq!(
            rules["gh"],
            ScopeRule::agents_and_tools(["a1", "a2"], ["t1", "t2"])
        );
        assert_eq!(rules["stripe"], ScopeRule::agents(["billing"]));
    }

    #[test]
    fn clause_order_and_surrounding_whitespace_do_not_matter() {
        let rules = parse_scope_spec(" gh = tools : t1 | t2 ; agents : a1 ").expect("valid spec");
        assert_eq!(
            rules["gh"],
            ScopeRule::agents_and_tools(["a1"], ["t1", "t2"])
        );
    }

    #[test]
    fn a_malformed_entry_fails_the_whole_spec() {
        // Each of these is a plausible operator typo. Unlike ClientKeys, NONE
        // may be read as "skip this entry, keep the rest": a dropped rule
        // here would silently unscope the secret it names.
        for spec in [
            "gh",                       // no '='
            "=agents:a1",               // no secret name
            "gh=",                      // no clause at all
            "gh=agents:",               // clause with no values
            "gh=bogus:a1",              // unknown clause label
            "gh=agents:a1;agents:a2",   // repeated clause
            "gh=agents:a1;;tools:t1",   // stray ';'
            "gh=agents:a1,gh=tools:t1", // same secret scoped twice
        ] {
            assert!(
                parse_scope_spec(spec).is_err(),
                "spec {spec:?} must be rejected outright, never partially applied"
            );
        }
    }

    #[test]
    fn the_invalid_spec_error_names_tokenfuse_mcp_secret_scopes() {
        let err = parse_scope_spec("gh=bogus:a1").unwrap_err();
        let msg = err.to_string();
        assert!(msg.contains("TOKENFUSE_MCP_SECRET_SCOPES"), "{msg:?}");
        assert!(
            msg.contains("bogus"),
            "the error should name the offending clause: {msg:?}"
        );
    }

    #[test]
    fn apply_scope_spec_wires_a_parsed_spec_onto_the_vault() {
        let mut vault = SecretVault::new();
        vault.insert("gh", "ghp_REAL");
        vault
            .apply_scope_spec("gh=agents:agent-a")
            .expect("valid spec");
        assert_eq!(
            vault.resolve("gh", Some("agent-a"), ""),
            Resolved::Allowed("ghp_REAL")
        );
        assert_eq!(
            vault.resolve("gh", Some("agent-z"), ""),
            Resolved::ScopeDenied
        );
    }

    #[test]
    fn apply_scope_spec_propagates_a_parse_error_and_touches_nothing() {
        let mut vault = SecretVault::new();
        vault.insert("gh", "ghp_REAL");
        assert!(vault.apply_scope_spec("gh=bogus:x").is_err());
        // The vault must be left exactly as it was: unscoped, resolvable.
        assert_eq!(vault.unscoped_count(), 1);
        assert_eq!(
            vault.resolve("gh", Some("anyone"), ""),
            Resolved::Allowed("ghp_REAL")
        );
    }
}
