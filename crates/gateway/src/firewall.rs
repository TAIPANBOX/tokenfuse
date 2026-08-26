//! Agent-firewall configuration: how tools map to taint labels and capabilities,
//! and the rules that deny capabilities under taint.

use std::collections::HashMap;
use tokenfuse_core::taint::{FirewallMode, TaintRule};

#[derive(Debug, Clone, Default)]
pub struct FirewallConfig {
    pub mode: FirewallMode,
    /// tool name → the taint labels its output carries (docs/07 B.2).
    pub sources: HashMap<String, Vec<String>>,
    /// tool name → capability it exercises.
    pub capabilities: HashMap<String, String>,
    pub rules: Vec<TaintRule>,
}

impl FirewallConfig {
    /// Firewall off — no taint tracking, no blocks.
    pub fn disabled() -> Self {
        FirewallConfig::default()
    }

    /// A sensible starter policy: untrusted input (web/file/unknown) blocks
    /// exec/write/egress; a context that read secrets can't send data out.
    pub fn defaults(mode: FirewallMode) -> Self {
        let sources = HashMap::from([
            ("web_search".to_string(), vec!["web".to_string()]),
            ("fetch_url".to_string(), vec!["web".to_string()]),
            ("browse".to_string(), vec!["web".to_string()]),
            ("read_email".to_string(), vec!["email".to_string()]),
            ("read_upload".to_string(), vec!["file".to_string()]),
            ("read_file".to_string(), vec!["file".to_string()]),
            ("vault_read".to_string(), vec!["secrets".to_string()]),
            ("read_secret".to_string(), vec!["secrets".to_string()]),
        ]);
        let capabilities = HashMap::from([
            ("run_shell".to_string(), "exec".to_string()),
            ("exec".to_string(), "exec".to_string()),
            ("bash".to_string(), "exec".to_string()),
            ("write_file".to_string(), "write".to_string()),
            ("db_write".to_string(), "write".to_string()),
            ("deploy".to_string(), "write".to_string()),
            ("send_email".to_string(), "network_egress".to_string()),
            ("http_post".to_string(), "network_egress".to_string()),
            ("send_message".to_string(), "network_egress".to_string()),
        ]);
        let rules = vec![
            TaintRule {
                // The names are docs/07 B.6's, verbatim. A rule renamed later
                // silently splits every count somebody has been keeping, so
                // they are treated as wire strings, not labels.
                name: "no-exec-after-untrusted".into(),
                when_any: vec![
                    "web".into(),
                    "email".into(),
                    "file".into(),
                    "unclassified".into(),
                ],
                deny: vec!["exec".into(), "write".into(), "network_egress".into()],
            },
            TaintRule {
                name: "anti-exfiltration".into(),
                when_any: vec!["secrets".into()],
                deny: vec!["network_egress".into()],
            },
        ];
        FirewallConfig {
            mode,
            sources,
            capabilities,
            rules,
        }
    }
}

/// The rule docs/07 B.9 says cannot be turned off, kept in one place so the
/// loader and the built-in policy cannot describe it differently.
///
/// Secrets in the context plus an outbound capability is the exfiltration
/// chain the whole taint model exists for. Every other rule is a judgement an
/// operator is invited to tune.
fn anti_exfiltration_rule() -> TaintRule {
    TaintRule {
        name: "anti-exfiltration".into(),
        when_any: vec!["secrets".into()],
        deny: vec!["network_egress".into()],
    }
}

/// Why a policy file was refused, in terms of the file rather than of serde.
#[derive(Debug, thiserror::Error)]
pub enum FirewallConfigError {
    #[error("firewall policy is not valid JSON: {0}")]
    NotJson(#[source] serde_json::Error),
    #[error("firewall policy field `mode` is `{0}`; accepted values are off, shadow, enforce")]
    BadMode(String),
    #[error("firewall policy rule #{0} has no `name`; a rule that cannot be named cannot be counted, so it is not accepted")]
    UnnamedRule(usize),
    #[error("firewall policy rule `{0}` has an empty `{1}`; a rule that matches nothing or denies nothing never fires")]
    EmptyRuleField(String, &'static str),
    #[error("firewall policy at {0} could not be read: {1}")]
    Unreadable(String, String),
}

/// The wire shape of a policy file. Mirrors docs/07 B.2/B.5/B.6.
///
/// JSON and not the YAML the spec's examples are written in: `serde_yaml` has
/// been unmaintained since 2024, and taking an abandoned parser for the config
/// of a security control is a worse trade than asking an operator to write
/// braces. It is also what this repository already does for the other artifact
/// it pins, `crates/core/src/mcp.rs`'s tool lock. The SHAPE is the spec's.
#[derive(Debug, serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct PolicyFile {
    #[serde(default)]
    mode: Option<String>,
    #[serde(default)]
    sources: HashMap<String, Vec<String>>,
    #[serde(default)]
    capabilities: HashMap<String, String>,
    #[serde(default)]
    rules: Vec<PolicyRule>,
}

#[derive(Debug, serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct PolicyRule {
    #[serde(default)]
    name: Option<String>,
    #[serde(default)]
    when_any: Vec<String>,
    #[serde(default)]
    deny: Vec<String>,
}

impl FirewallConfig {
    /// Parse a policy file.
    ///
    /// Three decisions worth stating, each with a test named after it:
    ///
    /// - **A file REPLACES the built-in starter policy, it does not merge into
    ///   it.** Merging would mean an operator who deletes a rule still has it,
    ///   which is the kind of surprise a security control cannot afford. `{}`
    ///   therefore means a firewall that classifies nothing and refuses
    ///   nothing, not the starter policy.
    /// - **Except the one floor.** docs/07 B.9 locks anti-exfiltration on in
    ///   enforce mode, so a file that omits it gets it back, FIRST in the
    ///   order. Not in shadow: shadow is the mode an operator runs to learn
    ///   what their own policy does, and a rule they did not write would make
    ///   that week's numbers describe somebody else's policy.
    /// - **`deny_unknown_fields`.** A misspelled key is the failure this whole
    ///   loader is most likely to meet, and silently ignoring it leaves an
    ///   operator certain a rule is live when it is not.
    pub fn from_json(text: &str) -> Result<FirewallConfig, FirewallConfigError> {
        let file: PolicyFile = serde_json::from_str(text).map_err(FirewallConfigError::NotJson)?;

        let mode = match file.mode.as_deref() {
            None | Some("off") => FirewallMode::Off,
            Some("shadow") => FirewallMode::Shadow,
            Some("enforce") => FirewallMode::Enforce,
            Some(other) => return Err(FirewallConfigError::BadMode(other.to_string())),
        };

        let mut rules = Vec::with_capacity(file.rules.len() + 1);
        for (i, r) in file.rules.into_iter().enumerate() {
            let name = r.name.ok_or(FirewallConfigError::UnnamedRule(i))?;
            if r.when_any.is_empty() {
                return Err(FirewallConfigError::EmptyRuleField(name, "when_any"));
            }
            if r.deny.is_empty() {
                return Err(FirewallConfigError::EmptyRuleField(name, "deny"));
            }
            rules.push(TaintRule {
                name,
                when_any: r.when_any,
                deny: r.deny,
            });
        }

        if mode == FirewallMode::Enforce
            && !rules
                .iter()
                .any(|r| r.name == anti_exfiltration_rule().name)
        {
            rules.insert(0, anti_exfiltration_rule());
        }

        Ok(FirewallConfig {
            mode,
            sources: file.sources,
            capabilities: file.capabilities,
            rules,
        })
    }

    /// Read and parse a policy file from disk.
    pub fn from_path(path: &str) -> Result<FirewallConfig, FirewallConfigError> {
        let text = std::fs::read_to_string(path)
            .map_err(|e| FirewallConfigError::Unreadable(path.to_string(), e.to_string()))?;
        FirewallConfig::from_json(&text)
    }
}

/// Build from the environment.
///
/// `TOKENFUSE_FIREWALL_CONFIG=<path>` loads a policy file; without it, the
/// built-in starter policy. `TOKENFUSE_FIREWALL = off | shadow | enforce` sets
/// the mode and WINS over the file's own `mode`: turning enforcement down is
/// the thing an operator does in a hurry, and it should not require editing a
/// file they may not have write access to.
///
/// # The default is `shadow`, and it was `off` until 2026-08-26
///
/// docs/07 B.9 has always named shadow as the on-ramp: "shadow mode for the
/// remaining rules during the first week". The default contradicted its own
/// specification, so out of the box this subsystem protected nothing and, worse,
/// measured nothing, and every argument for turning it on had to be made without
/// a single number from the fleet it would be turned on for.
///
/// `shadow` and not `enforce`, deliberately. Shadow refuses nothing: no request
/// that worked yesterday fails today, which is what makes this a default rather
/// than a breaking change. What it does is WRITE, and it only became worth
/// defaulting to on the day it started writing: before `taint_shadow` shipped,
/// a would-block set a response header and emitted nothing, so defaulting to
/// shadow then would have turned on a cost with no output.
///
/// What it costs a box that wanted nothing: taint is computed per call from a
/// request body already parsed for other reasons, and two event types are
/// written. `taint_raised` fires once per label per run because taint is
/// monotonic, and `taint_shadow` only when a rule actually matches a dangerous
/// action, which on a healthy fleet is never. An operator who wants silence
/// sets `TOKENFUSE_FIREWALL=off` and gets exactly what they had.
///
/// **A named config that cannot be read or parsed aborts the process.** The
/// alternative is a gateway running a starter policy while its operator
/// believes their own rules are live, and a security control that silently did
/// not load is worse than one that is plainly off.
pub fn from_env() -> FirewallConfig {
    let mut cfg = match std::env::var("TOKENFUSE_FIREWALL_CONFIG") {
        Ok(path) if !path.trim().is_empty() => match FirewallConfig::from_path(&path) {
            Ok(c) => c,
            Err(e) => {
                eprintln!("tokenfuse: refusing to start: {e}");
                std::process::exit(2);
            }
        },
        // SHADOW, not off, since 2026-08-26. See the note on this function.
        _ => FirewallConfig::defaults(FirewallMode::Shadow),
    };
    match std::env::var("TOKENFUSE_FIREWALL").as_deref() {
        Ok("enforce") => cfg.mode = FirewallMode::Enforce,
        Ok("shadow") => cfg.mode = FirewallMode::Shadow,
        Ok("off") => cfg.mode = FirewallMode::Off,
        _ => {}
    }
    // The floor again, because the env var can raise the mode to enforce after
    // a file was parsed in shadow: the guarantee is about the mode in effect,
    // not about how the config arrived at it.
    if cfg.mode == FirewallMode::Enforce
        && !cfg
            .rules
            .iter()
            .any(|r| r.name == anti_exfiltration_rule().name)
    {
        cfg.rules.insert(0, anti_exfiltration_rule());
    }
    cfg
}

#[cfg(test)]
mod config_tests {
    use super::*;

    // Every test below was run against the firewall as it stood before the
    // JSON loader existed and failed there, most of them because
    // `FirewallConfig::from_json` did not exist at all. They are kept as the
    // record of what the loader is FOR, not only that it parses.

    fn cfg(json: &str) -> FirewallConfig {
        FirewallConfig::from_json(json).expect("a valid config")
    }

    #[test]
    fn the_default_is_shadow_so_a_box_that_asked_for_nothing_still_measures() {
        // Red against every version before 2026-08-26. The default contradicted
        // docs/07 B.9, which names shadow as the on-ramp, so out of the box this
        // subsystem protected nothing AND measured nothing, and the case for
        // turning it on had to be made with no numbers from the fleet it was
        // about.
        //
        // Shadow and not enforce: shadow refuses nothing, so no request that
        // worked yesterday fails today. That is what makes it a default rather
        // than a breaking change.
        let saved = (
            std::env::var("TOKENFUSE_FIREWALL").ok(),
            std::env::var("TOKENFUSE_FIREWALL_CONFIG").ok(),
        );
        unsafe {
            std::env::remove_var("TOKENFUSE_FIREWALL");
            std::env::remove_var("TOKENFUSE_FIREWALL_CONFIG");
        }
        let c = from_env();
        assert_eq!(c.mode, FirewallMode::Shadow);
        assert!(
            !c.rules.is_empty() && !c.sources.is_empty(),
            "with the starter policy behind it, or the mode is on and judges nothing"
        );

        // And the off switch still means off, or this default has no exit.
        unsafe { std::env::set_var("TOKENFUSE_FIREWALL", "off") };
        assert_eq!(from_env().mode, FirewallMode::Off);

        unsafe {
            match saved.0 {
                Some(v) => std::env::set_var("TOKENFUSE_FIREWALL", v),
                None => std::env::remove_var("TOKENFUSE_FIREWALL"),
            }
            if let Some(v) = saved.1 {
                std::env::set_var("TOKENFUSE_FIREWALL_CONFIG", v);
            }
        }
    }

    #[test]
    fn a_policy_can_be_changed_without_a_rebuild() {
        // The point of the whole file. Before this, adding one tool to the
        // source map meant recompiling and redeploying the gateway, so in
        // practice nobody ever adjusted the firewall to their own tools and
        // it stayed on a starter policy that named nine tool names.
        let c = cfg(r#"{
              "mode": "enforce",
              "sources": { "crm_lookup": ["customer_data", "pii"] },
              "capabilities": { "wire_transfer": "financial" },
              "rules": [{
                "name": "no-payments-after-customer-data",
                "when_any": ["customer_data"],
                "deny": ["financial"]
              }]
            }"#);
        assert_eq!(c.mode, FirewallMode::Enforce);
        let labels =
            tokenfuse_core::taint::labels_for_tools(&["crm_lookup".to_string()], &c.sources);
        assert!(labels.contains("customer_data") && labels.contains("pii"));

        let requested = tokenfuse_core::taint::capabilities_for_tools(
            &["wire_transfer".to_string()],
            &c.capabilities,
        );
        let v = tokenfuse_core::taint::evaluate(&labels, &requested, &c.rules)
            .expect("the operator's own rule fires");
        assert_eq!(v.rule, "no-payments-after-customer-data");
    }

    #[test]
    fn one_tool_can_carry_more_than_one_label() {
        // docs/07 B.2 has always specified `labels: [...]`; the built-in map
        // was `tool -> ONE label`, so a file read that is both an upload and
        // PII could only ever be described as one of them.
        let c = cfg(r#"{"sources": {"read_patient_file": ["file", "phi"]}}"#);
        let labels =
            tokenfuse_core::taint::labels_for_tools(&["read_patient_file".to_string()], &c.sources);
        assert_eq!(labels.len(), 2);
    }

    #[test]
    fn anti_exfiltration_cannot_be_dropped_in_enforce_mode() {
        // docs/07 B.9, locked in: "anti-exfiltration is enabled out of the
        // box and cannot be disabled in enforce mode". A config file is
        // exactly how somebody would disable it, by accident far more often
        // than on purpose: write a file to add one rule of your own, and the
        // replacement semantics quietly take the other two away.
        let c = cfg(r#"{
              "mode": "enforce",
              "rules": [{"name": "mine", "when_any": ["web"], "deny": ["exec"]}]
            }"#);
        assert_eq!(c.rules.len(), 2, "the operator's rule, plus the floor");
        assert_eq!(c.rules[0].name, "anti-exfiltration", "and it goes first");
        assert!(c.rules[0].deny.contains(&"network_egress".to_string()));

        // It really refuses, not merely appears in the list.
        let labels: tokenfuse_core::taint::Labels = ["secrets".to_string()].into_iter().collect();
        let requested: std::collections::BTreeSet<String> =
            ["network_egress".to_string()].into_iter().collect();
        assert!(tokenfuse_core::taint::evaluate(&labels, &requested, &c.rules).is_some());
    }

    #[test]
    fn shadow_mode_does_not_get_the_floor_forced_on_it() {
        // The other half, so the guarantee stays honest about its own scope.
        // B.9 says enforce; shadow is the mode an operator runs to LEARN what
        // their policy does, and silently adding a rule they did not write
        // would make that week's numbers describe a policy that is not theirs.
        let c = cfg(r#"{
              "mode": "shadow",
              "rules": [{"name": "mine", "when_any": ["web"], "deny": ["exec"]}]
            }"#);
        assert_eq!(c.rules.len(), 1);
        assert_eq!(c.rules[0].name, "mine");
    }

    #[test]
    fn a_config_that_cannot_be_read_stops_the_box_rather_than_falling_back() {
        // The failure mode this exists to prevent: a typo in the policy file
        // leaves the gateway running on the built-in starter policy while its
        // operator believes their own rules are live. A security control that
        // silently did not load is worse than one that is plainly off.
        assert!(FirewallConfig::from_json("{ not json").is_err());
        assert!(FirewallConfig::from_json(r#"{"mode": "aggressive"}"#).is_err());
        assert!(
            FirewallConfig::from_json(r#"{"rules": [{"when_any": ["web"], "deny": ["exec"]}]}"#)
                .is_err(),
            "a rule with no name cannot be counted later, so it is not a rule"
        );
    }

    #[test]
    fn the_error_says_what_to_fix() {
        // An operator holding a rejected policy file needs the field, not
        // "invalid config". Named because the first version said the latter.
        let e = FirewallConfig::from_json(r#"{"mode": "aggressive"}"#).unwrap_err();
        let text = e.to_string();
        assert!(text.contains("mode"), "{text}");
        assert!(text.contains("aggressive"), "{text}");
        assert!(
            text.contains("off") && text.contains("shadow") && text.contains("enforce"),
            "the accepted values, so the fix needs no documentation: {text}"
        );
    }

    #[test]
    fn an_empty_config_is_the_off_switch_not_the_starter_policy() {
        // `{}` means "no sources, no capabilities, no rules": a firewall that
        // classifies nothing and refuses nothing. It must NOT silently become
        // the built-in starter policy, or an operator disabling their rules
        // gets somebody else's.
        let c = cfg("{}");
        assert_eq!(c.mode, FirewallMode::Off);
        assert!(c.sources.is_empty() && c.capabilities.is_empty() && c.rules.is_empty());
    }
}
