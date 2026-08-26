//! Agent-firewall configuration: how tools map to taint labels and capabilities,
//! and the rules that deny capabilities under taint.

use std::collections::HashMap;
use tokenfuse_core::taint::{FirewallMode, TaintRule};

#[derive(Debug, Clone, Default)]
pub struct FirewallConfig {
    pub mode: FirewallMode,
    /// Whether to scan tool results for instruction-shaped text
    /// (`tokenfuse_core::injection`). On unless a policy file says otherwise.
    ///
    /// Off means off: no scan, no label, no cost. It is a field rather than
    /// only a rule an operator can decline to write, because the detector's
    /// label gets a floor rule when nothing else denies it (see
    /// [`FirewallConfig::from_json`]), and a floor with no exit is a floor
    /// somebody escapes by turning the whole firewall off.
    pub detect_injection: bool,
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
                    // A tool result that read like an instruction, whatever
                    // the source map says about the tool that produced it.
                    // In the starter policy rather than left for an operator
                    // to add, because a label nothing denies is a label that
                    // does nothing, and the case this covers is one the source
                    // map cannot: a source they classified as TRUSTED carrying
                    // something the world put in it.
                    tokenfuse_core::injection::SUSPECTED_INJECTION.into(),
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
            detect_injection: true,
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
fn injection_rule() -> TaintRule {
    TaintRule {
        name: "no-action-after-an-injection-signal".into(),
        when_any: vec![tokenfuse_core::injection::SUSPECTED_INJECTION.into()],
        deny: vec!["exec".into(), "write".into(), "network_egress".into()],
    }
}

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
    /// Whether `tokenfuse_core::injection` runs. Absent means yes.
    #[serde(default)]
    detect_injection: Option<bool>,
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

        // Two floors, and anti-exfiltration goes in LAST so it ends up first.
        // They can both match only for a run carrying secrets AND an injection
        // signal that tries to send data out, and first match wins, so the
        // order decides which rule the record names. `anti-exfiltration` is the
        // one docs/07 B.9 locks and the one an auditor comes looking for; the
        // injection signal is still on the same event, in `data.signals`.
        // The detector's label gets a rule when nothing else denies it, and the
        // reasoning is different from anti-exfiltration's: that one is locked
        // by docs/07 B.9, this one is a judgement.
        //
        // `@claude` 2026-08-26. A policy file written before this detector
        // existed COULD NOT have mentioned the label, so reading its silence as
        // consent would give every operator who already wrote a policy a
        // detector that produces a label nothing acts on, which is the exact
        // case it exists for: their source map says a tool is trusted, and the
        // document it returned is not. They did not write "and if a page tells
        // you to ignore your instructions, proceed".
        //
        // The exit is `"detect_injection": false`, which turns the scan off
        // entirely rather than leaving a label with nothing behind it. A rule
        // of their own naming the label also wins, so narrowing it is one line.
        let detect_injection = file.detect_injection.unwrap_or(true);
        ensure_floors(mode, detect_injection, &mut rules);

        Ok(FirewallConfig {
            mode,
            detect_injection,
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
    // The floors again, because the env var can raise the mode to enforce after
    // a file was parsed in shadow: the guarantee is about the mode in effect,
    // not about how the config arrived at it.
    //
    // This called ONE of the two floors until 2026-08-26, and the sentence
    // above was already the correct rule while the code below applied it to
    // half of what it governed. `ensure_floors` is now the only place either
    // floor is decided, so the next floor added is added once.
    ensure_floors(cfg.mode, cfg.detect_injection, &mut cfg.rules);
    cfg
}

/// Put the floors under a config, for the mode IN EFFECT.
///
/// One function and not two blocks, because it is called from two places that
/// must not disagree and did: `from_json` inserted both floors, `from_env`
/// re-inserted one of them after the environment raised a shadow file to
/// enforce, and a policy naming neither floor then ran in enforce mode with the
/// injection detector on, the label attached, and nothing denying it. Which is
/// the case the injection floor exists for.
///
/// Idempotent by construction: each floor is skipped when a rule already reads
/// its label, so a config that has been through here twice is the same config,
/// and an operator's own narrower rule still wins.
fn ensure_floors(mode: FirewallMode, detect_injection: bool, rules: &mut Vec<TaintRule>) {
    if mode != FirewallMode::Enforce {
        // Shadow records and refuses nothing, so a floor there would be a rule
        // that cannot fire. Off is off.
        return;
    }
    if detect_injection
        && !rules.iter().any(|r| {
            r.when_any
                .iter()
                .any(|l| l == tokenfuse_core::injection::SUSPECTED_INJECTION)
        })
    {
        rules.insert(0, injection_rule());
    }
    if !rules
        .iter()
        .any(|r| r.name == anti_exfiltration_rule().name)
    {
        rules.insert(0, anti_exfiltration_rule());
    }
}

#[cfg(test)]
mod config_tests {
    use super::*;

    /// Every test in this module that touches `TOKENFUSE_FIREWALL` takes this
    /// first. Rust runs tests as threads of ONE process, so the environment is
    /// shared state, and two tests setting the same variable interleave. That
    /// is not hypothetical: the first version of the floor test below passed
    /// alone and failed in the workspace run, for exactly this reason and not
    /// for anything about the firewall.
    static ENV: std::sync::Mutex<()> = std::sync::Mutex::new(());

    fn cfg(json: &str) -> FirewallConfig {
        FirewallConfig::from_json(json).expect("a valid config")
    }

    /// Both floors answer to the mode IN EFFECT, not to how the config got there.
    ///
    /// `from_env` re-inserted the anti-exfiltration floor after the env var
    /// raised a shadow file to enforce, and did not re-insert the injection
    /// floor. The comment beside it stated the guarantee correctly and applied
    /// it to one floor of two.
    ///
    /// So a policy file saying `"mode":"shadow"` with no rule naming
    /// `suspected_injection`, plus `TOKENFUSE_FIREWALL=enforce`, produced:
    /// enforce mode, the detector on, the label attached to a tainted run, and
    /// nothing that denies it. Which is verbatim the case the injection floor
    /// exists for, in the one mode where it matters.
    ///
    /// Asserted against `ensure_floors` directly rather than through the
    /// environment, because the defect was never about parsing: it was that
    /// two call sites decided the floors and only one of them decided both.
    /// One function is now the only place either is decided, and this is that
    /// function asked the question the env path asks it.
    #[test]
    fn both_floors_answer_to_the_mode_in_effect() {
        // What a shadow policy naming neither floor parses to.
        let shadow = FirewallConfig::from_json(
            r#"{"mode":"shadow","sources":{"web_search":["web"]},"rules":[]}"#,
        )
        .expect("a valid config");
        assert_eq!(shadow.mode, FirewallMode::Shadow);
        assert!(
            shadow.rules.is_empty(),
            "shadow gets no floor: nothing can fire"
        );

        // Now the environment raises it, which is what `from_env` does after
        // parsing, and what it did to only one floor.
        let mut rules = shadow.rules.clone();
        ensure_floors(FirewallMode::Enforce, shadow.detect_injection, &mut rules);

        assert!(
            rules
                .iter()
                .any(|r| r.name == anti_exfiltration_rule().name),
            "the anti-exfiltration floor was already held"
        );
        assert!(
            rules.iter().any(|r| r
                .when_any
                .iter()
                .any(|l| l == tokenfuse_core::injection::SUSPECTED_INJECTION)),
            "enforce mode, the detector on, the label attached, and nothing denies it. \
             That is the case the injection floor exists for, and it was missing because \
             the file parsed in shadow and only one of the two floors was re-checked."
        );

        // Idempotent: through here twice is the same config, or `from_env`
        // would double every floor on a file that already had them.
        let before = rules.len();
        ensure_floors(FirewallMode::Enforce, shadow.detect_injection, &mut rules);
        assert_eq!(before, rules.len(), "a second pass added a floor again");

        // And an operator who turned the scan off does not get a rule for a
        // label nothing will ever attach.
        let mut off = Vec::new();
        ensure_floors(FirewallMode::Enforce, false, &mut off);
        assert!(!off.iter().any(|r| r
            .when_any
            .iter()
            .any(|l| l == tokenfuse_core::injection::SUSPECTED_INJECTION)));
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
        let _guard = ENV.lock().unwrap_or_else(|e| e.into_inner());
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
        // Their rule, plus both floors: this one and the injection rule that
        // arrived beside it. Asserted by NAME rather than by count, because a
        // count breaks every time a floor is added for a good reason.
        let names: Vec<&str> = c.rules.iter().map(|r| r.name.as_str()).collect();
        assert!(
            names.contains(&"mine") && names.contains(&"anti-exfiltration"),
            "{names:?}"
        );
        assert_eq!(
            c.rules[0].name, "anti-exfiltration",
            "and it judges first: it is the one B.9 locks and the one an \
             auditor comes looking for"
        );
        assert!(c.rules[0].deny.contains(&"network_egress".to_string()));

        // It really refuses, not merely appears in the list.
        let labels: tokenfuse_core::taint::Labels = ["secrets".to_string()].into_iter().collect();
        let requested: std::collections::BTreeSet<String> =
            ["network_egress".to_string()].into_iter().collect();
        assert!(tokenfuse_core::taint::evaluate(&labels, &requested, &c.rules).is_some());
    }

    #[test]
    fn a_policy_written_before_the_detector_existed_still_acts_on_its_label() {
        // The case the detector exists for, and the one an existing policy
        // cannot have covered: their source map says a tool is trusted, and
        // the document it returned is not. Reading a policy's SILENCE about a
        // label that did not exist when it was written as consent would give
        // every such operator a detector producing a label nothing acts on.
        let c = cfg(r#"{
              "mode": "enforce",
              "rules": [{"name": "mine", "when_any": ["web"], "deny": ["exec"]}]
            }"#);
        assert!(c.detect_injection);
        let names: Vec<&str> = c.rules.iter().map(|r| r.name.as_str()).collect();
        assert!(
            names.contains(&"no-action-after-an-injection-signal"),
            "{names:?}"
        );

        let labels: tokenfuse_core::taint::Labels =
            [tokenfuse_core::injection::SUSPECTED_INJECTION.to_string()]
                .into_iter()
                .collect();
        let requested: std::collections::BTreeSet<String> =
            ["exec".to_string()].into_iter().collect();
        assert!(tokenfuse_core::taint::evaluate(&labels, &requested, &c.rules).is_some());
    }

    #[test]
    fn an_operators_own_rule_about_the_label_wins_over_the_floor() {
        // The floor is there because silence is not consent. A rule that
        // MENTIONS the label is not silence, so narrowing it is one line and
        // nothing is added behind their back.
        let c = cfg(r#"{
              "mode": "enforce",
              "rules": [{
                "name": "injections-may-not-write",
                "when_any": ["suspected_injection"],
                "deny": ["write"]
              }]
            }"#);
        let names: Vec<&str> = c.rules.iter().map(|r| r.name.as_str()).collect();
        assert!(
            !names.contains(&"no-action-after-an-injection-signal"),
            "{names:?}"
        );

        // And theirs really is narrower: exec is theirs to allow.
        let labels: tokenfuse_core::taint::Labels =
            [tokenfuse_core::injection::SUSPECTED_INJECTION.to_string()]
                .into_iter()
                .collect();
        let exec: std::collections::BTreeSet<String> = ["exec".to_string()].into_iter().collect();
        assert!(tokenfuse_core::taint::evaluate(&labels, &exec, &c.rules).is_none());
    }

    #[test]
    fn the_detector_has_an_off_switch_that_is_really_off() {
        // A floor with no exit is a floor somebody escapes by turning the whole
        // firewall off, which costs them the coarse model as well. `false`
        // means no scan, no label and no rule, rather than a label with nothing
        // behind it.
        let c = cfg(r#"{
              "mode": "enforce",
              "detect_injection": false,
              "rules": [{"name": "mine", "when_any": ["web"], "deny": ["exec"]}]
            }"#);
        assert!(!c.detect_injection);
        let names: Vec<&str> = c.rules.iter().map(|r| r.name.as_str()).collect();
        assert!(
            !names.contains(&"no-action-after-an-injection-signal"),
            "{names:?}"
        );
    }

    #[test]
    fn shadow_does_not_get_the_injection_rule_forced_on_it_either() {
        // Same reasoning as anti-exfiltration's: shadow is the mode an operator
        // runs to learn what THEIR policy does, and a week's numbers describing
        // a policy they did not write is worse than no week.
        let c = cfg(r#"{
              "mode": "shadow",
              "rules": [{"name": "mine", "when_any": ["web"], "deny": ["exec"]}]
            }"#);
        assert_eq!(c.rules.len(), 1);
        assert!(
            c.detect_injection,
            "the scan still runs; only the forced rule is withheld, so the week \
             counts what would have happened"
        );
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
