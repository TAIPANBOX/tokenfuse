//! Agent-firewall configuration: how tools map to taint labels and capabilities,
//! and the rules that deny capabilities under taint.

use std::collections::{HashMap, HashSet};
use std::sync::Mutex;
use tokenfuse_core::taint::{
    is_unclassified, FirewallMode, TaintRule, NETWORK_READ_CAPABILITY, PRIVATE_DATA_LABELS,
    READ_TOOL_RULE, UNCLASSIFIED_CAPABILITY,
};

/// The taint label a run carries once its prompt holds the agent's memory
/// (CLAUDE.md invariant 95). Named once, here, because three places read it:
/// the starter source map, the starter rule and the floor.
pub const MEMORY_LABEL: &str = "memory";

/// The most distinct unclassified tool names one process will name in its log
/// (invariant 96). Past it a name is not remembered and so not named, and one
/// line says so the first time that happens.
pub const UNCLASSIFIED_NAME_CAP: usize = 256;

/// The longest tool name written to the log. Names come from the model's own
/// tool calls, so they are caller-chosen, and a name is never allowed to fill a
/// log line.
const LOGGED_NAME_CHARS: usize = 128;

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
    /// exec/write/egress and any tool the policy names nowhere; a context that
    /// read secrets can't send data out.
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
            // Engram's MCP memory tools that return stored content (invariant 95).
            // `remember` and `forget` return nothing a model reads back, so they
            // stay unmapped.
            ("recall".to_string(), vec![MEMORY_LABEL.to_string()]),
            ("why".to_string(), vec![MEMORY_LABEL.to_string()]),
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
            // A read is a network read as well as a source (design 4.2, invariant
            // 120): its request goes out, and its arguments can carry what the run
            // has read. Only the three reads the starter names are known. `http_get`
            // and `fetch` are named in neither map, so they are unclassified, and
            // after untrusted input the starter rule refuses them as any unmapped
            // tool is refused (invariant 115). Naming them here as network reads
            // would let them run after web input, which the starter rule does not deny.
            ("fetch_url".to_string(), NETWORK_READ_CAPABILITY.to_string()),
            ("browse".to_string(), NETWORK_READ_CAPABILITY.to_string()),
            (
                "web_search".to_string(),
                NETWORK_READ_CAPABILITY.to_string(),
            ),
            // Engram's `remember` writes to the agent's memory: a write, not an
            // unmapped tool (invariant 120).
            ("remember".to_string(), "write".to_string()),
        ]);
        let rules = vec![
            TaintRule {
                // The names are docs/07 B.6's, verbatim. A rule renamed later
                // silently splits every count somebody has been keeping, so
                // they are treated as wire strings, not labels.
                name: "no-exec-after-untrusted".into(),
                when_any: untrusted_labels(),
                deny: vec![
                    "exec".into(),
                    "write".into(),
                    "network_egress".into(),
                    // A tool the policy names nowhere (invariant 115). After
                    // untrusted input, `http_request` or an MCP tool outside the
                    // map is not presumed harmless: nobody said what it does.
                    tokenfuse_core::taint::UNCLASSIFIED_CAPABILITY.into(),
                ],
            },
            anti_exfiltration_rule(),
            read_tool_rule(),
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

/// The floor for memory (invariant 95), added in enforce mode when no rule of the
/// operator's reads the label. Same reasoning as [`injection_rule`]: a policy
/// file written before the label existed cannot have mentioned it, and reading
/// its silence as consent would leave a run that carries memory free to act.
fn memory_rule() -> TaintRule {
    TaintRule {
        name: "no-action-after-memory".into(),
        when_any: vec![MEMORY_LABEL.into()],
        deny: vec!["exec".into(), "write".into(), "network_egress".into()],
    }
}

/// The labels that make a run untrusted for the starter rule, and for the floor
/// that refuses an unmapped tool (invariant 120).
///
/// The injection label is in the starter rule because a label nothing denies is a
/// label that does nothing, and the case this covers is one the source map cannot
/// see: a source they classified as TRUSTED carrying something the world put in
/// it. The memory label is there because the agent's own memory is a place an
/// instruction can be planted in (invariant 95).
fn untrusted_labels() -> Vec<String> {
    vec![
        "web".into(),
        "email".into(),
        "file".into(),
        "unclassified".into(),
        tokenfuse_core::injection::SUSPECTED_INJECTION.into(),
        MEMORY_LABEL.into(),
    ]
}

/// The starter's anti-exfiltration rule, which is also the floor (docs/07 B.9).
///
/// A read after secrets is an exfiltration channel as much as a send: `fetch_url`
/// carries what it is asked to in its URL, so it is denied with `network_egress`
/// (design 4.2, invariant 120).
fn anti_exfiltration_rule() -> TaintRule {
    TaintRule {
        name: "anti-exfiltration".into(),
        when_any: vec!["secrets".into()],
        deny: vec!["network_egress".into(), NETWORK_READ_CAPABILITY.into()],
    }
}

/// The starter's read rule (design 4.2 point 3, invariant 120): after any private-data
/// label, a network read is judged on what its arguments carry, not refused on its
/// labels. `evaluate` never refuses it on labels alone; `read_argument_verdict` does.
fn read_tool_rule() -> TaintRule {
    TaintRule {
        name: READ_TOOL_RULE.into(),
        when_any: PRIVATE_DATA_LABELS.iter().map(|l| l.to_string()).collect(),
        deny: vec![NETWORK_READ_CAPABILITY.into()],
    }
}

/// The floor for an unmapped tool (design 4.2 point 4, invariant 120), added in
/// enforce mode when no rule of the operator's denies the `unclassified`
/// capability. Same reasoning as [`memory_rule`]: a policy file written before
/// this rule existed cannot have named it, and reading its silence as consent
/// would let an unmapped tool run after untrusted input.
///
/// Without the injection label when the scan is off: a label nothing attaches is
/// not one a rule should read.
fn unmapped_rule(detect_injection: bool) -> TaintRule {
    let mut when_any = untrusted_labels();
    if !detect_injection {
        when_any.retain(|l| l != tokenfuse_core::injection::SUSPECTED_INJECTION);
    }
    TaintRule {
        name: "no-unmapped-action-after-untrusted".into(),
        when_any,
        deny: vec![UNCLASSIFIED_CAPABILITY.into()],
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
/// file they may not have write access to. A value outside those three, in any
/// case other than the exact words, refuses to start (CLAUDE.md invariant 94);
/// see [`crate::defaults::firewall_mode_from`].
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
    // Read before the policy file, so a mistyped word refuses to start whatever
    // the file says (CLAUDE.md invariant 94). `None` is no override.
    let forced = crate::defaults::firewall_mode_from_env();
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
    if let Some(mode) = forced {
        cfg.mode = mode;
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
    // Every floor is decided from the operator's rules BEFORE any is inserted. The
    // unmapped floor names the injection and memory labels in its own `when_any`,
    // so checking after it went in would read those two floors as already present
    // and silently drop them.
    let injection = detect_injection
        && !rules.iter().any(|r| {
            r.when_any
                .iter()
                .any(|l| l == tokenfuse_core::injection::SUSPECTED_INJECTION)
        });
    let memory = !rules
        .iter()
        .any(|r| r.when_any.iter().any(|l| l == MEMORY_LABEL));
    let anti = !rules
        .iter()
        .any(|r| r.name == anti_exfiltration_rule().name);
    let unmapped = !rules
        .iter()
        .any(|r| r.deny.iter().any(|d| d == UNCLASSIFIED_CAPABILITY));
    // Each insert goes to the front, so the last one made is the first rule:
    // anti-exfiltration, memory, injection, unmapped.
    if unmapped {
        rules.insert(0, unmapped_rule(detect_injection));
    }
    if injection {
        rules.insert(0, injection_rule());
    }
    if memory {
        rules.insert(0, memory_rule());
    }
    if anti {
        rules.insert(0, anti_exfiltration_rule());
    }
}

/// The tool names this process has already named as unclassified (invariant 96).
#[derive(Debug, Default)]
pub struct UnclassifiedNames {
    named: HashSet<String>,
    cap_said: bool,
}

/// Name, once per process, each tool the policy leaves unclassified (invariant 96).
///
/// A tool whose output counts as untrusted only because the source map does not
/// name it is invisible to an operator: the refusal it causes says `unclassified`
/// and nothing says which tool. This writes one warning per distinct name, the
/// first time the name is seen, and says how to classify it.
///
/// Never in mode `off`: nothing is classified there, so nothing is unclassified.
///
/// Bounded. Past [`UNCLASSIFIED_NAME_CAP`] a new name is neither remembered nor
/// named, and one line says so the first time it happens, so an operator who
/// reads "256 names" knows the list is cut rather than complete. A name already
/// named is never named again, past the cap or before it.
pub fn name_unclassified(cfg: &FirewallConfig, seen: &Mutex<UnclassifiedNames>, names: &[String]) {
    if cfg.mode == FirewallMode::Off {
        return;
    }
    for name in names {
        if !is_unclassified(name, &cfg.sources) {
            continue;
        }
        let shown: String = name.chars().take(LOGGED_NAME_CHARS).collect();
        let mut s = seen.lock().unwrap_or_else(|e| e.into_inner());
        if s.named.contains(&shown) {
            continue;
        }
        if s.named.len() >= UNCLASSIFIED_NAME_CAP {
            let first = !s.cap_said;
            s.cap_said = true;
            drop(s);
            if first {
                tracing::warn!(
                    "firewall: more than {UNCLASSIFIED_NAME_CAP} distinct tools are unclassified; \
                     further names are not remembered and not named in this log. Classify them in \
                     the policy file named by TOKENFUSE_FIREWALL_CONFIG."
                );
            }
            continue;
        }
        s.named.insert(shown.clone());
        drop(s);
        tracing::warn!(
            tool = %shown,
            "firewall: tool `{shown}` is not in the source map, so its output counts as untrusted \
             (unclassified). Classify it in the policy file named by TOKENFUSE_FIREWALL_CONFIG to \
             stop this warning."
        );
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

    /// A policy file in the temp directory, named by process id so two test
    /// binaries cannot collide. Removed by the caller.
    fn write_policy(tag: &str, mode: &str) -> String {
        let path = std::env::temp_dir().join(format!(
            "tf-firewall-mode-{}-{}.json",
            tag,
            std::process::id()
        ));
        std::fs::write(&path, format!(r#"{{"mode":"{mode}","rules":[]}}"#)).unwrap();
        path.to_string_lossy().into_owned()
    }

    /// The variable, when set and valid, wins over the policy file's own mode,
    /// as it always has. Invariant 94 adds only that a MISTYPED variable is
    /// refused; a valid one still overrides the file, and a capitalised one is
    /// read the same way.
    #[test]
    fn a_valid_firewall_mode_overrides_the_policy_file() {
        let _guard = ENV.lock().unwrap_or_else(|e| e.into_inner());
        let saved = (
            std::env::var("TOKENFUSE_FIREWALL").ok(),
            std::env::var("TOKENFUSE_FIREWALL_CONFIG").ok(),
        );
        let shadow_file = write_policy("shadow", "shadow");
        let off_file = write_policy("off", "off");

        unsafe {
            std::env::set_var("TOKENFUSE_FIREWALL_CONFIG", &shadow_file);
            std::env::set_var("TOKENFUSE_FIREWALL", "enforce");
        }
        assert_eq!(from_env().mode, FirewallMode::Enforce, "lowercase enforce");

        unsafe { std::env::set_var("TOKENFUSE_FIREWALL", "ENFORCE") };
        assert_eq!(
            from_env().mode,
            FirewallMode::Enforce,
            "capitalised enforce"
        );

        unsafe {
            std::env::set_var("TOKENFUSE_FIREWALL_CONFIG", &off_file);
            std::env::set_var("TOKENFUSE_FIREWALL", "shadow");
        }
        assert_eq!(
            from_env().mode,
            FirewallMode::Shadow,
            "shadow beats a file's off"
        );

        unsafe {
            match saved.0 {
                Some(v) => std::env::set_var("TOKENFUSE_FIREWALL", v),
                None => std::env::remove_var("TOKENFUSE_FIREWALL"),
            }
            match saved.1 {
                Some(v) => std::env::set_var("TOKENFUSE_FIREWALL_CONFIG", v),
                None => std::env::remove_var("TOKENFUSE_FIREWALL_CONFIG"),
            }
        }
        let _ = std::fs::remove_file(&shadow_file);
        let _ = std::fs::remove_file(&off_file);
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
            &c.sources,
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

#[cfg(test)]
mod memory_and_unclassified_tests {
    //! Invariants 95 and 96, at the level of the policy and the once-per-name
    //! logic. The integration tests in `tests/it/memory_and_unclassified.rs` run
    //! the same through the real router.

    use super::*;
    use std::sync::Arc;

    #[derive(Clone, Default)]
    struct Buf(Arc<Mutex<Vec<u8>>>);

    impl std::io::Write for Buf {
        fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
            self.0.lock().unwrap().extend_from_slice(buf);
            Ok(buf.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    impl<'a> tracing_subscriber::fmt::MakeWriter<'a> for Buf {
        type Writer = Buf;
        fn make_writer(&'a self) -> Buf {
            self.clone()
        }
    }

    /// Run `f` under a capture of its own and return what it logged at WARN.
    fn logged(f: impl FnOnce()) -> String {
        let buf = Buf::default();
        let sub = tracing_subscriber::fmt()
            .with_writer(buf.clone())
            .with_ansi(false)
            .with_max_level(tracing::Level::WARN)
            .finish();
        tracing::subscriber::with_default(sub, f);
        let bytes = buf.0.lock().unwrap().clone();
        String::from_utf8_lossy(&bytes).to_string()
    }

    fn named_lines(text: &str) -> Vec<&str> {
        text.lines()
            .filter(|l| l.contains("not in the source map"))
            .collect()
    }

    #[test]
    fn the_starter_policy_denies_memory_after_exec() {
        // Asserted on the built-in policy itself, not on the file loader. The
        // floor would also deny a memory run, so a test through the loader could
        // not tell a dropped label from a restored floor.
        let c = FirewallConfig::defaults(FirewallMode::Enforce);
        let exec = c
            .rules
            .iter()
            .find(|r| r.name == "no-exec-after-untrusted")
            .expect("the starter rule");
        assert!(
            exec.when_any.iter().any(|l| l == MEMORY_LABEL),
            "memory is one of the labels the starter rule denies after: {:?}",
            exec.when_any
        );
        assert_eq!(
            c.sources.get("recall"),
            Some(&vec![MEMORY_LABEL.to_string()])
        );
        assert_eq!(c.sources.get("why"), Some(&vec![MEMORY_LABEL.to_string()]));
        assert!(
            !c.sources.contains_key("remember") && !c.sources.contains_key("forget"),
            "neither returns stored content, so neither is mapped to memory"
        );
    }

    #[test]
    fn the_starter_policy_denies_an_unclassified_action_after_untrusted_input() {
        // Invariant 115, on the built-in policy itself: the starter rule is the
        // only thing that denies the capability, so a test through the loader
        // could not see it dropped.
        let c = FirewallConfig::defaults(FirewallMode::Enforce);
        let exec = c
            .rules
            .iter()
            .find(|r| r.name == "no-exec-after-untrusted")
            .expect("the starter rule");
        assert!(
            exec.deny
                .iter()
                .any(|d| d == tokenfuse_core::taint::UNCLASSIFIED_CAPABILITY),
            "{:?}",
            exec.deny
        );
        let anti = c
            .rules
            .iter()
            .find(|r| r.name == "anti-exfiltration")
            .expect("the floor");
        assert_eq!(
            anti.deny,
            vec!["network_egress".to_string(), "network_read".to_string()],
            "a sensitivity label is not an untrusted source, so the rule gains no \
             untrusted-input denial; it gains network_read as a read is also an \
             exfiltration channel (invariant 120)"
        );
    }

    #[test]
    fn an_operator_rule_that_names_memory_is_not_given_a_second_floor() {
        let c = FirewallConfig::from_json(
            r#"{"mode":"enforce","rules":[{"name":"mine","when_any":["memory"],"deny":["exec"]}]}"#,
        )
        .expect("a valid policy");
        assert!(
            c.rules.iter().any(|r| r.name == "mine"),
            "the operator's rule is kept"
        );
        assert!(
            c.rules.iter().all(|r| r.name != "no-action-after-memory"),
            "a rule reads the label already, so the floor adds nothing: {:?}",
            c.rules.iter().map(|r| &r.name).collect::<Vec<_>>()
        );
    }

    #[test]
    fn off_names_nothing() {
        // Mutant: the mode gate removed. Asserted on the log as well as the set,
        // because the set alone would miss a warning written and not remembered.
        let cfg = FirewallConfig {
            mode: FirewallMode::Off,
            ..FirewallConfig::defaults(FirewallMode::Shadow)
        };
        let seen = Mutex::new(UnclassifiedNames::default());
        let text = logged(|| name_unclassified(&cfg, &seen, &["mystery_tool".to_string()]));
        assert!(named_lines(&text).is_empty(), "{text}");
        assert!(seen.lock().unwrap().named.is_empty());
    }

    #[test]
    fn a_name_is_named_once_however_often_it_is_seen() {
        // Mutant: the remembered-set check removed, so every call logs.
        let cfg = FirewallConfig::defaults(FirewallMode::Enforce);
        let seen = Mutex::new(UnclassifiedNames::default());
        let text = logged(|| {
            for _ in 0..3 {
                name_unclassified(&cfg, &seen, &["mystery_tool".to_string()]);
            }
        });
        let lines = named_lines(&text);
        assert_eq!(lines.len(), 1, "one warning per name: {text}");
        assert!(lines[0].contains("mystery_tool"));
        assert!(
            lines[0].contains("TOKENFUSE_FIREWALL_CONFIG"),
            "the line says how to classify it: {}",
            lines[0]
        );
    }

    #[test]
    fn a_classified_name_is_never_named() {
        let cfg = FirewallConfig::defaults(FirewallMode::Enforce);
        let seen = Mutex::new(UnclassifiedNames::default());
        let text = logged(|| name_unclassified(&cfg, &seen, &["web_search".to_string()]));
        assert!(named_lines(&text).is_empty(), "{text}");
    }

    #[test]
    fn the_names_remembered_are_capped_and_the_cap_is_said_once() {
        // Mutant: the cap removed, so all 300 are named and remembered. Also
        // checked: the cap line appears once however many names overflow it, and
        // a name seen again past the cap is not named again.
        let cfg = FirewallConfig::defaults(FirewallMode::Enforce);
        let seen = Mutex::new(UnclassifiedNames::default());
        let names: Vec<String> = (0..UNCLASSIFIED_NAME_CAP + 44)
            .map(|i| format!("tool-{i}"))
            .collect();
        let text = logged(|| {
            name_unclassified(&cfg, &seen, &names);
            name_unclassified(&cfg, &seen, &names);
        });
        assert_eq!(
            named_lines(&text).len(),
            UNCLASSIFIED_NAME_CAP,
            "exactly the remembered number is named"
        );
        let said = text
            .lines()
            .filter(|l| l.contains("more than 256 distinct"))
            .count();
        assert_eq!(said, 1, "one line says the list is cut: {text}");
        assert_eq!(seen.lock().unwrap().named.len(), UNCLASSIFIED_NAME_CAP);
    }

    #[test]
    fn a_very_long_name_is_cut_before_it_reaches_the_log() {
        let cfg = FirewallConfig::defaults(FirewallMode::Enforce);
        let seen = Mutex::new(UnclassifiedNames::default());
        let long = "x".repeat(10_000);
        let text = logged(|| name_unclassified(&cfg, &seen, std::slice::from_ref(&long)));
        let lines = named_lines(&text);
        assert_eq!(lines.len(), 1);
        assert!(
            !text.contains(&long),
            "the whole name never reaches the log"
        );
    }
}

#[cfg(test)]
mod read_tools_carry_no_data_tests {
    //! Agent-security wave 1, T4 (design 4.2), at the level of the policy: which
    //! capability a read exercises, which rule refuses it, and what an operator's
    //! file inherits. The argument judgement itself is tested in
    //! `tokenfuse_core::taint`, where it is defined.

    use super::*;
    use std::collections::BTreeSet;
    use tokenfuse_core::taint::{
        capabilities_for_tools, evaluate, Labels, NETWORK_READ_CAPABILITY, PRIVATE_DATA_LABELS,
        READ_TOOL_RULE, UNCLASSIFIED_CAPABILITY,
    };

    fn labels_of(names: &[&str]) -> Labels {
        names.iter().map(|s| s.to_string()).collect()
    }

    fn requested_of(names: &[&str]) -> BTreeSet<String> {
        names.iter().map(|s| s.to_string()).collect()
    }

    fn from_file(text: &str) -> FirewallConfig {
        FirewallConfig::from_json(text).expect("a valid policy file")
    }

    #[test]
    fn read_tools_are_network_read_as_well_as_sources() {
        // Dual classification: a read tool is a source (its output is labelled
        // web) and a capability (its request is a network read).
        let c = FirewallConfig::defaults(FirewallMode::Enforce);
        for tool in ["fetch_url", "browse", "web_search"] {
            assert_eq!(
                c.capabilities.get(tool).map(String::as_str),
                Some(NETWORK_READ_CAPABILITY),
                "{tool} is a read, so its request is a network read"
            );
            assert_eq!(
                c.sources.get(tool),
                Some(&vec!["web".to_string()]),
                "{tool} is a read, so its output is web-labelled"
            );
        }
        // `http_get` and `fetch` are named in neither map. They are not known reads,
        // so they stay unclassified and are refused after untrusted input, as any
        // unmapped tool is (invariant 115). They must not be network reads here:
        // a known read is not refused after web input, and these must be.
        for tool in ["http_get", "fetch"] {
            assert!(
                !c.capabilities.contains_key(tool),
                "{tool} is unmapped, so it is unclassified, not a network read"
            );
            assert!(
                !c.sources.contains_key(tool),
                "{tool} is unmapped, so its output is unclassified"
            );
        }
    }

    #[test]
    fn anti_exfiltration_denies_a_read_after_secrets() {
        let c = FirewallConfig::defaults(FirewallMode::Enforce);
        let v = evaluate(
            &labels_of(&["secrets"]),
            &requested_of(&[NETWORK_READ_CAPABILITY]),
            &c.rules,
        )
        .expect("a run that read a secret cannot fetch");
        assert_eq!(v.rule, "anti-exfiltration");
        assert_eq!(v.denied, vec![NETWORK_READ_CAPABILITY.to_string()]);
    }

    #[test]
    fn the_anti_exfiltration_floor_also_denies_a_read() {
        // A policy file replaces the starter policy, and the floor comes back
        // with it: a file that names no anti-exfiltration rule must still refuse
        // a read after secrets.
        let c = from_file(
            r#"{"mode":"enforce","rules":[{"name":"mine","when_any":["web"],"deny":["exec"]}]}"#,
        );
        let anti = c
            .rules
            .iter()
            .find(|r| r.name == "anti-exfiltration")
            .expect("the floor");
        assert!(
            anti.deny.iter().any(|d| d == NETWORK_READ_CAPABILITY),
            "{:?}",
            anti.deny
        );
        assert!(
            anti.deny.iter().any(|d| d == "network_egress"),
            "{:?}",
            anti.deny
        );
    }

    #[test]
    fn the_starter_policy_carries_the_read_rule() {
        let c = FirewallConfig::defaults(FirewallMode::Enforce);
        let read = c
            .rules
            .iter()
            .find(|r| r.name == READ_TOOL_RULE)
            .expect("the read rule");
        assert_eq!(
            read.when_any,
            PRIVATE_DATA_LABELS
                .iter()
                .map(|s| s.to_string())
                .collect::<Vec<_>>()
        );
        assert_eq!(read.deny, vec![NETWORK_READ_CAPABILITY.to_string()]);
    }

    #[test]
    fn remember_is_a_write_not_an_unmapped_tool() {
        let c = FirewallConfig::defaults(FirewallMode::Enforce);
        assert_eq!(
            c.capabilities.get("remember").map(String::as_str),
            Some("write")
        );
    }

    #[test]
    fn a_tainted_run_that_remembers_is_refused_as_a_write() {
        // A rule that names the capability says what the refusal is about: a
        // write, under the starter rule, not an unmapped tool.
        let c = FirewallConfig::defaults(FirewallMode::Enforce);
        let requested =
            capabilities_for_tools(&["remember".to_string()], &c.capabilities, &c.sources);
        let v = evaluate(&labels_of(&["web"]), &requested, &c.rules)
            .expect("a tainted run cannot write");
        assert_eq!(v.rule, "no-exec-after-untrusted");
        assert_eq!(v.denied, vec!["write".to_string()]);
    }

    #[test]
    fn an_operator_file_with_no_unmapped_rule_gets_the_untrusted_floor() {
        let c = from_file(
            r#"{"mode":"enforce","rules":[{"name":"mine","when_any":["secrets"],"deny":["exec"]}]}"#,
        );
        assert!(
            c.rules
                .iter()
                .any(|r| r.deny.iter().any(|d| d == UNCLASSIFIED_CAPABILITY)),
            "a file that names no rule denying unclassified lets an unmapped tool through after web input: {:?}",
            c.rules
        );
    }

    #[test]
    fn the_floor_refuses_an_unmapped_tool_after_web_taint() {
        let c = from_file(
            r#"{"mode":"enforce","rules":[{"name":"mine","when_any":["secrets"],"deny":["exec"]}]}"#,
        );
        let requested =
            capabilities_for_tools(&["http_request".to_string()], &c.capabilities, &c.sources);
        assert!(
            evaluate(&labels_of(&["web"]), &requested, &c.rules).is_some(),
            "web taint and an unmapped tool is refused by the floor"
        );
    }

    #[test]
    fn shadow_files_get_no_unmapped_floor() {
        // Shadow refuses nothing, so a floor there would be a rule that cannot fire.
        let c = from_file(
            r#"{"mode":"shadow","rules":[{"name":"mine","when_any":["secrets"],"deny":["exec"]}]}"#,
        );
        assert!(!c
            .rules
            .iter()
            .any(|r| r.deny.iter().any(|d| d == UNCLASSIFIED_CAPABILITY)));
    }

    #[test]
    fn an_operator_rule_that_already_denies_unmapped_tools_gets_no_second_floor() {
        let c = from_file(
            r#"{"mode":"enforce","rules":[{"name":"mine","when_any":["web"],"deny":["unclassified"]}]}"#,
        );
        let count = c
            .rules
            .iter()
            .filter(|r| r.deny.iter().any(|d| d == UNCLASSIFIED_CAPABILITY))
            .count();
        assert_eq!(count, 1, "{:?}", c.rules);
    }
}
