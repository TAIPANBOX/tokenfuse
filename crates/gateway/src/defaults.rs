//! The settings whose DEFAULT is a security decision, parsed in one place.
//!
//! Two of them changed direction on 2026-08-06, after a cloud range on
//! 2026-08-04 ran the shipped stack against a real provider and found that its
//! guarantees were all opt-in:
//!
//! - `TOKENFUSE_DLP` unset meant `off`, so the secret scanner the product
//!   advertises scanned nothing until somebody set a variable. The range had to
//!   enable it by hand before it could test it at all.
//! - a call with no `x-fuse-run-id` reached the provider and was recorded in no
//!   ledger, no trace and no event stream. `TOKENFUSE_REQUIRE_RUN_ID=1` existed
//!   to refuse those calls and was off unless asked for.
//!
//! Separately, each is defensible. Together they mean a deployment can be
//! governed on paper: secrets unscanned, part of the traffic unaccounted for,
//! and every check green because the checks read configuration rather than
//! behaviour. The defaults now point the other way, and the old behaviour is
//! one explicit variable away in each case, which is the difference between a
//! default and a prohibition.
//!
//! **Why the parsing lives here rather than inline in `main.rs`.** A default is
//! a claim about what happens when nobody configures anything, and that is the
//! case no integration test exercises, because a test that sets nothing has no
//! opinion. As a pure function of `Option<&str>` it is testable without touching
//! the process environment, which also keeps these tests out of the
//! env-var-mutation race that `events.rs`'s tests had to grow a mutex for.

use tokenfuse_core::{DlpMode, Microusd, Mode};

/// Secret scanning (`TOKENFUSE_DLP`): `off | shadow | mask | block`.
///
/// **Unset is `block`**, which is the change: a scanner nobody switched on is a
/// promise, not a control. An unrecognised value is also `block` rather than
/// `off`, for the reason `clientkeys` refuses to start on a malformed spec: a
/// typo must never be read as "protection disabled".
pub fn dlp_mode_from(value: Option<&str>) -> DlpMode {
    match value.map(str::trim) {
        Some("off") => DlpMode::Off,
        Some("shadow") => DlpMode::Shadow,
        Some("mask") => DlpMode::Mask,
        _ => DlpMode::Block,
    }
}

/// PII masks (`TOKENFUSE_DLP_PII`): the same four values, switched
/// independently of the secret scanner.
///
/// **Unset stays `off`, deliberately.** This is a different promise from the
/// one above: `pii_email`/`pii_card`/`pii_phone`/`pii_iban` are heuristics over ordinary
/// text, so their false positives are prose rather than credentials, and the
/// 2026-08-04 range said nothing about them. Turning something on by default is
/// a claim that its false positives are worth its true positives, and that
/// claim is only established here for the secret patterns.
/// PII masks (`TOKENFUSE_DLP_PII`): the same four values, switched
/// independently of the secret scanner.
///
/// **Unset stays `off`, deliberately.** This is a different promise from the
/// one above: `pii_email`/`pii_card`/`pii_phone`/`pii_iban` are heuristics over ordinary
/// text, so their false positives are prose rather than credentials, and the
/// 2026-08-04 range said nothing about them. Turning something on by default is
/// a claim that its false positives are worth its true positives, and that
/// claim is only established here for the secret patterns.
///
/// An unknown value is refused (invariant 98). It used to read as `off`, so a
/// typo for `block` ran the gateway with the PII masks off.
pub fn dlp_pii_mode_from(value: Option<&str>) -> Result<DlpMode, String> {
    pii_mode("TOKENFUSE_DLP_PII", value)
}

/// The same four words for the MCP broker's PII masks (`TOKENFUSE_MCP_DLP_PII`).
pub fn mcp_dlp_pii_mode_from(value: Option<&str>) -> Result<DlpMode, String> {
    pii_mode("TOKENFUSE_MCP_DLP_PII", value)
}

fn pii_mode(name: &str, value: Option<&str>) -> Result<DlpMode, String> {
    Ok(
        match switch_word(name, value, &["off", "shadow", "mask", "block"])? {
            Some("shadow") => DlpMode::Shadow,
            Some("mask") => DlpMode::Mask,
            Some("block") => DlpMode::Block,
            _ => DlpMode::Off,
        },
    )
}

/// The MCP broker's secret scanner (`TOKENFUSE_MCP_DLP`): `off | shadow | block`.
///
/// **Unset is `shadow`**, which is what the broker has always done. An unknown
/// value used to read as `shadow` too, so a typo for `block` was a broker that
/// logged the secret and forwarded it; it is refused now (invariant 98).
pub fn mcp_dlp_mode_from(value: Option<&str>) -> Result<DlpMode, String> {
    Ok(
        match switch_word("TOKENFUSE_MCP_DLP", value, &["off", "shadow", "block"])? {
            Some("block") => DlpMode::Block,
            Some("off") => DlpMode::Off,
            _ => DlpMode::Shadow,
        },
    )
}

/// The MCP broker's tool-listing scan (`TOKENFUSE_MCP_SCAN`): `off | warn | block`.
///
/// **Unset is `warn`.** An unknown value used to read as `warn`, so a typo for
/// `block` let a poisoned listing through with a log line; it is refused now
/// (invariant 98).
pub fn mcp_scan_mode_from(value: Option<&str>) -> Result<crate::mcpbroker::ScanMode, String> {
    use crate::mcpbroker::ScanMode;
    Ok(
        match switch_word("TOKENFUSE_MCP_SCAN", value, &["off", "warn", "block"])? {
            Some("off") => ScanMode::Off,
            Some("block") => ScanMode::Block,
            _ => ScanMode::Warn,
        },
    )
}

/// What the broker does when the taint gateway cannot be reached
/// (`TOKENFUSE_MCP_TAINT_FAILMODE`): `open | closed`. Returns whether it fails
/// closed.
///
/// **Unset is `open`.** An unknown value used to read as `open`, so a typo for
/// `closed` turned an outage of the gate into permission; it is refused now
/// (invariant 98).
pub fn mcp_taint_failclosed_from(value: Option<&str>) -> Result<bool, String> {
    Ok(matches!(
        switch_word("TOKENFUSE_MCP_TAINT_FAILMODE", value, &["open", "closed"])?,
        Some("closed")
    ))
}

/// A switch that turns a protection on, read as `1|true` (on) or `0|false`
/// (off). `name` is the variable, for the refusal message.
///
/// **Unset is off**, as before. Until 2026-10-13 any other value read as off,
/// so `TOKENFUSE_MCP_REQUIRE_PROOF=yes` left the bearer door open while the
/// operator believed it closed. `yes`, `on` and `no` are refused rather than
/// guessed at; `0` and `false` remain the explicit way to say off (invariant 98).
pub fn required_switch_from(name: &str, value: Option<&str>) -> Result<bool, String> {
    Ok(matches!(
        switch_word(name, value, &["0", "false", "1", "true"])?,
        Some("1") | Some("true")
    ))
}

/// The wardryx policy hook's mode (`TOKENFUSE_WARDRYX_MODE`): `off | shadow | enforce`.
///
/// **Unset is `off`**, as before. An unknown value used to read as `off`
/// silently, so `TOKENFUSE_WARDRYX_MODE=enfroce` ran a gateway whose policy
/// decided nothing while its operator believed `enforce` was on; it is refused
/// now (invariant 98). Case is folded, so `ENFORCE` is `enforce`: an operator
/// who wrote the word in capitals meant it, and a deployment that did so before
/// this change now enforces (see the feature file's upgrade note).
pub fn wardryx_mode_from(value: Option<&str>) -> Result<crate::wardryx::WardryxMode, String> {
    wardryx_mode_under(Profile::Observe, value)
}

/// [`wardryx_mode_from`] with the profile's default for an unset value.
pub fn wardryx_mode_under(
    profile: Profile,
    value: Option<&str>,
) -> Result<crate::wardryx::WardryxMode, String> {
    use crate::wardryx::WardryxMode;
    Ok(
        match switch_word(
            "TOKENFUSE_WARDRYX_MODE",
            value,
            &["off", "shadow", "enforce"],
        )? {
            Some("shadow") => WardryxMode::Shadow,
            Some("enforce") => WardryxMode::Enforce,
            Some(_) => WardryxMode::Off,
            None => profile.wardryx_mode(),
        },
    )
}

/// What the wardryx hook does when its PDP cannot be reached
/// (`TOKENFUSE_WARDRYX_FAILMODE`): `open | closed`, for a hook in `mode`.
///
/// **Unset is `closed` under `enforce`** (invariant 117), and `open` in every
/// other mode. Until 2026-10-17 it was `open` everywhere, and measured on the
/// bare binary that day: a call the policy denied while wardryx was up was
/// allowed four seconds after wardryx stopped, answered `x-fuse-wardryx:
/// allow`. With a 50 ms deadline a busy PDP is enough. An operator who chose
/// enforcement did not choose an outage that turns every deny into an allow;
/// `open` stays one variable away. Shadow keeps `open` because shadow blocks
/// nothing whatever the failmode says.
///
/// An unknown value used to read as `open`, so a typo for `closed` let every
/// call through during an outage of the policy plane; it is refused (invariant
/// 98). Blank is unset, so it gets the mode's default.
pub fn wardryx_failmode_from(
    mode: crate::wardryx::WardryxMode,
    value: Option<&str>,
) -> Result<crate::wardryx::FailMode, String> {
    use crate::wardryx::{FailMode, WardryxMode};
    Ok(
        match switch_word("TOKENFUSE_WARDRYX_FAILMODE", value, &["open", "closed"])? {
            Some("closed") => FailMode::Closed,
            Some(_) => FailMode::Open,
            None if mode == WardryxMode::Enforce => FailMode::Closed,
            None => FailMode::Open,
        },
    )
}

/// Reads one switch whose words are a closed set: the single copy of the rule
/// every security switch in this module follows (CLAUDE.md invariant 98).
///
/// Unset, empty or only spaces is `Ok(None)`: the caller keeps the switch's own
/// default. A set value is matched against `words` in any case, ignoring the
/// spaces around it, and comes back as the word in `words`. Anything else is an
/// `Err` naming the variable, the value and the words, for the caller to exit
/// with ([`exit_on_refusal`]).
///
/// The rule lives here once on purpose. Each of these switches had its own
/// `match` with a catch-all arm, and each catch-all quietly chose a mode for a
/// value nobody had written; for some of them the chosen mode was the weaker
/// one. A rule written nine times is a rule that drifts nine times.
pub fn switch_word(
    name: &str,
    value: Option<&str>,
    words: &[&'static str],
) -> Result<Option<&'static str>, String> {
    let Some(raw) = value.map(str::trim).filter(|v| !v.is_empty()) else {
        return Ok(None);
    };
    let lower = raw.to_ascii_lowercase();
    match words.iter().copied().find(|w| *w == lower) {
        Some(word) => Ok(Some(word)),
        None => Err(format!(
            "tokenfuse: {name} must be {}, got `{raw}`",
            words.join("|")
        )),
    }
}

/// Unwraps a refusal from a parser in this module by printing its message and
/// exiting 2, before the listener binds. Every `_from_env` wrapper here ends
/// in this, so the exit code and the message shape are one thing.
pub fn exit_on_refusal<T>(result: Result<T, String>) -> T {
    match result {
        Ok(value) => value,
        Err(message) => {
            eprintln!("{message}");
            std::process::exit(2);
        }
    }
}

/// The governance profile (`TOKENFUSE_PROFILE`, CLAUDE.md invariant 136).
///
/// **Governed is the default.** An unconfigured gateway used to be a
/// pass-through: budgets shadowed, the firewall shadowed, the policy hook off,
/// declassification open, and the admin routes answering anyone on loopback.
/// The review of 2026-10-17 (F-010) found that a quickstart produced exactly
/// that, an observer and not a control. `Observe` reproduces those defaults
/// and says at startup that it enforces nothing that is not set explicitly.
///
/// The profile supplies DEFAULTS only. Every variable an operator sets wins
/// over it, and so does a policy file's own `mode`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Profile {
    Governed,
    Observe,
}

impl Profile {
    pub fn as_str(self) -> &'static str {
        match self {
            Profile::Governed => "governed",
            Profile::Observe => "observe",
        }
    }

    pub fn is_governed(self) -> bool {
        self == Profile::Governed
    }

    /// The budget mode an unset `TOKENFUSE_MODE` gets: enforce under governed,
    /// shadow under observe (the drop-in default, as before).
    pub fn policy_mode(self) -> Mode {
        match self {
            Profile::Governed => Mode::Enforce,
            Profile::Observe => Mode::Shadow,
        }
    }

    /// The firewall mode when neither `TOKENFUSE_FIREWALL` nor a policy file
    /// names one: enforce under governed, shadow under observe.
    pub fn firewall_mode(self) -> tokenfuse_core::taint::FirewallMode {
        match self {
            Profile::Governed => tokenfuse_core::taint::FirewallMode::Enforce,
            Profile::Observe => tokenfuse_core::taint::FirewallMode::Shadow,
        }
    }

    /// The mode a policy file gets when it names none (CLAUDE.md invariant 136):
    /// enforce under governed, off under observe, which is what every file got
    /// before the profile existed. A file that names a mode is never overridden.
    pub fn absent_file_mode(self) -> tokenfuse_core::taint::FirewallMode {
        match self {
            Profile::Governed => tokenfuse_core::taint::FirewallMode::Enforce,
            Profile::Observe => tokenfuse_core::taint::FirewallMode::Off,
        }
    }

    /// The policy hook's mode when `TOKENFUSE_WARDRYX_MODE` is unset. Enforce
    /// under governed; the hook still stays off without a `TOKENFUSE_WARDRYX_URL`
    /// (`wardryx::Wardryx::from_vars`), and the startup line says so.
    pub fn wardryx_mode(self) -> crate::wardryx::WardryxMode {
        match self {
            Profile::Governed => crate::wardryx::WardryxMode::Enforce,
            Profile::Observe => crate::wardryx::WardryxMode::Off,
        }
    }
}

/// Whether a variable's value counts as unset: absent, empty, or only spaces.
fn is_unset(value: Option<&str>) -> bool {
    value.map(str::trim).unwrap_or_default().is_empty()
}

/// `TOKENFUSE_PROFILE`: `governed | observe`, any case. Unset, empty or only
/// spaces is governed. Anything else is an `Err` naming both words, and the
/// caller exits: a profile nobody can read must not start the gateway as
/// whichever one happened to be the default.
pub fn profile_from(value: Option<&str>) -> Result<Profile, String> {
    Ok(
        match switch_word("TOKENFUSE_PROFILE", value, &["governed", "observe"])? {
            Some("observe") => Profile::Observe,
            _ => Profile::Governed,
        },
    )
}

/// [`profile_from`] against the process environment, exiting 2 on a value it
/// cannot read.
pub fn profile_from_env() -> Profile {
    exit_on_refusal(profile_from(
        std::env::var("TOKENFUSE_PROFILE").ok().as_deref(),
    ))
}

/// [`policy_mode_from`] with the profile's default for an unset value.
pub fn policy_mode_under(profile: Profile, value: Option<&str>) -> Result<Mode, String> {
    if is_unset(value) {
        return Ok(profile.policy_mode());
    }
    policy_mode_from(value)
}

/// [`policy_mode_under`] against the process environment, exiting 2.
pub fn policy_mode_under_env(profile: Profile) -> Mode {
    exit_on_refusal(policy_mode_under(
        profile,
        std::env::var("TOKENFUSE_MODE").ok().as_deref(),
    ))
}

/// Where a setting's value came from, for the startup line: `env` when the
/// variable is set, `profile` when the profile's default stands.
pub fn source_of(name: &str) -> &'static str {
    match std::env::var(name).ok().as_deref() {
        v if !is_unset(v) => "env",
        _ => "profile",
    }
}

/// The one startup line that names the profile and every governed setting
/// with where it came from (CLAUDE.md invariant 136). `settings` is
/// `(setting, value, source)`, in the order the caller computed them.
pub fn governance_line(profile: Profile, settings: &[(&str, String, &str)]) -> String {
    let mut line = format!("governance profile={}", profile.as_str());
    for (name, value, source) in settings {
        line.push_str(&format!(" {name}={value}({source})"));
    }
    line
}

/// [`dlp_pii_mode_from`] against the process environment.
pub fn dlp_pii_mode_from_env() -> DlpMode {
    exit_on_refusal(dlp_pii_mode_from(
        std::env::var("TOKENFUSE_DLP_PII").ok().as_deref(),
    ))
}

/// [`mcp_dlp_mode_from`] against the process environment.
pub fn mcp_dlp_mode_from_env() -> DlpMode {
    exit_on_refusal(mcp_dlp_mode_from(
        std::env::var("TOKENFUSE_MCP_DLP").ok().as_deref(),
    ))
}

/// [`mcp_dlp_pii_mode_from`] against the process environment.
pub fn mcp_dlp_pii_mode_from_env() -> DlpMode {
    exit_on_refusal(mcp_dlp_pii_mode_from(
        std::env::var("TOKENFUSE_MCP_DLP_PII").ok().as_deref(),
    ))
}

/// [`mcp_scan_mode_from`] against the process environment.
pub fn mcp_scan_mode_from_env() -> crate::mcpbroker::ScanMode {
    exit_on_refusal(mcp_scan_mode_from(
        std::env::var("TOKENFUSE_MCP_SCAN").ok().as_deref(),
    ))
}

/// [`mcp_taint_failclosed_from`] against the process environment.
pub fn mcp_taint_failclosed_from_env() -> bool {
    exit_on_refusal(mcp_taint_failclosed_from(
        std::env::var("TOKENFUSE_MCP_TAINT_FAILMODE")
            .ok()
            .as_deref(),
    ))
}

/// [`required_switch_from`] against the process environment, for the named
/// variable.
pub fn required_switch_from_env(name: &str) -> bool {
    exit_on_refusal(required_switch_from(
        name,
        std::env::var(name).ok().as_deref(),
    ))
}

/// [`wardryx_mode_from`] against the process environment.
pub fn wardryx_mode_from_env() -> crate::wardryx::WardryxMode {
    exit_on_refusal(wardryx_mode_from(
        std::env::var("TOKENFUSE_WARDRYX_MODE").ok().as_deref(),
    ))
}

/// [`wardryx_failmode_from`] against the process environment, for a hook in `mode`.
/// `TOKENFUSE_UPSTREAM_AUTH` (invariant 122): the header the held provider key goes in. Unset is
/// `Ok(None)`, which means the wire's own header; `x-api-key` or `bearer` in any case otherwise.
pub fn upstream_auth_from(
    value: Option<&str>,
) -> Result<Option<crate::provider::UpstreamAuth>, String> {
    let word = switch_word(
        "TOKENFUSE_UPSTREAM_AUTH",
        value,
        crate::provider::UPSTREAM_AUTH_WORDS,
    )?;
    Ok(word.and_then(crate::provider::UpstreamAuth::parse))
}

/// `upstream_auth_from` for the process environment, exiting 2 on a value it cannot read.
pub fn upstream_auth_from_env() -> Option<crate::provider::UpstreamAuth> {
    exit_on_refusal(upstream_auth_from(
        std::env::var("TOKENFUSE_UPSTREAM_AUTH").ok().as_deref(),
    ))
}

pub fn wardryx_failmode_from_env(mode: crate::wardryx::WardryxMode) -> crate::wardryx::FailMode {
    exit_on_refusal(wardryx_failmode_from(
        mode,
        std::env::var("TOKENFUSE_WARDRYX_FAILMODE").ok().as_deref(),
    ))
}

/// Whether a call with no `x-fuse-run-id` is refused (`TOKENFUSE_REQUIRE_RUN_ID`).
///
/// **Unset is `true`**: a call this gateway cannot account for is not a call it
/// makes. `0`, `false`, `no` and `off` restore the pass-through, and they are
/// the only things that do, so an operator who wants an unmetered path has said
/// so in writing.
pub fn require_run_id_from(value: Option<&str>) -> bool {
    !matches!(
        value.map(str::trim),
        Some("0") | Some("false") | Some("no") | Some("off")
    )
}

/// Shadow tool-pruning measurement (`TOKENFUSE_TOOLS_PRUNE`): `off | shadow`.
///
/// W2a, invariant 61: shadow only MEASURES how many input tokens go to
/// schemas of tools the wardryx policy would deny; it never changes the
/// forwarded request in any mode.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum ToolsPruneMode {
    #[default]
    Off,
    Shadow,
}

/// **Unset is `off`**, unlike `TOKENFUSE_DLP` above: this is a measurement
/// feature with a network call attached (`filter_tools`), not a security
/// control, so there is no argument for defaulting it on the way invariant 17
/// argues for DLP and `TOKENFUSE_REQUIRE_RUN_ID`. An unrecognised value is
/// also `off`, with one warn line naming the value it could not parse -
/// the same "say so, do not guess" posture as every other setting here, just
/// resolving to the SAFER value (no call, no behaviour change) rather than
/// the stricter one, because there is no stricter reading of a measurement
/// toggle.
pub fn tools_prune_mode_from(value: Option<&str>) -> ToolsPruneMode {
    match value.map(str::trim) {
        Some("shadow") => ToolsPruneMode::Shadow,
        None | Some("") | Some("off") => ToolsPruneMode::Off,
        Some(other) => {
            tracing::warn!(
                value = %other,
                "TOKENFUSE_TOOLS_PRUNE must be off or shadow; treating this value as off"
            );
            ToolsPruneMode::Off
        }
    }
}

/// [`tools_prune_mode_from`] against the process environment.
pub fn tools_prune_mode_from_env() -> ToolsPruneMode {
    tools_prune_mode_from(std::env::var("TOKENFUSE_TOOLS_PRUNE").ok().as_deref())
}

/// Semantic cache mode (`TOKENFUSE_CACHE`): `off | shadow | on`.
///
/// **Unset is `off`**, since invariant 63. It used to be `shadow`, which put
/// `SemanticCache::get`'s single global `Mutex`, a `retain` sweep and a
/// linear cosine walk over the whole partition on every non-streaming
/// eligible call whether or not an operator had ever asked for the cache -
/// issue #319: 79-92% of gateway CPU in `SemanticCache::get` under load, 50
/// agents at 177 req/s with 403s where the cache off measured 1102 req/s. A
/// measurement feature that costs every request by default is the same
/// mistake `TOKENFUSE_TOOLS_PRUNE` above was written not to make; `shadow`
/// is still one word away for an operator who wants the projected savings.
/// An unrecognised value is also `off`, with one warn line naming the value,
/// the same posture as `tools_prune_mode_from`.
pub fn cache_mode_from(value: Option<&str>) -> tokenfuse_core::cache::CacheMode {
    use tokenfuse_core::cache::CacheMode;
    match value.map(str::trim) {
        Some("on") => CacheMode::On,
        Some("shadow") => CacheMode::Shadow,
        None | Some("") | Some("off") => CacheMode::Off,
        Some(other) => {
            tracing::warn!(
                value = %other,
                "TOKENFUSE_CACHE must be off, shadow or on; treating this value as off"
            );
            CacheMode::Off
        }
    }
}

/// [`cache_mode_from`] against the process environment.
pub fn cache_mode_from_env() -> tokenfuse_core::cache::CacheMode {
    cache_mode_from(std::env::var("TOKENFUSE_CACHE").ok().as_deref())
}

/// [`dlp_mode_from`] against the process environment.
pub fn dlp_mode_from_env() -> DlpMode {
    dlp_mode_from(std::env::var("TOKENFUSE_DLP").ok().as_deref())
}

/// [`require_run_id_from`] against the process environment.
pub fn require_run_id_from_env() -> bool {
    require_run_id_from(std::env::var("TOKENFUSE_REQUIRE_RUN_ID").ok().as_deref())
}

/// The budget policy's rollout mode (`TOKENFUSE_MODE`): `shadow | warn | enforce`.
///
/// **Unset or empty is `shadow`**, unchanged: a gateway dropped in front of a
/// running agent records what it would block before it blocks anything.
///
/// An unknown value is an `Err` carrying that value, never a reading of it.
/// Until 2026-10-04 anything but the exact words `enforce` and `warn` fell
/// through to `shadow`, so `TOKENFUSE_MODE=enfroce` or `=Enforce` started a
/// gateway that enforced no budget while its operator believed it did, the
/// one failure a budget control must never have. `TOKENFUSE_IDENTITY_STRICT`
/// already refuses a mistyped mode for the same reason; this matches it,
/// case-insensitively, and the caller owns the exit.
pub fn policy_mode_from(value: Option<&str>) -> Result<Mode, String> {
    let trimmed = value.unwrap_or_default().trim();
    match trimmed.to_lowercase().as_str() {
        "" | "shadow" => Ok(Mode::Shadow),
        "warn" => Ok(Mode::Warn),
        "enforce" => Ok(Mode::Enforce),
        _ => Err(trimmed.to_string()),
    }
}

/// [`policy_mode_from`] against the process environment; exits 2 on a value
/// it cannot read, naming the value and the three it accepts.
pub fn policy_mode_from_env() -> Mode {
    match policy_mode_from(std::env::var("TOKENFUSE_MODE").ok().as_deref()) {
        Ok(mode) => mode,
        Err(raw) => {
            eprintln!("tokenfuse: TOKENFUSE_MODE must be shadow|warn|enforce, got `{raw}`");
            std::process::exit(2);
        }
    }
}

/// The agent firewall's mode override (`TOKENFUSE_FIREWALL`): `off | shadow |
/// enforce`, or nothing.
///
/// **Unset or empty (or only spaces) is `Ok(None)`**: no override, so the mode
/// stays what the policy file's own `mode` says, or the default. That is what a
/// deployment that never set the variable has always had, and it is unchanged.
///
/// Otherwise the three words in any case, `Ok(Some(mode))`. Anything else is an
/// `Err` carrying the value, never a reading of it. Until 2026-10-13 the match
/// took only the exact lowercase words and ignored the rest, so
/// `TOKENFUSE_FIREWALL=enfroce` or `=ENFORCE` started a gateway at whatever mode
/// the file or the default gave, while its operator believed enforcement was on.
/// Invariant 72 closed the same hole for `TOKENFUSE_MODE`; this mirrors it, and
/// the caller owns the exit.
pub fn firewall_mode_from(
    value: Option<&str>,
) -> Result<Option<tokenfuse_core::taint::FirewallMode>, String> {
    use tokenfuse_core::taint::FirewallMode;
    let trimmed = value.unwrap_or_default().trim();
    match trimmed.to_lowercase().as_str() {
        "" => Ok(None),
        "off" => Ok(Some(FirewallMode::Off)),
        "shadow" => Ok(Some(FirewallMode::Shadow)),
        "enforce" => Ok(Some(FirewallMode::Enforce)),
        _ => Err(trimmed.to_string()),
    }
}

/// [`firewall_mode_from`] against the process environment; exits 2 on a value
/// it cannot read, naming the variable, the value and the three words it
/// accepts. Called before the listener binds, from `firewall::from_env`.
pub fn firewall_mode_from_env() -> Option<tokenfuse_core::taint::FirewallMode> {
    match firewall_mode_from(std::env::var("TOKENFUSE_FIREWALL").ok().as_deref()) {
        Ok(mode) => mode,
        Err(raw) => {
            eprintln!("tokenfuse: TOKENFUSE_FIREWALL must be off|shadow|enforce, got `{raw}`");
            std::process::exit(2);
        }
    }
}

/// The operator's ceiling on any run budget the caller or a default chose
/// (`TOKENFUSE_MAX_RUN_BUDGET_USD`), invariant 73.
///
/// **Unset or empty is `Ok(None)`: no ceiling**, which is the behaviour every
/// deployment had before the variable existed. The ceiling is an additive
/// operator setting, so a gateway upgraded with nothing configured changes
/// nothing.
///
/// Why it exists. A run's budget came from `x-fuse-budget-usd`, the header the
/// AGENT sends, and `Ledger::open_run` rewrites an open run's budget on every
/// call, so in a deployment with no client keys and no identity map the
/// per-run ceiling was whatever the agent declared, widened again by its next
/// call. Widening stays (it is the one release valve for a reservation kept
/// open after an unknown outcome, invariant 50); this bounds it.
///
/// The value is a positive decimal number of dollars read as integers, never
/// through `f64`: digits, optionally a point and one to six more digits.
/// Anything else is an `Err` carrying the value: zero (a ceiling that refuses
/// every call is a different setting and an easy typo), a sign, an exponent
/// (`1e9` is a billion dollars, not a typo to guess at), a second point, a
/// seventh decimal (it would silently round to a different ceiling), words,
/// and any figure too large for the ledger's integer microdollars. The caller
/// owns the exit, as with [`policy_mode_from`].
pub fn max_run_budget_from(value: Option<&str>) -> Result<Option<Microusd>, String> {
    let trimmed = value.unwrap_or_default().trim();
    if trimmed.is_empty() {
        return Ok(None);
    }
    match usd_to_microusd(trimmed) {
        Some(micro) if micro > 0 => Ok(Some(Microusd(micro))),
        _ => Err(trimmed.to_string()),
    }
}

/// Exact decimal dollars to integer microdollars, `None` for anything that is
/// not `digits` or `digits.1-6digits`, or that overflows `i64`.
fn usd_to_microusd(s: &str) -> Option<i64> {
    let (whole, frac) = match s.split_once('.') {
        Some((w, f)) if !f.is_empty() => (w, f),
        Some(_) => return None,
        None => (s, ""),
    };
    let digits = |t: &str| t.bytes().all(|b| b.is_ascii_digit());
    if whole.is_empty() || !digits(whole) || !digits(frac) || frac.len() > 6 {
        return None;
    }
    let whole: i64 = whole.parse().ok()?;
    let frac_micro: i64 = if frac.is_empty() {
        0
    } else {
        frac.parse::<i64>().ok()? * 10_i64.pow(6 - frac.len() as u32)
    };
    whole.checked_mul(1_000_000)?.checked_add(frac_micro)
}

/// [`max_run_budget_from`] against the process environment; exits 2 on a
/// value it cannot read, naming the variable and the form it accepts.
pub fn max_run_budget_from_env() -> Option<Microusd> {
    match max_run_budget_from(
        std::env::var("TOKENFUSE_MAX_RUN_BUDGET_USD")
            .ok()
            .as_deref(),
    ) {
        Ok(ceiling) => ceiling,
        Err(raw) => {
            // A hostile value can be any length; the operator needs to see
            // which value, not all of it.
            let shown: String = raw.chars().take(64).collect();
            eprintln!(
                "tokenfuse: TOKENFUSE_MAX_RUN_BUDGET_USD must be a positive number of US dollars \
                 with at most six decimals (for example 25 or 2.50), got `{shown}`"
            );
            std::process::exit(2);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn secret_scanning_is_on_when_nothing_is_configured() {
        assert_eq!(dlp_mode_from(None), DlpMode::Block);
        assert_eq!(dlp_mode_from(Some("")), DlpMode::Block);
    }

    #[test]
    fn every_documented_dlp_value_still_means_what_it_says() {
        assert_eq!(dlp_mode_from(Some("off")), DlpMode::Off);
        assert_eq!(dlp_mode_from(Some("shadow")), DlpMode::Shadow);
        assert_eq!(dlp_mode_from(Some("mask")), DlpMode::Mask);
        assert_eq!(dlp_mode_from(Some("block")), DlpMode::Block);
    }

    /// A typo is the case that decides which way "unrecognised" falls. Reading
    /// `TOKENFUSE_DLP=blcok` as `off` would disable the scanner at exactly the
    /// moment an operator believed they had configured it, which is the same
    /// fault `ClientKeys::from_spec` refuses to start on.
    #[test]
    fn a_misspelt_dlp_value_never_reads_as_disabled() {
        for typo in ["blcok", "on", "true", "1", "enabled"] {
            assert_eq!(dlp_mode_from(Some(typo)), DlpMode::Block, "{typo}");
        }
    }

    /// The other scanner did NOT change, and this is what says so: the two are
    /// switched independently, and only one of them has evidence behind its
    /// default.
    #[test]
    fn pii_masks_stay_off_when_nothing_is_configured() {
        assert_eq!(dlp_pii_mode_from(None), Ok(DlpMode::Off));
        assert_eq!(dlp_pii_mode_from(Some("")), Ok(DlpMode::Off));
        assert_eq!(dlp_pii_mode_from(Some("mask")), Ok(DlpMode::Mask));
        assert_eq!(dlp_pii_mode_from(Some("block")), Ok(DlpMode::Block));
    }

    #[test]
    fn tools_prune_is_off_when_nothing_is_configured() {
        assert_eq!(tools_prune_mode_from(None), ToolsPruneMode::Off);
        assert_eq!(tools_prune_mode_from(Some("")), ToolsPruneMode::Off);
    }

    #[test]
    fn tools_prune_shadow_is_the_one_word_that_turns_it_on() {
        assert_eq!(
            tools_prune_mode_from(Some("shadow")),
            ToolsPruneMode::Shadow
        );
        assert_eq!(tools_prune_mode_from(Some("off")), ToolsPruneMode::Off);
    }

    #[test]
    fn an_unrecognised_tools_prune_value_is_off_not_a_guess() {
        for typo in ["Shadow", "on", "enforce", "1", "true"] {
            assert_eq!(
                tools_prune_mode_from(Some(typo)),
                ToolsPruneMode::Off,
                "{typo}"
            );
        }
    }

    #[test]
    fn metering_is_required_when_nothing_is_configured() {
        assert!(require_run_id_from(None));
        assert!(require_run_id_from(Some("")));
        assert!(require_run_id_from(Some("1")));
    }

    /// The explicit opt-out, and its exact vocabulary. An operator restoring
    /// the old drop-in pass-through has to write one of these four words, and
    /// anything else leaves metering required rather than quietly disabling it.
    #[test]
    fn the_pass_through_needs_an_explicit_word() {
        for off in ["0", "false", "no", "off"] {
            assert!(!require_run_id_from(Some(off)), "{off}");
        }
        for other in ["nope", "disabled", "2", "  "] {
            assert!(require_run_id_from(Some(other)), "{other}");
        }
    }

    /// The red-first case for invariant 63: on the unfixed code (`TOKENFUSE_CACHE`
    /// unset falling to `Shadow`) this assertion fails. It must read `Off`.
    #[test]
    fn cache_is_off_when_nothing_is_configured() {
        use tokenfuse_core::cache::CacheMode;
        assert_eq!(cache_mode_from(None), CacheMode::Off);
        assert_eq!(cache_mode_from(Some("")), CacheMode::Off);
    }

    #[test]
    fn every_named_cache_mode_is_honoured() {
        use tokenfuse_core::cache::CacheMode;
        assert_eq!(cache_mode_from(Some("off")), CacheMode::Off);
        assert_eq!(cache_mode_from(Some("shadow")), CacheMode::Shadow);
        assert_eq!(cache_mode_from(Some("on")), CacheMode::On);
    }

    #[test]
    fn an_unrecognised_cache_value_is_off_not_a_guess() {
        use tokenfuse_core::cache::CacheMode;
        for typo in ["Shadow", "On", "enforce", "1", "true"] {
            assert_eq!(cache_mode_from(Some(typo)), CacheMode::Off, "{typo}");
        }
    }

    #[test]
    fn the_profile_nobody_set_is_governed() {
        assert_eq!(profile_from(None), Ok(Profile::Governed));
        assert_eq!(profile_from(Some("")), Ok(Profile::Governed));
        assert_eq!(profile_from(Some("   ")), Ok(Profile::Governed));
    }

    #[test]
    fn every_named_profile_is_honoured_in_any_case() {
        assert_eq!(profile_from(Some("observe")), Ok(Profile::Observe));
        assert_eq!(profile_from(Some("OBSERVE")), Ok(Profile::Observe));
        assert_eq!(profile_from(Some(" Governed ")), Ok(Profile::Governed));
    }

    #[test]
    fn an_unknown_profile_value_is_refused_naming_both_profiles() {
        let err = profile_from(Some("gov")).unwrap_err();
        for needle in ["TOKENFUSE_PROFILE", "governed", "observe", "`gov`"] {
            assert!(err.contains(needle), "{needle} missing from {err}");
        }
    }

    #[test]
    fn observe_resolves_every_default_to_what_it_always_was() {
        // The v1.18.0 defaults table, written out here rather than read from the
        // code under test: an unset variable under observe must mean exactly what
        // it meant before the profile existed.
        assert_eq!(policy_mode_under(Profile::Observe, None), Ok(Mode::Shadow));
        assert_eq!(
            wardryx_mode_under(Profile::Observe, None),
            Ok(crate::wardryx::WardryxMode::Off)
        );
        assert_eq!(
            Profile::Observe.firewall_mode(),
            tokenfuse_core::taint::FirewallMode::Shadow
        );
        assert_eq!(
            wardryx_failmode_from(crate::wardryx::WardryxMode::Off, None),
            Ok(crate::wardryx::FailMode::Open)
        );
    }

    #[test]
    /// RED-FIRST (CLAUDE.md invariant 136): a policy file that names no `mode`
    /// takes this value, and it was off under both profiles before the profile
    /// existed. Mutant: `Profile::Governed => Off` here, which keeps the file off
    /// under governed; caught by this test and by the binary test
    /// `a_policy_file_with_no_mode_is_enforce_under_governed`.
    #[test]
    fn the_absent_file_mode_is_enforce_under_governed_and_off_under_observe() {
        assert_eq!(
            Profile::Governed.absent_file_mode(),
            tokenfuse_core::taint::FirewallMode::Enforce
        );
        assert_eq!(
            Profile::Observe.absent_file_mode(),
            tokenfuse_core::taint::FirewallMode::Off
        );
    }

    fn governed_resolves_every_default_to_enforce_with_a_closed_failmode() {
        assert_eq!(
            policy_mode_under(Profile::Governed, None),
            Ok(Mode::Enforce)
        );
        assert_eq!(
            wardryx_mode_under(Profile::Governed, None),
            Ok(crate::wardryx::WardryxMode::Enforce)
        );
        assert_eq!(
            Profile::Governed.firewall_mode(),
            tokenfuse_core::taint::FirewallMode::Enforce
        );
        assert_eq!(
            wardryx_failmode_from(crate::wardryx::WardryxMode::Enforce, None),
            Ok(crate::wardryx::FailMode::Closed)
        );
    }

    #[test]
    fn an_explicit_budget_mode_wins_over_either_profile() {
        assert_eq!(
            policy_mode_under(Profile::Governed, Some("shadow")),
            Ok(Mode::Shadow)
        );
        assert_eq!(
            policy_mode_under(Profile::Governed, Some("warn")),
            Ok(Mode::Warn)
        );
        assert_eq!(
            policy_mode_under(Profile::Observe, Some("enforce")),
            Ok(Mode::Enforce)
        );
        assert!(policy_mode_under(Profile::Governed, Some("enfroce")).is_err());
    }

    #[test]
    fn an_explicit_policy_hook_mode_wins_over_either_profile() {
        use crate::wardryx::WardryxMode;
        assert_eq!(
            wardryx_mode_under(Profile::Governed, Some("off")),
            Ok(WardryxMode::Off)
        );
        assert_eq!(
            wardryx_mode_under(Profile::Observe, Some("shadow")),
            Ok(WardryxMode::Shadow)
        );
        assert!(wardryx_mode_under(Profile::Governed, Some("enfroce")).is_err());
    }

    #[test]
    fn the_startup_line_names_the_profile_and_each_setting_with_its_source() {
        let line = governance_line(
            Profile::Governed,
            &[
                ("budget", "enforce".to_string(), "profile"),
                ("policy_hook", "off".to_string(), "no-url"),
            ],
        );
        assert_eq!(
            line,
            "governance profile=governed budget=enforce(profile) policy_hook=off(no-url)"
        );
    }

    #[test]
    fn the_policy_mode_is_shadow_when_nothing_is_configured() {
        assert_eq!(policy_mode_from(None), Ok(Mode::Shadow));
        assert_eq!(policy_mode_from(Some("")), Ok(Mode::Shadow));
        assert_eq!(policy_mode_from(Some("  ")), Ok(Mode::Shadow));
    }

    #[test]
    fn every_named_policy_mode_is_honoured_in_any_case() {
        for (raw, want) in [
            ("shadow", Mode::Shadow),
            ("warn", Mode::Warn),
            ("enforce", Mode::Enforce),
            ("Enforce", Mode::Enforce),
            (" ENFORCE ", Mode::Enforce),
            ("Warn", Mode::Warn),
        ] {
            assert_eq!(policy_mode_from(Some(raw)), Ok(want), "{raw:?}");
        }
    }

    #[test]
    fn a_mistyped_policy_mode_is_refused_not_read_as_shadow() {
        for typo in ["enfroce", "enforced", "on", "1", "true", "block", "off"] {
            assert_eq!(
                policy_mode_from(Some(typo)),
                Err(typo.to_string()),
                "{typo} must be refused, not started as shadow"
            );
        }
    }

    #[test]
    fn the_firewall_mode_is_left_alone_when_nothing_is_configured() {
        assert_eq!(firewall_mode_from(None), Ok(None));
        assert_eq!(firewall_mode_from(Some("")), Ok(None));
        assert_eq!(firewall_mode_from(Some("   ")), Ok(None));
    }

    #[test]
    fn every_named_firewall_mode_is_honoured_in_any_case() {
        use tokenfuse_core::taint::FirewallMode;
        for (raw, want) in [
            ("off", FirewallMode::Off),
            ("OFF", FirewallMode::Off),
            ("shadow", FirewallMode::Shadow),
            ("Shadow", FirewallMode::Shadow),
            ("enforce", FirewallMode::Enforce),
            ("Enforce", FirewallMode::Enforce),
            (" ENFORCE ", FirewallMode::Enforce),
        ] {
            assert_eq!(firewall_mode_from(Some(raw)), Ok(Some(want)), "{raw:?}");
        }
    }

    #[test]
    fn a_mistyped_firewall_mode_is_refused_not_ignored() {
        // Ignoring it leaves the mode at whatever the policy file or the default
        // says, which is the gateway that refuses nothing while its operator
        // believes it refuses. Refused, with the value, instead.
        for typo in ["enfroce", "enforced", "on", "1", "true", "block", "warn"] {
            assert_eq!(
                firewall_mode_from(Some(typo)),
                Err(typo.to_string()),
                "{typo} must be refused, not read as no override"
            );
        }
    }

    #[test]
    fn no_run_budget_ceiling_is_set_when_nothing_is_configured() {
        assert_eq!(max_run_budget_from(None), Ok(None));
        assert_eq!(max_run_budget_from(Some("")), Ok(None));
        assert_eq!(max_run_budget_from(Some("   ")), Ok(None));
    }

    #[test]
    fn a_run_budget_ceiling_is_read_as_exact_microdollars() {
        for (raw, micro) in [
            ("1", 1_000_000),
            ("1.00", 1_000_000),
            ("0.5", 500_000),
            ("25", 25_000_000),
            (" 25 ", 25_000_000),
            ("0.000001", 1),
            ("12.345678", 12_345_678),
            ("1000000", 1_000_000_000_000),
            // 0.1 + 0.2 style values must not pick up float error.
            ("0.3", 300_000),
            ("4.35", 4_350_000),
        ] {
            assert_eq!(
                max_run_budget_from(Some(raw)),
                Ok(Some(Microusd(micro))),
                "{raw:?}"
            );
        }
    }

    #[test]
    fn a_run_budget_ceiling_nobody_can_read_is_refused_not_ignored() {
        let huge = "9".repeat(400);
        let overflow = "9223372036855"; // one dollar past i64 microdollars
        for bad in [
            "0",
            "0.0",
            "0.000000",
            "-1",
            "+1",
            "1e9",
            "1E3",
            "abc",
            "1.2.3",
            ".5",
            "5.",
            "0.0000001",
            "1,5",
            "NaN",
            "inf",
            "0x10",
            "1 000",
            "$5",
            "--1",
            overflow,
            huge.as_str(),
        ] {
            assert_eq!(
                max_run_budget_from(Some(bad)),
                Err(bad.trim().to_string()),
                "{bad:?} must be refused, never read as no ceiling"
            );
        }
    }

    /// The rule every switch below must keep, asserted once so the nine
    /// tests cannot drift apart: unset, empty and blank keep the switch's own
    /// default; a value nobody can read is refused with an error naming the
    /// variable, the value and the words it accepts; every accepted word is
    /// honoured in any case and with surrounding spaces.
    fn assert_switch<T: std::fmt::Debug + PartialEq>(
        name: &str,
        words: &str,
        parse: impl Fn(Option<&str>) -> Result<T, String>,
        default: T,
        honoured: &[(&str, T)],
    ) {
        for unset in [None, Some(""), Some("   ")] {
            match parse(unset) {
                Ok(v) => assert!(
                    v == default,
                    "{name}: {unset:?} must keep {default:?}, got {v:?}"
                ),
                Err(e) => panic!("{name}: {unset:?} must not be refused: {e}"),
            }
        }
        match parse(Some("enfroce")) {
            Ok(v) => panic!("{name}: a mistyped word must be refused, it read as {v:?}"),
            Err(e) => {
                assert!(
                    e.contains(name),
                    "{name}: refusal does not name the variable: {e}"
                );
                assert!(
                    e.contains("enfroce"),
                    "{name}: refusal does not name the value: {e}"
                );
                assert!(
                    e.contains(words),
                    "{name}: refusal does not name the words {words}: {e}"
                );
            }
        }
        for (word, expected) in honoured {
            for raw in [word.to_string(), word.to_uppercase(), format!(" {word} ")] {
                match parse(Some(&raw)) {
                    Ok(v) => assert!(
                        v == *expected,
                        "{name}: {raw:?} must read as {expected:?}, got {v:?}"
                    ),
                    Err(e) => panic!("{name}: {raw:?} is a named word and must be honoured: {e}"),
                }
            }
        }
    }

    #[test]
    fn dlp_pii_refuses_a_mistyped_word() {
        assert_switch(
            "TOKENFUSE_DLP_PII",
            "off|shadow|mask|block",
            dlp_pii_mode_from,
            DlpMode::Off,
            &[
                ("off", DlpMode::Off),
                ("shadow", DlpMode::Shadow),
                ("mask", DlpMode::Mask),
                ("block", DlpMode::Block),
            ],
        );
    }

    #[test]
    fn mcp_dlp_refuses_a_mistyped_word() {
        assert_switch(
            "TOKENFUSE_MCP_DLP",
            "off|shadow|block",
            mcp_dlp_mode_from,
            DlpMode::Shadow,
            &[
                ("off", DlpMode::Off),
                ("shadow", DlpMode::Shadow),
                ("block", DlpMode::Block),
            ],
        );
    }

    #[test]
    fn mcp_dlp_pii_refuses_a_mistyped_word() {
        assert_switch(
            "TOKENFUSE_MCP_DLP_PII",
            "off|shadow|mask|block",
            mcp_dlp_pii_mode_from,
            DlpMode::Off,
            &[
                ("off", DlpMode::Off),
                ("shadow", DlpMode::Shadow),
                ("mask", DlpMode::Mask),
                ("block", DlpMode::Block),
            ],
        );
    }

    #[test]
    fn mcp_scan_refuses_a_mistyped_word() {
        use crate::mcpbroker::ScanMode;
        assert_switch(
            "TOKENFUSE_MCP_SCAN",
            "off|warn|block",
            mcp_scan_mode_from,
            ScanMode::Warn,
            &[
                ("off", ScanMode::Off),
                ("warn", ScanMode::Warn),
                ("block", ScanMode::Block),
            ],
        );
    }

    #[test]
    fn mcp_taint_failmode_refuses_a_mistyped_word() {
        assert_switch(
            "TOKENFUSE_MCP_TAINT_FAILMODE",
            "open|closed",
            mcp_taint_failclosed_from,
            false,
            &[("open", false), ("closed", true)],
        );
    }

    #[test]
    fn wardryx_mode_refuses_a_mistyped_word() {
        use crate::wardryx::WardryxMode;
        assert_switch(
            "TOKENFUSE_WARDRYX_MODE",
            "off|shadow|enforce",
            wardryx_mode_from,
            WardryxMode::Off,
            &[
                ("off", WardryxMode::Off),
                ("shadow", WardryxMode::Shadow),
                ("enforce", WardryxMode::Enforce),
            ],
        );
    }

    #[test]
    fn wardryx_failmode_refuses_a_mistyped_word() {
        use crate::wardryx::{FailMode, WardryxMode};
        // Shadow, where unset still means open.
        assert_switch(
            "TOKENFUSE_WARDRYX_FAILMODE",
            "open|closed",
            |v| wardryx_failmode_from(WardryxMode::Shadow, v),
            FailMode::Open,
            &[("open", FailMode::Open), ("closed", FailMode::Closed)],
        );
        // Enforce, where unset means closed (invariant 117) and both words
        // still mean what they say.
        assert_switch(
            "TOKENFUSE_WARDRYX_FAILMODE",
            "open|closed",
            |v| wardryx_failmode_from(WardryxMode::Enforce, v),
            FailMode::Closed,
            &[("open", FailMode::Open), ("closed", FailMode::Closed)],
        );
    }

    #[test]
    fn the_failmode_nobody_set_is_closed_only_under_enforce() {
        use crate::wardryx::{FailMode, WardryxMode};
        assert_eq!(
            wardryx_failmode_from(WardryxMode::Enforce, None),
            Ok(FailMode::Closed)
        );
        assert_eq!(
            wardryx_failmode_from(WardryxMode::Shadow, None),
            Ok(FailMode::Open)
        );
        assert_eq!(
            wardryx_failmode_from(WardryxMode::Off, None),
            Ok(FailMode::Open)
        );
    }

    #[test]
    fn require_proof_refuses_a_mistyped_word() {
        assert_switch(
            "TOKENFUSE_MCP_REQUIRE_PROOF",
            "0|false|1|true",
            |v| required_switch_from("TOKENFUSE_MCP_REQUIRE_PROOF", v),
            false,
            &[("0", false), ("false", false), ("1", true), ("true", true)],
        );
    }

    #[test]
    fn require_secret_scopes_refuses_a_mistyped_word() {
        assert_switch(
            "TOKENFUSE_MCP_REQUIRE_SECRET_SCOPES",
            "0|false|1|true",
            |v| required_switch_from("TOKENFUSE_MCP_REQUIRE_SECRET_SCOPES", v),
            false,
            &[("0", false), ("false", false), ("1", true), ("true", true)],
        );
    }

    /// The measurement switches are deliberately NOT in the list above
    /// (invariants 61 and 63): an unknown value stays `off` with one warn line,
    /// because a measurement toggle has no stricter reading to fall back to.
    #[test]
    fn measurement_switches_keep_unknown_as_off_by_decision() {
        use tokenfuse_core::cache::CacheMode;
        assert!(matches!(cache_mode_from(Some("enfroce")), CacheMode::Off));
        assert_eq!(tools_prune_mode_from(Some("enfroce")), ToolsPruneMode::Off);
    }
}
