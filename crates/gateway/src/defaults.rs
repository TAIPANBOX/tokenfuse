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
/// one above: `pii_email`/`pii_card`/`pii_phone` are heuristics over ordinary
/// text, so their false positives are prose rather than credentials, and the
/// 2026-08-04 range said nothing about them. Turning something on by default is
/// a claim that its false positives are worth its true positives, and that
/// claim is only established here for the secret patterns.
pub fn dlp_pii_mode_from(value: Option<&str>) -> DlpMode {
    match value.map(str::trim) {
        Some("shadow") => DlpMode::Shadow,
        Some("mask") => DlpMode::Mask,
        Some("block") => DlpMode::Block,
        _ => DlpMode::Off,
    }
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

/// [`dlp_pii_mode_from`] against the process environment.
pub fn dlp_pii_mode_from_env() -> DlpMode {
    dlp_pii_mode_from(std::env::var("TOKENFUSE_DLP_PII").ok().as_deref())
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
        assert_eq!(dlp_pii_mode_from(None), DlpMode::Off);
        assert_eq!(dlp_pii_mode_from(Some("")), DlpMode::Off);
        assert_eq!(dlp_pii_mode_from(Some("mask")), DlpMode::Mask);
        assert_eq!(dlp_pii_mode_from(Some("block")), DlpMode::Block);
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
}
