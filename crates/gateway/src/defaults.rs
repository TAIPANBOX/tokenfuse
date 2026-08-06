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

use tokenfuse_core::DlpMode;

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
}
