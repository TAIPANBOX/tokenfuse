//! DLP — secret detection in prompts (Ring 3.2).
//!
//! Agents routinely slurp `.env` files, keys, and tokens into their context. We
//! sit on the LLM path — the one place a traditional DLP can't see — so we scan
//! the outgoing prompt for credentials and either flag, mask, or block them
//! before they reach the provider.
//!
//! Pattern-based (low false-positive), operating on the raw request text so
//! masking is a plain substring replacement that keeps the JSON valid.
//!
//! PII masks (`scan_pii`/`pii_summary`) are a separate, opt-in extension of
//! this same scanner. Regex-only, like everything else here: no ML, no
//! external call. Card numbers are Luhn-gated (a checksum plus a
//! same-digit-run rejection) to keep the false-positive rate down on a plain
//! 13 to 19 digit run; phone numbers only match the international `+` form,
//! never a bare national number, since a bare digit string is too easy to
//! confuse with an id, an amount, or a card number. False negatives are
//! expected and accepted by design, the same way a missed secret pattern is.
//! PII scanning only runs when an operator turns on the separate PII mode
//! (`TOKENFUSE_DLP_PII` / `TOKENFUSE_MCP_DLP_PII` in the gateway); with it
//! left off, `scan`, `redact`, and `summary` behave exactly as before.

use regex::Regex;
use serde::{Deserialize, Serialize};
use std::sync::OnceLock;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum DlpMode {
    #[default]
    Off,
    /// Detect and report, forward unchanged.
    Shadow,
    /// Replace secrets with `[REDACTED:kind]` before forwarding.
    Mask,
    /// Block the request if any secret is found.
    Block,
}

/// A detected secret: its kind and byte span in the scanned text.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Finding {
    pub kind: &'static str,
    pub start: usize,
    pub end: usize,
}

/// `true` if two findings' byte spans intersect at all. Used by callers that
/// combine findings from more than one scan (a secret scan plus the PII scan,
/// see `scan_pii`'s doc comment) so a single merged `redact` pass never sees
/// two entries claiming the same bytes.
pub fn spans_overlap(a: &Finding, b: &Finding) -> bool {
    a.start < b.end && b.start < a.end
}

fn patterns() -> &'static [(&'static str, Regex)] {
    static PATTERNS: OnceLock<Vec<(&'static str, Regex)>> = OnceLock::new();
    PATTERNS.get_or_init(|| {
        // Order matters: more specific patterns first so overlap dedup keeps them.
        vec![
            (
                "private_key",
                Regex::new(r"-----BEGIN [A-Z ]*PRIVATE KEY-----").unwrap(),
            ),
            (
                "anthropic_key",
                Regex::new(r"sk-ant-[A-Za-z0-9_\-]{20,}").unwrap(),
            ),
            ("openai_key", Regex::new(r"sk-[A-Za-z0-9_\-]{20,}").unwrap()),
            ("aws_access_key", Regex::new(r"AKIA[0-9A-Z]{16}").unwrap()),
            (
                "google_api_key",
                Regex::new(r"AIza[0-9A-Za-z_\-]{35}").unwrap(),
            ),
            (
                "github_token",
                Regex::new(r"gh[pousr]_[A-Za-z0-9]{36,}").unwrap(),
            ),
            (
                "slack_token",
                Regex::new(r"xox[baprs]-[A-Za-z0-9\-]{10,}").unwrap(),
            ),
            (
                "jwt",
                Regex::new(r"eyJ[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+").unwrap(),
            ),
            (
                "bearer_token",
                Regex::new(r"Bearer\s+[A-Za-z0-9._\-]{20,}").unwrap(),
            ),
        ]
    })
}

/// Find all secrets in `text`, de-overlapped (leftmost, longest, most-specific).
pub fn scan(text: &str) -> Vec<Finding> {
    let mut found = Vec::new();
    for (kind, re) in patterns() {
        for m in re.find_iter(text) {
            found.push(Finding {
                kind,
                start: m.start(),
                end: m.end(),
            });
        }
    }
    dedup_overlaps(found)
}

/// The three PII kinds this module detects, deliberately narrow: an email
/// address, a card-number candidate, and an international (`+`) phone number.
/// The card entry's regex only finds *candidates*; `scan_pii` still has to
/// run the Luhn check (a regex alone can't compute a checksum).
fn pii_patterns() -> &'static [(&'static str, Regex)] {
    static PII_PATTERNS: OnceLock<Vec<(&'static str, Regex)>> = OnceLock::new();
    PII_PATTERNS.get_or_init(|| {
        vec![
            (
                "pii_email",
                Regex::new(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}").unwrap(),
            ),
            (
                // Candidate digit runs only: 13 to 19 digits, at most one
                // space or dash between any two digits, so it matches common
                // groupings (4-4-4-4, 4-6-5, ungrouped, ...) without
                // hardcoding a layout. scan_pii still requires a Luhn pass
                // and rejects an all-same-digit run before calling this a
                // finding.
                "pii_card",
                Regex::new(r"\b\d(?:[ -]?\d){12,18}\b").unwrap(),
            ),
            (
                // Leading + required, 7 to 15 digits total (E.164's own
                // range), at most one space/dash/parenthesis between any two
                // digits. A bare national number (no leading +) never
                // matches this pattern at all - deliberate, see the module
                // doc: a plain digit string is too easy to confuse with an
                // id, an amount, or a card number to flag as a phone number
                // on its own.
                "pii_phone",
                Regex::new(r"\+\d(?:[ ()\-]?\d){6,14}\b").unwrap(),
            ),
        ]
    })
}

/// Find PII (email, card, phone) in `text`, de-overlapped the same way `scan`
/// de-overlaps secrets (`dedup_overlaps`, shared so the two scans cannot
/// drift apart). Regex-only, no ML: see the module doc for the
/// conservative-by-design limits. Callers gate this behind their own opt-in
/// PII mode; `scan` never calls it and its own findings are unaffected by
/// whatever PII-shaped text sits alongside a secret in the same request.
pub fn scan_pii(text: &str) -> Vec<Finding> {
    let mut found = Vec::new();
    for (kind, re) in pii_patterns() {
        for m in re.find_iter(text) {
            if *kind == "pii_card" {
                let digits: String = m.as_str().chars().filter(char::is_ascii_digit).collect();
                if all_same_digit(&digits) || !luhn_valid(&digits) {
                    continue;
                }
            }
            found.push(Finding {
                kind,
                start: m.start(),
                end: m.end(),
            });
        }
    }
    dedup_overlaps(found)
}

/// Standard mod-10 Luhn checksum over an ASCII-digit string: pure arithmetic,
/// no external call. `false` on any non-digit character or an empty string.
fn luhn_valid(digits: &str) -> bool {
    if digits.is_empty() {
        return false;
    }
    let mut sum: u32 = 0;
    let mut double = false;
    for c in digits.chars().rev() {
        let Some(d) = c.to_digit(10) else {
            return false;
        };
        let d = if double {
            let doubled = d * 2;
            if doubled > 9 {
                doubled - 9
            } else {
                doubled
            }
        } else {
            d
        };
        sum += d;
        double = !double;
    }
    sum.is_multiple_of(10)
}

/// `true` when every character in `digits` is the same, e.g.
/// "4444444444444444" - a common false-positive shape that scan_pii rejects
/// as a card candidate regardless of what the Luhn check says about it.
/// Empty reads as `false`: the 13-19 digit regex never hands this an empty
/// string, so it is a defensive default only.
fn all_same_digit(digits: &str) -> bool {
    let mut chars = digits.chars();
    match chars.next() {
        Some(first) => chars.all(|c| c == first),
        None => false,
    }
}

/// Shared de-overlap pass for `scan` and `scan_pii`: leftmost first, longer
/// on a tie, stable so earlier-declared patterns win the remaining ties.
/// Extracted into one function so the two scans cannot drift apart.
fn dedup_overlaps(mut found: Vec<Finding>) -> Vec<Finding> {
    found.sort_by(|a, b| a.start.cmp(&b.start).then(b.end.cmp(&a.end)));

    let mut result: Vec<Finding> = Vec::new();
    let mut last_end = 0usize;
    for f in found {
        if f.start >= last_end {
            last_end = f.end;
            result.push(f);
        }
    }
    result
}

/// Replace each finding with `[REDACTED:kind]`, preserving the rest of the text.
pub fn redact(text: &str, findings: &[Finding]) -> String {
    let mut s = text.to_string();
    // Replace from the end so earlier byte offsets stay valid.
    let mut ordered: Vec<&Finding> = findings.iter().collect();
    ordered.sort_by_key(|f| std::cmp::Reverse(f.start));
    for f in ordered {
        if f.end <= s.len() && s.is_char_boundary(f.start) && s.is_char_boundary(f.end) {
            s.replace_range(f.start..f.end, &format!("[REDACTED:{}]", f.kind));
        }
    }
    s
}

/// A short human summary, e.g. "2 secret(s): anthropic_key, aws_access_key".
pub fn summary(findings: &[Finding]) -> String {
    format_summary(findings, "secret(s)")
}

/// A short human summary, e.g. "2 pii finding(s): pii_card, pii_email".
pub fn pii_summary(findings: &[Finding]) -> String {
    format_summary(findings, "pii finding(s)")
}

/// Shared by `summary`/`pii_summary` so the two label formats cannot drift
/// apart. `noun` supplies only the trailing label ("secret(s)" vs
/// "pii finding(s)"); the count and the sorted, de-duplicated kind list are
/// built identically either way.
fn format_summary(findings: &[Finding], noun: &str) -> String {
    let mut kinds: Vec<&str> = findings.iter().map(|f| f.kind).collect();
    kinds.sort_unstable();
    kinds.dedup();
    format!("{} {}: {}", findings.len(), noun, kinds.join(", "))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detects_common_key_shapes() {
        let text = "here is sk-ant-abc12345678901234567890 and AKIA1234567890ABCDEF end";
        let f = scan(text);
        let kinds: Vec<_> = f.iter().map(|x| x.kind).collect();
        assert!(kinds.contains(&"anthropic_key"));
        assert!(kinds.contains(&"aws_access_key"));
    }

    #[test]
    fn anthropic_wins_over_openai_for_sk_ant() {
        // sk-ant- also loosely matches the openai sk- pattern; dedup must keep
        // the more specific anthropic label.
        let f = scan("sk-ant-abcdefghij0123456789xyz");
        assert_eq!(f.len(), 1);
        assert_eq!(f[0].kind, "anthropic_key");
    }

    #[test]
    fn redaction_replaces_secret_and_keeps_surroundings() {
        let text = r#"{"content":"my key is AKIA1234567890ABCDEF ok"}"#;
        let f = scan(text);
        let out = redact(text, &f);
        assert!(!out.contains("AKIA1234567890ABCDEF"));
        assert!(out.contains("[REDACTED:aws_access_key]"));
        assert!(out.starts_with(r#"{"content":"my key is "#));
    }

    #[test]
    fn clean_text_has_no_findings() {
        assert!(scan("just a normal prompt about refunds").is_empty());
    }

    #[test]
    fn summary_counts_and_lists_kinds() {
        let f = scan("AKIA1234567890ABCDEF sk-ant-abcdefghij0123456789xyz");
        let s = summary(&f);
        assert!(s.starts_with("2 secret(s):"));
        assert!(s.contains("aws_access_key"));
        assert!(s.contains("anthropic_key"));
    }

    // -- PII masks (opt-in extension) ----------------------------------------

    #[test]
    fn pii_email_is_detected() {
        let f = scan_pii("reach me at jane.doe+work@example.co.uk please");
        assert_eq!(f.len(), 1);
        assert_eq!(f[0].kind, "pii_email");
    }

    #[test]
    fn pii_card_with_valid_luhn_is_detected() {
        // 4111111111111111 is the standard Luhn-valid test Visa number.
        let f = scan_pii("card 4111111111111111 on file");
        assert_eq!(f.len(), 1);
        assert_eq!(f[0].kind, "pii_card");
    }

    #[test]
    fn pii_card_failing_luhn_is_not_detected() {
        // Last digit bumped by one from the valid number above: the Luhn
        // check digit is never doubled, so this always breaks the checksum.
        let f = scan_pii("card 4111111111111112 on file");
        assert!(f.is_empty());
    }

    #[test]
    fn pii_card_all_same_digit_is_not_detected() {
        // 16 identical digits: a common false-positive shape, rejected even
        // though it is a candidate the regex alone would happily match.
        let f = scan_pii("card 4444444444444444 on file");
        assert!(f.is_empty());
    }

    #[test]
    fn pii_phone_international_form_is_detected() {
        let f = scan_pii("call +1 415 555 2671 today");
        assert_eq!(f.len(), 1);
        assert_eq!(f[0].kind, "pii_phone");
    }

    #[test]
    fn pii_phone_bare_national_number_is_not_detected() {
        // No leading + -> deliberately not matched (false-positive control
        // on ordinary digit strings; see the module doc).
        let f = scan_pii("call 415 555 2671 today");
        assert!(f.is_empty());
    }

    #[test]
    fn pii_overlapping_a_secret_span_is_detected_as_overlap() {
        // A JWT's middle segment happens to be a Luhn-valid 16-digit run,
        // bounded by dots (non-word characters) on both sides, so pii_card
        // candidates it too. A caller merging both scans (see proxy.rs /
        // mcpbroker.rs) drops the overlapping pii finding and keeps the
        // secret; this proves spans_overlap actually flags the overlap for
        // that logic to act on.
        let text = "token eyJhbGciOiJIUzI1NiJ9.4111111111111111.dGVzdHNpZ25hdHVyZQ end";
        let secrets = scan(text);
        let pii = scan_pii(text);
        assert_eq!(secrets.len(), 1);
        assert_eq!(secrets[0].kind, "jwt");
        assert_eq!(pii.len(), 1);
        assert_eq!(pii[0].kind, "pii_card");
        assert!(
            spans_overlap(&secrets[0], &pii[0]),
            "the card candidate sits inside the jwt span"
        );

        // Secrets win: a caller merging findings drops any pii span that
        // overlaps a secret one before redacting.
        let kept: Vec<_> = pii
            .iter()
            .filter(|p| !spans_overlap(&secrets[0], p))
            .collect();
        assert!(
            kept.is_empty(),
            "the overlapping pii finding must be dropped"
        );
    }

    #[test]
    fn redaction_replaces_pii_and_keeps_surroundings() {
        let text = r#"{"content":"email me at jane.doe@example.com ok"}"#;
        let f = scan_pii(text);
        let out = redact(text, &f);
        assert!(!out.contains("jane.doe@example.com"));
        assert!(out.contains("[REDACTED:pii_email]"));
        assert!(out.starts_with(r#"{"content":"email me at "#));
    }

    #[test]
    fn pii_summary_counts_and_lists_kinds() {
        let f = scan_pii("email jane.doe@example.com and phone +14155552671");
        let s = pii_summary(&f);
        assert!(s.starts_with("2 pii finding(s):"));
        assert!(s.contains("pii_email"));
        assert!(s.contains("pii_phone"));
    }

    #[test]
    fn scan_secrets_unaffected_by_pii_content_in_the_same_text() {
        // scan() (secrets) must not change shape just because pii-looking
        // text sits in the same request.
        let text = "email jane.doe@example.com key AKIA1234567890ABCDEF phone +14155552671";
        let f = scan(text);
        let kinds: Vec<_> = f.iter().map(|x| x.kind).collect();
        assert_eq!(kinds, vec!["aws_access_key"]);
    }
}
