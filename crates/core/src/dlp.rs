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
//! this same scanner. Pattern-based, like everything else here: no ML, no
//! external call. Card numbers are Luhn-gated (a checksum plus a
//! same-digit-run rejection) to keep the false-positive rate down on a plain
//! 13 to 19 digit run, and a run that is part of a decimal number (`0.4193...`,
//! `4193....5`) is not a candidate at all (invariant 110); IBANs are checked
//! against the ISO 13616 registry's country lengths and the mod-97 checksum
//! (invariant 110); phone numbers only match the international `+` form,
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

/// The regex PII kinds this module detects, deliberately narrow: an email
/// address, a card-number candidate, and an international (`+`) phone number.
/// The fourth kind, `pii_iban`, is found by [`scan_ibans`], since its length
/// depends on its country.
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
    // IBANs first, so an IBAN wins the de-overlap against a card candidate
    // inside its own digits (leftmost, then longer, then earlier).
    let mut found = scan_ibans(text);
    for (kind, re) in pii_patterns() {
        for m in re.find_iter(text) {
            if *kind == "pii_card" {
                if part_of_a_decimal(text.as_bytes(), m.start(), m.end()) {
                    continue;
                }
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

/// Invariant 110: whether the digit run at `start..end` is part of a decimal
/// number rather than a number of its own. A fraction (`0.41935483870967744`,
/// `-0.4193...`, `.4193...`) follows a `.` that no letter precedes (`no.4111...`
/// still reads as a card); an integer part (`41935483870967744.5`) is followed
/// by `.` and a digit. An exponent needs nothing here: the candidate pattern's
/// `\b` already refuses a run that runs on into `e` or `E`. Measured on GCP,
/// 2026-10-14: a typed answer's probability, `0.41935483870967744`, passes
/// Luhn, and the broker in PII block mode refused a clean answer as a card.
fn part_of_a_decimal(text: &[u8], start: usize, end: usize) -> bool {
    let fraction = start >= 1
        && text[start - 1] == b'.'
        && (start < 2 || !text[start - 2].is_ascii_alphabetic());
    let integer_part =
        text.get(end) == Some(&b'.') && text.get(end + 1).is_some_and(|b| b.is_ascii_digit());
    fraction || integer_part
}

/// The ISO 13616 IBAN registry: each country code and its IBAN's exact
/// length. The 89 countries of the registry as Wikipedia's IBAN article lists
/// them, read 2026-10-14; the "aspirational" codes outside the registry are
/// left out on purpose, since a bank there issues no IBAN yet.
const IBAN_LENGTHS: &[(&str, usize)] = &[
    ("AD", 24),
    ("AE", 23),
    ("AL", 28),
    ("AT", 20),
    ("AZ", 28),
    ("BA", 20),
    ("BE", 16),
    ("BG", 22),
    ("BH", 22),
    ("BI", 27),
    ("BR", 29),
    ("BY", 28),
    ("CH", 21),
    ("CR", 22),
    ("CY", 28),
    ("CZ", 24),
    ("DE", 22),
    ("DJ", 27),
    ("DK", 18),
    ("DO", 28),
    ("EE", 20),
    ("EG", 29),
    ("ES", 24),
    ("FI", 18),
    ("FK", 18),
    ("FO", 18),
    ("FR", 27),
    ("GB", 22),
    ("GE", 22),
    ("GI", 23),
    ("GL", 18),
    ("GR", 27),
    ("GT", 28),
    ("HN", 28),
    ("HR", 21),
    ("HU", 28),
    ("IE", 22),
    ("IL", 23),
    ("IQ", 23),
    ("IS", 26),
    ("IT", 27),
    ("JO", 30),
    ("KW", 30),
    ("KZ", 20),
    ("LB", 28),
    ("LC", 32),
    ("LI", 21),
    ("LT", 20),
    ("LU", 20),
    ("LV", 21),
    ("LY", 25),
    ("MC", 27),
    ("MD", 24),
    ("ME", 22),
    ("MK", 19),
    ("MN", 20),
    ("MR", 27),
    ("MT", 31),
    ("MU", 30),
    ("NI", 28),
    ("NL", 18),
    ("NO", 15),
    ("OM", 23),
    ("PK", 24),
    ("PL", 28),
    ("PS", 29),
    ("PT", 25),
    ("QA", 29),
    ("RO", 24),
    ("RS", 22),
    ("RU", 33),
    ("SA", 24),
    ("SC", 31),
    ("SD", 18),
    ("SE", 24),
    ("SI", 19),
    ("SK", 24),
    ("SM", 27),
    ("SO", 23),
    ("ST", 25),
    ("SV", 28),
    ("TL", 23),
    ("TN", 24),
    ("TR", 26),
    ("UA", 29),
    ("VA", 22),
    ("VG", 24),
    ("XK", 20),
    ("YE", 30),
];

/// Invariant 110: IBANs in `text`, compact (`GB82WEST12345698765432`) or in
/// groups of four (`GB82 WEST 1234 ...`), upper case only. A candidate starts
/// with two capital letters and two digits at a word boundary; its country
/// fixes its length; that many letters and digits are read, a single space
/// allowed between any two; the next character must not continue the word;
/// and the ISO 7064 mod-97 check over the rearranged string must give 1.
/// Like the Luhn gate on a card, the checksum is what keeps a random
/// alphanumeric run from being called an IBAN.
fn scan_ibans(text: &str) -> Vec<Finding> {
    static START: OnceLock<Regex> = OnceLock::new();
    let start = START.get_or_init(|| Regex::new(r"\b[A-Z]{2}[0-9]{2}").unwrap());
    let bytes = text.as_bytes();
    let mut out = Vec::new();
    for m in start.find_iter(text) {
        let s = m.start();
        let Some(&(_, len)) = IBAN_LENGTHS
            .iter()
            .find(|(c, _)| text.get(s..s + 2) == Some(*c))
        else {
            continue;
        };
        let mut compact = String::with_capacity(len);
        let mut i = s;
        while compact.len() < len && i < bytes.len() {
            let b = bytes[i];
            if b.is_ascii_uppercase() || b.is_ascii_digit() {
                compact.push(b as char);
                i += 1;
            } else if b == b' '
                && !compact.is_empty()
                && bytes
                    .get(i + 1)
                    .is_some_and(|n| n.is_ascii_uppercase() || n.is_ascii_digit())
            {
                i += 1;
            } else {
                break;
            }
        }
        if compact.len() < len || bytes.get(i).is_some_and(|b| b.is_ascii_alphanumeric()) {
            continue;
        }
        if iban_checksum_holds(&compact) {
            out.push(Finding {
                kind: "pii_iban",
                start: s,
                end: i,
            });
        }
    }
    out
}

/// ISO 7064 mod 97-10 as IBANs use it: move the first four characters to the
/// end, read each letter as two digits (A = 10 ... Z = 35), and the number
/// modulo 97 must be 1. Computed piecewise, so no length overflows.
fn iban_checksum_holds(compact: &str) -> bool {
    let rearranged = compact[4..].chars().chain(compact[..4].chars());
    let mut rem: u32 = 0;
    for c in rearranged {
        let Some(v) = c.to_digit(36) else {
            return false;
        };
        rem = if v < 10 {
            (rem * 10 + v) % 97
        } else {
            (rem * 100 + v) % 97
        };
    }
    rem == 1
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

/// Each kind found and how often, `kind=count` joined by `,` and sorted by
/// kind: `pii_card=1,pii_email=2`. Kinds and counts only, never a matched
/// span, so it can go into a trace column and onto the Cloud wire (invariant
/// 106). Empty for no findings.
pub fn kind_counts(findings: &[Finding]) -> String {
    let mut counts: std::collections::BTreeMap<&str, usize> = std::collections::BTreeMap::new();
    for f in findings {
        *counts.entry(f.kind).or_insert(0) += 1;
    }
    counts
        .iter()
        .map(|(k, n)| format!("{k}={n}"))
        .collect::<Vec<_>>()
        .join(",")
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
    fn kind_counts_name_each_kind_and_how_often_never_the_text() {
        let text = "mail a@example.com and b@example.com, card 4111 1111 1111 1111";
        let found = scan_pii(text);
        let counts = kind_counts(&found);
        assert_eq!(counts, "pii_card=1,pii_email=2");
        assert!(!counts.contains("example.com") && !counts.contains("4111"));
        assert_eq!(kind_counts(&[]), "");
    }

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
        let text = "token eyJhbGciOiJIUzI1NiJ9.x4111111111111111.dGVzdHNpZ25hdHVyZQ end";
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

    // -- Invariant 110: IBANs, and digits inside a decimal are not a card ----

    fn kinds(text: &str) -> Vec<&'static str> {
        let mut k: Vec<&'static str> = scan_pii(text).iter().map(|f| f.kind).collect();
        k.sort_unstable();
        k
    }

    /// The forge prompt of 2026-10-14, verbatim: the IBAN is the standard
    /// valid example (mod-97 holds) and was the one item the scan missed.
    #[test]
    fn the_forge_prompt_finds_the_iban_beside_the_card_and_the_email() {
        let prompt = "Reply OK. My email is jane.doe@example.com, my card is 4111 1111 1111 1111 \
                      and my IBAN is GB82WEST12345698765432.";
        assert_eq!(kinds(prompt), vec!["pii_card", "pii_email", "pii_iban"]);
        let iban = scan_pii(prompt)
            .into_iter()
            .find(|f| f.kind == "pii_iban")
            .unwrap();
        assert_eq!(&prompt[iban.start..iban.end], "GB82WEST12345698765432");
    }

    #[test]
    fn an_iban_written_in_groups_is_one_finding() {
        for text in [
            "pay GB82 WEST 1234 5698 7654 32 today",
            "DE89 3704 0044 0532 0130 00",
            "DE89370400440532013000",
            "FR1420041010050500013M02606",
            "NO9386011117947",
        ] {
            let f = scan_pii(text);
            assert_eq!(f.len(), 1, "{text}: {f:?}");
            assert_eq!(f[0].kind, "pii_iban", "{text}");
        }
        let text = "pay GB82 WEST 1234 5698 7654 32 today";
        let f = scan_pii(text);
        assert_eq!(&text[f[0].start..f[0].end], "GB82 WEST 1234 5698 7654 32");
    }

    #[test]
    fn a_wrong_checksum_length_or_country_is_not_an_iban() {
        for text in [
            "GB82WEST12345698765433",
            "GB82WEST1234569876543",
            "GB82WEST123456987654321",
            "ZZ82WEST12345698765432",
            "gb82west12345698765432",
            "GB82WEST12345698765432X",
        ] {
            assert!(
                !kinds(text).contains(&"pii_iban"),
                "{text}: {:?}",
                scan_pii(text)
            );
        }
    }

    #[test]
    fn a_masked_iban_reads_as_its_kind() {
        let text = "IBAN GB82WEST12345698765432 ok";
        let out = redact(text, &scan_pii(text));
        assert_eq!(out, "IBAN [REDACTED:pii_iban] ok");
    }

    /// Strings shaped like an IBAN (a registered country, its exact length,
    /// random alphanumerics) pass mod-97 about once in 97; the checksum is
    /// what keeps the kind honest. 200 seeds.
    #[test]
    fn iban_shaped_noise_is_rarely_an_iban() {
        let mut seed: u64 = 0x1ba2_2026_1014;
        let mut hits = 0;
        for _ in 0..200 {
            let mut s = String::from("GB");
            for i in 0..20 {
                seed ^= seed << 13;
                seed ^= seed >> 7;
                seed ^= seed << 17;
                let pick = (seed % 36) as u8;
                let c = if i < 2 || pick < 10 {
                    (b'0' + pick % 10) as char
                } else {
                    (b'A' + pick - 10) as char
                };
                s.push(c);
            }
            if kinds(&s).contains(&"pii_iban") {
                hits += 1;
            }
        }
        assert!(hits <= 8, "{hits} of 200 random strings read as an IBAN");
    }

    /// GCP, 2026-10-14: a clean typed answer (`TOKENFUSE_MCP_DLP_PII=block`)
    /// was refused as a card because a probability's 17-digit fraction passed
    /// Luhn. This is the answer the broker relayed, verbatim; both fractions
    /// of 0.41935483870967744 are Luhn-valid.
    #[test]
    fn a_probability_in_a_typed_answer_is_not_a_card() {
        let answer = r#"{"answer_id":"232db9c18dbe9521e3e83ff63ed6b947","template":"eval.outcome_met","template_version":"2d3ecbdc88d71358c281ba2163f056bc56559beff4af6a4d937cd6a66f0f732d","type":"noul","answer":0.41935483870967744,"probabilities":{"false":0.5806451612903226,"true":0.41935483870967744},"backend":"stub","model":"stub-0","latency_ms":0,"held_back_fields":0}"#;
        assert!(scan_pii(answer).is_empty(), "{:?}", scan_pii(answer));
        assert!(scan_pii("x = -0.41935483870967744;").is_empty());
        assert!(scan_pii("total 41935483870967744.5 units").is_empty());
    }

    #[test]
    fn a_card_written_like_a_card_is_still_found() {
        for text in [
            "card 4111 1111 1111 1111.",
            "card 4111-1111-1111-1111, thanks",
            "card 4111111111111111.",
            "(4111111111111111)",
        ] {
            assert_eq!(kinds(text), vec!["pii_card"], "{text}");
        }
    }
}
