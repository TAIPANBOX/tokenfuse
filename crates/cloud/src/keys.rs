//! API-key → principal mapping. A key spec is `key:org[:role[:site]]`, the
//! role defaulting to `admin` (`viewer` can read but not mutate; `ingest` may
//! push telemetry and read what a viewer reads, but nothing else - invariant
//! 65). The optional 4th segment names the site (gateway) this key is bound
//! to, so `/v1/ingest` can attribute every record it pushes to that site
//! without trusting anything in the request body. Ported from the Go plane's
//! `parseKeys`.
//!
//! **Fails closed.** An unset/empty/all-malformed spec yields an *empty* map:
//! every request then gets `401`, nobody authenticates. There is no fallback
//! credential: no spec value ever grants access on its own.

use std::collections::HashMap;

/// Who a key belongs to: an organization, a role (`admin` | `viewer` |
/// `ingest`, or any other string - see [`parse_keys`]), and, optionally, the
/// site (gateway) it is bound to (invariant 65).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Principal {
    pub org: String,
    pub role: String,
    /// The site this key pushes as, from the key spec's 4th segment. `None`
    /// for a key with no 4th segment, an empty one, or a principal that isn't
    /// an org key at all (OIDC, a paired device - see `http.rs`'s
    /// `Mutator::site`). Never set from anything in a request: the whole
    /// point of invariant 65 is that a site comes from the credential, never
    /// from the body or headers.
    pub site: Option<String>,
}

/// Matches `^[a-z0-9][a-z0-9._-]{0,62}$`, checked by hand rather than with a
/// regex crate: `tokenfuse-cloud` does not depend on `regex` (unlike
/// `tokenfuse-core`, invariant 1), and this grammar is simple enough that
/// adding one just for it would not be worth the dependency.
fn is_valid_site_name(s: &str) -> bool {
    if s.is_empty() || s.len() > 63 {
        return false;
    }
    let mut chars = s.chars();
    let first_ok = matches!(chars.next(), Some(c) if c.is_ascii_lowercase() || c.is_ascii_digit());
    first_ok
        && chars
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || matches!(c, '.' | '_' | '-'))
}

/// Parse `"key:org[:role[:site]],…"`. Entries missing a key or an org, or
/// carrying more than four colon-separated segments, are skipped. Segments
/// are positional: the 3rd is the role (default `admin`), the 4th the site.
///
/// The site segment (invariant 65) fails closed on its own: present and
/// non-empty, it must match [`is_valid_site_name`] or the WHOLE entry is
/// skipped, same as any other malformed entry - a key with an invalid site is
/// not silently admitted with no site, because that would authenticate a
/// caller nobody asked to authenticate under that shape. Present and empty
/// (`k:o:admin:`) means no site, same as the segment being absent.
///
/// With no valid entries, this **fails closed**: an empty map is returned, so
/// every request gets `401`. There is no fallback credential.
pub fn parse_keys(spec: &str) -> HashMap<String, Principal> {
    let mut keys = HashMap::new();
    for pair in spec.split(',') {
        let pair = pair.trim();
        if pair.is_empty() {
            continue;
        }
        let parts: Vec<&str> = pair.split(':').collect();
        if parts.len() < 2
            || parts.len() > 4
            || parts[0].trim().is_empty()
            || parts[1].trim().is_empty()
        {
            continue;
        }
        let role = parts
            .get(2)
            .map(|s| s.trim())
            .filter(|s| !s.is_empty())
            .unwrap_or("admin");
        let site = match parts.get(3).map(|s| s.trim()) {
            None | Some("") => None,
            Some(s) if is_valid_site_name(s) => Some(s.to_string()),
            Some(_) => continue, // invalid site name: skip the whole entry
        };
        keys.insert(
            parts[0].trim().to_string(),
            Principal {
                org: parts[1].trim().to_string(),
                role: role.to_string(),
                site,
            },
        );
    }
    keys
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_org_and_role() {
        let k = parse_keys("a:acme,b:globex:viewer");
        assert_eq!(
            k["a"],
            Principal {
                org: "acme".into(),
                role: "admin".into(),
                site: None,
            }
        );
        assert_eq!(
            k["b"],
            Principal {
                org: "globex".into(),
                role: "viewer".into(),
                site: None,
            }
        );
    }

    #[test]
    fn skips_malformed_entries() {
        let k = parse_keys("nokey, :noorg , good:org");
        assert_eq!(k.len(), 1);
        assert!(k.contains_key("good"));
    }

    // -- fails closed: there is no fallback credential ---------------------

    #[test]
    fn empty_spec_fails_closed() {
        // The security-critical case: an unset/empty TOKENFUSE_CLOUD_KEYS
        // must NOT grant anything. The map must be empty, so every request
        // gets 401 (nobody authenticates).
        let k = parse_keys("");
        assert!(
            k.is_empty(),
            "expected no keys for an empty spec, got {k:?}"
        );
        assert!(!k.contains_key("devkey"));
    }

    #[test]
    fn all_malformed_spec_fails_closed() {
        // Same fail-closed guarantee when every entry is malformed (missing
        // key or org) rather than the spec being literally empty.
        let k = parse_keys("nokey, :noorg ,   ");
        assert!(k.is_empty());
    }

    #[test]
    fn normal_spec_never_adds_devkey() {
        // A real, non-empty spec parses to exactly its own keys, and never
        // injects an extra "devkey" entry.
        let k = parse_keys("a:acme");
        assert_eq!(k.len(), 1);
        assert!(!k.contains_key("devkey"));
        assert_eq!(k["a"].org, "acme");
    }

    // -- invariant 65: the 4th segment names a site -------------------------

    #[test]
    fn a_fourth_segment_is_parsed_as_the_site() {
        let k = parse_keys("s:acme:ingest:site-a");
        assert_eq!(k["s"].org, "acme");
        assert_eq!(k["s"].role, "ingest");
        assert_eq!(k["s"].site.as_deref(), Some("site-a"));
    }

    #[test]
    fn an_empty_fourth_segment_means_no_site() {
        let k = parse_keys("s:acme:admin:");
        assert_eq!(k["s"].site, None);
    }

    #[test]
    fn an_invalid_site_name_skips_the_whole_entry() {
        // Fail closed like any other malformed entry: an entry naming an
        // invalid site authenticates nobody, rather than silently dropping
        // just the site and admitting the key anyway.
        for bad in [
            "s1:acme:admin:UPPER",                        // uppercase not allowed
            "s2:acme:admin:-leading",                     // must start with [a-z0-9]
            "s3:acme:admin:has/slash",                    // '/' not allowed
            &format!("s4:acme:admin:{}", "a".repeat(64)), // over 63 chars
        ] {
            let k = parse_keys(bad);
            assert!(k.is_empty(), "expected {bad:?} to be skipped, got {k:?}");
        }
    }

    #[test]
    fn five_segments_are_malformed_and_skipped() {
        let k = parse_keys("s:acme:admin:site-a:extra");
        assert!(k.is_empty());
    }

    #[test]
    fn three_segment_specs_parse_exactly_as_before() {
        let k = parse_keys("a:acme:viewer");
        assert_eq!(k["a"].role, "viewer");
        assert_eq!(k["a"].site, None);
    }
}
