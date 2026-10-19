//! Client credentials for the gateway itself: who is allowed to send calls
//! through it, and which stable `key_id` their spend is attributed to.
//!
//! ## Why this exists
//!
//! Until now the gateway authenticated nobody. Every identity on a metered
//! call arrived as a request header the caller wrote: `x-fuse-run-id`,
//! `x-fuse-agent-id`, `x-fuse-parent-run-id`. That is fine for attribution a
//! cooperating fleet reports about itself, and it is documented as
//! attribution-only. It is NOT fine as the key of a budget: anything a caller
//! can choose, a caller can change, so a per-agent cap keyed on
//! `x-fuse-agent-id` is bypassed by sending a different one, and an agent id
//! that belongs to someone else can be burned on purpose.
//!
//! So a budget above the run keys on the credential the caller presented,
//! resolved here, server-side. This module is that resolution and nothing
//! more: it does not enforce a budget, it establishes the identity a later
//! slice can enforce one against.
//!
//! ## Off unless configured, then fail closed
//!
//! `TOKENFUSE_CLIENT_KEYS` unset means the gateway behaves exactly as it
//! always has: no credential is required and `key_id` is empty on every
//! record. Existing deployments are unaffected, which matters for a drop-in
//! proxy: requiring a credential by default would break every live install on
//! upgrade.
//!
//! Set, and the posture inverts: every metered call must present a known key
//! or get `401`, and calls carry the resolved `key_id`.
//!
//! The dangerous middle case is a spec that is set but yields nothing usable -
//! a typo, a stray quote, an empty interpolated variable. Treating that like
//! "unset" would silently leave the gateway open precisely when the operator
//! believed they had just closed it, so [`ClientKeys::from_spec`] returns an
//! error and startup refuses. The sibling `crates/cloud/src/keys.rs` reaches
//! the same conclusion from the other direction (it has no "off" state, so an
//! unusable spec there simply authenticates nobody); both refuse to guess.
//!
//! ## The credential header
//!
//! `x-fuse-key`, not `Authorization`. `Authorization` on an inbound call is
//! the caller's PROVIDER credential and is deliberately forwarded upstream
//! (`crate::provider::FORWARD_HEADERS`); reusing it would either send the
//! gateway's credential to Anthropic or steal the provider's. `x-fuse-*` is
//! not in that allowlist, so the gateway's own credential is never forwarded.

use std::collections::HashMap;

use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;

/// The header carrying a client's gateway credential.
pub const CLIENT_KEY_HEADER: &str = "x-fuse-key";

/// Resolved client credentials: SHA-256 of each secret -> stable `key_id`.
///
/// The map is keyed by a digest, never by the configured secret (invariant 134,
/// F-023). A presented secret is hashed and the digest looked up, so no
/// comparison runs over a secret's bytes and a value of this type, Debug output
/// included, holds no configured secret in the clear. Lookup cost depends only
/// on the presented digest, which an attacker cannot choose to match a stored
/// one. This is the same posture `crate::adminkeys` takes with a constant-time
/// comparison, for a set that may hold many keys.
#[derive(Debug, Clone, Default)]
pub struct ClientKeys {
    by_digest: HashMap<[u8; 32], String>,
}

/// SHA-256 of a secret, the key a [`ClientKeys`] map is indexed by.
fn digest(secret: &str) -> [u8; 32] {
    Sha256::digest(secret.as_bytes()).into()
}

/// Whether two presented or configured secrets are equal, compared in constant
/// time for same-length inputs (invariant 134). A length mismatch is not secret
/// and short-circuits, as `crate::adminkeys` already does.
#[must_use]
pub fn secret_eq(a: &str, b: &str) -> bool {
    let (a, b) = (a.as_bytes(), b.as_bytes());
    a.len() == b.len() && bool::from(a.ct_eq(b))
}

/// A `TOKENFUSE_CLIENT_KEYS` spec that was set but unusable. Startup refuses
/// rather than falling back to "no authentication", because that fallback
/// would leave the gateway open at exactly the moment an operator believed
/// they had closed it.
#[derive(Debug, PartialEq, Eq)]
pub struct EmptySpec;

impl std::fmt::Display for EmptySpec {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(
            "TOKENFUSE_CLIENT_KEYS is set but contains no usable `secret:key_id` entry \
             (expected e.g. `sk-live-abc:billing-agent,sk-live-def:research-agent`); \
             refusing to start rather than run with client authentication silently off",
        )
    }
}

impl std::error::Error for EmptySpec {}

impl ClientKeys {
    /// Parse `"secret:key_id,…"`.
    ///
    /// Entries missing either half are skipped, mirroring
    /// `cloud::keys::parse_keys`. A secret may contain `:` (many API-key
    /// formats do), so the split is on the LAST colon: everything before it is
    /// the secret, everything after is the `key_id`.
    ///
    /// A blank/whitespace-only spec is "not configured" and yields disabled
    /// keys. A non-blank spec that yields no entries is [`EmptySpec`].
    pub fn from_spec(spec: &str) -> Result<Self, EmptySpec> {
        let trimmed = spec.trim();
        if trimmed.is_empty() {
            return Ok(Self::default());
        }
        let mut by_digest = HashMap::new();
        for entry in trimmed.split(',') {
            let entry = entry.trim();
            if entry.is_empty() {
                continue;
            }
            let Some((secret, key_id)) = entry.rsplit_once(':') else {
                continue;
            };
            let (secret, key_id) = (secret.trim(), key_id.trim());
            if secret.is_empty() || key_id.is_empty() {
                continue;
            }
            by_digest.insert(digest(secret), key_id.to_string());
        }
        if by_digest.is_empty() {
            return Err(EmptySpec);
        }
        Ok(Self { by_digest })
    }

    /// Whether client authentication is on at all.
    #[must_use]
    pub fn enabled(&self) -> bool {
        !self.by_digest.is_empty()
    }

    /// How many distinct credentials are configured (startup logging).
    #[must_use]
    pub fn len(&self) -> usize {
        self.by_digest.len()
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.by_digest.is_empty()
    }

    /// The `key_id` a presented secret resolves to, or `None` if unknown.
    #[must_use]
    pub fn resolve(&self, secret: &str) -> Option<&str> {
        self.by_digest.get(&digest(secret)).map(String::as_str)
    }

    /// Every configured `key_id` (startup cross-checks against the identity
    /// map, docs/20). Unordered; duplicates possible when two secrets share a
    /// `key_id`, which is legal.
    pub fn key_ids(&self) -> impl Iterator<Item = &str> {
        self.by_digest.values().map(String::as_str)
    }
}

/// The startup warning for a gateway that authenticates nobody and listens
/// beyond loopback, or `None` when there is nothing to warn about (invariant
/// 119).
///
/// The shipped image binds `0.0.0.0:4100`. With `TOKENFUSE_CLIENT_KEYS` unset,
/// anyone who can reach that port spends through the gateway's provider
/// credential and names any run and agent they like. That is a legitimate
/// posture behind a network that only trusted callers reach, so it is said
/// loudly rather than refused: refusing would break every deployment that
/// relies on placement, at boot. Loopback is the standard library's answer
/// (`mcpbroker::is_loopback`), as for the admin gate (invariant 41).
#[must_use]
pub fn open_bind_warning(addr: &str, client_auth_enabled: bool) -> Option<String> {
    if client_auth_enabled || crate::mcpbroker::is_loopback(addr) {
        return None;
    }
    Some(format!(
        "client authentication is OFF and the gateway is bound to {addr}, which is not \
         loopback: anyone who can reach this address can spend through it and name any run \
         and agent. Set TOKENFUSE_CLIENT_KEYS to require a key on every call, or bind to \
         127.0.0.1."
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_open_bind_with_no_keys_is_warned_about_and_names_the_fix() {
        for addr in ["0.0.0.0:4100", "[::]:4100", "10.0.0.5:4100"] {
            let w = open_bind_warning(addr, false).unwrap_or_else(|| panic!("{addr}: no warning"));
            assert!(w.contains("client authentication is OFF"), "{w}");
            assert!(w.contains("TOKENFUSE_CLIENT_KEYS"), "{w}");
            assert!(w.contains(addr), "{w}");
        }
    }

    #[test]
    fn loopback_or_keys_is_not_warned_about() {
        for addr in [
            "127.0.0.1:4100",
            "[::1]:4100",
            "localhost:4100",
            "127.0.0.2:4100",
        ] {
            assert_eq!(open_bind_warning(addr, false), None, "{addr}");
        }
        assert_eq!(open_bind_warning("0.0.0.0:4100", true), None);
    }

    #[test]
    fn an_unset_spec_leaves_authentication_off() {
        for spec in ["", "   ", "\n"] {
            let keys =
                ClientKeys::from_spec(spec).expect("blank is 'not configured', not an error");
            assert!(!keys.enabled(), "blank spec {spec:?} must not enable auth");
            assert_eq!(keys.resolve("anything"), None);
        }
    }

    #[test]
    fn a_set_but_unusable_spec_refuses_rather_than_failing_open() {
        // Each of these is a plausible operator mistake. None may be read as
        // "authentication off" - that is the whole point of the error.
        for spec in [
            "garbage",           // forgot the :key_id
            ":no-secret",        // empty secret
            "no-key-id:",        // empty key_id
            ",,,",               // an empty interpolated variable
            "  :  ",             // whitespace on both sides
            "${TOKENFUSE_KEYS}", // an unexpanded shell variable
        ] {
            assert_eq!(
                ClientKeys::from_spec(spec).err(),
                Some(EmptySpec),
                "spec {spec:?} must be rejected, never silently disable auth"
            );
        }
    }

    #[test]
    fn secret_eq_accepts_only_the_identical_secret() {
        assert!(secret_eq("sk-live-abc", "sk-live-abc"));
        assert!(!secret_eq("sk-live-abc", "sk-live-abd"), "one byte off");
        assert!(!secret_eq("sk-live-abc", "sk-live-ab"), "a strict prefix");
        assert!(
            !secret_eq("sk-live-ab", "sk-live-abc"),
            "a longer presented value"
        );
        assert!(!secret_eq("sk-live-abc", ""), "an absent secret");
        assert!(
            !secret_eq("SK-LIVE-ABC", "sk-live-abc"),
            "case is part of the secret"
        );
    }

    #[test]
    fn the_configured_secret_is_never_kept_in_the_map() {
        // Invariant 134: the map is keyed by a digest of each secret, so a Debug
        // print of the whole value cannot disclose a configured secret.
        let keys = ClientKeys::from_spec("sk-live-zq9-distinct:billing-agent").expect("valid spec");
        assert!(
            !format!("{keys:?}").contains("sk-live-zq9-distinct"),
            "the configured secret must not be stored in the lookup map"
        );
    }

    #[test]
    fn resolves_a_known_secret_and_rejects_an_unknown_one() {
        let keys = ClientKeys::from_spec("sk-live-abc:billing-agent,sk-live-def:research-agent")
            .expect("valid spec");
        assert!(keys.enabled());
        assert_eq!(keys.len(), 2);
        assert_eq!(keys.resolve("sk-live-abc"), Some("billing-agent"));
        assert_eq!(keys.resolve("sk-live-def"), Some("research-agent"));
        assert_eq!(
            keys.resolve("sk-live-xyz"),
            None,
            "an unknown secret resolves to nothing"
        );
        assert_eq!(keys.resolve(""), None);
        assert_eq!(
            keys.resolve("billing-agent"),
            None,
            "the key_id is not itself a credential"
        );
    }

    #[test]
    fn a_secret_may_contain_colons() {
        // Real API keys often do (`sk-proj:abc:def`), so the split is on the
        // LAST colon, not the first.
        let keys = ClientKeys::from_spec("sk-proj:abc:def:billing-agent").expect("valid spec");
        assert_eq!(keys.resolve("sk-proj:abc:def"), Some("billing-agent"));
    }

    #[test]
    fn malformed_entries_are_skipped_beside_valid_ones() {
        // Matching cloud::keys::parse_keys: one bad entry does not discard the
        // rest. The spec is still usable, so this is not EmptySpec.
        let keys = ClientKeys::from_spec("garbage,sk-ok:agent-a,:also-bad,").expect("valid spec");
        assert_eq!(keys.len(), 1);
        assert_eq!(keys.resolve("sk-ok"), Some("agent-a"));
    }

    #[test]
    fn surrounding_whitespace_is_tolerated() {
        let keys = ClientKeys::from_spec(" sk-a : agent-a , sk-b : agent-b ").expect("valid spec");
        assert_eq!(keys.resolve("sk-a"), Some("agent-a"));
        assert_eq!(keys.resolve("sk-b"), Some("agent-b"));
    }
}
