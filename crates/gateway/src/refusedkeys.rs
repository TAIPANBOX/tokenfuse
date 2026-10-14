//! Invariant 105: a call refused for its client key is on the bus, and a scan
//! cannot flood it.
//!
//! A `401` for a missing or unknown `x-fuse-key` used to bump one aggregate
//! counter (`keystats`) and say nothing else, so a key scan was invisible to
//! every consumer of the event bus (forge, 2026-10-14). Each refusal now goes
//! on the bus as `identity_mismatch`, the type of the gateway's identity gate,
//! with a `reason` no real identity mismatch uses (`missing_key`,
//! `unknown_key`) and, for an unknown key, a fingerprint of what was presented.
//!
//! A call that names no `x-fuse-agent-id` (a key scan names none) is filed
//! under [`UNIDENTIFIED_CALLER`], so the case that matters most is not the
//! one the bus cannot see.
//!
//! The caller's answer does not change: both causes stay one `401` with one
//! body, because telling a caller which half it got wrong tells an attacker
//! whether a secret exists (`clientkeys`). Only the operator's record learns
//! which it was.
//!
//! **The fingerprint, never the key.** `sha256:` and the first 16 hex digits
//! of the SHA-256 of the presented value: enough for an operator to match it
//! against the keys they issued (hash each one the same way) and to see one
//! client retrying the same wrong key, not enough to recover a key of any real
//! length. A short guess is recoverable from its fingerprint by trying
//! guesses, which costs nothing, since a guess is not a secret.
//!
//! **Rate-limited per source.** A source is the fingerprint (or "no key") and
//! the agent the call claimed. One source is reported at most once a minute,
//! and the next report says how many refusals from it went unreported in
//! between; the whole gateway reports at most sixty a minute. A scan of a
//! million keys is sixty events a minute, not a million.

use std::collections::HashMap;
use std::sync::Mutex;

use sha2::{Digest, Sha256};

/// The subject a refusal is filed under when the call named no agent: a
/// key scan names none, and an event must name an agent (SPEC 6.1). The
/// trust domain is under `.invalid` (RFC 2606), so it can never be an agent
/// anybody issued; the agent-passport registry is asked to reserve it.
pub const UNIDENTIFIED_CALLER: &str = "agent://unidentified.invalid/caller";

/// One source is reported at most once in this interval.
pub const PER_SOURCE_INTERVAL_MILLIS: i64 = 60_000;
/// At most this many refusal events per minute from the whole gateway.
pub const PER_MINUTE_CAP: u32 = 60;
/// How many sources the limiter remembers before it starts over; sources are
/// caller-chosen, so the map is bounded.
pub const SOURCES_CAP: usize = 4096;

/// `sha256:<first 16 hex digits>` of the presented value.
pub fn fingerprint(presented: &str) -> String {
    let digest = Sha256::digest(presented.as_bytes());
    let mut hex = String::with_capacity(16);
    for b in digest.iter().take(8) {
        hex.push_str(&format!("{b:02x}"));
    }
    format!("sha256:{hex}")
}

#[derive(Debug, Default)]
struct Window {
    /// When the current minute of the global cap began.
    started: i64,
    emitted: u32,
    /// Per source: when it was last reported, and how many refusals since.
    sources: HashMap<String, (i64, u64)>,
}

/// The limiter. One per gateway process, on `AppState`.
#[derive(Debug, Default)]
pub struct RefusedKeys {
    window: Mutex<Window>,
}

impl RefusedKeys {
    /// Count one refusal from `source` at `now`. `Some(n)` when it goes on the
    /// bus, `n` being the refusals from the same source not reported since its
    /// last event; `None` when it is held back by either limit.
    pub fn admit(&self, source: &str, now: i64) -> Option<u64> {
        let mut w = self.window.lock().unwrap();
        if now - w.started >= 60_000 || now < w.started {
            w.started = now;
            w.emitted = 0;
        }
        if w.sources.len() >= SOURCES_CAP && !w.sources.contains_key(source) {
            w.sources.clear();
        }
        let global_full = w.emitted >= PER_MINUTE_CAP;
        let entry = w.sources.entry(source.to_string()).or_insert((i64::MIN, 0));
        let due = entry.0 == i64::MIN || now - entry.0 >= PER_SOURCE_INTERVAL_MILLIS;
        if !due || global_full {
            entry.1 = entry.1.saturating_add(1);
            return None;
        }
        let unreported = entry.1;
        *entry = (now, 0);
        w.emitted += 1;
        Some(unreported)
    }
}

/// The `data` of the event: the reason, the fingerprint of an unknown key,
/// the agent the call claimed, and how many refusals from this source went
/// unreported since its last event. Never the presented value.
pub fn refused_key_data(
    reason: &str,
    key_fingerprint: Option<&str>,
    claimed_agent: &str,
    unreported: u64,
) -> serde_json::Value {
    serde_json::json!({
        "reason": reason,
        "key_fingerprint": key_fingerprint,
        "agent_id": (!claimed_agent.is_empty()).then_some(claimed_agent),
        "unreported_since_last": unreported,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_fingerprint_is_a_prefix_of_the_sha256_and_never_the_key() {
        let f = fingerprint("sk-wrong-key-77");
        assert!(f.starts_with("sha256:"));
        assert_eq!(f.len(), "sha256:".len() + 16);
        assert!(!f.contains("sk-wrong"));
        assert_eq!(f, fingerprint("sk-wrong-key-77"), "stable");
        assert_ne!(f, fingerprint("sk-wrong-key-78"));
        // The SHA-256 of the empty string begins e3b0c44298fc1c14.
        assert_eq!(fingerprint(""), "sha256:e3b0c44298fc1c14");
    }

    #[test]
    fn one_source_is_reported_once_a_minute_with_what_it_held_back() {
        let r = RefusedKeys::default();
        assert_eq!(r.admit("a", 1_000), Some(0));
        assert_eq!(r.admit("a", 2_000), None);
        assert_eq!(r.admit("a", 60_999), None);
        assert_eq!(r.admit("a", 61_000), Some(2), "two held back in between");
        assert_eq!(r.admit("b", 61_001), Some(0), "another source is its own");
    }

    #[test]
    fn the_whole_gateway_reports_at_most_sixty_a_minute() {
        let r = RefusedKeys::default();
        let reported = (0..500)
            .filter(|i| r.admit(&format!("k{i}"), 10_000).is_some())
            .count();
        assert_eq!(reported, PER_MINUTE_CAP as usize);
        assert_eq!(
            r.admit("fresh", 70_000),
            Some(0),
            "a new minute reports again"
        );
    }

    #[test]
    fn the_sources_remembered_are_bounded() {
        let r = RefusedKeys::default();
        for i in 0..(SOURCES_CAP + 10) {
            let _ = r.admit(&format!("k{i}"), i as i64 * 60_000);
        }
        assert!(r.window.lock().unwrap().sources.len() <= SOURCES_CAP);
    }

    #[test]
    fn the_unidentified_subject_is_a_valid_agent_id_no_one_can_hold() {
        assert!(tokenfuse_core::agent_event::is_canonical_agent_id(
            UNIDENTIFIED_CALLER
        ));
        assert!(UNIDENTIFIED_CALLER.starts_with("agent://unidentified.invalid/"));
    }

    #[test]
    fn the_data_names_the_reason_and_never_carries_the_key() {
        let d = refused_key_data("unknown_key", Some("sha256:00"), "agent://a/b", 3);
        assert_eq!(d["reason"], "unknown_key");
        assert_eq!(d["key_fingerprint"], "sha256:00");
        assert_eq!(d["agent_id"], "agent://a/b");
        assert_eq!(d["unreported_since_last"], 3);
        let none = refused_key_data("missing_key", None, "", 0);
        assert!(none["key_fingerprint"].is_null());
        assert!(none["agent_id"].is_null());
    }
}
