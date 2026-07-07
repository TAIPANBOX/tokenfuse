//! Tamper-evident, append-only, hash-chained audit trail of control-plane
//! mutations (operator kill, budget change, device pairing, incident ack).
//!
//! Pure and I/O-free: this module only *builds* and *verifies* the chain; the
//! storage and durable snapshotting live in the control plane
//! (`crates/cloud/src/store.rs`). Each entry binds to its predecessor by hashing
//! the predecessor's `entry_hash` into its own pre-image, so any edit, deletion,
//! or reordering of a past entry breaks every hash from that point on and
//! [`verify_chain`] pinpoints the first break.
//!
//! Scope: this is the *authenticated action* log — who killed a run, who moved a
//! budget — not the enforcement (block) stream, which already lives in the
//! gateway's Parquet trace and is not duplicated here.
//!
//! Deferred: a cryptographically-signed manifest over the chain tip (so a
//! verifier need not trust the store to have retained the whole chain) is a
//! later PR; this module deliberately stops at the hash chain.

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

/// Canonical field separator folded into every entry's hash pre-image. ASCII
/// Unit Separator (`0x1f`) — a control byte that never appears in the JSON-text
/// field values, so no combination of field contents can be re-partitioned into
/// a different tuple that hashes the same (`"a\x1fb"` can only split one way).
const SEP: char = '\u{1f}';

/// One link in an org's audit chain: a single authenticated control-plane
/// mutation and the identity that performed it. `entry_hash` binds every field
/// (including `prev_hash`) so the sequence as a whole is tamper-evident.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuditEntry {
    /// 0-based position in the chain; the genesis entry is `0`.
    pub seq: u64,
    /// Wall-clock time the action was recorded, epoch millis.
    pub ts_millis: i64,
    /// Who performed it — a stable, non-secret identity (e.g. an API-key
    /// fingerprint or a device id), never a bearer secret.
    pub actor: String,
    /// What was done: a stable dotted verb, e.g. `control.kill`.
    pub action: String,
    /// What it acted on: a run id, device id, or incident id.
    pub subject: String,
    /// Free-form context, e.g. the new budget or the kill mode.
    pub detail: String,
    /// The predecessor's `entry_hash`; the empty string for the genesis entry.
    pub prev_hash: String,
    /// `hex(sha256(canonical pre-image))` over the fields above — see [`append`].
    pub entry_hash: String,
}

/// Lowercase-hex encode bytes (no external `hex` dep in core).
fn hex_lower(bytes: &[u8]) -> String {
    use std::fmt::Write;
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        let _ = write!(s, "{b:02x}");
    }
    s
}

/// The canonical `entry_hash`: `hex(sha256(...))` over the fields joined, in a
/// fixed order, by [`SEP`]. Private so the one canonicalization is shared by
/// [`append`] (writing) and [`verify_chain`] (recomputing).
fn compute_hash(
    seq: u64,
    ts_millis: i64,
    actor: &str,
    action: &str,
    subject: &str,
    detail: &str,
    prev_hash: &str,
) -> String {
    let pre = format!(
        "{seq}{SEP}{ts_millis}{SEP}{actor}{SEP}{action}{SEP}{subject}{SEP}{detail}{SEP}{prev_hash}"
    );
    hex_lower(&Sha256::digest(pre.as_bytes()))
}

/// Append a new entry after `prev` (the current chain tip, or `None` for the
/// genesis entry): `seq` is `prev.seq + 1` (or `0`), `prev_hash` is
/// `prev.entry_hash` (or `""`), and `entry_hash` is computed over the canonical
/// pre-image. Pure — the caller owns storage and ordering.
pub fn append(
    prev: Option<&AuditEntry>,
    ts_millis: i64,
    actor: impl Into<String>,
    action: impl Into<String>,
    subject: impl Into<String>,
    detail: impl Into<String>,
) -> AuditEntry {
    let seq = prev.map(|p| p.seq + 1).unwrap_or(0);
    let prev_hash = prev.map(|p| p.entry_hash.clone()).unwrap_or_default();
    let actor = actor.into();
    let action = action.into();
    let subject = subject.into();
    let detail = detail.into();
    let entry_hash = compute_hash(
        seq, ts_millis, &actor, &action, &subject, &detail, &prev_hash,
    );
    AuditEntry {
        seq,
        ts_millis,
        actor,
        action,
        subject,
        detail,
        prev_hash,
        entry_hash,
    }
}

/// Verify a chain end-to-end. For each entry (oldest first) recompute its
/// `entry_hash` and check it matches, that `seq` increases by one from `0`, and
/// that `prev_hash` equals the predecessor's `entry_hash` (genesis links to
/// `""`). Returns `Err(index)` at the FIRST entry that fails any check; `Ok(())`
/// for an intact — or empty — chain.
pub fn verify_chain(entries: &[AuditEntry]) -> Result<(), usize> {
    let mut prev: Option<&AuditEntry> = None;
    for (i, e) in entries.iter().enumerate() {
        let expected_seq = prev.map(|p| p.seq + 1).unwrap_or(0);
        let expected_prev_hash = prev.map(|p| p.entry_hash.as_str()).unwrap_or("");
        if e.seq != expected_seq || e.prev_hash != expected_prev_hash {
            return Err(i);
        }
        let recomputed = compute_hash(
            e.seq,
            e.ts_millis,
            &e.actor,
            &e.action,
            &e.subject,
            &e.detail,
            &e.prev_hash,
        );
        if recomputed != e.entry_hash {
            return Err(i);
        }
        prev = Some(e);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Build a small chain of `n` entries linked from genesis.
    fn chain(n: usize) -> Vec<AuditEntry> {
        let mut out: Vec<AuditEntry> = Vec::new();
        for i in 0..n {
            let e = append(
                out.last(),
                1_000 + i as i64,
                format!("key:actor{i}"),
                "control.kill",
                format!("run-{i}"),
                "mode=hard",
            );
            out.push(e);
        }
        out
    }

    #[test]
    fn a_built_chain_verifies() {
        let c = chain(4);
        assert_eq!(c[0].seq, 0);
        assert_eq!(c[0].prev_hash, "");
        assert_eq!(c[3].seq, 3);
        assert_eq!(c[1].prev_hash, c[0].entry_hash);
        assert_eq!(c[2].prev_hash, c[1].entry_hash);
        assert_eq!(verify_chain(&c), Ok(()));
    }

    #[test]
    fn empty_chain_is_ok() {
        assert_eq!(verify_chain(&[]), Ok(()));
    }

    #[test]
    fn single_genesis_entry_is_ok() {
        let c = chain(1);
        assert_eq!(c.len(), 1);
        assert_eq!(verify_chain(&c), Ok(()));
    }

    #[test]
    fn tampering_a_detail_is_detected_at_that_index() {
        let mut c = chain(4);
        // Edit a past entry's payload without recomputing its stored hash: the
        // recomputed hash no longer matches, caught exactly at that index.
        c[2].detail = "mode=soft".to_string();
        assert_eq!(verify_chain(&c), Err(2));
    }

    #[test]
    fn a_broken_prev_hash_is_detected() {
        let mut c = chain(3);
        c[1].prev_hash = "deadbeef".to_string();
        assert_eq!(verify_chain(&c), Err(1));
    }

    #[test]
    fn reordering_breaks_the_chain() {
        let mut c = chain(3);
        c.swap(1, 2);
        // The entry now at index 1 carries seq 2, but seq 1 is expected there.
        assert_eq!(verify_chain(&c), Err(1));
    }

    #[test]
    fn dropping_an_entry_breaks_the_prev_link() {
        let mut c = chain(4);
        // Remove the middle: the follower's prev_hash/seq no longer line up.
        c.remove(2);
        assert_eq!(verify_chain(&c), Err(2));
    }
}
