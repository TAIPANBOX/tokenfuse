//! The attestation method the policy plane is told, derived from the door that
//! authenticated the call (CLAUDE.md invariant 116).
//!
//! Both doors used to copy `x-fuse-attestation-method` from the caller into the
//! question they put to wardryx. wardryx's `deny_if_unattested` denies only when
//! that value is empty or `none`, so any caller that wrote `spiffe-svid` in a
//! header passed a policy meant to admit only attested agents, and the decision
//! record said the agent was attested (agent-security review 2026-10-17, F-005).
//!
//! The method is now a fact about the request this process verified, in the
//! words of agent-passport SPEC 4.3, which is a closed enum:
//!
//! - `dpop-key` when the caller proved possession of a key on THIS request: a
//!   DPoP-bound delegation token the gateway verified (`chainproof`), or the
//!   MCP broker's proof door (`mcpdoor`). SPEC 4.3 defines `dpop-key` as exactly
//!   that mechanism.
//! - `none` otherwise. A client key and an XAA bearer token authenticate a
//!   caller, but a bearer secret binds no workload: whoever holds the string is
//!   the caller. `none` is legal and honest in the SPEC's own words, and it is
//!   sent rather than left out, so a record says the enforcement point looked.
//!
//! The header is read for one purpose only: to say once per process that it is
//! ignored, so an operator whose agents still send it learns why their
//! `deny_if_unattested` policy now refuses them.

use axum::http::HeaderMap;
use std::sync::atomic::{AtomicBool, Ordering};

/// The header callers used to write their own attestation in. Ignored.
pub const CLIENT_HEADER: &str = "x-fuse-attestation-method";

/// agent-passport SPEC 4.3: the workload proved possession of a key on the request.
pub const DPOP_KEY: &str = "dpop-key";

/// agent-passport SPEC 4.3: nothing binds the name to a workload.
pub const NONE: &str = "none";

/// The method for a request whose door did, or did not, verify a proof of
/// possession of a key on that request.
#[must_use]
pub fn from_door(possession_proven: bool) -> &'static str {
    if possession_proven {
        DPOP_KEY
    } else {
        NONE
    }
}

static SAID: AtomicBool = AtomicBool::new(false);

/// Say, once per process, that a caller's attestation header was ignored.
///
/// Returns whether this call was the one that said it, so a test can tell the
/// first time from the rest without reading a log.
pub fn note_ignored_header(headers: &HeaderMap, door: &str) -> bool {
    if !headers.contains_key(CLIENT_HEADER) {
        return false;
    }
    if SAID.swap(true, Ordering::Relaxed) {
        return false;
    }
    tracing::warn!(
        door,
        "{CLIENT_HEADER} is ignored: the attestation method the policy plane is told \
         comes from the door that authenticated the call ({DPOP_KEY} for a verified \
         proof of possession, {NONE} otherwise), never from a header the caller writes. \
         Said once per process."
    );
    true
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_door_decides_the_word() {
        assert_eq!(from_door(true), "dpop-key");
        assert_eq!(from_door(false), "none");
    }

    #[test]
    fn the_header_is_named_once_however_often_it_arrives() {
        let mut with = HeaderMap::new();
        with.insert(CLIENT_HEADER, "spiffe-svid".parse().unwrap());
        let without = HeaderMap::new();
        // Other tests in this binary may have tripped the flag already, so the
        // assertion is about the count across many calls: at most one says it.
        assert!(
            !note_ignored_header(&without, "test"),
            "no header, nothing said"
        );
        let said = (0..50)
            .filter(|_| note_ignored_header(&with, "test"))
            .count();
        assert!(said <= 1, "said {said} times");
        assert!(SAID.load(Ordering::Relaxed), "and it has been said");
    }
}
