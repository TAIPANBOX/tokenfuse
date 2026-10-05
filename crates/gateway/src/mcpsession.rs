//! MCP session ids across the broker (invariant 77).
//!
//! A server on MCP's streamable HTTP transport may open a session on
//! `initialize` and name it in an `Mcp-Session-Id` response header; the client
//! then sends that header on everything after. The official Python SDK does
//! this by default and refuses a later call without it.
//!
//! # Why the broker does not pass the id through untouched
//!
//! The broker is where many callers become one: behind it, an upstream sees
//! the broker's own credentials (and whatever it injected), never which caller
//! opened a session. So the upstream cannot bind a session to a caller, and the
//! broker has to. It also forwards to several named upstreams, and a session
//! belongs to the one that issued it.
//!
//! So the id a client receives is the upstream's id with a tag in front:
//! `tf1.<tag>.<upstream id>`, the tag an HMAC-SHA-256 over the upstream's URL,
//! the door credential that opened the session, and the upstream id. A
//! presented id is unwrapped only when the tag matches the upstream the request
//! is about to go to and the credential it arrived with; anything else is
//! refused with 404 before anything is forwarded, which tells an MCP client to
//! start a new session. Nothing is stored: the tag carries the binding, so the
//! broker holds no table to grow or evict.
//!
//! The key is drawn once per process. A restarted broker, or a second replica
//! behind a balancer that is not sticky, cannot verify a tag the first one made
//! and answers 404, which is the session-expired path the protocol already
//! has. The stacks run the broker as one replica
//! (`stack-k8s/manifests/52-tokenfuse-mcp-broker.yaml`).
//!
//! Stdio needs none of this: one process is one client, and the broker holds
//! the upstream id itself (`mcpbroker::run_lines`).

use std::sync::OnceLock;

use hmac::{Hmac, Mac};
use sha2::Sha256;

/// The header a session id travels in, both directions.
pub const SESSION_HEADER: &str = "mcp-session-id";
/// The protocol version a client negotiated, sent on every request after
/// `initialize`.
pub const PROTOCOL_VERSION_HEADER: &str = "mcp-protocol-version";

const PREFIX: &str = "tf1.";
const TAG_BYTES: usize = 16;
/// Longer than any id an SDK issues (a UUID's hex is 32), short enough that a
/// hostile upstream cannot make the broker relay a header of any size.
const MAX_ID_BYTES: usize = 512;

/// What a session is bound to: the upstream it was opened on and the door
/// credential that opened it (empty when the broker's door is open).
#[derive(Clone, Copy, Debug)]
pub struct Binding<'a> {
    pub upstream: &'a str,
    pub principal: &'a str,
}

/// Whether `id` may travel as a session id: the specification allows visible
/// ASCII only (0x21 to 0x7E), and this broker also bounds the length.
pub fn is_valid_id(id: &str) -> bool {
    !id.is_empty() && id.len() <= MAX_ID_BYTES && id.bytes().all(|b| (0x21..=0x7e).contains(&b))
}

fn process_key() -> &'static [u8; 32] {
    static KEY: OnceLock<[u8; 32]> = OnceLock::new();
    KEY.get_or_init(|| {
        let mut k = [0u8; 32];
        getrandom::getrandom(&mut k).expect("os rng");
        k
    })
}

fn tag(key: &[u8], binding: Binding<'_>, upstream_id: &str) -> Hmac<Sha256> {
    let mut mac = Hmac::<Sha256>::new_from_slice(key).expect("hmac takes any key length");
    mac.update(b"tokenfuse mcp session v1");
    // Length-prefixed, so no two different bindings serialize alike.
    for field in [binding.upstream, binding.principal, upstream_id] {
        mac.update(&(field.len() as u64).to_be_bytes());
        mac.update(field.as_bytes());
    }
    mac
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn unhex(s: &str) -> Option<Vec<u8>> {
    if !s.len().is_multiple_of(2) {
        return None;
    }
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(s.get(i..i + 2)?, 16).ok())
        .collect()
}

pub(crate) fn wrap_with(key: &[u8], binding: Binding<'_>, upstream_id: &str) -> Option<String> {
    if !is_valid_id(upstream_id) {
        return None;
    }
    let full = tag(key, binding, upstream_id).finalize().into_bytes();
    Some(format!("{PREFIX}{}.{upstream_id}", hex(&full[..TAG_BYTES])))
}

pub(crate) fn unwrap_with<'p>(
    key: &[u8],
    binding: Binding<'_>,
    presented: &'p str,
) -> Option<&'p str> {
    let rest = presented.strip_prefix(PREFIX)?;
    let (tag_hex, upstream_id) = rest.split_once('.')?;
    if !is_valid_id(upstream_id) {
        return None;
    }
    let presented_tag = unhex(tag_hex)?;
    if presented_tag.len() != TAG_BYTES {
        return None;
    }
    // `verify_truncated_left` compares in constant time.
    tag(key, binding, upstream_id)
        .verify_truncated_left(&presented_tag)
        .ok()?;
    Some(upstream_id)
}

/// The id a client receives for the session `upstream_id` an upstream opened,
/// or `None` when the upstream's id is not one a header may carry.
pub fn wrap(binding: Binding<'_>, upstream_id: &str) -> Option<String> {
    wrap_with(process_key(), binding, upstream_id)
}

/// The upstream's own id inside a presented one, or `None` when this process
/// did not issue it for this binding.
pub fn unwrap<'p>(binding: Binding<'_>, presented: &'p str) -> Option<&'p str> {
    unwrap_with(process_key(), binding, presented)
}

#[cfg(test)]
mod tests {
    use super::*;

    const KEY: &[u8] = b"a fixed key for the tests, 32 b!";

    fn b<'a>(upstream: &'a str, principal: &'a str) -> Binding<'a> {
        Binding {
            upstream,
            principal,
        }
    }

    #[test]
    fn a_bound_session_survives_only_its_own_binding() {
        let here = b("http://a/mcp", "key:first");
        let id = wrap_with(KEY, here, "sid-1").unwrap();
        assert!(id.starts_with("tf1.") && id.ends_with(".sid-1"), "{id}");
        assert_eq!(unwrap_with(KEY, here, &id), Some("sid-1"));
        // Deterministic: the same session is the same id on every response.
        assert_eq!(wrap_with(KEY, here, "sid-1").unwrap(), id);

        assert_eq!(unwrap_with(KEY, b("http://b/mcp", "key:first"), &id), None);
        assert_eq!(unwrap_with(KEY, b("http://a/mcp", "key:second"), &id), None);
        assert_eq!(unwrap_with(KEY, b("http://a/mcp", ""), &id), None);
        assert_eq!(
            unwrap_with(b"another key entirely, 32 bytes!!", here, &id),
            None
        );
        // The id swapped under a valid tag.
        assert_eq!(
            unwrap_with(KEY, here, &id.replace(".sid-1", ".sid-2")),
            None
        );
        // Fields cannot slide into each other.
        let shifted = wrap_with(KEY, b("http://a/mcpkey:", "first"), "sid-1").unwrap();
        assert_ne!(shifted, id);
        // A tag cut short is not a shorter valid tag.
        let (head, _) = id.rsplit_once('.').unwrap();
        assert_eq!(
            unwrap_with(KEY, here, &format!("{}.sid-1", &head[..head.len() - 2])),
            None
        );
        assert_eq!(unwrap_with(KEY, here, "sid-1"), None);
        assert_eq!(unwrap_with(KEY, here, "tf1..sid-1"), None);
    }

    #[test]
    fn an_upstream_id_a_header_cannot_carry_is_not_relayed() {
        let here = b("http://a/mcp", "");
        for bad in [
            "",
            "has space",
            "tab\there",
            "nul\0",
            "caf\u{e9}",
            &"x".repeat(513),
        ] {
            assert_eq!(wrap_with(KEY, here, bad), None, "{bad:?}");
        }
        assert!(wrap_with(KEY, here, &"x".repeat(512)).is_some());
        assert!(wrap_with(KEY, here, "!~").is_some());
    }

    #[test]
    fn hostile_session_ids_never_panic_and_never_unwrap() {
        let here = b("http://a/mcp", "key:first");
        let real = wrap_with(KEY, here, "sid-1").unwrap();
        let mut seed: u64 = 0x2026_1005_0077;
        for _ in 0..200 {
            let mut s = Vec::new();
            seed = seed.wrapping_mul(6364136223846793005).wrapping_add(1);
            // Half start from a real id, so the sweep reaches the tag check
            // rather than dying at the prefix.
            if seed.is_multiple_of(2) {
                s.extend_from_slice(real.as_bytes());
            }
            let len = (seed >> 33) % 96;
            for _ in 0..len {
                seed = seed.wrapping_mul(6364136223846793005).wrapping_add(1);
                let alphabet = b"tf1.0123456789abcdef-sid\x00\xff ";
                let pick = (seed >> 40) as usize;
                let at = (seed >> 20) as usize % (s.len() + 1);
                let byte = if pick.is_multiple_of(5) {
                    (seed >> 24) as u8
                } else {
                    alphabet[pick % alphabet.len()]
                };
                s.insert(at, byte);
            }
            let text = String::from_utf8_lossy(&s);
            if text != real {
                assert_eq!(unwrap_with(KEY, here, &text), None, "{text:?}");
            }
        }
    }
}
