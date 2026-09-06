//! Authentication for the gateway's own observability and kill routes:
//! `GET /v1/runs`, `POST /v1/runs/{id}/kill`, `GET /v1/keys`,
//! `GET /v1/policy-plane`, `GET /v1/agent-ids`.
//!
//! ## Why this exists
//!
//! Those five routes were registered with no authentication at all. The
//! comment beside them said the gateway binds loopback by default, which was
//! true and was not the whole picture: the shipped `Dockerfile` sets
//! `TOKENFUSE_ADDR=0.0.0.0:4100`, and a deployment that publishes that port
//! (stack-single documents 4100 as the port "agents elsewhere must reach")
//! hands anyone who can reach it every run's budget and spend, every key id,
//! every agent identity, and a kill switch for any run.
//!
//! This module is the fix, and it mirrors the MCP broker's door
//! (`crate::mcpbroker::refuse_open_bind`, CLAUDE.md invariant 20) rather than
//! inventing a second shape: the same three-way split between "nothing
//! configured and it's loopback, so nothing changes", "nothing configured and
//! it's not loopback, so refuse", and "something is configured, so require
//! it". The one difference is that a bad bearer key on one of five endpoints
//! is not the same emergency as a vault with a stranger's hand in it, so this
//! refuses the REQUEST rather than refusing the process to start: an operator
//! who forgets `TOKENFUSE_ADMIN_KEYS` on a wide bind gets a 403 on `/v1/keys`,
//! not a gateway that will not serve `/v1/messages` either.
//!
//! ## Off unless configured, then fail closed
//!
//! `TOKENFUSE_ADMIN_KEYS` unset on a loopback bind changes nothing: local dev,
//! `tokenfuse top`, and every taipan/stack-single deployment that never
//! widens the bind see the routes exactly as before. Set, and every one of
//! the five routes needs a matching `Authorization: Bearer <key>` regardless
//! of where the gateway is bound: a credential set for a loopback deployment
//! is still worth honouring, and silently ignoring it because the bind
//! "doesn't need it yet" is how a later re-bind reopens a door somebody
//! thought was shut.
//!
//! Unset AND bound off loopback is the dangerous middle case invariant 20
//! already named for the MCP broker: nothing at all is on the door. That
//! refuses every one of the five routes with `403 admin_keys_required`, once
//! `TOKENFUSE_ALLOW_OPEN_OBS=1` has not been set, and the refusal reason
//! itself is logged once at startup rather than left for an operator to
//! infer from a wall of 403s.

use std::sync::Arc;
use subtle::ConstantTimeEq;

use axum::extract::{Request, State};
use axum::http::StatusCode;
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};
use axum::Json;

use crate::state::AppState;

/// Configured admin bearer keys (`TOKENFUSE_ADMIN_KEYS`).
///
/// Deliberately simpler than [`crate::clientkeys::ClientKeys`]: there is no
/// `key_id` here, only "does the presented value match one of the configured
/// keys", so this holds a flat list rather than a map.
#[derive(Debug, Clone, Default)]
pub struct AdminKeys {
    keys: Vec<String>,
}

/// A `TOKENFUSE_ADMIN_KEYS` spec that was set but yielded no usable key.
/// Refusing to start is the same conclusion `ClientKeys::from_spec` and
/// `TOKENFUSE_MCP_KEYS` both reached: falling back to "not configured" would
/// leave the five routes exactly as exposed as they are today, at the moment
/// an operator believed they had just locked them.
#[derive(Debug, PartialEq, Eq)]
pub struct EmptySpec;

impl std::fmt::Display for EmptySpec {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(
            "TOKENFUSE_ADMIN_KEYS is set but contains no usable key (expected a \
             comma-separated list, e.g. `sk-admin-abc,sk-admin-def`); refusing to start rather \
             than leave the observability and kill routes exactly as open as before",
        )
    }
}

impl std::error::Error for EmptySpec {}

impl AdminKeys {
    /// Parse `"key,key,…"`. Same trimming rules as
    /// `ClientKeys::from_spec`: entries are split on `,`, each is trimmed,
    /// and blank entries are dropped. A blank/whitespace-only spec is "not
    /// configured"; a non-blank spec that yields no entries is
    /// [`EmptySpec`].
    pub fn from_spec(spec: &str) -> Result<Self, EmptySpec> {
        let trimmed = spec.trim();
        if trimmed.is_empty() {
            return Ok(Self::default());
        }
        let keys: Vec<String> = trimmed
            .split(',')
            .map(str::trim)
            .filter(|e| !e.is_empty())
            .map(str::to_string)
            .collect();
        if keys.is_empty() {
            return Err(EmptySpec);
        }
        Ok(Self { keys })
    }

    /// Whether any admin key is configured at all.
    #[must_use]
    pub fn enabled(&self) -> bool {
        !self.keys.is_empty()
    }

    /// How many distinct keys are configured (startup logging).
    #[must_use]
    pub fn len(&self) -> usize {
        self.keys.len()
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.keys.is_empty()
    }

    /// Whether `presented` matches one of the configured keys.
    ///
    /// Constant-time per candidate: the length is checked first (a length
    /// mismatch is not secret and short-circuiting on it costs nothing worth
    /// hiding), and a same-length comparison goes through
    /// `subtle::ConstantTimeEq` so a byte-at-a-time timing attack against one
    /// key cannot narrow it down. This repository's other bearer comparisons
    /// (`ClientKeys::resolve`, the Cloud's own bearer lookup) are plain
    /// `HashMap`/`==` lookups by deliberate, documented choice; this is a new
    /// door and starts from the stronger posture rather than inheriting
    /// theirs.
    #[must_use]
    pub fn matches(&self, presented: &str) -> bool {
        let presented = presented.as_bytes();
        self.keys.iter().any(|k| {
            let k = k.as_bytes();
            k.len() == presented.len() && bool::from(k.ct_eq(presented))
        })
    }
}

/// What the five admin routes do with an incoming request, decided once at
/// startup from `TOKENFUSE_ADMIN_KEYS`, the bind address, and
/// `TOKENFUSE_ALLOW_OPEN_OBS`.
#[derive(Debug, Clone)]
pub enum AdminGate {
    /// No credential required: either nothing is configured and the bind is
    /// loopback (today's behaviour, unchanged), or an operator has opted out
    /// of the refusal with `TOKENFUSE_ALLOW_OPEN_OBS=1`.
    Open,
    /// A credential is required, and checked against these keys.
    Keyed(Arc<AdminKeys>),
    /// Nothing is configured and the bind is not loopback: every request to
    /// one of the five routes is refused.
    Forbidden,
}

impl Default for AdminGate {
    /// The default state a freshly built `AppState` carries until `main.rs`
    /// (or a test) sets one explicitly: open, matching this repository's
    /// behaviour before this module existed. Every existing test that hits
    /// `/v1/runs`, `/v1/keys`, etc. without configuring an admin gate must see
    /// no change.
    fn default() -> Self {
        AdminGate::Open
    }
}

impl AdminGate {
    /// Decide the gate from configuration, mirroring
    /// `mcpbroker::refuse_open_bind`'s three-way split.
    #[must_use]
    pub fn resolve(admin_keys: AdminKeys, is_loopback: bool, allow_open_obs: bool) -> Self {
        if admin_keys.enabled() {
            AdminGate::Keyed(Arc::new(admin_keys))
        } else if is_loopback || allow_open_obs {
            AdminGate::Open
        } else {
            AdminGate::Forbidden
        }
    }
}

/// Whether `addr` names a loopback interface, re-exported for `main.rs`
/// (a separate crate) to compute the third argument to
/// [`AdminGate::resolve`]. `crate::mcpbroker::is_loopback` stays `pub(crate)`
/// so this stays the one public door onto that answer rather than two crates
/// agreeing to call the same private function two different ways.
#[must_use]
pub fn bind_is_loopback(addr: &str) -> bool {
    crate::mcpbroker::is_loopback(addr)
}

/// The five routes this gate covers, named once so the startup warning and
/// this module's doc comment cannot drift apart from what `lib.rs` actually
/// registers behind it.
const GUARDED_ROUTES: &str =
    "/v1/runs, /v1/runs/{id}/kill, /v1/keys, /v1/policy-plane, /v1/agent-ids";

/// Startup warning for a wide-open bind with no admin keys, or `None` when
/// the gate needs no explanation (loopback, or admin keys configured).
///
/// One function covers both the refusal case and the opted-out case,
/// because both leave the same variable unset and an operator reading the
/// log wants the same fix named either way: set `TOKENFUSE_ADMIN_KEYS`.
pub fn open_obs_warning(
    addr: &str,
    admin_keys_enabled: bool,
    allow_open_obs: bool,
) -> Option<String> {
    if admin_keys_enabled || crate::mcpbroker::is_loopback(addr) {
        return None;
    }
    if allow_open_obs {
        Some(format!(
            "gateway bound to {addr} (not loopback) with no TOKENFUSE_ADMIN_KEYS: the \
             observability and kill routes ({GUARDED_ROUTES}) are reachable from the network \
             with no credential because TOKENFUSE_ALLOW_OPEN_OBS=1 is set. Set \
             TOKENFUSE_ADMIN_KEYS to require one instead."
        ))
    } else {
        Some(format!(
            "gateway bound to {addr} (not loopback) with no TOKENFUSE_ADMIN_KEYS: the \
             observability and kill routes ({GUARDED_ROUTES}) will refuse every request with \
             403 admin_keys_required until TOKENFUSE_ADMIN_KEYS is set, or \
             TOKENFUSE_ALLOW_OPEN_OBS=1 is set to restore the old open behaviour."
        ))
    }
}

/// The bearer token from the `Authorization` header, with or without the
/// `Bearer ` prefix. Same shape as `crates/cloud/src/http.rs`'s `bearer()`.
fn bearer_token(req: &Request) -> Option<&str> {
    let raw = req
        .headers()
        .get(axum::http::header::AUTHORIZATION)?
        .to_str()
        .ok()?;
    let token = raw.strip_prefix("Bearer ").unwrap_or(raw).trim();
    (!token.is_empty()).then_some(token)
}

fn unauthorized() -> Response {
    (
        StatusCode::UNAUTHORIZED,
        Json(serde_json::json!({ "error": "unauthorized" })),
    )
        .into_response()
}

fn forbidden() -> Response {
    (
        StatusCode::FORBIDDEN,
        Json(serde_json::json!({ "error": "admin_keys_required" })),
    )
        .into_response()
}

/// Axum middleware applied to exactly the five admin routes (`lib.rs::app`),
/// never to `/healthz`, `/v1/messages`, or `/v1/fuse/*`.
pub async fn admin_gate(State(st): State<AppState>, req: Request, next: Next) -> Response {
    match &st.admin_gate {
        AdminGate::Open => next.run(req).await,
        AdminGate::Forbidden => forbidden(),
        AdminGate::Keyed(keys) => match bearer_token(&req) {
            Some(tok) if keys.matches(tok) => next.run(req).await,
            _ => unauthorized(),
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // --- AdminKeys::from_spec ------------------------------------------

    #[test]
    fn an_unset_spec_leaves_admin_auth_off() {
        for spec in ["", "   ", "\n"] {
            let keys = AdminKeys::from_spec(spec).expect("blank is 'not configured'");
            assert!(!keys.enabled());
        }
    }

    #[test]
    fn a_spec_with_only_separators_is_refused_rather_than_read_as_unset() {
        assert_eq!(AdminKeys::from_spec(" , , ,").unwrap_err(), EmptySpec);
    }

    #[test]
    fn a_comma_separated_spec_trims_each_entry() {
        let keys = AdminKeys::from_spec(" sk-a , sk-b ,sk-c").unwrap();
        assert_eq!(keys.len(), 3);
        assert!(keys.matches("sk-a"));
        assert!(keys.matches("sk-b"));
        assert!(keys.matches("sk-c"));
        assert!(!keys.matches(" sk-a"));
    }

    // --- AdminKeys::matches ---------------------------------------------

    #[test]
    fn a_matching_key_matches_and_a_wrong_one_does_not() {
        let keys = AdminKeys::from_spec("sk-admin-abc").unwrap();
        assert!(keys.matches("sk-admin-abc"));
        assert!(!keys.matches("sk-admin-abd"));
        assert!(!keys.matches("sk-admin-ab"));
        assert!(!keys.matches("sk-admin-abcx"));
        assert!(!keys.matches(""));
    }

    // --- AdminGate::resolve ----------------------------------------------

    #[test]
    fn nothing_configured_on_loopback_is_open() {
        let gate = AdminGate::resolve(AdminKeys::default(), true, false);
        assert!(matches!(gate, AdminGate::Open));
    }

    #[test]
    fn nothing_configured_off_loopback_is_forbidden() {
        let gate = AdminGate::resolve(AdminKeys::default(), false, false);
        assert!(matches!(gate, AdminGate::Forbidden));
    }

    #[test]
    fn the_opt_out_reopens_a_wide_bind_with_nothing_configured() {
        let gate = AdminGate::resolve(AdminKeys::default(), false, true);
        assert!(matches!(gate, AdminGate::Open));
    }

    #[test]
    fn configured_keys_are_required_even_on_loopback() {
        let keys = AdminKeys::from_spec("sk-admin-abc").unwrap();
        let gate = AdminGate::resolve(keys, true, false);
        assert!(matches!(gate, AdminGate::Keyed(_)));
    }

    #[test]
    fn configured_keys_win_over_the_forbidden_case() {
        let keys = AdminKeys::from_spec("sk-admin-abc").unwrap();
        let gate = AdminGate::resolve(keys, false, false);
        assert!(matches!(gate, AdminGate::Keyed(_)));
    }

    // --- open_obs_warning --------------------------------------------------

    #[test]
    fn no_warning_on_loopback() {
        assert_eq!(open_obs_warning("127.0.0.1:4100", false, false), None);
    }

    #[test]
    fn no_warning_when_keys_are_configured() {
        assert_eq!(open_obs_warning("0.0.0.0:4100", true, false), None);
    }

    #[test]
    fn a_wide_open_bind_with_nothing_configured_warns_and_names_the_variable() {
        let w = open_obs_warning("0.0.0.0:4100", false, false).expect("warns");
        assert!(w.contains("TOKENFUSE_ADMIN_KEYS"));
        assert!(w.contains("403"));
    }

    #[test]
    fn opting_out_of_the_refusal_does_not_silence_the_warning() {
        let w = open_obs_warning("0.0.0.0:4100", false, true).expect("still warns");
        assert!(w.contains("TOKENFUSE_ADMIN_KEYS"));
        assert!(w.contains("TOKENFUSE_ALLOW_OPEN_OBS"));
    }
}
