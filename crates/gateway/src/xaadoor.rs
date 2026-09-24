//! The MCP credential-broker's third door: a vouchryx-issued Cross App Access
//! (XAA) bearer access token (W3-tokenfuse, draft-ietf-oauth-identity-assertion-authz-grant-04).
//!
//! # What this is, in one sentence
//!
//! `TOKENFUSE_MCP_ACCEPT_XAA=on` plus `TOKENFUSE_MCP_RESOURCE` lets a caller
//! present `Authorization: Bearer <token>` where the token is one vouchryx
//! minted by redeeming an ID-JAG (RFC 7523 jwt-bearer) for this broker's
//! resource. It is judged before, and instead of,
//! [`crate::mcpdoor::admit`]'s two existing doors, and never through
//! [`crate::chainproof::resolve`]: see `mcpbroker::handle`.
//!
//! @claude 2026-09-24, a decision taken under delegated authority, open to
//! reversal: this is a third door rather than a special case of either
//! existing one, because unlike a shared secret or a proof of possession, it
//! proves who is calling by a signature this broker verifies offline
//! (`tokenfuse_delegation::verify_access_token`).
//!
//! # It is closed exactly like the other two, not left half-open
//!
//! Invariant 20 refuses a non-loopback bind with nothing on the door; XAA
//! counts as something on the door ([`crate::mcpbroker::something_on_the_door`]).
//! A caller presenting none of the three door credentials is refused once
//! XAA is configured, even where the other two doors would have answered
//! `Admission::Open`: see the `Admission::Open if st.xaa.is_some()` arm in
//! `mcpbroker::handle`. A delegation token
//! (`Authorization: DPoP <token>` plus a `dpop` proof,
//! [`crate::chainproof::resolve`]'s own door) is a CHAIN PROOF, not a door
//! credential: it says whom a call acts for, never whether the call may be
//! served at all, so it does not open this door either.
//!
//! # The record never claims a proof
//!
//! `chain_proven` is `true` for an XAA admission (the chain came from a
//! signature this broker verified) and `delegation_proof` stays `None`
//! (agent-passport SPEC 5.2's proof is holder-bound, `jkt` with
//! `minLength: 1` in both event schemas, and a bearer token has no holder).
//! Before this door existed those two facts were the same thing everywhere in
//! `mcpbroker.rs`; see the doc on `CallContext::delegation_proof` and the
//! design's own section on it.

use std::sync::Arc;

use tokenfuse_delegation::DelegationConfig;

/// The XAA door's verifier config plus the resource identifier it was built
/// for. Kept as its own field beside `cfg.audience` (the same value) because
/// the RFC 9728 metadata body and the well-known path both need it as a
/// plain string and `DelegationConfig` does not derive `Clone`.
#[derive(Debug)]
pub struct XaaDoor {
    /// Issuer and JWKS shared with the delegation door's own config
    /// (`TOKENFUSE_DELEGATION_ISSUER`, `TOKENFUSE_DELEGATION_JWKS`);
    /// `audience` is this broker's own resource, never
    /// `TOKENFUSE_DELEGATION_AUDIENCE`.
    pub cfg: DelegationConfig,
    /// `TOKENFUSE_MCP_RESOURCE`, verbatim: an absolute https URL, no query,
    /// no fragment.
    pub resource: String,
}

pub type Xaa = Option<Arc<XaaDoor>>;

/// Whether `s` is an absolute https URL with a host and no query or
/// fragment, split into its origin (no trailing slash) and its path (empty,
/// or starting with `/`).
///
/// Hand-rolled rather than pulled from a URL-parsing crate, the same
/// reasoning `mcpdoor::is_https_url` already gives for the same shape of
/// question: this is checked once at startup, not per request, but adding a
/// dependency for four conditions is still a dependency the whole binary
/// carries.
fn valid_https_resource(s: &str) -> Option<(String, String)> {
    let rest = s.strip_prefix("https://")?;
    if s.chars().any(char::is_whitespace) || s.contains('?') || s.contains('#') {
        return None;
    }
    let host_end = rest.find('/').unwrap_or(rest.len());
    let host = &rest[..host_end];
    if host.is_empty() {
        return None;
    }
    Some((format!("https://{host}"), rest[host_end..].to_string()))
}

/// The pure decision from already-read values. `None` for `accept` is
/// "unset", matching what `std::env::var(..).ok()` gives `from_env` below.
///
/// `Ok(None)`: XAA is off. `Ok(Some(door))`: on and usable. `Err`: set but
/// unusable, and the caller's job is to print the message and exit(2).
pub fn from_values(
    accept: Option<&str>,
    resource: Option<&str>,
    base: Option<DelegationConfig>,
) -> Result<Xaa, String> {
    let on = match accept {
        None | Some("off") => false,
        Some("on") => true,
        Some(other) => {
            return Err(format!(
                "TOKENFUSE_MCP_ACCEPT_XAA={other:?}, only \"off\" or \"on\" (or leaving it \
                 unset, which means off) are accepted; refusing to start rather than guessing \
                 which one was meant."
            ));
        }
    };
    let resource = resource.unwrap_or("").trim();
    if !on {
        if !resource.is_empty() {
            return Err(
                "TOKENFUSE_MCP_RESOURCE is set while TOKENFUSE_MCP_ACCEPT_XAA is off (or \
                 unset). A resource with nothing to serve it is set-but-unusable: set \
                 TOKENFUSE_MCP_ACCEPT_XAA=on, or unset TOKENFUSE_MCP_RESOURCE."
                    .to_string(),
            );
        }
        return Ok(None);
    }
    if resource.is_empty() {
        return Err(
            "TOKENFUSE_MCP_ACCEPT_XAA=on requires TOKENFUSE_MCP_RESOURCE: the broker's own \
             resource identifier, an absolute https URL with no query or fragment."
                .to_string(),
        );
    }
    if valid_https_resource(resource).is_none() {
        return Err(format!(
            "TOKENFUSE_MCP_RESOURCE ({resource:?}) must be an absolute https URL with a host \
             and no query or fragment."
        ));
    }
    let base = base.ok_or_else(|| {
        "TOKENFUSE_MCP_ACCEPT_XAA=on requires TOKENFUSE_DELEGATION_ISSUER and \
         TOKENFUSE_DELEGATION_JWKS already configured: the XAA door verifies against the same \
         issuer and key set the delegation door uses."
            .to_string()
    })?;
    Ok(Some(Arc::new(XaaDoor {
        cfg: DelegationConfig {
            audience: resource.to_string(),
            ..base
        },
        resource: resource.to_string(),
    })))
}

/// `TOKENFUSE_MCP_ACCEPT_XAA` / `TOKENFUSE_MCP_RESOURCE`, read in
/// `mcp_broker` only. See the `process-local:` comment above this function's
/// one call site in `main.rs`.
pub fn from_env() -> Xaa {
    let accept = std::env::var("TOKENFUSE_MCP_ACCEPT_XAA").ok();
    let resource = std::env::var("TOKENFUSE_MCP_RESOURCE").ok();
    // Only read when XAA is actually being turned on: a deployment that
    // leaves this off must not gain a new startup dependency on the
    // delegation JWKS being well-formed. `chainproof::from_env` already
    // checks that, on its own schedule, whenever IT is configured.
    let base = if accept.as_deref() == Some("on") {
        match crate::chainproof::base_config_from_env() {
            Ok(b) => b,
            Err(msg) => {
                eprintln!("tokenfuse: {msg}");
                std::process::exit(2);
            }
        }
    } else {
        None
    };
    match from_values(accept.as_deref(), resource.as_deref(), base) {
        Ok(xaa) => xaa,
        Err(msg) => {
            eprintln!("tokenfuse: {msg}");
            std::process::exit(2);
        }
    }
}

/// `TOKENFUSE_MCP_ACCEPT_XAA=on` together with `TOKENFUSE_MCP_REQUIRE_PROOF`:
/// an operator who closed the bearer-key door on one axis cannot reopen a
/// different bearer door on another. `None` when it is fine to start.
pub fn refuse_xaa_with_require_proof(xaa_on: bool, require_proof: bool) -> Option<String> {
    if !(xaa_on && require_proof) {
        return None;
    }
    Some(
        "refusing to start: TOKENFUSE_MCP_ACCEPT_XAA=on and TOKENFUSE_MCP_REQUIRE_PROOF are \
         both set. An operator who closed the bearer-key door with \
         TOKENFUSE_MCP_REQUIRE_PROOF cannot also open a different bearer door (XAA) at the \
         same time; unset one of the two."
            .to_string(),
    )
}

/// The RFC 9728 well-known path suffixed for the configured resource's own
/// path (`https://h/mcp` names `/.well-known/oauth-protected-resource/mcp`),
/// or `None` when the resource carries no distinct path (bare origin, or
/// `/`), so `mcpbroker::app` never registers the same axum route twice.
pub fn resource_metadata_path(resource: &str) -> Option<String> {
    let (_, path) = valid_https_resource(resource)?;
    (!path.is_empty() && path != "/")
        .then(|| format!("/.well-known/oauth-protected-resource{path}"))
}

/// The RFC 9728 metadata body, identical at both the bare and the
/// path-suffixed well-known route.
pub fn resource_metadata_body(door: &XaaDoor) -> serde_json::Value {
    serde_json::json!({
        "resource": door.resource,
        "authorization_servers": [door.cfg.issuer],
        "bearer_methods_supported": ["header"],
    })
}

/// The `WWW-Authenticate` value every 401 carries while XAA is on, built
/// from the CONFIGURED resource's own scheme/host/port, never from a
/// request's `Host` header: the same reason `chainproof::Proving::origin`
/// and `mcpdoor::ClientRegistry::origin` are both operator-configured rather
/// than read off the request, since a caller who supplies the host can make
/// it agree with anything.
pub fn www_authenticate_value(door: &XaaDoor) -> String {
    let (origin, path) =
        valid_https_resource(&door.resource).expect("door.resource was validated when built");
    let suffix = if path.is_empty() || path == "/" {
        String::new()
    } else {
        path
    };
    format!("Bearer resource_metadata=\"{origin}/.well-known/oauth-protected-resource{suffix}\"")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn base() -> DelegationConfig {
        tokenfuse_delegation::testing::cfg(&tokenfuse_delegation::testing::Key::new())
    }

    #[test]
    fn nothing_configured_is_off() {
        let xaa = from_values(None, None, None).expect("nothing configured never refuses");
        assert!(xaa.is_none());
    }

    #[test]
    fn explicit_off_with_no_resource_is_off() {
        let xaa = from_values(Some("off"), None, None).expect("explicit off never refuses");
        assert!(xaa.is_none());
    }

    /// Mutant #9's guard, and correction 2's own binding test: the value
    /// must never be read as on by anything other than the literal string.
    #[test]
    fn a_bad_accept_xaa_value_refuses_to_start() {
        for bogus in ["1", "true", "ON", "On", "yes", " on"] {
            let err = from_values(Some(bogus), None, None).unwrap_err();
            assert!(
                err.contains("TOKENFUSE_MCP_ACCEPT_XAA"),
                "{bogus:?} did not name the variable: {err}"
            );
        }
    }

    #[test]
    fn xaa_on_with_no_resource_refuses_to_start() {
        let err = from_values(Some("on"), None, Some(base())).unwrap_err();
        assert!(err.contains("TOKENFUSE_MCP_RESOURCE"), "message was: {err}");
    }

    #[test]
    fn xaa_on_with_a_malformed_resource_refuses_to_start() {
        for bad in [
            "http://h/mcp",       // not https
            "https://h/mcp?x=1",  // query
            "https://h/mcp#frag", // fragment
            "https://",           // no host
            "not a url at all",
        ] {
            let err = from_values(Some("on"), Some(bad), Some(base())).unwrap_err();
            assert!(
                err.contains("TOKENFUSE_MCP_RESOURCE"),
                "{bad:?}: message was {err}"
            );
        }
    }

    #[test]
    fn a_resource_set_while_xaa_is_off_refuses_to_start() {
        for accept in [None, Some("off")] {
            let err = from_values(accept, Some("https://h/mcp"), None).unwrap_err();
            assert!(
                err.contains("TOKENFUSE_MCP_RESOURCE") && err.contains("TOKENFUSE_MCP_ACCEPT_XAA"),
                "message was: {err}"
            );
        }
    }

    #[test]
    fn xaa_on_with_no_delegation_issuer_configured_refuses_to_start() {
        let err = from_values(Some("on"), Some("https://h/mcp"), None).unwrap_err();
        assert!(
            err.contains("TOKENFUSE_DELEGATION_ISSUER")
                && err.contains("TOKENFUSE_DELEGATION_JWKS"),
            "message was: {err}"
        );
    }

    #[test]
    fn a_well_formed_configuration_builds_a_door() {
        let xaa = from_values(Some("on"), Some("https://h.example/mcp"), Some(base()))
            .expect("well-formed")
            .expect("Some, not None");
        assert_eq!(xaa.resource, "https://h.example/mcp");
        assert_eq!(xaa.cfg.audience, "https://h.example/mcp");
    }

    #[test]
    fn xaa_on_together_with_require_proof_refuses_to_start() {
        let msg = refuse_xaa_with_require_proof(true, true).expect("must refuse");
        assert!(
            msg.contains("TOKENFUSE_MCP_ACCEPT_XAA") && msg.contains("TOKENFUSE_MCP_REQUIRE_PROOF")
        );
    }

    #[test]
    fn xaa_off_with_require_proof_is_unaffected() {
        assert_eq!(refuse_xaa_with_require_proof(false, true), None);
        assert_eq!(refuse_xaa_with_require_proof(true, false), None);
        assert_eq!(refuse_xaa_with_require_proof(false, false), None);
    }

    #[test]
    fn the_metadata_path_is_suffixed_for_a_resource_with_a_path() {
        assert_eq!(
            resource_metadata_path("https://h.example/mcp"),
            Some("/.well-known/oauth-protected-resource/mcp".to_string())
        );
    }

    #[test]
    fn a_bare_resource_has_no_distinct_suffixed_path() {
        assert_eq!(resource_metadata_path("https://h.example"), None);
        assert_eq!(resource_metadata_path("https://h.example/"), None);
    }

    #[test]
    fn the_metadata_body_names_the_resource_and_the_issuer() {
        let door = from_values(Some("on"), Some("https://h.example/mcp"), Some(base()))
            .unwrap()
            .unwrap();
        let body = resource_metadata_body(&door);
        assert_eq!(body["resource"], "https://h.example/mcp");
        assert_eq!(body["authorization_servers"][0], door.cfg.issuer);
        assert_eq!(body["bearer_methods_supported"][0], "header");
    }

    #[test]
    fn the_www_authenticate_value_names_the_configured_origin_not_a_host_header() {
        let door = from_values(Some("on"), Some("https://h.example/mcp"), Some(base()))
            .unwrap()
            .unwrap();
        assert_eq!(
            www_authenticate_value(&door),
            "Bearer resource_metadata=\"https://h.example/.well-known/oauth-protected-resource/mcp\""
        );
    }
}
