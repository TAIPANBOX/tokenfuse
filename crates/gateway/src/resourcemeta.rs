//! RFC 9728 protected resource metadata for the MCP broker's agent-token door
//! (WAVE1-DESIGN 1.5, and the MCP authorization spec revision 2026-07-28, which
//! requires an MCP server to publish this document).
//!
//! # What is published, and when
//!
//! With `TOKENFUSE_AGENT_TOKENS` on, the broker answers
//! `GET /.well-known/oauth-protected-resource` (and the RFC 9728 section 3.1
//! path-suffixed twin of its resource's own path) with the agent door's
//! description: `resource` is `TOKENFUSE_DELEGATION_AUDIENCE`, the identifier
//! an agent's token is minted for; `authorization_servers` is the delegation
//! door's issuer; `dpop_signing_alg_values_supported` is `ES256`; and
//! `dpop_bound_access_tokens_required` is true under `require` and false under
//! `accept`. With XAA on as well, the one document is XAA's own
//! ([`crate::xaadoor::resource_metadata_body`], unchanged) plus the three
//! agent fields, and it never says bound tokens are required, because an XAA
//! bearer token is unbound and is still admitted under `require`.
//!
//! # What a refused agent token is told
//!
//! The broker's 401 for a refused or missing agent token carries a DPoP
//! challenge naming that document, built from configuration: the origin and
//! path of the configured resource, never a request's `Host` header, which the
//! caller writes. The resource's origin is used, not `TOKENFUSE_DELEGATION_URL`,
//! for the reason `xaadoor::www_authenticate_value` already gives for XAA: RFC
//! 9728 section 3 forms the metadata URL from the resource identifier, and with
//! XAA on the two challenges must name the same URL for the same document.
//!
//! # What the process refuses to start with
//!
//! An agent audience that is not an absolute https URL with no query or
//! fragment, because the document's `resource` must be one (RFC 9728 section 2).
//! And an XAA resource and an agent audience that differ, because one document
//! cannot name two resources.
//!
//! `startup_refusal` holds the agent audience to the same rule the XAA resource
//! already meets (`crate::xaadoor`), so the document can always name its
//! resource. The unit tests below hold each decision.

use serde_json::Value;

use crate::agenttoken::Tokens;
use crate::chainproof::ChainProof;
use crate::xaadoor::XaaDoor;

/// The agent-token door as the metadata describes it, read from the
/// delegation door's own configuration and the switch's mode.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AgentDoor {
    /// `TOKENFUSE_DELEGATION_AUDIENCE`: the resource identifier an agent's
    /// token is minted for.
    pub resource: String,
    /// `TOKENFUSE_DELEGATION_ISSUER`: the authorization server.
    pub issuer: String,
    /// `TOKENFUSE_AGENT_TOKENS=require`.
    pub require: bool,
}

/// The agent door as the metadata describes it: `None` when the door is off, and
/// the delegation door's audience and issuer, read from the process that verifies
/// its tokens, when it is on.
pub fn agent_door(chain: &ChainProof, tokens: &Tokens) -> Option<AgentDoor> {
    if tokens.is_none() {
        return None;
    }
    let proving = chain.as_ref()?;
    Some(AgentDoor {
        resource: proving.cfg.audience.clone(),
        issuer: proving.cfg.issuer.clone(),
        require: crate::agenttoken::required(tokens),
    })
}

/// The document to serve at the well-known path, or `None` when neither door
/// publishes one. With both doors on it is XAA's own body plus the agent fields:
/// one document for one resource, which `startup_refusal` holds to be the same.
pub fn document(agent: Option<&AgentDoor>, xaa: Option<&XaaDoor>) -> Option<Value> {
    match (agent, xaa) {
        (None, None) => None,
        (None, Some(xaa)) => Some(crate::xaadoor::resource_metadata_body(xaa)),
        (Some(agent), None) => Some(serde_json::json!({
            "resource": agent.resource,
            "authorization_servers": [agent.issuer],
            "bearer_methods_supported": ["header"],
            "dpop_signing_alg_values_supported": ["ES256"],
            "dpop_bound_access_tokens_required": agent.require,
        })),
        (Some(_), Some(xaa)) => {
            let mut body = crate::xaadoor::resource_metadata_body(xaa);
            if let Some(fields) = body.as_object_mut() {
                // XAA's bearer tokens are unbound and `require` admits them, so the
                // one document never says bound tokens are required.
                fields.insert(
                    "dpop_signing_alg_values_supported".to_string(),
                    serde_json::json!(["ES256"]),
                );
                fields.insert(
                    "dpop_bound_access_tokens_required".to_string(),
                    serde_json::json!(false),
                );
            }
            Some(body)
        }
    }
}

/// The document URL for a resource: its origin, the well-known path, then the
/// resource's own path (RFC 9728 section 3.1). `None` for a resource that is not a
/// valid https resource, which startup refuses before any URL is formed.
fn metadata_url(resource: &str) -> Option<String> {
    let (origin, path) = crate::xaadoor::valid_https_resource(resource)?;
    let suffix = if path == "/" { String::new() } else { path };
    Some(format!(
        "{origin}/.well-known/oauth-protected-resource{suffix}"
    ))
}

/// The `WWW-Authenticate` value for a refused or missing agent token: a DPoP
/// challenge naming the metadata. `token_refused` adds `error="invalid_token"`,
/// which RFC 6750 section 3.1 reserves for a token that was presented.
pub fn agent_challenge(agent: &AgentDoor, token_refused: bool) -> String {
    let error = if token_refused {
        ", error=\"invalid_token\""
    } else {
        ""
    };
    match metadata_url(&agent.resource) {
        Some(url) => format!("DPoP algs=\"ES256\"{error}, resource_metadata=\"{url}\""),
        None => format!("DPoP algs=\"ES256\"{error}"),
    }
}

/// The startup refusal for the agent door's audience, or for an agent door beside
/// an XAA resource that is not the same URL, or `None` when the document can name
/// its resource.
pub fn startup_refusal(agent: Option<&AgentDoor>, xaa_resource: Option<&str>) -> Option<String> {
    let agent = agent?;
    let audience = agent.resource.as_str();
    if !usable_resource(audience) {
        return Some(format!(
            "TOKENFUSE_AGENT_TOKENS is on, but TOKENFUSE_DELEGATION_AUDIENCE ({audience:?}) is \
             not an absolute https URL with a host, no query or fragment, and printable ASCII \
             only. That audience is the resource an agent's token is minted for, and the \
             protected resource metadata publishes it (RFC 9728 section 2), so it must be one."
        ));
    }
    match xaa_resource {
        Some(xaa) if xaa != audience => Some(format!(
            "TOKENFUSE_MCP_RESOURCE ({xaa:?}) and TOKENFUSE_DELEGATION_AUDIENCE ({audience:?}) \
             name two resources, and one protected resource metadata document cannot name both. \
             Set them to the same URL, or turn XAA off with TOKENFUSE_MCP_ACCEPT_XAA."
        )),
        _ => None,
    }
}

/// Whether `s` can be published as a protected resource identifier and carried in
/// a `WWW-Authenticate` challenge: an absolute https URL the metadata can be formed
/// from, of printable ASCII, with no double quote or backslash to end the quoted
/// value early.
fn usable_resource(s: &str) -> bool {
    s.bytes()
        .all(|b| b.is_ascii_graphic() && b != b'"' && b != b'\\')
        && crate::xaadoor::valid_https_resource(s).is_some()
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    use tokenfuse_delegation::testing::{cfg, Key};

    const RESOURCE: &str = "https://mcp.acme.example/mcp";
    const ISSUER: &str = "https://vouchryx.acme.example";

    fn agent(resource: &str, require: bool) -> AgentDoor {
        AgentDoor {
            resource: resource.to_string(),
            issuer: ISSUER.to_string(),
            require,
        }
    }

    fn xaa_door(resource: &str) -> XaaDoor {
        XaaDoor {
            cfg: cfg(&Key::new()),
            resource: resource.to_string(),
        }
    }

    #[test]
    fn the_agent_only_document_names_its_resource_issuer_and_dpop_algorithm() {
        let doc = document(Some(&agent(RESOURCE, false)), None)
            .expect("the agent door publishes a document");
        assert_eq!(
            doc,
            json!({
                "resource": RESOURCE,
                "authorization_servers": [ISSUER],
                "bearer_methods_supported": ["header"],
                "dpop_signing_alg_values_supported": ["ES256"],
                "dpop_bound_access_tokens_required": false,
            })
        );
    }

    #[test]
    fn require_marks_dpop_bound_tokens_as_required_and_accept_does_not() {
        let required = document(Some(&agent(RESOURCE, true)), None).expect("a document");
        assert_eq!(required["dpop_bound_access_tokens_required"], json!(true));
        let accepted = document(Some(&agent(RESOURCE, false)), None).expect("a document");
        assert_eq!(accepted["dpop_bound_access_tokens_required"], json!(false));
    }

    #[test]
    fn with_xaa_the_document_is_one_document_and_never_requires_bound_tokens() {
        let xaa = xaa_door(RESOURCE);
        for require in [false, true] {
            let doc = document(Some(&agent(RESOURCE, require)), Some(&xaa))
                .expect("one document for both doors");
            assert_eq!(doc["resource"], json!(RESOURCE));
            assert_eq!(doc["authorization_servers"], json!([ISSUER]));
            assert_eq!(doc["bearer_methods_supported"], json!(["header"]));
            assert_eq!(doc["dpop_signing_alg_values_supported"], json!(["ES256"]));
            assert_eq!(
                doc["dpop_bound_access_tokens_required"],
                json!(false),
                "XAA's unbound bearer tokens are still admitted under require (require={require})"
            );
        }
    }

    #[test]
    fn xaa_alone_publishes_exactly_the_xaa_document() {
        let xaa = xaa_door(RESOURCE);
        let doc = document(None, Some(&xaa)).expect("the XAA document");
        assert_eq!(doc, crate::xaadoor::resource_metadata_body(&xaa));
    }

    #[test]
    fn the_challenge_names_the_metadata_built_from_the_resource() {
        assert_eq!(
            agent_challenge(&agent(RESOURCE, false), true),
            "DPoP algs=\"ES256\", error=\"invalid_token\", \
             resource_metadata=\"https://mcp.acme.example/.well-known/oauth-protected-resource/mcp\""
        );
    }

    #[test]
    fn the_error_parameter_is_present_only_when_a_token_was_refused() {
        let bare = agent("https://mcp.acme.example", true);
        assert_eq!(
            agent_challenge(&bare, false),
            "DPoP algs=\"ES256\", \
             resource_metadata=\"https://mcp.acme.example/.well-known/oauth-protected-resource\""
        );
        assert_eq!(
            agent_challenge(&bare, true),
            "DPoP algs=\"ES256\", error=\"invalid_token\", \
             resource_metadata=\"https://mcp.acme.example/.well-known/oauth-protected-resource\""
        );
    }

    #[test]
    fn an_audience_that_is_not_an_https_resource_refuses_to_start() {
        for bad in [
            "tokenfuse-broker",
            "http://mcp.acme.example/mcp",
            "https://mcp.acme.example/mcp?x=1",
            "https://mcp.acme.example/mcp#top",
            "https:///mcp",
        ] {
            let msg = startup_refusal(Some(&agent(bad, false)), None)
                .unwrap_or_else(|| panic!("{bad:?} is not an https resource and must refuse"));
            assert!(msg.contains("TOKENFUSE_DELEGATION_AUDIENCE"), "{msg}");
        }
    }

    #[test]
    fn an_xaa_resource_and_an_agent_audience_that_differ_refuse_to_start() {
        let msg = startup_refusal(
            Some(&agent("https://b.acme.example/mcp", false)),
            Some(RESOURCE),
        )
        .expect("one document cannot name two resources");
        assert!(msg.contains("TOKENFUSE_MCP_RESOURCE"), "{msg}");
        assert!(msg.contains("TOKENFUSE_DELEGATION_AUDIENCE"), "{msg}");
    }

    #[test]
    fn equal_resources_and_the_agent_door_alone_start_cleanly() {
        assert_eq!(
            startup_refusal(Some(&agent(RESOURCE, true)), Some(RESOURCE)),
            None
        );
        assert_eq!(startup_refusal(Some(&agent(RESOURCE, false)), None), None);
        assert_eq!(startup_refusal(None, Some(RESOURCE)), None);
    }
}
