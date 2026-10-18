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
//! The scaffold below answers nothing yet: it is the red commit of this
//! change, and every decision is the test module's to hold.

use serde_json::Value;

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

/// The document to serve at the well-known path, or `None` when neither door
/// publishes one.
pub fn document(agent: Option<&AgentDoor>, xaa: Option<&XaaDoor>) -> Option<Value> {
    let _ = (agent, xaa);
    None
}

/// The `WWW-Authenticate` value for a refused or missing agent token: a DPoP
/// challenge naming the metadata. `token_refused` adds `error="invalid_token"`,
/// which RFC 6750 section 3.1 reserves for a token that was presented.
pub fn agent_challenge(agent: &AgentDoor, token_refused: bool) -> String {
    let _ = (agent, token_refused);
    String::new()
}

/// The startup refusal for an agent door beside an XAA resource, or `None`
/// when the two can share one document.
pub fn startup_refusal(agent: Option<&AgentDoor>, xaa_resource: Option<&str>) -> Option<String> {
    let _ = (agent, xaa_resource);
    None
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
