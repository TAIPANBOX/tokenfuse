//! The public origins a DPoP proof's `htu` may name (CLAUDE.md invariant 138).
//!
//! A gateway is reached at one address by its clients and at another by the
//! containers beside it, so one configured origin cannot describe every caller.
//! The operator lists each origin this process is reached at, and a proof is
//! accepted for a route when its `htu`, with the query removed, is one of them
//! plus that route's path. The `Host` header is never consulted: the caller
//! writes it, and a check against it would agree with whatever the caller liked.
//!
//! Origins are compared in the form wardryx's agent-token door uses for its own
//! list (`WARDRYX_AGENT_TOKEN_DOOR_ORIGINS`): scheme and host in lower case, the
//! default port written out, and nothing after the port but an optional `/`.

/// Why an origin was refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OriginRefusal {
    /// Not `http` or `https`, no host, user information, a path, query or
    /// fragment after the port, a port that is not 1 to 65535, or a host that
    /// is not a host.
    NotAnOrigin,
}

/// Normalise one configured origin written `scheme://host[:port]`.
///
/// STUB for the red-first commit: returns the trimmed input unchanged, which is
/// what the code did before the list existed.
pub fn normalize_origin(raw: &str) -> Result<String, OriginRefusal> {
    Ok(raw.trim().to_string())
}

/// The normalised origin and the path of an absolute `htu`, query removed.
///
/// STUB for the red-first commit: always `None`.
pub fn origin_and_path(_htu: &str) -> Option<(String, String)> {
    None
}

/// The `htu` claim of a compact JWS payload, read WITHOUT checking the signature.
///
/// STUB for the red-first commit: always `None`.
pub fn unverified_htu(_proof: &str) -> Option<String> {
    None
}

/// The URL a proof must name for a request on `path`.
///
/// STUB for the red-first commit: the first configured origin plus the path,
/// which is what the single-origin code computed.
pub fn expected_url(origins: &[String], _proof: Option<&str>, path: &str) -> String {
    format!(
        "{}{}",
        origins.first().map(String::as_str).unwrap_or_default(),
        path
    )
}

/// Parse a comma-separated list of origins, normalising each entry.
///
/// STUB for the red-first commit: the whole value as one entry, trailing slash
/// removed, which is what `TOKENFUSE_MCP_PROOF_URL` alone meant.
pub fn parse_origin_list(list: &str) -> Result<Vec<String>, String> {
    let list = list.trim();
    Ok(if list.is_empty() {
        Vec::new()
    } else {
        vec![list.trim_end_matches('/').to_string()]
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::Engine as _;

    /// A compact JWS with an unchecked signature, carrying `claims`. Only the
    /// payload is read by `unverified_htu`, so the header and signature are
    /// placeholders here.
    fn unsigned(claims: serde_json::Value) -> String {
        let enc = |b: &[u8]| base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(b);
        format!(
            "{}.{}.{}",
            enc(br#"{"alg":"ES256","typ":"dpop+jwt"}"#),
            enc(claims.to_string().as_bytes()),
            enc(b"sig")
        )
    }

    #[test]
    fn an_origin_is_normalised_the_way_wardryx_normalises_its_door_origins() {
        assert_eq!(
            normalize_origin("https://tokenfuse.acme.example").unwrap(),
            "https://tokenfuse.acme.example:443"
        );
        assert_eq!(
            normalize_origin("HTTPS://TokenFuse.Acme.Example:443/").unwrap(),
            "https://tokenfuse.acme.example:443"
        );
        assert_eq!(
            normalize_origin("http://tokenfuse-gateway").unwrap(),
            "http://tokenfuse-gateway:80"
        );
        assert_eq!(
            normalize_origin("http://127.0.0.1:4100").unwrap(),
            "http://127.0.0.1:4100"
        );
        assert_eq!(
            normalize_origin("http://[::1]:4100").unwrap(),
            "http://[::1]:4100"
        );
        assert_eq!(
            normalize_origin("https://[::1]").unwrap(),
            "https://[::1]:443"
        );
    }

    #[test]
    fn an_origin_with_anything_after_the_port_or_the_wrong_scheme_is_refused() {
        for bad in [
            "",
            "tokenfuse.acme.example",
            "ftp://tokenfuse.acme.example",
            "https://",
            "https://user:pass@tokenfuse.acme.example",
            "https://tokenfuse.acme.example/prefix",
            "https://tokenfuse.acme.example//",
            "https://tokenfuse.acme.example?x=1",
            "https://tokenfuse.acme.example#frag",
            "https://tokenfuse.acme.example:0",
            "https://tokenfuse.acme.example:99999",
            "https://tokenfuse.acme.example:",
            "https://tokenfuse.acme.example:44a",
            "https://a:b:c",
            "https://2001:db8::1",
        ] {
            assert_eq!(
                normalize_origin(bad),
                Err(OriginRefusal::NotAnOrigin),
                "{bad:?} must be refused"
            );
        }
    }

    #[test]
    fn a_proof_names_an_origin_and_a_path_and_the_query_is_part_of_neither() {
        assert_eq!(
            origin_and_path("https://Tokenfuse.acme.example/v1/messages?cache=1"),
            Some((
                "https://tokenfuse.acme.example:443".to_string(),
                "/v1/messages".to_string()
            ))
        );
        assert_eq!(
            origin_and_path("https://tokenfuse.acme.example"),
            Some((
                "https://tokenfuse.acme.example:443".to_string(),
                "/".to_string()
            ))
        );
        for bad in [
            "https://user@tokenfuse.acme.example/v1/messages",
            "https://tokenfuse.acme.example/v1/messages#frag",
            "wss://tokenfuse.acme.example/v1/messages",
            "/v1/messages",
            "",
        ] {
            assert_eq!(origin_and_path(bad), None, "{bad:?} must name no origin");
        }
    }

    #[test]
    fn the_list_is_normalised_an_empty_entry_is_refused_and_an_empty_list_is_empty() {
        assert_eq!(parse_origin_list("").unwrap(), Vec::<String>::new());
        assert_eq!(parse_origin_list("   ").unwrap(), Vec::<String>::new());
        assert_eq!(
            parse_origin_list("https://a.example, https://b.example:8443").unwrap(),
            vec![
                "https://a.example:443".to_string(),
                "https://b.example:8443".to_string()
            ]
        );
        assert_eq!(
            parse_origin_list("https://a.example,https://A.example:443")
                .unwrap()
                .len(),
            1,
            "two spellings of one origin are one entry"
        );
        assert_eq!(
            parse_origin_list("https://a.example,").unwrap_err(),
            "",
            "a trailing comma is an empty entry: refused, not skipped"
        );
        assert_eq!(
            parse_origin_list("https://a.example,https://b.example/x").unwrap_err(),
            "https://b.example/x"
        );
    }

    #[test]
    fn a_proof_is_checked_against_the_origin_it_names_at_this_path_and_no_other() {
        let origins = vec![
            "https://tokenfuse.acme.example:443".to_string(),
            "http://tokenfuse-gateway:4100".to_string(),
        ];
        let at = |htu: &str| {
            unsigned(serde_json::json!({"htm": "POST", "htu": htu, "iat": 1, "jti": "j"}))
        };

        // A configured origin at the route's path: the htu the proof carries is
        // the one it is checked against.
        let named = at("http://tokenfuse-gateway:4100/v1/messages");
        assert_eq!(
            expected_url(&origins, Some(&named), "/v1/messages"),
            "http://tokenfuse-gateway:4100/v1/messages"
        );
        // The same origin spelled another way is the same origin.
        let spelt = at("HTTPS://Tokenfuse.acme.example/v1/messages");
        assert_eq!(
            expected_url(&origins, Some(&spelt), "/v1/messages"),
            "HTTPS://Tokenfuse.acme.example/v1/messages"
        );

        // Anything else gets the first configured origin plus the route's path,
        // which the verifier refuses, because the proof named something else.
        for htu in [
            "https://evil.example/v1/messages",
            "http://tokenfuse-gateway:4100/v1/chat/completions",
            "http://tokenfuse-gateway:4100/prefix/v1/messages",
            "https://user@tokenfuse.acme.example/v1/messages",
            "https://tokenfuse.acme.example/v1/messages#frag",
        ] {
            let proof = at(htu);
            assert_eq!(
                expected_url(&origins, Some(&proof), "/v1/messages"),
                "https://tokenfuse.acme.example:443/v1/messages",
                "{htu} must not be the url the proof is checked against"
            );
        }
        assert_eq!(
            expected_url(&origins, None, "/v1/messages"),
            "https://tokenfuse.acme.example:443/v1/messages"
        );
        assert_eq!(
            expected_url(&origins, Some("not-a-jws"), "/v1/messages"),
            "https://tokenfuse.acme.example:443/v1/messages"
        );
    }

    #[test]
    fn the_htu_is_read_without_checking_the_signature_and_a_missing_one_is_none() {
        assert_eq!(
            unverified_htu(&unsigned(serde_json::json!({"htu": "https://a.example/x"}))),
            Some("https://a.example/x".to_string())
        );
        assert_eq!(
            unverified_htu(&unsigned(serde_json::json!({"jti": "j"}))),
            None
        );
        assert_eq!(unverified_htu("not-a-jws"), None);
    }
}
