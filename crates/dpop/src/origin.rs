//! The public origins a DPoP proof's `htu` may name (CLAUDE.md invariant 141).
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

use base64::Engine as _;

/// Why an origin was refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OriginRefusal {
    /// Not `http` or `https`, no host, user information, a path, query or
    /// fragment after the port, a port that is not 1 to 65535, or a host that
    /// is not a host.
    NotAnOrigin,
}

/// Normalise one configured origin written `scheme://host[:port]`, with nothing after the
/// port but an optional `/`.
///
/// The result is `scheme://host:port`, with the scheme and host in lower case and the
/// default port (443 for https, 80 for http) written out, so two spellings of one origin
/// compare equal. This is wardryx's `normalizeOrigin` (`internal/agenttoken/verifier.go`):
/// the same inputs are accepted and refused. A port of zero is refused too, since nothing
/// is served on it.
pub fn normalize_origin(raw: &str) -> Result<String, OriginRefusal> {
    let raw = raw.trim();
    let (scheme, rest) = raw.split_once("://").ok_or(OriginRefusal::NotAnOrigin)?;
    let (authority, tail) = match rest.find(['/', '?', '#']) {
        Some(i) => rest.split_at(i),
        None => (rest, ""),
    };
    if !(tail.is_empty() || tail == "/") || authority.contains('@') {
        return Err(OriginRefusal::NotAnOrigin);
    }
    let scheme = scheme.to_ascii_lowercase();
    let default_port = match scheme.as_str() {
        "https" => 443,
        "http" => 80,
        _ => return Err(OriginRefusal::NotAnOrigin),
    };
    let (host, port) = split_host_port(authority)?;
    let host = if host.contains(':') {
        format!("[{host}]")
    } else {
        host
    };
    Ok(format!(
        "{scheme}://{host}:{}",
        port.unwrap_or(default_port)
    ))
}

/// The host (lower case, brackets removed) and the explicit port of an authority.
fn split_host_port(authority: &str) -> Result<(String, Option<u16>), OriginRefusal> {
    let (host, port) = if let Some(inner) = authority.strip_prefix('[') {
        let end = inner.find(']').ok_or(OriginRefusal::NotAnOrigin)?;
        let host = &inner[..end];
        let after = &inner[end + 1..];
        let port = match after {
            "" => None,
            _ => Some(after.strip_prefix(':').ok_or(OriginRefusal::NotAnOrigin)?),
        };
        if host.is_empty()
            || !host
                .chars()
                .all(|c| c.is_ascii_hexdigit() || c == ':' || c == '.')
        {
            return Err(OriginRefusal::NotAnOrigin);
        }
        (host, port)
    } else {
        let (host, port) = match authority.split_once(':') {
            Some((h, p)) => (h, Some(p)),
            None => (authority, None),
        };
        if host.is_empty()
            || !host
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '.' | '_'))
        {
            return Err(OriginRefusal::NotAnOrigin);
        }
        (host, port)
    };
    let port = match port {
        None => None,
        Some(p) => {
            if p.is_empty() || !p.bytes().all(|b| b.is_ascii_digit()) {
                return Err(OriginRefusal::NotAnOrigin);
            }
            match p.parse::<u16>() {
                Ok(n) if n != 0 => Some(n),
                _ => return Err(OriginRefusal::NotAnOrigin),
            }
        }
    };
    Ok((host.to_ascii_lowercase(), port))
}

/// The normalised origin and the path of an absolute `htu`, its query removed.
///
/// `None` for a fragment, user information, a scheme other than http or https, or no host.
/// RFC 9449 section 4.3: an `htu` names a URI without its query and fragment, and a proof
/// whose `htu` names one of those is not for this request.
pub fn origin_and_path(htu: &str) -> Option<(String, String)> {
    if htu.contains('#') {
        return None;
    }
    let bare = htu.split('?').next().unwrap_or_default();
    let (scheme, rest) = bare.split_once("://")?;
    let cut = rest.find('/').unwrap_or(rest.len());
    let (authority, path) = rest.split_at(cut);
    let origin = normalize_origin(&format!("{scheme}://{authority}")).ok()?;
    let path = if path.is_empty() { "/" } else { path };
    Some((origin, path.to_string()))
}

/// The `htu` claim of a compact JWS payload, read WITHOUT checking the signature.
///
/// Used only to choose which configured origin a proof is verified against. The verifier
/// then checks the signature over the same claim, so a claim altered after the choice fails
/// there.
pub fn unverified_htu(proof: &str) -> Option<String> {
    let payload = proof.split('.').nth(1)?;
    let raw = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(payload)
        .ok()?;
    let claims: serde_json::Value = serde_json::from_slice(&raw).ok()?;
    claims.get("htu")?.as_str().map(str::to_string)
}

/// The URL a proof must name for a request on `path`, given the origins configured.
///
/// When the proof's `htu`, read unverified, names one of `origins` (each normalised, as
/// configured or not) at exactly `path`, the `htu` as the proof wrote it is returned. The
/// verifier then checks the signature over that claim and compares it with itself, so the
/// signature is the only thing that decides. Otherwise the first configured origin plus
/// `path` is returned, which the verifier refuses, because the proof named something else.
/// Never a `Host` header.
///
/// `origins` is never empty where this runs: both doors refuse to start without one.
pub fn expected_url(origins: &[String], proof: Option<&str>, path: &str) -> String {
    let fallback = format!(
        "{}{}",
        origins.first().map(String::as_str).unwrap_or_default(),
        path
    );
    let Some(htu) = proof.and_then(unverified_htu) else {
        return fallback;
    };
    match origin_and_path(&htu) {
        Some((origin, htu_path))
            if htu_path == path
                && origins
                    .iter()
                    .any(|o| normalize_origin(o).is_ok_and(|n| n == origin)) =>
        {
            htu
        }
        _ => fallback,
    }
}

/// Parse a comma-separated list of origins, normalising each entry.
///
/// A blank list is an empty list. An empty entry is refused, not skipped: a trailing comma
/// is a typo, and a typo in an allow-list must not read as a shorter one. The error is the
/// entry that was refused, as written.
pub fn parse_origin_list(list: &str) -> Result<Vec<String>, String> {
    let mut origins: Vec<String> = Vec::new();
    if list.trim().is_empty() {
        return Ok(origins);
    }
    for entry in list.split(',') {
        let origin = normalize_origin(entry).map_err(|_| entry.trim().to_string())?;
        if !origins.contains(&origin) {
            origins.push(origin);
        }
    }
    Ok(origins)
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
