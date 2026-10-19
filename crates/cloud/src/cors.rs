//! Which browser origins the control plane answers (CLAUDE.md invariant 131).
//!
//! Before this, every response carried `Access-Control-Allow-Origin: *`, so any
//! web page an operator had open could call the control plane from the browser
//! with the operator's own cookies or stored key. Now an origin is answered
//! only if it is on the operator's list (`TOKENFUSE_CLOUD_CORS_ORIGINS`), or,
//! when that list is unset, if it is a loopback origin, which keeps the local
//! dashboard working. A list the operator sets replaces the loopback default.

/// The origins a browser may call the control plane from.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct CorsPolicy {
    /// Lowercased exact origins from the operator's list. `None` when unset:
    /// loopback origins only.
    configured: Option<Vec<String>>,
}

impl CorsPolicy {
    /// Parse `TOKENFUSE_CLOUD_CORS_ORIGINS`: comma-separated exact origins.
    /// Unset, empty or blank is the loopback default. Any entry that is not an
    /// exact origin refuses the whole list, and the error names that entry, so
    /// a typo cannot quietly leave a dashboard unanswered or a page unrefused.
    pub fn from_spec(spec: Option<&str>) -> Result<Self, String> {
        let entries: Vec<&str> = spec
            .unwrap_or("")
            .split(',')
            .map(str::trim)
            .filter(|e| !e.is_empty())
            .collect();
        if entries.is_empty() {
            return Ok(Self::default());
        }
        for entry in &entries {
            if !is_exact_origin(entry) {
                return Err(format!(
                    "TOKENFUSE_CLOUD_CORS_ORIGINS entry {entry} is not an exact origin \
                     (scheme://host[:port], with no path, query, fragment, credentials or wildcard)"
                ));
            }
        }
        Ok(Self {
            configured: Some(entries.iter().map(|e| e.to_ascii_lowercase()).collect()),
        })
    }

    /// The policy in words, for the startup log: what an operator reads when a
    /// dashboard stops being answered after an upgrade.
    pub fn describe(&self) -> String {
        match &self.configured {
            Some(list) => format!(
                "the origins named in TOKENFUSE_CLOUD_CORS_ORIGINS: {}",
                list.join(", ")
            ),
            None => "loopback origins only (set TOKENFUSE_CLOUD_CORS_ORIGINS to name others)"
                .to_string(),
        }
    }

    /// Whether `origin` (as a browser sends it in `Origin`) may call the plane.
    pub fn allows(&self, origin: &str) -> bool {
        let origin = origin.to_ascii_lowercase();
        match &self.configured {
            Some(list) => list.iter().any(|allowed| *allowed == origin),
            None => is_loopback_origin(&origin),
        }
    }
}

/// `scheme://host[:port]` with nothing else: http or https, a host name or a
/// bracketed IPv6 address, and an optional port in 1..=65535.
fn is_exact_origin(s: &str) -> bool {
    let Some((scheme, rest)) = s.split_once("://") else {
        return false;
    };
    if !(scheme.eq_ignore_ascii_case("http") || scheme.eq_ignore_ascii_case("https")) {
        return false;
    }
    if rest.is_empty() || rest.contains(['/', '?', '#', '@', '*', ' ', '\t']) {
        return false;
    }
    let Some((host, port)) = split_host_port(rest) else {
        return false;
    };
    host_is_valid(host) && port.is_none_or(port_is_valid)
}

/// Split `host[:port]`, where a bracketed IPv6 host keeps its colons.
fn split_host_port(rest: &str) -> Option<(&str, Option<&str>)> {
    if rest.starts_with('[') {
        let end = rest.find(']')?;
        let host = &rest[..=end];
        match &rest[end + 1..] {
            "" => Some((host, None)),
            tail => Some((host, Some(tail.strip_prefix(':')?))),
        }
    } else {
        match rest.rsplit_once(':') {
            Some((host, port)) => Some((host, Some(port))),
            None => Some((rest, None)),
        }
    }
}

fn host_is_valid(host: &str) -> bool {
    if let Some(v6) = host.strip_prefix('[').and_then(|h| h.strip_suffix(']')) {
        return !v6.is_empty()
            && v6
                .chars()
                .all(|c| c.is_ascii_hexdigit() || c == ':' || c == '.');
    }
    !host.is_empty()
        && host.split('.').all(|label| {
            !label.is_empty() && label.chars().all(|c| c.is_ascii_alphanumeric() || c == '-')
        })
}

fn port_is_valid(port: &str) -> bool {
    !port.is_empty()
        && port.len() <= 5
        && port.chars().all(|c| c.is_ascii_digit())
        && port.parse::<u32>().is_ok_and(|n| (1..=65535).contains(&n))
}

/// `http://localhost`, `http://127.0.0.1` or `http://[::1]`, on any port. Plain
/// http only: a loopback dashboard is served that way, and an https origin is
/// not loopback by this rule and must be named.
fn is_loopback_origin(origin: &str) -> bool {
    let Some(rest) = origin.strip_prefix("http://") else {
        return false;
    };
    let (host, port) = if rest.starts_with('[') {
        match rest.find(']') {
            Some(end) => (&rest[..=end], &rest[end + 1..]),
            None => return false,
        }
    } else {
        match rest.find(':') {
            Some(i) => (&rest[..i], &rest[i..]),
            None => (rest, ""),
        }
    };
    if !matches!(host, "127.0.0.1" | "localhost" | "[::1]") {
        return false;
    }
    match port {
        "" => true,
        p => p.strip_prefix(':').is_some_and(port_is_valid),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unset_or_blank_is_loopback_only_and_refuses_nothing() {
        for spec in [None, Some(""), Some("   "), Some(" , ")] {
            let p = CorsPolicy::from_spec(spec).expect("nothing configured is not an error");
            assert!(
                p.allows("http://localhost:3000"),
                "{spec:?}: loopback is the default"
            );
            assert!(
                !p.allows("https://dash.example.com"),
                "{spec:?}: nothing else is"
            );
        }
    }

    #[test]
    fn an_entry_must_be_an_exact_origin() {
        for good in [
            "https://a.example",
            "https://a.example:8443",
            "http://localhost:3000",
            "http://[::1]:9000",
            "https://a.example:65535",
        ] {
            assert!(
                CorsPolicy::from_spec(Some(good)).is_ok(),
                "{good} is an exact origin and must be accepted"
            );
        }
        for bad in [
            "a.example",
            "https://a.example/",
            "https://a.example/x",
            "https://a.example?x=1",
            "https://a.example#frag",
            "*",
            "https://*.example",
            "ftp://a.example",
            "https://user@a.example",
            "https://a.example:0",
            "https://a.example:99999",
            "https://a .example",
            "https://a.example:",
            "https:///x",
        ] {
            let err = CorsPolicy::from_spec(Some(bad))
                .expect_err(&format!("{bad} is not an origin and must refuse"));
            assert!(
                err.contains(bad),
                "the refusal names the entry it could not read: {err}"
            );
        }
    }

    #[test]
    fn one_bad_entry_refuses_the_whole_list() {
        let err = CorsPolicy::from_spec(Some("https://ok.example, ftp://bad.example"))
            .expect_err("a list with one bad entry is refused, not partly honoured");
        assert!(err.contains("ftp://bad.example"));
    }

    #[test]
    fn a_configured_list_matches_exactly_and_case_insensitively_on_the_host() {
        let p = CorsPolicy::from_spec(Some("https://Dash.Example.com:8443")).unwrap();
        assert!(p.allows("https://dash.example.com:8443"));
        assert!(
            !p.allows("https://dash.example.com"),
            "the port is part of the origin"
        );
        assert!(
            !p.allows("http://dash.example.com:8443"),
            "the scheme is part of the origin"
        );
        assert!(!p.allows("https://dash.example.com.evil.example:8443"));
        assert!(!p.allows("https://evil-dash.example.com:8443"));
    }

    #[test]
    fn a_configured_list_replaces_loopback() {
        let p = CorsPolicy::from_spec(Some("https://dash.example.com")).unwrap();
        assert!(!p.allows("http://localhost:3000"));
    }

    #[test]
    fn loopback_is_http_and_one_of_three_hosts_on_any_port() {
        let p = CorsPolicy::default();
        for ok in [
            "http://127.0.0.1:5173",
            "http://127.0.0.1",
            "http://localhost:3000",
            "http://localhost",
            "http://[::1]:9000",
            "http://[::1]",
        ] {
            assert!(p.allows(ok), "{ok} is loopback and must be allowed");
        }
        for no in [
            "https://localhost:3000",
            "http://localhost.evil.example",
            "http://127.0.0.1.evil.example:80",
            "http://127.0.0.2:80",
            "http://evil.example:3000",
            "http://localhost:3000/path",
            "null",
            "",
        ] {
            assert!(!p.allows(no), "{no} is not loopback and must be refused");
        }
    }
}
