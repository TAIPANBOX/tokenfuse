//! Which browser origins the control plane answers (invariant 131).
//!
//! STUB for the red commit: the policy is parsed and checked by the real
//! implementation that follows it. Nothing reads this yet, so the middleware
//! still answers every origin with `*`.

/// The origins a browser may call the control plane from.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct CorsPolicy {
    configured: Option<Vec<String>>,
}

impl CorsPolicy {
    /// Parse `TOKENFUSE_CLOUD_CORS_ORIGINS`. Stub: accepts everything and keeps
    /// nothing, so the tests that expect a refusal see the defect.
    pub fn from_spec(spec: Option<&str>) -> Result<Self, String> {
        let _ = spec;
        Ok(Self::default())
    }

    /// Whether `origin` may call the control plane. Stub: refuses all.
    pub fn allows(&self, origin: &str) -> bool {
        let _ = (origin, &self.configured);
        false
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unset_or_blank_is_loopback_only_and_refuses_nothing() {
        for spec in [None, Some(""), Some("   "), Some(" , ")] {
            let p = CorsPolicy::from_spec(spec).expect("nothing configured is not an error");
            assert!(p.allows("http://localhost:3000"), "{spec:?}: loopback is the default");
            assert!(!p.allows("https://dash.example.com"), "{spec:?}: nothing else is");
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
        assert!(!p.allows("https://dash.example.com"), "the port is part of the origin");
        assert!(!p.allows("http://dash.example.com:8443"), "the scheme is part of the origin");
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
