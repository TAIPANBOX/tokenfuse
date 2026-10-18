//! The issuer's key set, fetched from a URL and polled (`TOKENFUSE_DELEGATION_JWKS_URL`).
//!
//! The file form (`TOKENFUSE_DELEGATION_JWKS`) is read once at start and never
//! changes, so a vouchryx key rotation needed a restart of every door. The URL
//! form is fetched once at start and then polled the way the revocation list
//! is polled (`revocations.rs`): one background task per process, the set held
//! behind a lock, and a synchronous read on the request path.
//!
//! # Refusing to start without the set
//!
//! The first fetch must succeed. A door that has never fetched holds no keys,
//! and every delegation it is asked about is refused while its log says the
//! door is on. `start` returns the error and the caller exits 2, as the
//! revocation feed does.
//!
//! # A poll replaces the set, and a failed poll keeps it
//!
//! A successful poll replaces the held set whole, so a key the server no longer
//! names stops verifying at that poll. A poll that fails, or that serves a body
//! this module refuses, leaves the set held. There is no age limit on a held
//! set: a verifier that cannot reach its issuer keeps the keys it has, which is
//! the cache the design asks for (KEYRYX-DESIGN section 2.6).

use std::sync::{Arc, RwLock};

use jsonwebtoken::jwk::JwkSet;
use tokenfuse_delegation::KeySource;

/// How often the poller asks, when the operator names no interval. A set is
/// rotated with an overlap window far longer than a minute, so a minute of lag
/// never strands a token.
pub const DEFAULT_INTERVAL_MS: u64 = 60_000;

/// A body bigger than this is refused, as the revocation poller refuses its own.
pub const MAX_KEYSET_BYTES: usize = 4 << 20;

/// The set a door holds, shared with the poller that replaces it.
pub type Live = Arc<RwLock<JwkSet>>;

/// What the environment asked for.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Wanted {
    /// No URL named. The file variable, or nothing, decides the keys.
    Off,
    /// A set to fetch and poll.
    On { url: String, interval_ms: u64 },
    /// The configuration cannot be honoured. The caller prints this and exits.
    Refused(String),
}

/// Read the environment: the URL, the file variable, the issuer and the interval.
pub fn wanted(get: impl Fn(&str) -> Option<String>) -> Wanted {
    // Red stage: the URL is not read yet, so every configuration keeps today's behaviour.
    let _ = get;
    Wanted::Off
}

/// A key set from a body. Refuses a body that is not a JWKS and a set with no
/// keys, which would refuse every token while the door reports itself as on.
pub fn accept(body: &str) -> Result<JwkSet, String> {
    tokenfuse_delegation::parse_jwks(body).map_err(|e| format!("not a JWKS: {e}"))
}

async fn fetch_body(client: &reqwest::Client, url: &str) -> Result<String, String> {
    let res = client
        .get(url)
        .send()
        .await
        .map_err(|e| format!("fetching {url}: {e}"))?;
    if !res.status().is_success() {
        return Err(format!("fetching {url}: HTTP {}", res.status()));
    }
    let body = res
        .bytes()
        .await
        .map_err(|e| format!("reading {url}: {e}"))?;
    if body.len() > MAX_KEYSET_BYTES {
        return Err(format!(
            "{url} served {} bytes, over the {MAX_KEYSET_BYTES} cap",
            body.len()
        ));
    }
    String::from_utf8(body.to_vec()).map_err(|e| format!("{url} is not UTF-8: {e}"))
}

/// One fetch, and the same acceptance rule for the first fetch and every poll.
pub async fn fetch(client: &reqwest::Client, url: &str) -> Result<JwkSet, String> {
    accept(&fetch_body(client, url).await?).map_err(|why| format!("{url}: {why}"))
}

/// The first fetch, which must succeed. Red stage: the fetch is not made yet.
pub async fn start(client: &reqwest::Client, url: &str, interval_ms: u64) -> Result<Live, String> {
    let _ = (client, url, interval_ms);
    Ok(Arc::new(RwLock::new(JwkSet { keys: Vec::new() })))
}

/// One poll: fetch, and replace the held set only if the body was accepted.
/// Red stage: the held set is never replaced.
pub async fn poll_once(client: &reqwest::Client, url: &str, live: &Live) -> Result<(), String> {
    let _ = (client, url, live);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;
    use tokenfuse_delegation::testing::{proof, token, Key, AUD, ISS, URL};
    use tokenfuse_delegation::{verify_delegation, DelegationConfig};

    const NOW: i64 = 1_800_000_000;
    const KEYS_URL: &str = "https://vouchryx.internal/.well-known/jwks.json";

    /// A stand-in for the process environment, as `revocations.rs` tests use.
    fn env<'a>(pairs: &'a [(&'a str, &'a str)]) -> impl Fn(&str) -> Option<String> + 'a {
        move |k| {
            pairs
                .iter()
                .find(|(n, _)| *n == k)
                .map(|(_, v)| v.to_string())
        }
    }

    /// A set holding `issuer`'s key under `kid`, as the server would serve it.
    fn set_of(issuer: &Key, kid: &str) -> String {
        serde_json::json!({"keys": [issuer.jwk_value(Some(kid))]}).to_string()
    }

    /// Whether a token `issuer` signs, presented by `holder`, verifies against
    /// the set `live` holds at this moment. The token names kid "v-1".
    fn verifies(live: &Live, issuer: &Key, holder: &Key) -> bool {
        let cfg = DelegationConfig {
            jwks: KeySource::Live(live.clone()),
            issuer: ISS.into(),
            audience: AUD.into(),
        };
        let tok = token(issuer, holder, NOW, serde_json::json!({}));
        let prf = proof(holder, NOW);
        verify_delegation(
            &cfg,
            &tok,
            Some(prf.as_str()),
            "POST",
            URL,
            NOW,
            |_, _, _| false,
        )
        .is_ok()
    }

    /// A stand-in key server: each connection is answered with the body
    /// `current` holds at that moment, or with a 500 while it holds none.
    async fn key_server(current: Arc<Mutex<Option<String>>>) -> String {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind");
        let addr = listener.local_addr().expect("addr");
        tokio::spawn(async move {
            loop {
                let Ok((mut sock, _)) = listener.accept().await else {
                    break;
                };
                let body = current.lock().unwrap_or_else(|p| p.into_inner()).clone();
                tokio::spawn(async move {
                    use tokio::io::{AsyncReadExt, AsyncWriteExt};
                    let mut request = [0u8; 4096];
                    let _ = sock.read(&mut request).await;
                    let reply = match body {
                        Some(b) => format!(
                            "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\
                             Content-Length: {}\r\nConnection: close\r\n\r\n{}",
                            b.len(),
                            b
                        ),
                        None => "HTTP/1.1 500 Internal Server Error\r\nContent-Length: 0\r\n\
                                 Connection: close\r\n\r\n"
                            .to_string(),
                    };
                    let _ = sock.write_all(reply.as_bytes()).await;
                    let _ = sock.shutdown().await;
                });
            }
        });
        format!("http://{addr}/jwks.json")
    }

    #[test]
    fn naming_no_key_url_leaves_the_file_behaviour_alone() {
        assert_eq!(wanted(env(&[])), Wanted::Off);
        assert_eq!(
            wanted(env(&[
                ("TOKENFUSE_DELEGATION_JWKS", "/etc/keys.json"),
                ("TOKENFUSE_DELEGATION_ISSUER", ISS),
            ])),
            Wanted::Off,
            "the file variable on its own names no URL and must switch nothing"
        );
        assert_eq!(
            wanted(env(&[("TOKENFUSE_DELEGATION_JWKS_URL", "   ")])),
            Wanted::Off,
            "whitespace is not a URL"
        );
    }

    #[test]
    fn a_key_url_together_with_a_key_file_refuses_to_start() {
        let w = wanted(env(&[
            ("TOKENFUSE_DELEGATION_JWKS_URL", KEYS_URL),
            ("TOKENFUSE_DELEGATION_JWKS", "/etc/keys.json"),
            ("TOKENFUSE_DELEGATION_ISSUER", ISS),
        ]));
        let Wanted::Refused(why) = w else {
            panic!("a URL and a file were both accepted as the key set: {w:?}");
        };
        assert!(why.contains("TOKENFUSE_DELEGATION_JWKS"), "{why}");
    }

    #[test]
    fn a_key_url_with_no_issuer_refuses_to_start() {
        let w = wanted(env(&[("TOKENFUSE_DELEGATION_JWKS_URL", KEYS_URL)]));
        let Wanted::Refused(why) = w else {
            panic!("a key set with no issuer was accepted: {w:?}");
        };
        assert!(why.contains("TOKENFUSE_DELEGATION_ISSUER"), "{why}");
    }

    #[test]
    fn a_key_url_that_is_not_absolute_http_is_refused() {
        for bad in [
            "/.well-known/jwks.json",
            "keys.internal",
            "file:///tmp/keys.json",
        ] {
            let w = wanted(env(&[
                ("TOKENFUSE_DELEGATION_JWKS_URL", bad),
                ("TOKENFUSE_DELEGATION_ISSUER", ISS),
            ]));
            assert!(
                matches!(w, Wanted::Refused(_)),
                "{bad} was accepted as somewhere to fetch keys from: {w:?}"
            );
        }
    }

    #[test]
    fn the_interval_defaults_and_a_bad_one_is_refused() {
        let w = wanted(env(&[
            ("TOKENFUSE_DELEGATION_JWKS_URL", KEYS_URL),
            ("TOKENFUSE_DELEGATION_ISSUER", ISS),
        ]));
        assert_eq!(
            w,
            Wanted::On {
                url: KEYS_URL.to_string(),
                interval_ms: DEFAULT_INTERVAL_MS,
            }
        );
        for bad in ["soon", "0"] {
            let w = wanted(env(&[
                ("TOKENFUSE_DELEGATION_JWKS_URL", KEYS_URL),
                ("TOKENFUSE_DELEGATION_ISSUER", ISS),
                ("TOKENFUSE_DELEGATION_JWKS_INTERVAL_MS", bad),
            ]));
            assert!(
                matches!(w, Wanted::Refused(_)),
                "interval {bad} was quietly turned into something: {w:?}"
            );
        }
    }

    #[test]
    fn an_empty_or_unparsable_key_set_is_never_installed() {
        assert!(
            accept("not json").is_err(),
            "a body that is not a JWKS was accepted"
        );
        assert!(
            accept(r#"{"keys":[]}"#).is_err(),
            "a key set with no keys was accepted, which would refuse every token while \
             the door reports itself as on"
        );
        assert!(
            accept(&set_of(&Key::default(), "v-1")).is_ok(),
            "a valid key set was refused"
        );
    }

    #[test]
    fn a_key_set_over_the_size_cap_is_refused_before_it_is_read() {
        let body = " ".repeat(MAX_KEYSET_BYTES + 1);
        assert!(accept(&body).is_err(), "a body over the cap was accepted");
    }

    #[tokio::test]
    async fn a_first_fetch_that_fails_refuses_to_start() {
        let client = reqwest::Client::new();
        // Port 1 refuses every connection on the machines this runs on.
        let res = start(&client, "http://127.0.0.1:1/jwks.json", DEFAULT_INTERVAL_MS).await;
        assert!(
            res.is_err(),
            "a door that never fetched its key set started anyway"
        );
    }

    #[tokio::test]
    async fn a_poll_installs_the_set_the_server_now_holds() {
        let first = Key::default();
        let second = Key::default();
        let holder = Key::default();
        let current = Arc::new(Mutex::new(Some(set_of(&first, "v-1"))));
        let url = key_server(current.clone()).await;
        let client = reqwest::Client::new();
        let live = start(&client, &url, DEFAULT_INTERVAL_MS)
            .await
            .expect("the first fetch");
        assert!(
            verifies(&live, &first, &holder),
            "the first set must verify its key"
        );

        *current.lock().unwrap_or_else(|p| p.into_inner()) = Some(set_of(&second, "v-1"));
        poll_once(&client, &url, &live).await.expect("the poll");
        assert!(
            verifies(&live, &second, &holder),
            "after a poll the key the server now serves must verify"
        );
        assert!(
            !verifies(&live, &first, &holder),
            "after a poll the key it replaced must not verify"
        );
    }

    #[tokio::test]
    async fn a_removed_key_stops_verifying_after_a_poll() {
        let gone = Key::default();
        let holder = Key::default();
        let current = Arc::new(Mutex::new(Some(set_of(&gone, "v-1"))));
        let url = key_server(current.clone()).await;
        let client = reqwest::Client::new();
        let live = start(&client, &url, DEFAULT_INTERVAL_MS)
            .await
            .expect("the first fetch");
        assert!(
            verifies(&live, &gone, &holder),
            "before the poll it verifies"
        );

        let successor = Key::default();
        *current.lock().unwrap_or_else(|p| p.into_inner()) = Some(set_of(&successor, "v-2"));
        poll_once(&client, &url, &live).await.expect("the poll");
        assert!(
            !verifies(&live, &gone, &holder),
            "a key the polled set no longer names must stop verifying"
        );
    }

    #[tokio::test]
    async fn a_failed_poll_keeps_the_keys_already_held() {
        let issuer = Key::default();
        let holder = Key::default();
        let current = Arc::new(Mutex::new(Some(set_of(&issuer, "v-1"))));
        let url = key_server(current.clone()).await;
        let client = reqwest::Client::new();
        let live = start(&client, &url, DEFAULT_INTERVAL_MS)
            .await
            .expect("the first fetch");
        assert!(
            verifies(&live, &issuer, &holder),
            "the first set must verify its key"
        );

        // The server now answers 500 to every request.
        *current.lock().unwrap_or_else(|p| p.into_inner()) = None;
        assert!(
            poll_once(&client, &url, &live).await.is_err(),
            "a 500 is a failed poll"
        );
        assert!(
            verifies(&live, &issuer, &holder),
            "a failed poll must keep the keys already held, not empty the set"
        );
    }
}
