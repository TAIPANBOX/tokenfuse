//! The poller that fills the `revoked` closure both doors pass to
//! [`crate::chainproof::resolve`].
//!
//! `tokenfuse_delegation::revocations` is the cache and the staleness rule; it
//! has no client and deliberately cannot fetch, because invariant 29 is that
//! the FETCH is out of band and the CHECK is local. This module is the out of
//! band half: one background task per process, a snapshot installed under a
//! lock, and a synchronous read on the request path.
//!
//! # Off unless asked, and refusing to start rather than pretending
//!
//! Naming no URL leaves this off, which is what every deployment did before
//! 2026-08-26 and what the two doors did even after the cache existed: both
//! passed `|_, _, _| false`, so the closure was a hole with a type.
//!
//! Naming one turns it on, and then the FIRST fetch happens at startup and must
//! succeed. A door that has never fetched holds nothing, and under the default
//! [`FailMode::Closed`] that door refuses every delegated call. Refusing per
//! request would be a running gateway that turns away traffic while its log
//! says the door is on, which is the failure mode `chainproof::from_env` and
//! `firewall::from_env` both already exit 2 rather than enter.
//!
//! # Asking for this without a door to check is refused too
//!
//! The check lives inside `verify_delegation`, which only runs when an issuer
//! is configured. So a deployment that names a revocation URL and no issuer has
//! asked for a check that can never fire, and every token still walks in as a
//! claim. That is two of three again: not a weaker configuration, an ambiguous
//! one, and it is refused with the same exit code for the same reason.

use std::sync::{Arc, RwLock};
use std::time::Duration;

use tokenfuse_delegation::revocations::{
    FailMode, Install, Revocations, Snapshot, DEFAULT_MAX_AGE_SECS,
};

/// How often the poller asks, when the operator names no interval.
///
/// A fifth of [`DEFAULT_MAX_AGE_SECS`], so four consecutive fetches have to
/// fail before a miss stops being answered from the list. One failed poll is a
/// blip and should not change what the door answers; four in a row is an
/// outage, and that is the one the fail mode is for.
pub const DEFAULT_INTERVAL_MS: u64 = 12_000;

/// A body bigger than this is refused. The list comes off somebody else's wire
/// and this runs for the life of the process.
pub const MAX_SNAPSHOT_BYTES: usize = 4 << 20;

/// The handle both doors hold. `None` is the check being off, not a degraded
/// mode: nothing is polled, so nothing is refused.
pub type Feed = Option<Arc<RwLock<Revocations>>>;

/// What the environment asked for.
///
/// Separate from the doing, so what an operator's variables MEAN is a pure
/// function with tests, and the process exit is the only untested part. The
/// existing `from_env` functions in this crate decide and exit in one body,
/// which is why none of their decisions has a test.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Wanted {
    /// No URL named. The doors keep answering "not revoked" and say so.
    Off,
    /// A poller, with the policy an operator chose or fell into.
    On {
        url: String,
        interval_ms: u64,
        max_age_secs: i64,
        fail_mode: FailMode,
    },
    /// The configuration cannot be honoured. The caller prints this and exits.
    Refused(String),
}

/// Read the environment. `door_on` is whether an issuer is configured, since a
/// revocation check with no door to check is the ambiguous configuration.
pub fn wanted(get: impl Fn(&str) -> Option<String>, door_on: bool) -> Wanted {
    let url = get("TOKENFUSE_DELEGATION_REVOCATIONS").unwrap_or_default();
    let url = url.trim().to_string();
    if url.is_empty() {
        return Wanted::Off;
    }
    if !door_on {
        return Wanted::Refused(
            "TOKENFUSE_DELEGATION_REVOCATIONS names a list to poll, but no delegation \
             issuer is configured, so nothing verifies a token and the revocation check \
             can never fire. Set TOKENFUSE_DELEGATION_ISSUER and TOKENFUSE_DELEGATION_JWKS \
             too, or unset this."
                .to_string(),
        );
    }
    if !(url.starts_with("http://") || url.starts_with("https://")) {
        return Wanted::Refused(format!(
            "TOKENFUSE_DELEGATION_REVOCATIONS ({url}) is not an absolute http(s) URL."
        ));
    }
    let interval_ms = match get("TOKENFUSE_DELEGATION_REVOCATIONS_INTERVAL_MS") {
        None => DEFAULT_INTERVAL_MS,
        Some(v) => match v.trim().parse::<u64>() {
            Ok(n) if n > 0 => n,
            _ => {
                return Wanted::Refused(format!(
                    "TOKENFUSE_DELEGATION_REVOCATIONS_INTERVAL_MS ({v}) is not a positive \
                     number of milliseconds."
                ));
            }
        },
    };
    let max_age_secs = match get("TOKENFUSE_DELEGATION_REVOCATIONS_MAX_AGE_SECS") {
        None => DEFAULT_MAX_AGE_SECS,
        // Zero and negative are accepted and mean "only a hit counts", which is
        // a real policy. The cache says so itself and does not correct it.
        Some(v) => match v.trim().parse::<i64>() {
            Ok(n) => n,
            Err(_) => {
                return Wanted::Refused(format!(
                    "TOKENFUSE_DELEGATION_REVOCATIONS_MAX_AGE_SECS ({v}) is not a number \
                     of seconds."
                ));
            }
        },
    };
    let fail_mode = match get("TOKENFUSE_DELEGATION_REVOCATIONS_FAILMODE") {
        None => FailMode::default(),
        Some(v) => match v.trim().to_ascii_lowercase().as_str() {
            "closed" => FailMode::Closed,
            "open" => FailMode::Open,
            _ => {
                return Wanted::Refused(format!(
                    "TOKENFUSE_DELEGATION_REVOCATIONS_FAILMODE ({v}) is not `open` or \
                     `closed`. Unset means closed."
                ));
            }
        },
    };
    Wanted::On {
        url,
        interval_ms,
        max_age_secs,
        fail_mode,
    }
}

/// One fetch. Separate so the startup fetch and the poll are the same code:
/// a startup that accepted a body the poller would refuse is a door whose
/// first list is the only one it ever trusts.
pub async fn fetch(client: &reqwest::Client, url: &str) -> Result<Snapshot, String> {
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
    if body.len() > MAX_SNAPSHOT_BYTES {
        return Err(format!(
            "{url} served {} bytes, over the {MAX_SNAPSHOT_BYTES} cap",
            body.len()
        ));
    }
    let raw = std::str::from_utf8(&body).map_err(|e| format!("{url} is not UTF-8: {e}"))?;
    Snapshot::from_json(raw).map_err(|e| format!("{url} is not a revocation snapshot: {e}"))
}

/// Build the feed from the environment: decide, refuse loudly, fetch once, then
/// poll in the background.
///
/// Exits 2 rather than returning an error, for the reason in the module doc.
pub async fn from_env(client: &reqwest::Client, door_on: bool, now: i64) -> Feed {
    match wanted(|k| std::env::var(k).ok(), door_on) {
        Wanted::Off => None,
        Wanted::Refused(why) => {
            eprintln!("tokenfuse: {why}");
            std::process::exit(2);
        }
        Wanted::On {
            url,
            interval_ms,
            max_age_secs,
            fail_mode,
        } => {
            let mut cache = Revocations::new(max_age_secs, fail_mode);
            match fetch(client, &url).await {
                Ok(snapshot) => {
                    let entries = snapshot.revocations.len();
                    match cache.install(snapshot, now) {
                        Install::Applied => {
                            tracing::info!(
                                url = %url,
                                entries,
                                interval_ms,
                                max_age_secs,
                                fail_mode = ?fail_mode,
                                "revocation list: polling"
                            );
                        }
                        refused => {
                            eprintln!(
                                "tokenfuse: the first revocation snapshot from {url} was \
                                 refused ({refused:?}), so this door holds no list. Under \
                                 the configured fail mode it would refuse every delegated \
                                 call while reporting itself as on."
                            );
                            std::process::exit(2);
                        }
                    }
                }
                Err(why) => {
                    eprintln!(
                        "tokenfuse: {why}. A door that has never fetched the revocation \
                         list holds nothing, and would refuse every delegated call while \
                         reporting itself as on."
                    );
                    std::process::exit(2);
                }
            }
            let feed = Arc::new(RwLock::new(cache));
            spawn_poller(feed.clone(), client.clone(), url, interval_ms);
            Some(feed)
        }
    }
}

/// The background poll. A failed poll leaves the held list ageing, which is the
/// whole point of the age: it is not an empty list and it is not a fresh one.
pub fn spawn_poller(
    feed: Arc<RwLock<Revocations>>,
    client: reqwest::Client,
    url: String,
    interval_ms: u64,
) {
    tokio::spawn(async move {
        let mut ticker = tokio::time::interval(Duration::from_millis(interval_ms));
        ticker.tick().await; // fires immediately; the startup fetch already ran
        loop {
            ticker.tick().await;
            let now = crate::sink::now_millis() / 1000;
            match fetch(&client, &url).await {
                Ok(snapshot) => {
                    let mut guard = feed.write().unwrap_or_else(|p| p.into_inner());
                    match guard.install(snapshot, now) {
                        Install::Applied => {}
                        refused => {
                            tracing::warn!(url = %url, refused = ?refused, "revocation list: snapshot refused");
                        }
                    }
                }
                Err(why) => {
                    let age = feed.read().unwrap_or_else(|p| p.into_inner()).age_secs(now);
                    tracing::warn!(url = %url, age_secs = ?age, "revocation list: poll failed, held list ageing: {why}");
                }
            }
        }
    });
}

/// The closure [`crate::chainproof::resolve`] takes.
///
/// With no feed it answers `false` for every token, which is the check being
/// off. That is the same value the two doors passed as a literal before this
/// module existed, and the difference is that it is now reachable only when an
/// operator asked for nothing.
pub fn hook(feed: &Feed, now: i64) -> impl Fn(&str, &str, i64) -> bool + '_ {
    move |jti, subject, issued_at| {
        let Some(cache) = feed else {
            return false;
        };
        let answer = cache
            .read()
            .unwrap_or_else(|p| p.into_inner())
            .check(jti, subject, issued_at, now);
        if answer.basis.is_fallback() {
            // A fallback is the fail mode answering, not the list. An operator
            // who never sees these cannot tell a working poller from a dead one
            // that happens to be refusing nothing.
            tracing::warn!(
                basis = ?answer.basis,
                revoked = answer.revoked,
                "revocation list: answered by the fail mode rather than by the list"
            );
        }
        answer.revoked
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A stand-in for the process environment. Tests take a map rather than
    /// `std::env`, which is process-global and would make these race each other
    /// as threads of one test binary.
    fn env<'a>(pairs: &'a [(&'a str, &'a str)]) -> impl Fn(&str) -> Option<String> + 'a {
        move |k| {
            pairs
                .iter()
                .find(|(n, _)| *n == k)
                .map(|(_, v)| v.to_string())
        }
    }

    const URL: &str = "https://vouchryx.internal/v1/revocations";

    #[test]
    fn naming_no_list_leaves_the_check_off() {
        assert_eq!(wanted(env(&[]), true), Wanted::Off);
        assert_eq!(
            wanted(env(&[("TOKENFUSE_DELEGATION_REVOCATIONS", "   ")]), true),
            Wanted::Off,
            "whitespace is not a URL and must not switch a check on"
        );
    }

    #[test]
    fn a_list_to_poll_with_no_door_to_check_is_refused() {
        // The whole configuration, correct in every other way, with no issuer.
        // The check lives inside `verify_delegation`, which never runs, so this
        // deployment polls a list forever and refuses nothing.
        let w = wanted(env(&[("TOKENFUSE_DELEGATION_REVOCATIONS", URL)]), false);
        let Wanted::Refused(why) = w else {
            panic!("a revocation list with no delegation door was accepted: {w:?}");
        };
        assert!(why.contains("TOKENFUSE_DELEGATION_ISSUER"), "{why}");
    }

    #[test]
    fn the_policy_an_operator_falls_into_is_the_safe_one() {
        let w = wanted(env(&[("TOKENFUSE_DELEGATION_REVOCATIONS", URL)]), true);
        assert_eq!(
            w,
            Wanted::On {
                url: URL.to_string(),
                interval_ms: DEFAULT_INTERVAL_MS,
                max_age_secs: DEFAULT_MAX_AGE_SECS,
                fail_mode: FailMode::Closed,
            },
            "the defaults are the answer for a deployment that named only a URL"
        );
        assert!(
            DEFAULT_INTERVAL_MS * 4 <= DEFAULT_MAX_AGE_SECS as u64 * 1000,
            "four consecutive polls must fail before a miss stops being answered \
             from the list, or one blip changes what the door says"
        );
    }

    #[test]
    fn a_url_that_is_not_absolute_http_is_refused() {
        for bad in [
            "/v1/revocations",
            "vouchryx.internal",
            "file:///tmp/revs.json",
        ] {
            let w = wanted(env(&[("TOKENFUSE_DELEGATION_REVOCATIONS", bad)]), true);
            assert!(
                matches!(w, Wanted::Refused(_)),
                "{bad} was accepted as somewhere to poll: {w:?}"
            );
        }
    }

    #[test]
    fn a_setting_that_cannot_be_read_is_refused_rather_than_guessed() {
        for (key, value) in [
            ("TOKENFUSE_DELEGATION_REVOCATIONS_INTERVAL_MS", "soon"),
            ("TOKENFUSE_DELEGATION_REVOCATIONS_INTERVAL_MS", "0"),
            ("TOKENFUSE_DELEGATION_REVOCATIONS_MAX_AGE_SECS", "a minute"),
            ("TOKENFUSE_DELEGATION_REVOCATIONS_FAILMODE", "ajar"),
            // The one that matters most: a typo of the safe word must not fall
            // back to a default, because the operator asking for `closed` and
            // silently getting it is indistinguishable from asking and being
            // ignored.
            ("TOKENFUSE_DELEGATION_REVOCATIONS_FAILMODE", "close"),
        ] {
            let w = wanted(
                env(&[("TOKENFUSE_DELEGATION_REVOCATIONS", URL), (key, value)]),
                true,
            );
            assert!(
                matches!(w, Wanted::Refused(_)),
                "{key}={value} was quietly turned into something: {w:?}"
            );
        }
    }

    #[test]
    fn a_max_age_of_zero_or_less_is_a_policy_and_not_a_mistake() {
        // "Only a hit counts": every list is stale the instant it lands, so a
        // miss always goes to the fail mode. The cache documents this as a real
        // configuration, and correcting it here would be this module deciding
        // something the operator already decided.
        for value in ["0", "-1"] {
            let w = wanted(
                env(&[
                    ("TOKENFUSE_DELEGATION_REVOCATIONS", URL),
                    ("TOKENFUSE_DELEGATION_REVOCATIONS_MAX_AGE_SECS", value),
                ]),
                true,
            );
            let Wanted::On { max_age_secs, .. } = w else {
                panic!("max age {value} was refused: {w:?}");
            };
            assert_eq!(max_age_secs, value.parse::<i64>().unwrap());
        }
    }

    #[test]
    fn an_operator_can_still_choose_open() {
        let w = wanted(
            env(&[
                ("TOKENFUSE_DELEGATION_REVOCATIONS", URL),
                ("TOKENFUSE_DELEGATION_REVOCATIONS_FAILMODE", "OPEN"),
            ]),
            true,
        );
        let Wanted::On { fail_mode, .. } = w else {
            panic!("open was refused: {w:?}");
        };
        assert_eq!(fail_mode, FailMode::Open, "case is not the operator's job");
    }

    #[test]
    fn with_no_feed_the_hook_answers_not_revoked() {
        let feed: Feed = None;
        assert!(
            !hook(&feed, 1_800_000_000)("tok-1", "user://acme/alice", 1_799_999_990),
            "a door polling nothing must not refuse: that is the check being off"
        );
    }

    #[test]
    fn the_hook_answers_from_the_list_the_poller_installed() {
        let now = 1_800_000_000;
        let snapshot = Snapshot::from_json(&format!(
            r#"{{"as_of":{now},"revocations":[{{"jti":"tok-dead","reason":"compromised"}}]}}"#
        ))
        .expect("a snapshot in vouchryx's own shape");
        let mut cache = Revocations::new(DEFAULT_MAX_AGE_SECS, FailMode::Closed);
        assert_eq!(cache.install(snapshot, now), Install::Applied);
        let feed: Feed = Some(Arc::new(RwLock::new(cache)));

        let ask = hook(&feed, now);
        assert!(
            ask("tok-dead", "user://acme/alice", now - 10),
            "the revoked token was let through, which is the hole this closes"
        );
        assert!(
            !ask("tok-live", "user://acme/alice", now - 10),
            "a token the list does not name is not revoked"
        );
    }

    #[test]
    fn a_door_that_has_never_fetched_refuses_under_the_default() {
        // What `from_env` exits rather than enters. Kept as a test so the
        // reason the exit exists is asserted somewhere: a running door in this
        // state turns away every delegated call.
        let feed: Feed = Some(Arc::new(RwLock::new(Revocations::with_defaults())));
        assert!(
            hook(&feed, 1_800_000_000)("tok-1", "user://acme/alice", 1_799_999_990),
            "an empty cache under the default fail mode must refuse, which is why \
             a door that cannot fetch must not start"
        );
    }
}
