//! Provider failures, told to the Cloud once every couple of seconds
//! (invariant 144).
//!
//! The gateway puts one `dependency_failed` on the agent-event bus for every
//! call a provider fails, and every one of those is its own run, so a provider
//! that is down for an hour is thousands of events and no single row an
//! operator can read. The Cloud folds a provider's failures into one incident
//! (`dependency_failed:provider:<name>`, `crates/cloud/src/store.rs`,
//! `note_provider_failures_at`); this module is the gateway's half, and only
//! that: it counts, and it reports.
//!
//! Best effort by design, and not the telemetry path: a report that cannot be
//! delivered is dropped, not queued, because a provider failure that is
//! already ten minutes old is exactly what the next report supersedes, and a
//! queue would be one more thing a gateway holds while its provider is the
//! thing that is down. The per-call event on the bus is unchanged and stays
//! the record. Nothing here is on a request's path beyond one short lock to
//! add one to a counter; the POST happens on a timer, in the background, with
//! the same Cloud URL and key the telemetry sink uses (`TOKENFUSE_CLOUD_URL`,
//! `TOKENFUSE_CLOUD_KEY`), which must be an `ingest` or `admin` key.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, OnceLock, PoisonError};
use std::time::Duration;

/// How often what has been counted is sent.
pub const FLUSH_EVERY: Duration = Duration::from_secs(2);

/// A report that gets no answer in this long is dropped.
const POST_TIMEOUT: Duration = Duration::from_secs(5);

/// The longest detail sent, in characters. The Cloud cuts at the same length.
const DETAIL_MAX_CHARS: usize = 160;

/// What one flush did.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Flush {
    /// Nothing had failed since the last flush; nothing was sent.
    Nothing,
    /// This many failed calls were reported and the Cloud accepted them.
    Sent(u64),
    /// This many failed calls were counted and could not be delivered: the
    /// Cloud was unreachable or refused the report. They are not retried.
    Dropped(u64),
}

#[derive(Default)]
struct Pending {
    count: u64,
    detail: String,
}

/// Counts provider failures and reports them to the Cloud.
pub struct ProviderFailureReporter {
    url: String,
    key: String,
    provider: String,
    client: reqwest::Client,
    pending: Mutex<Pending>,
    refusal_reported: AtomicBool,
}

impl ProviderFailureReporter {
    /// `base` is the Cloud's base URL, `key` the org key, `provider` the label
    /// failures are filed under (see [`provider_label`]).
    pub fn new(base: &str, key: &str, provider: &str) -> Self {
        let client = reqwest::Client::builder()
            .timeout(POST_TIMEOUT)
            .build()
            .unwrap_or_else(|_| reqwest::Client::new());
        Self {
            url: format!("{}/v1/provider-failures", base.trim_end_matches('/')),
            key: key.to_string(),
            provider: provider.to_string(),
            client,
            pending: Mutex::new(Pending::default()),
            refusal_reported: AtomicBool::new(false),
        }
    }

    /// Count one failed provider call. `detail` is the most recent failure in
    /// words; control characters are removed and it is cut, so what a provider
    /// puts in an error message cannot grow what is sent.
    pub fn note(&self, detail: &str) {
        let mut pending = self.pending.lock().unwrap_or_else(PoisonError::into_inner);
        pending.count = pending.count.saturating_add(1);
        pending.detail = detail
            .chars()
            .filter(|c| !c.is_control())
            .take(DETAIL_MAX_CHARS)
            .collect();
    }

    /// What a test reads instead of the Cloud: the count and the detail
    /// waiting for the next flush.
    #[cfg(test)]
    pub(crate) fn pending_count(&self) -> u64 {
        self.pending
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .count
    }

    #[cfg(test)]
    pub(crate) fn pending_detail(&self) -> String {
        self.pending
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .detail
            .clone()
    }

    /// Send what has been counted since the last flush as one report. The
    /// counter is cleared first, whatever the answer: a failed delivery is
    /// dropped, not retried (see the module comment).
    pub async fn flush(&self) -> Flush {
        let (count, detail) = {
            let mut pending = self.pending.lock().unwrap_or_else(PoisonError::into_inner);
            if pending.count == 0 {
                return Flush::Nothing;
            }
            (
                std::mem::take(&mut pending.count),
                std::mem::take(&mut pending.detail),
            )
        };
        let body = serde_json::json!({
            "failures": [{ "provider": self.provider, "count": count, "detail": detail }]
        });
        let payload = match serde_json::to_vec(&body) {
            Ok(p) => p,
            Err(_) => return Flush::Dropped(count),
        };
        let sent = self
            .client
            .post(&self.url)
            .bearer_auth(&self.key)
            .header("content-type", "application/json")
            .body(payload)
            .send()
            .await;
        match sent {
            Ok(resp) if resp.status().is_success() => Flush::Sent(count),
            Ok(resp) => {
                // A refusal repeats every flush for as long as the provider
                // fails, so it is said once and then at debug.
                let status = resp.status();
                if self.refusal_reported.swap(true, Ordering::Relaxed) {
                    tracing::debug!(%status, "Cloud refused a provider failure report");
                } else {
                    tracing::warn!(
                        %status,
                        "the Cloud refused a provider failure report; its key needs the ingest or admin role (later refusals log at debug)"
                    );
                }
                Flush::Dropped(count)
            }
            Err(e) => {
                tracing::debug!("provider failure report not delivered: {e}");
                Flush::Dropped(count)
            }
        }
    }

    /// Flush every [`FLUSH_EVERY`] on the current runtime.
    pub fn spawn(self: &Arc<Self>) {
        let reporter = Arc::clone(self);
        tokio::spawn(async move {
            let mut tick = tokio::time::interval(FLUSH_EVERY);
            loop {
                tick.tick().await;
                let _ = reporter.flush().await;
            }
        });
    }
}

/// The label a provider's failures are filed under: the authority (host and
/// port) of `TOKENFUSE_UPSTREAM`, scheme, path, query and any `user:password@`
/// removed, so a credential written into the URL never leaves the process.
/// `stub` when no upstream is set (the offline loop), `unknown` when the URL
/// has no host.
pub fn provider_label(upstream: Option<&str>) -> String {
    let Some(url) = upstream.map(str::trim).filter(|u| !u.is_empty()) else {
        return "stub".to_string();
    };
    let rest = url.split_once("://").map_or(url, |(_, rest)| rest);
    let authority = rest.split(['/', '?', '#']).next().unwrap_or("");
    let host = authority.rsplit_once('@').map_or(authority, |(_, h)| h);
    if host.is_empty() {
        "unknown".to_string()
    } else {
        host.to_string()
    }
}

static REPORTER: OnceLock<Arc<ProviderFailureReporter>> = OnceLock::new();

#[cfg(test)]
thread_local! {
    /// A reporter a test installs for its own thread, so a test can watch the
    /// wiring without sharing the process-wide one with every other test.
    static TEST_REPORTER: std::cell::RefCell<Option<Arc<ProviderFailureReporter>>> =
        const { std::cell::RefCell::new(None) };
}

/// Install the process-wide reporter and start flushing. `None` when one is
/// already installed. Called once by `main`, only when a Cloud is configured:
/// a gateway with no Cloud counts nothing and sends nothing.
pub fn install(
    base: &str,
    key: &str,
    upstream: Option<&str>,
) -> Option<Arc<ProviderFailureReporter>> {
    let reporter = Arc::new(ProviderFailureReporter::new(
        base,
        key,
        &provider_label(upstream),
    ));
    REPORTER.set(Arc::clone(&reporter)).ok()?;
    reporter.spawn();
    Some(reporter)
}

/// Count one failed provider call, if a reporter is installed. A no-op
/// otherwise, so every caller can call it without asking.
pub fn note_provider_failure(detail: &str) {
    if let Some(reporter) = this_thread_reporter() {
        reporter.note(detail);
        return;
    }
    if let Some(reporter) = REPORTER.get() {
        reporter.note(detail);
    }
}

#[cfg(test)]
fn this_thread_reporter() -> Option<Arc<ProviderFailureReporter>> {
    TEST_REPORTER.with(|t| t.borrow().clone())
}

#[cfg(not(test))]
fn this_thread_reporter() -> Option<Arc<ProviderFailureReporter>> {
    None
}

#[cfg(test)]
pub(crate) fn install_for_this_thread(reporter: Arc<ProviderFailureReporter>) {
    TEST_REPORTER.with(|t| *t.borrow_mut() = Some(reporter));
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::AtomicUsize;

    type Received = Arc<Mutex<Vec<(Option<String>, serde_json::Value)>>>;

    /// A Cloud that records what it is sent to `/v1/provider-failures`
    /// (authorization header and JSON body) and answers `status`.
    async fn stub_cloud(status: u16) -> (String, Received, Arc<AtomicUsize>) {
        use axum::{http::HeaderMap, routing::post, Router};
        let received: Received = Arc::new(Mutex::new(Vec::new()));
        let hits = Arc::new(AtomicUsize::new(0));
        let (store, counter) = (Arc::clone(&received), Arc::clone(&hits));
        let app = Router::new().route(
            "/v1/provider-failures",
            post(move |headers: HeaderMap, body: axum::body::Bytes| {
                let (store, counter) = (Arc::clone(&store), Arc::clone(&counter));
                async move {
                    counter.fetch_add(1, Ordering::SeqCst);
                    let auth = headers
                        .get("authorization")
                        .and_then(|v| v.to_str().ok())
                        .map(str::to_string);
                    let json = serde_json::from_slice(&body).unwrap_or(serde_json::Value::Null);
                    store.lock().unwrap().push((auth, json));
                    axum::http::StatusCode::from_u16(status).unwrap()
                }
            }),
        );
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            let _ = axum::serve(listener, app).await;
        });
        (format!("http://{addr}"), received, hits)
    }

    #[tokio::test]
    async fn a_storm_of_failures_is_one_report_with_the_count() {
        let (base, received, hits) = stub_cloud(200).await;
        let reporter = ProviderFailureReporter::new(&base, "org-key", "api.example.test");
        for _ in 0..1000 {
            reporter.note("provider answered HTTP 503 for model m");
        }
        assert_eq!(reporter.flush().await, Flush::Sent(1000));
        assert_eq!(
            hits.load(Ordering::SeqCst),
            1,
            "one POST for the whole storm"
        );
        let got = received.lock().unwrap();
        let (auth, body) = &got[0];
        assert_eq!(auth.as_deref(), Some("Bearer org-key"));
        let entry = &body["failures"][0];
        assert_eq!(entry["provider"], "api.example.test");
        assert_eq!(entry["count"], 1000);
        assert_eq!(entry["detail"], "provider answered HTTP 503 for model m");
    }

    #[tokio::test]
    async fn nothing_counted_sends_nothing() {
        let (base, _received, hits) = stub_cloud(200).await;
        let reporter = ProviderFailureReporter::new(&base, "k", "p");
        assert_eq!(reporter.flush().await, Flush::Nothing);
        assert_eq!(hits.load(Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn a_flush_clears_the_count_so_the_next_report_is_only_what_is_new() {
        let (base, received, _hits) = stub_cloud(200).await;
        let reporter = ProviderFailureReporter::new(&base, "k", "p");
        reporter.note("a");
        reporter.note("a");
        assert_eq!(reporter.flush().await, Flush::Sent(2));
        reporter.note("b");
        assert_eq!(reporter.flush().await, Flush::Sent(1));
        let got = received.lock().unwrap();
        assert_eq!(got[0].1["failures"][0]["count"], 2);
        assert_eq!(got[1].1["failures"][0]["count"], 1);
    }

    #[tokio::test]
    async fn a_refused_report_is_dropped_and_not_replayed() {
        let (base, _received, hits) = stub_cloud(403).await;
        let reporter = ProviderFailureReporter::new(&base, "viewer-key", "p");
        reporter.note("x");
        reporter.note("x");
        assert_eq!(reporter.flush().await, Flush::Dropped(2));
        assert_eq!(
            reporter.flush().await,
            Flush::Nothing,
            "a dropped report is not queued for the next flush"
        );
        assert_eq!(hits.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn an_unreachable_cloud_drops_the_report_and_does_not_hang() {
        // Bind and release a port, so nothing is listening on it.
        let port = {
            let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
            l.local_addr().unwrap().port()
        };
        let reporter = ProviderFailureReporter::new(&format!("http://127.0.0.1:{port}"), "k", "p");
        reporter.note("x");
        let flushed = tokio::time::timeout(Duration::from_secs(10), reporter.flush())
            .await
            .expect("an unreachable Cloud must not hold the flush");
        assert_eq!(flushed, Flush::Dropped(1));
    }

    #[tokio::test]
    async fn the_detail_is_cut_and_stripped_of_control_characters() {
        let (base, received, _hits) = stub_cloud(200).await;
        let reporter = ProviderFailureReporter::new(&base, "k", "p");
        let hostile = format!("line one\r\nline two\u{0}\u{1b}[31m{}", "z".repeat(10_000));
        reporter.note(&hostile);
        assert_eq!(reporter.flush().await, Flush::Sent(1));
        let got = received.lock().unwrap();
        let detail = got[0].1["failures"][0]["detail"].as_str().unwrap();
        assert!(detail.chars().count() <= DETAIL_MAX_CHARS);
        assert!(!detail.chars().any(char::is_control));
        assert!(detail.starts_with("line oneline two"));
    }

    #[test]
    fn the_provider_label_is_the_authority_of_the_upstream() {
        assert_eq!(
            provider_label(Some("https://api.anthropic.com")),
            "api.anthropic.com"
        );
        assert_eq!(
            provider_label(Some("http://127.0.0.1:4199/v1/messages?x=1#f")),
            "127.0.0.1:4199"
        );
        assert_eq!(provider_label(None), "stub");
        assert_eq!(provider_label(Some("   ")), "stub");
        assert_eq!(provider_label(Some("https:///only-a-path")), "unknown");
    }

    #[test]
    fn a_credential_written_into_the_upstream_url_is_not_in_the_label() {
        // Built at run time, so the file holds no credential-shaped URL.
        let (user, password) = ("svc-user", "placeholder-not-a-secret");
        let url = ["https://", user, ":", password, "@llm.example.test:8443/v1"].concat();
        let label = provider_label(Some(&url));
        assert_eq!(label, "llm.example.test:8443");
        assert!(!label.contains(password));
        assert!(!label.contains('@'));
    }

    #[test]
    fn noting_with_no_reporter_installed_is_a_no_op() {
        // Nothing in this test binary installs the process-wide reporter.
        note_provider_failure("nobody is listening");
    }
}
