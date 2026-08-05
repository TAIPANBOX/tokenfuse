//! `CloudSink` — ships settled-call telemetry to the TokenFuse Cloud control
//! plane, so many gateways roll up into one cross-fleet view.
//!
//! It batches records and POSTs them asynchronously (fire-and-forget) so the
//! request path is never blocked on the network; a failed push is dropped, not
//! retried — the local Parquet trace remains the source of truth. Enable with
//! `TOKENFUSE_CLOUD_URL` + `TOKENFUSE_CLOUD_KEY`; composes with other sinks via
//! `TeeSink`.

use std::collections::HashSet;
use std::sync::{Arc, Mutex};

use serde::Serialize;

use crate::sink::{CallRecord, EventSink};

/// How many records to buffer before an automatic flush.
const BATCH: usize = 20;

pub struct CloudSink {
    url: String,
    key: String,
    client: reqwest::Client,
    buf: Mutex<Vec<CallRecord>>,
    /// Non-success statuses this sink has already warned about, so a control
    /// plane that refuses every batch costs one warning per distinct status
    /// rather than one per batch. See [`report_refusal`].
    reported: Arc<Mutex<HashSet<u16>>>,
}

#[derive(Serialize)]
struct Batch<'a> {
    records: &'a [CallRecord],
}

impl CloudSink {
    /// `base` is the control plane's base URL (e.g. `http://control-plane:8080`);
    /// telemetry is POSTed to `{base}/v1/ingest`. `key` is the org API key.
    pub fn new(base: impl Into<String>, key: impl Into<String>) -> Self {
        let base = base.into();
        let url = format!("{}/v1/ingest", base.trim_end_matches('/'));
        CloudSink {
            url,
            key: key.into(),
            client: reqwest::Client::new(),
            buf: Mutex::new(Vec::new()),
            reported: Arc::new(Mutex::new(HashSet::new())),
        }
    }

    /// POST a batch in the background. Best-effort: nothing is retried, and a
    /// failure is reported rather than acted on. The push does not block the
    /// request path and never fails a call.
    fn ship(&self, records: Vec<CallRecord>) {
        if records.is_empty() {
            return;
        }
        let (client, url, key) = (self.client.clone(), self.url.clone(), self.key.clone());
        let reported = Arc::clone(&self.reported);
        tokio::spawn(async move {
            let payload = match serde_json::to_vec(&Batch { records: &records }) {
                Ok(p) => p,
                Err(e) => {
                    tracing::debug!("cloud telemetry encode failed: {e}");
                    return;
                }
            };
            let req = client
                .post(&url)
                .bearer_auth(&key)
                .header("content-type", "application/json")
                .body(payload);
            match req.send().await {
                // Never reached it: the URL is wrong, the host is down, the
                // network dropped it. Transient by nature and already logged
                // per attempt, so it stays where it was.
                Err(e) => tracing::debug!("cloud telemetry push failed: {e}"),
                Ok(resp) if resp.status().is_success() => {}
                // Reached it and was refused. `reqwest` hands back `Ok` here,
                // which is why this used to fall through the `Err` arm above
                // and vanish.
                Ok(resp) => report_refusal(&reported, resp.status(), &url),
            }
        });
    }

    fn take_if_full(&self) -> Option<Vec<CallRecord>> {
        let mut buf = self.buf.lock().unwrap();
        if buf.len() >= BATCH {
            Some(std::mem::take(&mut *buf))
        } else {
            None
        }
    }
}

impl EventSink for CloudSink {
    fn record(&self, rec: CallRecord) {
        self.buf.lock().unwrap().push(rec);
        if let Some(batch) = self.take_if_full() {
            self.ship(batch);
        }
    }

    fn flush(&self) {
        let batch = std::mem::take(&mut *self.buf.lock().unwrap());
        self.ship(batch);
    }
}

/// Say as much about a refused push as it is worth, and no more.
///
/// A push the control plane REFUSES is a different fault from one that never
/// arrived. It is almost always configuration, it does not clear itself, and
/// nothing else in the estate reports it: the gateway goes on metering locally
/// and answering every call exactly as before, so a gateway whose cloud key is
/// wrong, rotated, or short of the role `/v1/ingest` requires looks identical
/// to a healthy one from both ends while the org's spend simply never appears
/// in the control plane. That is worth a warning, not a debug line.
///
/// It is worth exactly one, though. The same wrong key refuses every batch for
/// as long as the process runs, so warning per push would write a single
/// configuration fault into the log several times a second on a busy gateway
/// and bury the enforcement decisions that share it. The first of each distinct
/// status warns; the repeats drop to debug, which keeps the count available to
/// anyone already looking and costs nothing to anyone who is not. The set is
/// bounded by the number of HTTP status codes, so it cannot grow.
///
/// Per sink rather than per process: a gateway builds one `CloudSink`, so the
/// two are the same thing in production, and keeping the state here is what
/// lets each test below start from a clean slate.
fn report_refusal(reported: &Mutex<HashSet<u16>>, status: reqwest::StatusCode, url: &str) {
    let code = status.as_u16();
    let first_of_its_kind = reported.lock().unwrap().insert(code);
    if first_of_its_kind {
        tracing::warn!(
            status = code,
            url = %url,
            "cloud telemetry rejected by the control plane: this gateway's spend \
             is not reaching the org, and nothing else reports that. A 401 or 403 \
             means TOKENFUSE_CLOUD_KEY is wrong, rotated, or lacks the role \
             /v1/ingest requires. Further refusals with this status log at debug."
        );
    } else {
        tracing::debug!(
            status = code,
            "cloud telemetry rejected by the control plane"
        );
    }
}

/// Poll the control plane's per-run budget overrides and hand them to `apply`
/// (run id → µUSD), so an operator can set/tighten budgets centrally and every
/// gateway of the org enforces them. Best-effort; runs until the process exits.
///
/// Defensive against a `402` from any Cloud that still answers with one: the
/// entitlement gate this handled was removed from Cloud in v0.4.0, so on a
/// current deployment this branch never fires. It is kept because a gateway
/// may point at an older Cloud, and a crash there would be worse than a skip.
/// A non-2xx is treated as "no data this tick" (no crash, no apply); a `402` is
/// logged **once** at info and then skipped silently, so it never
/// spams the log every 3 s. The `200` path is unchanged.
pub fn spawn_budget_poller<F>(base: String, key: String, apply: F)
where
    F: Fn(std::collections::HashMap<String, i64>) + Send + Sync + 'static,
{
    let url = format!("{}/v1/budgets", base.trim_end_matches('/'));
    let client = reqwest::Client::new();
    tokio::spawn(async move {
        let mut tick = tokio::time::interval(std::time::Duration::from_secs(3));
        let mut plan_warned = false;
        loop {
            tick.tick().await;
            let resp = match client.get(&url).bearer_auth(&key).send().await {
                Ok(r) => r,
                Err(e) => {
                    tracing::debug!("cloud budget poll failed: {e}");
                    continue;
                }
            };
            if resp.status() == reqwest::StatusCode::PAYMENT_REQUIRED {
                if !plan_warned {
                    tracing::info!("cloud central-budget sync answered 402; skipping this tick");
                    plan_warned = true;
                }
                continue;
            }
            if !resp.status().is_success() {
                tracing::debug!("cloud budget poll: unexpected status {}", resp.status());
                continue;
            }
            let bytes = match resp.bytes().await {
                Ok(b) => b,
                Err(_) => continue,
            };
            if let Ok(map) =
                serde_json::from_slice::<std::collections::HashMap<String, i64>>(&bytes)
            {
                apply(map);
            }
        }
    });
}

/// Poll the control plane's per-UNIT monthly budget overrides and hand them to
/// `apply` (unit id → µUSD) as a full replacement map, so an operator can
/// centrally cap a business unit and every gateway of the org enforces it
/// (docs/20). A separate endpoint from `/v1/budgets` on purpose: that payload
/// is a flat `run_id -> i64` map old gateways parse verbatim, so it cannot
/// grow a nested key without breaking them. Best-effort; runs until the
/// process exits.
pub fn spawn_unit_budget_poller<F>(base: String, key: String, apply: F)
where
    F: Fn(std::collections::HashMap<String, i64>) + Send + Sync + 'static,
{
    let url = format!("{}/v1/unit-budgets", base.trim_end_matches('/'));
    let client = reqwest::Client::new();
    tokio::spawn(async move {
        let mut tick = tokio::time::interval(std::time::Duration::from_secs(3));
        loop {
            tick.tick().await;
            let resp = match client.get(&url).bearer_auth(&key).send().await {
                Ok(r) => r,
                Err(e) => {
                    tracing::debug!("cloud unit-budget poll failed: {e}");
                    continue;
                }
            };
            if !resp.status().is_success() {
                // Includes an older control plane without the endpoint (404):
                // no data this tick, never a crash.
                tracing::debug!(
                    "cloud unit-budget poll: unexpected status {}",
                    resp.status()
                );
                continue;
            }
            let bytes = match resp.bytes().await {
                Ok(b) => b,
                Err(_) => continue,
            };
            if let Ok(map) =
                serde_json::from_slice::<std::collections::HashMap<String, i64>>(&bytes)
            {
                apply(map);
            }
        }
    });
}

/// Poll the control plane's kill list and apply each killed run id locally, so an
/// operator's "Kill" in the Cloud dashboard propagates to every gateway of the
/// org (which then hard-stops that run — `402 killed`). Best-effort; runs until
/// the process exits.
///
/// Defensive against a `402` from any Cloud that still answers with one: the
/// entitlement gate this handled was removed from Cloud in v0.4.0, so on a
/// current deployment this branch never fires. It is kept because a gateway
/// may point at an older Cloud, and a crash there would be worse than a skip.
/// A non-2xx is treated as "no data this tick" (no crash, no apply); a `402` is
/// logged **once** at info and then skipped silently, so it never
/// spams the log every 3 s. The `200` path is unchanged.
pub fn spawn_kill_poller<F>(base: String, key: String, apply: F)
where
    F: Fn(&str) + Send + Sync + 'static,
{
    let url = format!("{}/v1/kills", base.trim_end_matches('/'));
    let client = reqwest::Client::new();
    tokio::spawn(async move {
        let mut tick = tokio::time::interval(std::time::Duration::from_secs(3));
        let mut plan_warned = false;
        loop {
            tick.tick().await;
            let resp = match client.get(&url).bearer_auth(&key).send().await {
                Ok(r) => r,
                Err(e) => {
                    tracing::debug!("cloud kill poll failed: {e}");
                    continue;
                }
            };
            if resp.status() == reqwest::StatusCode::PAYMENT_REQUIRED {
                if !plan_warned {
                    tracing::info!("cloud kill-switch sync answered 402; skipping this tick");
                    plan_warned = true;
                }
                continue;
            }
            if !resp.status().is_success() {
                tracing::debug!("cloud kill poll: unexpected status {}", resp.status());
                continue;
            }
            let bytes = match resp.bytes().await {
                Ok(b) => b,
                Err(_) => continue,
            };
            if let Ok(runs) = serde_json::from_slice::<Vec<String>>(&bytes) {
                for run in runs {
                    apply(&run);
                }
            }
        }
    });
}

#[cfg(test)]
mod tests {
    // Every test here holds `log_lock()` across awaits, which is exactly what
    // it is for: one shared log buffer, read by tests cargo runs in parallel.
    // The deadlock the lint guards against needs a second task on the SAME
    // runtime waiting for the same guard, and there is none. Each
    // `#[tokio::test]` gets its own runtime, so a test waiting here is a
    // blocked thread, not a stalled runtime that could starve the holder.
    #![allow(clippy::await_holding_lock)]

    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::{Arc, MutexGuard, OnceLock};

    /// The substring both halves of a refusal report carry: the first-of-its-
    /// kind warning and the quiet repeats after it. These tests match on it, so
    /// it is the one part of the message wording that is a contract.
    const REFUSAL: &str = "cloud telemetry rejected";

    // --- reading what an operator would actually see ----------------------
    //
    // The fault being fixed here is that a refused push produced NO observable
    // effect at all, which leaves the log as the only place a test can look.
    // These tests therefore capture the log rather than assert on a counter
    // added for their benefit: what is under test is exactly what an operator
    // reads, including the level it is written at.

    /// A `MakeWriter` that appends formatted tracing output to a shared buffer.
    #[derive(Clone)]
    struct Captured(Arc<Mutex<Vec<u8>>>);

    impl std::io::Write for Captured {
        fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
            self.0.lock().unwrap().extend_from_slice(buf);
            Ok(buf.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    impl<'a> tracing_subscriber::fmt::MakeWriter<'a> for Captured {
        type Writer = Captured;
        fn make_writer(&'a self) -> Self::Writer {
            self.clone()
        }
    }

    /// The one buffer, behind the process-wide default subscriber. It has to be
    /// global rather than per-test: `ship` does its work in a spawned task, so
    /// a thread-local subscriber set by the test's own thread would never see
    /// the line it is waiting for.
    fn captured_log() -> &'static Arc<Mutex<Vec<u8>>> {
        static BUF: OnceLock<Arc<Mutex<Vec<u8>>>> = OnceLock::new();
        BUF.get_or_init(|| {
            let buf = Arc::new(Mutex::new(Vec::new()));
            let subscriber = tracing_subscriber::fmt()
                .with_writer(Captured(Arc::clone(&buf)))
                .with_ansi(false)
                .with_max_level(tracing::Level::DEBUG)
                .finish();
            tracing::subscriber::set_global_default(subscriber).expect(
                "these assertions read the subscriber installed here, so nothing \
                 else in this test binary may install one first",
            );
            buf
        })
    }

    /// Serialises the tests that read the shared buffer. Cargo runs a binary's
    /// tests on parallel threads, and without this they would count each
    /// other's lines. Same reason, and the same shape, as the exporter tests in
    /// `crate::events`.
    fn log_lock() -> MutexGuard<'static, ()> {
        static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
        LOCK.get_or_init(|| Mutex::new(()))
            .lock()
            .unwrap_or_else(|e| e.into_inner())
    }

    fn clear_log() {
        captured_log().lock().unwrap().clear();
    }

    fn log_text() -> String {
        String::from_utf8_lossy(&captured_log().lock().unwrap()).into_owned()
    }

    /// The refusal lines the log carries at `level` (`"WARN"` or `"DEBUG"`).
    fn refusals_at<'a>(log: &'a str, level: &str) -> Vec<&'a str> {
        log.lines()
            .filter(|l| l.contains(level) && l.contains(REFUSAL))
            .collect()
    }

    // --- the stub control plane -------------------------------------------

    /// Answers `/v1/ingest` with `statuses` in order, repeating the last one
    /// once the list runs out, and counts what it received so a test can wait
    /// for the push to actually land rather than sleep a guess.
    async fn stub_control_plane(statuses: Vec<u16>) -> (String, Arc<AtomicUsize>) {
        use axum::{routing::post, Router};

        let received = Arc::new(AtomicUsize::new(0));
        let counter = Arc::clone(&received);
        let app = Router::new().route(
            "/v1/ingest",
            post(move |_body: axum::body::Bytes| {
                let statuses = statuses.clone();
                let counter = Arc::clone(&counter);
                async move {
                    let n = counter.fetch_add(1, Ordering::SeqCst);
                    let code = statuses.get(n).copied().unwrap_or_else(|| {
                        *statuses.last().expect("a stub needs at least one status")
                    });
                    axum::http::StatusCode::from_u16(code).unwrap()
                }
            }),
        );
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            let _ = axum::serve(listener, app).await;
        });
        (format!("http://{addr}"), received)
    }

    /// Poll until `done`, or give up loudly. Nothing here depends on a fixed
    /// sleep being long enough on a loaded machine.
    async fn wait_for(label: &str, mut done: impl FnMut() -> bool) {
        for _ in 0..300 {
            if done() {
                return;
            }
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        }
        panic!("timed out waiting for {label}");
    }

    fn one_record() -> CallRecord {
        CallRecord {
            ts_millis: 1_785_000_000_000,
            run_id: "run-1".into(),
            model: "gpt-4o".into(),
            decision: "allow".into(),
            input_tokens: 10,
            output_tokens: 20,
            cost_microusd: 300,
            step: 1,
            agent_id: String::new(),
            saved_microusd: 0,
            parent_run_id: String::new(),
            on_behalf_of: String::new(),
            outcome: String::new(),
            key_id: String::new(),
            unit: String::new(),
            tool_calls: None,
        }
    }

    /// Push one batch and wait until the stub has received `n` of them.
    async fn push_one(sink: &CloudSink, received: &Arc<AtomicUsize>, n: usize) {
        sink.record(one_record());
        sink.flush();
        wait_for(&format!("the control plane to receive batch {n}"), || {
            received.load(Ordering::SeqCst) >= n
        })
        .await;
    }

    // --- the tests ---------------------------------------------------------

    /// The fault this fix is about. `reqwest` returns `Ok(Response)` for a 403
    /// exactly as it does for a 200, so the old `if let Err(e) = send().await`
    /// arm never ran on a refusal: a control plane rejecting every batch looked,
    /// from inside the gateway and from the operator's log, identical to one
    /// accepting them, while the org's spend silently never arrived.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_refused_push_is_visible_to_the_operator() {
        let _g = log_lock();
        clear_log();

        let (base, received) = stub_control_plane(vec![403]).await;
        let sink = CloudSink::new(base, "a-key-without-the-role");
        push_one(&sink, &received, 1).await;

        wait_for("the refusal to reach the log", || {
            !refusals_at(&log_text(), "WARN").is_empty()
        })
        .await;

        let log = log_text();
        let warnings = refusals_at(&log, "WARN");
        assert_eq!(warnings.len(), 1, "one refusal, one warning:\n{log}");
        // The recorded field, not a bare "403": the message text names 401 and
        // 403 as the auth cases, so a substring match on the number alone would
        // hold even if the status were reported wrong.
        assert!(
            warnings[0].contains("status=403"),
            "the warning has to name the status the control plane gave, or it \
             cannot be acted on:\n{log}"
        );
    }

    /// The other half of the same decision, and the reason the level could be
    /// raised at all. A wrong key does not refuse one batch, it refuses every
    /// batch for as long as the gateway runs, so a warning per push would turn
    /// one configuration fault into per-batch log spam on the busiest
    /// deployments. Telemetry here is best-effort by design; it must not be
    /// able to shout down the log it shares with enforcement decisions.
    ///
    /// The repeats stay reported at debug rather than dropped: the count still
    /// matters to whoever is already looking.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_control_plane_that_refuses_every_batch_is_reported_once() {
        let _g = log_lock();
        clear_log();

        let (base, received) = stub_control_plane(vec![403]).await;
        let sink = CloudSink::new(base, "a-key-without-the-role");
        for n in 1..=3 {
            push_one(&sink, &received, n).await;
        }

        wait_for("all three refusals to be classified", || {
            refusals_at(&log_text(), "WARN").len() + refusals_at(&log_text(), "DEBUG").len() == 3
        })
        .await;

        let log = log_text();
        assert_eq!(
            refusals_at(&log, "WARN").len(),
            1,
            "three refused batches, one warning:\n{log}"
        );
        assert_eq!(
            refusals_at(&log, "DEBUG").len(),
            2,
            "the repeats stay visible at debug, they are not dropped:\n{log}"
        );
    }

    /// What keeps the suppression honest: it is per status, not per process.
    /// A key that starts failing differently, say a 403 that becomes a 500 when
    /// the control plane itself breaks, is new information and says so. This
    /// one passes before the gate exists as well as after; it is here so that
    /// tightening the gate to "warn once, ever" cannot pass unnoticed.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_second_distinct_status_is_reported_again() {
        let _g = log_lock();
        clear_log();

        let (base, received) = stub_control_plane(vec![403, 500]).await;
        let sink = CloudSink::new(base, "a-key-without-the-role");
        push_one(&sink, &received, 1).await;
        wait_for("the first refusal to reach the log", || {
            !refusals_at(&log_text(), "WARN").is_empty()
        })
        .await;
        push_one(&sink, &received, 2).await;
        wait_for("the second refusal to reach the log", || {
            refusals_at(&log_text(), "WARN").len() == 2
        })
        .await;

        let log = log_text();
        let warnings = refusals_at(&log, "WARN");
        assert_eq!(
            warnings.len(),
            2,
            "two distinct statuses, two warnings:\n{log}"
        );
        assert!(warnings[0].contains("status=403"), "{log}");
        assert!(warnings[1].contains("status=500"), "{log}");
    }

    /// The success path stays silent, at every level. It runs several times a
    /// second on a busy gateway, and a line per accepted batch would cost more
    /// than the fault this whole change exists to surface.
    ///
    /// The refusal that follows is what stops this passing vacuously: it proves
    /// the reporting path is alive in this test, so the silence about the 200 is
    /// the code's decision and not a broken capture.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn an_accepted_batch_is_never_reported() {
        let _g = log_lock();
        clear_log();

        let (base, received) = stub_control_plane(vec![200, 403]).await;
        let sink = CloudSink::new(base, "a-key-that-works");
        push_one(&sink, &received, 1).await;
        push_one(&sink, &received, 2).await;

        wait_for("the refusal to reach the log", || {
            !refusals_at(&log_text(), "WARN").is_empty()
        })
        .await;

        let log = log_text();
        let warnings = refusals_at(&log, "WARN");
        assert_eq!(
            warnings.len(),
            1,
            "only the refused batch is reported:\n{log}"
        );
        assert!(
            warnings[0].contains("status=403"),
            "and it is the refused batch, not the accepted one:\n{log}"
        );
        assert!(
            refusals_at(&log, "DEBUG").is_empty(),
            "an accepted batch is not reported at debug either:\n{log}"
        );
    }

    /// The boundary this fix deliberately did not cross, and this test is what
    /// holds it. A control plane that cannot be REACHED is a different fault
    /// from one that refuses: it is usually transient, it was already logged
    /// per attempt before this change, and it recovers without anybody editing
    /// configuration. It stays at debug.
    ///
    /// This one passes before the fix as well as after. It is here so that a
    /// later "make every failed push a warning" cannot pass unnoticed, which is
    /// the shape of change that turns best-effort telemetry into log spam.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_control_plane_that_cannot_be_reached_is_not_a_refusal() {
        let _g = log_lock();
        clear_log();

        // A port with nothing behind it: bind one, learn its number, drop it.
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        drop(listener);

        let sink = CloudSink::new(format!("http://{addr}"), "a-key-that-works");
        sink.record(one_record());
        sink.flush();

        wait_for("the unreachable push to be logged", || {
            log_text().contains("cloud telemetry push failed")
        })
        .await;

        let log = log_text();
        assert!(
            refusals_at(&log, "WARN").is_empty(),
            "nothing refused this push, so nothing may be reported as refused:\n{log}"
        );
    }
}
