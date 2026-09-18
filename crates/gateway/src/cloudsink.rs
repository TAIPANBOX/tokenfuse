//! `CloudSink`: ships settled-call telemetry to the TokenFuse Cloud control
//! plane, so many gateways roll up into one cross-fleet view.
//!
//! It batches records and POSTs them in the background so the request path is
//! never blocked on the network. A push the control plane cannot be REACHED
//! for is queued in memory, `QUEUE_CAP` records, oldest dropped first, and
//! replayed in order when it answers again (invariant 53); a push the control
//! plane REFUSES is dropped and reported once per status (invariant 13); a
//! restart loses the queue, and the local Parquet trace remains the source of
//! truth. Every record carries its unit's owner beside the trace's fields
//! (invariant 54). At startup the unit ledger's month is seeded from the same
//! control plane (`seed_unit_ledger`, invariant 52). Enable with
//! `TOKENFUSE_CLOUD_URL` + `TOKENFUSE_CLOUD_KEY`; composes with other sinks via
//! `TeeSink`.

use std::collections::{HashMap, HashSet, VecDeque};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use serde::Serialize;

use crate::sink::{CallRecord, EventSink};

/// How many records to buffer before an automatic flush.
const BATCH: usize = 20;

/// #294: how many records the retry queue holds while the control plane
/// cannot be reached, oldest dropped first past it. Read off `CallRecord`
/// (272 bytes of struct plus a run id, a model, a decision, an agent id, a
/// key id and a unit, about 0.5 KiB a record, 4.5 KiB with a 4 KiB chain):
/// about 5 MB at the cap, 45 MB if every row carried a full chain. In time:
/// 26 s at BENCHMARKS.md's 384 req/s ceiling on a 2 vCPU box against a 41 ms
/// mock, 100 s at 100 calls/s, 17 minutes at 10 calls/s, days at the
/// appliance run's rate (272 calls in a day). The 40 s outage of
/// tokenfuse#294 fits at up to 250 calls/s. A constant, not a variable: making
/// it one is a `components.json`, `tests/manifest.rs` and `compat/1.0.json`
/// decision that is not taken here.
const QUEUE_CAP: usize = 10_000;

/// #294: a push that gets no answer in this long is a transport failure and
/// is queued like a connection refused. Bounds how long the single drainer
/// can be held by a control plane that accepts a connection and says nothing;
/// without it that wait is the operating system's connect timeout, minutes.
const PUSH_TIMEOUT: Duration = Duration::from_secs(10);

/// The literal the control plane files unattributed spend under
/// (`crates/cloud/src/store.rs`, `units_at`/`owners`); never a unit here.
#[allow(dead_code)]
const UNASSIGNED: &str = "unassigned";

pub struct CloudSink {
    push: Arc<Pusher>,
    buf: Mutex<Vec<CallRecord>>,
    queue: Arc<Queue>,
    unit_owners: Arc<HashMap<String, String>>,
}

/// What one push needs, shared by the fast path and the drainer.
struct Pusher {
    url: String,
    key: String,
    client: reqwest::Client,
    /// Non-success statuses this sink has already warned about (invariant 13).
    reported: Mutex<HashSet<u16>>,
}

enum PushOutcome {
    Accepted,
    Refused(reqwest::StatusCode),
    /// `send()` returned `Err`: connection refused, reset, closed before the
    /// answer, DNS, or `PUSH_TIMEOUT` elapsed. The one kind that queues.
    Unreachable(reqwest::Error),
    Unencodable(serde_json::Error),
}

/// #294: records whose push never reached the control plane, oldest first.
struct Queue {
    records: Mutex<VecDeque<CallRecord>>,
    /// One drainer at a time.
    draining: AtomicBool,
    /// An outage is in progress: set by the first `Unreachable`, cleared when a
    /// drain empties the queue. Gates the once-per-outage lines.
    outage: AtomicBool,
    /// The first-drop warning of this outage was written.
    drop_warned: AtomicBool,
    /// Records the control plane accepted during this outage's drains.
    replayed: AtomicUsize,
    /// Records dropped at the cap during this outage.
    dropped: AtomicUsize,
}

impl Default for Queue {
    fn default() -> Self {
        Queue {
            records: Mutex::new(VecDeque::new()),
            draining: AtomicBool::new(false),
            outage: AtomicBool::new(false),
            drop_warned: AtomicBool::new(false),
            replayed: AtomicUsize::new(0),
            dropped: AtomicUsize::new(0),
        }
    }
}

/// One record on the wire: every `CallRecord` field as it is (the trace's
/// shape, invariant 6, frozen in `compat/1.0.json`) plus the unit's owner
/// beside them (#295). `flatten` is what keeps the sixteen where they are and
/// keeps `owner` off the Parquet row: the trace never sees this struct.
#[derive(Serialize)]
struct WireRecord<'a> {
    #[serde(flatten)]
    rec: &'a CallRecord,
    /// `units[].owner` for `rec.unit` from the identity map, `""` when the
    /// map is off, the call resolved to no unit, or the unit names nobody.
    owner: &'a str,
}

#[derive(Serialize)]
struct Batch<'a> {
    records: Vec<WireRecord<'a>>,
}

/// Every unit that names an owner, `unit -> owner`, taken from the identity
/// map once at startup (`IdentityMap::unit_owners`).
fn wire<'a>(records: &'a [CallRecord], owners: &'a HashMap<String, String>) -> Vec<WireRecord<'a>> {
    records
        .iter()
        .map(|rec| WireRecord {
            rec,
            owner: owners.get(&rec.unit).map(String::as_str).unwrap_or(""),
        })
        .collect()
}

impl CloudSink {
    /// `base` is the control plane's base URL (e.g. `http://control-plane:8080`);
    /// telemetry is POSTed to `{base}/v1/ingest`. `key` is the org API key.
    pub fn new(base: impl Into<String>, key: impl Into<String>) -> Self {
        Self::with_options(base, key, PUSH_TIMEOUT)
    }

    /// The one constructor; `new` is it with the production timeout. Tests
    /// shorten the timeout to prove the stall path without waiting 10 s.
    fn with_options(
        base: impl Into<String>,
        key: impl Into<String>,
        push_timeout: Duration,
    ) -> Self {
        let base = base.into();
        let url = format!("{}/v1/ingest", base.trim_end_matches('/'));
        let client = reqwest::Client::builder()
            .timeout(push_timeout)
            .build()
            .unwrap_or_else(|_| reqwest::Client::new());
        CloudSink {
            push: Arc::new(Pusher {
                url,
                key: key.into(),
                client,
                reported: Mutex::new(HashSet::new()),
            }),
            buf: Mutex::new(Vec::new()),
            queue: Arc::new(Queue::default()),
            unit_owners: Arc::new(HashMap::new()),
        }
    }

    /// Hand the sink the identity map's `unit -> owner` pairs (#295). Chainable,
    /// called once in `main.rs` before the sink is shared; a sink built without
    /// it pushes `owner: ""` on every record, which is what a gateway older
    /// than this field's reader is taken to mean.
    pub fn with_unit_owners(mut self, owners: HashMap<String, String>) -> Self {
        self.unit_owners = Arc::new(owners);
        self
    }

    /// Push a batch. While the queue holds anything, new batches go behind it so
    /// replay stays in order; otherwise one background task POSTs at once and a
    /// transport failure puts the batch at the FRONT of the queue (it was taken
    /// while the queue was empty, so before anything appended since). Nothing
    /// here awaits, nothing here touches the network.
    fn ship(&self, records: Vec<CallRecord>) {
        if records.is_empty() {
            return;
        }
        if self.queue.is_holding() {
            self.queue.push_back_capped(records);
            self.drain();
            return;
        }
        let (push, queue, owners) = (
            Arc::clone(&self.push),
            Arc::clone(&self.queue),
            Arc::clone(&self.unit_owners),
        );
        tokio::spawn(async move {
            match push.post(&records, &owners).await {
                PushOutcome::Accepted => {}
                PushOutcome::Unencodable(e) => {
                    tracing::debug!("cloud telemetry encode failed: {e}")
                }
                PushOutcome::Refused(status) => report_refusal(&push.reported, status, &push.url),
                PushOutcome::Unreachable(e) => {
                    tracing::debug!("cloud telemetry push failed: {e}");
                    queue.outage_began(&push.url, &e);
                    queue.push_front_capped(records);
                }
            }
        });
    }

    /// Replay the queue from the front, `BATCH` records a POST, one drainer at a
    /// time; stop at the first transport failure and put that chunk back at the
    /// front. Attempted on every `ship` and every `flush`, so the 2 s flush tick
    /// in `main.rs` is the retry cadence. A no-op when nothing is queued.
    fn drain(&self) {
        if !self.queue.is_holding() {
            return;
        }
        if self
            .queue
            .draining
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .is_err()
        {
            return;
        }
        let (push, queue, owners) = (
            Arc::clone(&self.push),
            Arc::clone(&self.queue),
            Arc::clone(&self.unit_owners),
        );
        tokio::spawn(async move {
            loop {
                let chunk = queue.pop_front_chunk(BATCH);
                if chunk.is_empty() {
                    break;
                }
                match push.post(&chunk, &owners).await {
                    PushOutcome::Accepted => {
                        queue.replayed.fetch_add(chunk.len(), Ordering::SeqCst);
                    }
                    PushOutcome::Unencodable(e) => {
                        tracing::debug!("cloud telemetry encode failed: {e}")
                    }
                    // Reached and refused: dropped and reported as today (invariant 13), the
                    // drain goes on because the control plane is answering.
                    PushOutcome::Refused(status) => {
                        report_refusal(&push.reported, status, &push.url)
                    }
                    PushOutcome::Unreachable(e) => {
                        tracing::debug!("cloud telemetry push failed: {e}");
                        queue.outage_began(&push.url, &e);
                        queue.push_front_capped(chunk);
                        break;
                    }
                }
            }
            if !queue.is_holding() {
                queue.outage_ended();
            }
            queue.draining.store(false, Ordering::Release);
            // A record appended between the last pop and this store waits for
            // the next ship or flush, at most one tick.
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

    #[cfg(test)]
    fn queued(&self) -> usize {
        self.queue.records.lock().unwrap().len()
    }
}

impl Pusher {
    async fn post(&self, records: &[CallRecord], owners: &HashMap<String, String>) -> PushOutcome {
        let payload = match serde_json::to_vec(&Batch {
            records: wire(records, owners),
        }) {
            Ok(p) => p,
            Err(e) => return PushOutcome::Unencodable(e),
        };
        let req = self
            .client
            .post(&self.url)
            .bearer_auth(&self.key)
            .header("content-type", "application/json")
            .body(payload);
        match req.send().await {
            Err(e) => PushOutcome::Unreachable(e),
            Ok(resp) if resp.status().is_success() => PushOutcome::Accepted,
            Ok(resp) => PushOutcome::Refused(resp.status()),
        }
    }
}

impl Queue {
    fn is_holding(&self) -> bool {
        !self.records.lock().unwrap().is_empty()
    }

    fn pop_front_chunk(&self, n: usize) -> Vec<CallRecord> {
        let mut q = self.records.lock().unwrap();
        let n = n.min(q.len());
        q.drain(..n).collect()
    }

    /// Append behind everything queued, then drop from the FRONT until the
    /// cap holds: the oldest records go first.
    fn push_back_capped(&self, records: Vec<CallRecord>) {
        let dropped = {
            let mut q = self.records.lock().unwrap();
            q.extend(records);
            Self::truncate_front(&mut q)
        };
        self.note_dropped(dropped);
    }

    /// Put a failed chunk back where it came from, its order kept, then the
    /// same truncation: past the cap the returning chunk's own head is the
    /// oldest and goes first.
    fn push_front_capped(&self, records: Vec<CallRecord>) {
        let dropped = {
            let mut q = self.records.lock().unwrap();
            for r in records.into_iter().rev() {
                q.push_front(r);
            }
            Self::truncate_front(&mut q)
        };
        self.note_dropped(dropped);
    }

    fn truncate_front(q: &mut VecDeque<CallRecord>) -> usize {
        let mut dropped = 0;
        while q.len() > QUEUE_CAP {
            q.pop_front();
            dropped += 1;
        }
        dropped
    }

    /// The transition into an outage: one WARN, then every failed attempt of
    /// the same outage stays at debug (the per-attempt line `ship` and `drain`
    /// already write), the once-per-kind shape invariant 13 set.
    fn outage_began(&self, url: &str, error: &reqwest::Error) {
        if self.outage.swap(true, Ordering::SeqCst) {
            return;
        }
        self.drop_warned.store(false, Ordering::SeqCst);
        self.replayed.store(0, Ordering::SeqCst);
        self.dropped.store(0, Ordering::SeqCst);
        tracing::warn!(
            url = %url,
            cap = QUEUE_CAP,
            error = ?error,
            "cloud telemetry cannot reach the control plane: records are queued in memory, \
             oldest dropped first past the cap, and replayed in order when it answers again; \
             said once per outage, each failed attempt logs at debug"
        );
    }

    /// The queue is empty again after an outage: one INFO with the two counts.
    fn outage_ended(&self) {
        if !self.outage.swap(false, Ordering::SeqCst) {
            return;
        }
        tracing::info!(
            replayed = self.replayed.swap(0, Ordering::SeqCst),
            dropped = self.dropped.swap(0, Ordering::SeqCst),
            "cloud telemetry queue drained: the control plane is reachable again; the records \
             queued while it was not have been replayed in order, less those the cap dropped"
        );
    }

    fn note_dropped(&self, n: usize) {
        if n == 0 {
            return;
        }
        let total = self.dropped.fetch_add(n, Ordering::SeqCst) + n;
        if !self.drop_warned.swap(true, Ordering::SeqCst) {
            tracing::warn!(
                cap = QUEUE_CAP,
                dropped = total,
                "cloud telemetry queue is full: the oldest records are being dropped while the \
                 control plane is unreachable; said once per outage, further drops log at debug"
            );
        } else {
            tracing::debug!(
                dropped = total,
                "cloud telemetry queue is full, dropped {n} more"
            );
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
        self.drain();
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
    use crate::testlog::{captured_log, log_lock};
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Arc;

    /// The substring both halves of a refusal report carry: the first-of-its-
    /// kind warning and the quiet repeats after it. These tests match on it, so
    /// it is the one part of the message wording that is a contract.
    const REFUSAL: &str = "cloud telemetry rejected";
    /// #294: the once-per-outage transition lines.
    const QUEUED: &str = "cloud telemetry cannot reach the control plane";
    const DROPPING: &str = "cloud telemetry queue is full";
    const DRAINED: &str = "cloud telemetry queue drained";

    // --- reading what an operator would actually see ----------------------
    //
    // The fault being fixed here is that a refused push produced NO observable
    // effect at all, which leaves the log as the only place a test can look.
    // These tests therefore capture the log rather than assert on a counter
    // added for their benefit: what is under test is exactly what an operator
    // reads, including the level it is written at.

    fn clear_log() {
        captured_log().lock().unwrap().clear();
    }

    fn log_text() -> String {
        String::from_utf8_lossy(&captured_log().lock().unwrap()).into_owned()
    }

    /// The refusal lines the log carries at `level` (`"WARN"` or `"DEBUG"`).
    fn refusals_at<'a>(log: &'a str, level: &str) -> Vec<&'a str> {
        lines_at(log, level, REFUSAL)
    }

    /// The lines the log carries at `level` containing `needle`. `refusals_at`
    /// is this, pinned to `REFUSAL`; the #294 tests need the same shape for
    /// `QUEUED` and `DROPPING`.
    fn lines_at<'a>(log: &'a str, level: &str, needle: &str) -> Vec<&'a str> {
        log.lines()
            .filter(|l| l.contains(level) && l.contains(needle))
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

    // --- the owner rides the wire (#295) ------------------------------------

    #[test]
    fn the_wire_record_carries_the_units_owner_beside_every_existing_field() {
        let mut r = one_record();
        r.unit = "treasury".into();
        let owners = HashMap::from([(
            "treasury".to_string(),
            "user://bank.example/olena".to_string(),
        )]);
        let v = serde_json::to_value(Batch {
            records: wire(&[r.clone()], &owners),
        })
        .unwrap();
        let rec = v["records"][0].as_object().unwrap();
        assert_eq!(rec.len(), 17, "sixteen record fields plus owner: {rec:?}");
        assert_eq!(rec["owner"], "user://bank.example/olena");

        // Every field the plain record serialises to must survive the
        // flatten unchanged, `tool_calls: null` included.
        let plain = serde_json::to_value(&r).unwrap();
        let plain = plain.as_object().unwrap();
        assert_eq!(plain.len(), 16);
        for (k, val) in plain {
            assert_eq!(&rec[k], val, "field {k} must survive the flatten unchanged");
        }
    }

    #[test]
    fn a_unit_without_an_owner_and_a_record_without_a_unit_carry_an_empty_owner() {
        let owners = HashMap::from([(
            "treasury".to_string(),
            "user://bank.example/olena".to_string(),
        )]);

        // A unit the owners map names nobody for.
        let mut lending = one_record();
        lending.unit = "lending".into();
        let v = serde_json::to_value(Batch {
            records: wire(&[lending], &owners),
        })
        .unwrap();
        let rec = v["records"][0].as_object().unwrap();
        assert_eq!(rec.len(), 17);
        assert_eq!(rec["owner"], "");

        // A record that resolved to no unit at all.
        let mut no_unit = one_record();
        no_unit.unit = String::new();
        let v = serde_json::to_value(Batch {
            records: wire(&[no_unit], &owners),
        })
        .unwrap();
        let rec = v["records"][0].as_object().unwrap();
        assert_eq!(rec.len(), 17);
        assert_eq!(rec["owner"], "");
    }

    // --- the retry queue (#294): a controllable control plane ---------------
    //
    // A raw TCP accept loop, not axum, because a transport failure (the
    // connection closed before any answer) cannot be produced by a handler,
    // and adding hyper/hyper-util as dev-dependencies for one stub is the
    // escalation this repository avoids.

    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    enum Plane {
        /// Accept the connection and close it at once: `send()` returns `Err`.
        Down,
        /// Accept and hold the socket open, never answering, until the test ends.
        Stall,
        /// Read one HTTP/1.1 request, keep its body, answer `200` with
        /// `connection: close` so the client pools nothing.
        Up,
    }

    #[derive(serde::Deserialize)]
    struct ReceivedRecord {
        run_id: String,
    }

    #[derive(serde::Deserialize)]
    struct ReceivedBatch {
        records: Vec<ReceivedRecord>,
    }

    #[derive(Clone)]
    struct Toggle {
        mode: Arc<Mutex<Plane>>,
        /// Every accepted request body, in arrival order.
        bodies: Arc<Mutex<Vec<Vec<u8>>>>,
        /// `Up` answers this many requests, then flips itself to `Down`;
        /// `usize::MAX` means forever.
        up_for: Arc<AtomicUsize>,
    }

    impl Toggle {
        /// Set the mode directly; always means "answer forever" for `Up`,
        /// resetting whatever `up_for` count a previous transition left.
        fn set(&self, mode: Plane) {
            self.up_for.store(usize::MAX, Ordering::SeqCst);
            *self.mode.lock().unwrap() = mode;
        }

        /// `Up` for exactly `n` accepted connections, then `Down`.
        fn up_for(&self, n: usize) {
            self.up_for.store(n, Ordering::SeqCst);
            *self.mode.lock().unwrap() = Plane::Up;
        }

        /// `run_id` of every record received, in arrival order, batch after batch.
        fn received_run_ids(&self) -> Vec<String> {
            self.bodies
                .lock()
                .unwrap()
                .iter()
                .flat_map(|body| {
                    let batch: ReceivedBatch =
                        serde_json::from_slice(body).unwrap_or(ReceivedBatch { records: vec![] });
                    batch.records.into_iter().map(|r| r.run_id)
                })
                .collect()
        }
    }

    async fn toggle_control_plane(initial: Plane) -> (String, Toggle) {
        let toggle = Toggle {
            mode: Arc::new(Mutex::new(initial)),
            bodies: Arc::new(Mutex::new(Vec::new())),
            up_for: Arc::new(AtomicUsize::new(usize::MAX)),
        };
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let t = toggle.clone();
        tokio::spawn(async move {
            loop {
                let (mut sock, _) = match listener.accept().await {
                    Ok(pair) => pair,
                    Err(_) => break,
                };
                let mode = *t.mode.lock().unwrap();
                match mode {
                    Plane::Down => drop(sock),
                    Plane::Stall => {
                        tokio::spawn(async move {
                            tokio::time::sleep(Duration::from_secs(60)).await;
                            drop(sock);
                        });
                    }
                    Plane::Up => {
                        let t2 = t.clone();
                        tokio::spawn(async move {
                            use tokio::io::{AsyncReadExt, AsyncWriteExt};
                            let mut buf = Vec::new();
                            let mut byte = [0u8; 1];
                            loop {
                                if sock.read_exact(&mut byte).await.is_err() {
                                    return;
                                }
                                buf.push(byte[0]);
                                if buf.len() >= 4 && &buf[buf.len() - 4..] == b"\r\n\r\n" {
                                    break;
                                }
                            }
                            let header = String::from_utf8_lossy(&buf);
                            let len: usize = header
                                .lines()
                                .find_map(|l| {
                                    let (name, value) = l.split_once(':')?;
                                    if name.trim().eq_ignore_ascii_case("content-length") {
                                        value.trim().parse().ok()
                                    } else {
                                        None
                                    }
                                })
                                .unwrap_or(0);
                            let mut body = vec![0u8; len];
                            if sock.read_exact(&mut body).await.is_err() {
                                return;
                            }
                            t2.bodies.lock().unwrap().push(body);
                            let _ = sock
                                .write_all(
                                    b"HTTP/1.1 200 OK\r\ncontent-length: 0\r\nconnection: close\r\n\r\n",
                                )
                                .await;
                            let _ = sock.shutdown().await;
                            if t2.up_for.load(Ordering::SeqCst) != usize::MAX {
                                let prev = t2.up_for.fetch_sub(1, Ordering::SeqCst);
                                if prev == 1 {
                                    t2.set(Plane::Down);
                                }
                            }
                        });
                    }
                }
            }
        });
        (format!("http://{addr}"), toggle)
    }

    /// `one_record()` with `run_id` replaced.
    fn record_named(run_id: &str) -> CallRecord {
        let mut r = one_record();
        r.run_id = run_id.to_string();
        r
    }

    /// `wait_for` with 3 000 polls (30 s), for the cap test's 500 POSTs.
    async fn wait_long(label: &str, mut done: impl FnMut() -> bool) {
        for _ in 0..3_000 {
            if done() {
                return;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        panic!("timed out waiting for {label}");
    }

    // --- the retry queue (#294): the tests -----------------------------------
    //
    // Determinism rule for order: cause the outage with ONE batch and wait
    // for `queued() == BATCH` before pushing the batches whose order is
    // asserted; those append in order.

    /// tokenfuse#294's own shape: nothing pushed during an outage may be lost,
    /// and it must arrive in the order it was recorded once the plane answers
    /// again.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn records_pushed_during_an_outage_arrive_in_order_after_recovery() {
        let _g = log_lock();
        clear_log();

        let (base, toggle) = toggle_control_plane(Plane::Down).await;
        let sink = CloudSink::new(base, "k");

        let mut expected = Vec::new();
        for i in 1..=20 {
            let id = format!("b1-{i:02}");
            sink.record(record_named(&id));
            expected.push(id);
        }
        sink.flush();
        wait_for("the first batch to queue", || sink.queued() == 20).await;

        for prefix in ["b2", "b3"] {
            for i in 1..=20 {
                let id = format!("{prefix}-{i:02}");
                sink.record(record_named(&id));
                expected.push(id);
            }
            sink.flush();
        }
        wait_for("all three batches to queue", || sink.queued() == 60).await;
        assert!(
            toggle.bodies.lock().unwrap().is_empty(),
            "nothing must have reached the plane while it is down"
        );
        wait_for("the queued warning to reach the log", || {
            log_text().contains(QUEUED)
        })
        .await;
        assert_eq!(
            lines_at(&log_text(), "WARN", QUEUED).len(),
            1,
            "{}",
            log_text()
        );

        toggle.set(Plane::Up);
        sink.flush();
        wait_for("every record to arrive", || {
            toggle.received_run_ids().len() == 60
        })
        .await;
        assert_eq!(toggle.received_run_ids(), expected);

        wait_for("the drained line", || log_text().contains(DRAINED)).await;
        let log = log_text();
        let drained = log.lines().find(|l| l.contains(DRAINED)).unwrap();
        assert!(drained.contains("replayed=60"), "{drained}");
        assert!(drained.contains("dropped=0"), "{drained}");
        assert_eq!(sink.queued(), 0);
        assert!(
            refusals_at(&log, "WARN").is_empty(),
            "nothing was ever refused: {log}"
        );
    }

    /// The transition is said once per outage, not once per failed attempt,
    /// and a later, separate outage is said again.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn one_transition_line_per_outage() {
        let _g = log_lock();
        clear_log();

        let (base, toggle) = toggle_control_plane(Plane::Down).await;
        let sink = CloudSink::new(base, "k");

        for i in 1..=20 {
            sink.record(record_named(&format!("t1-{i:02}")));
        }
        sink.flush();
        wait_for("the first batch to queue", || sink.queued() == 20).await;
        assert_eq!(lines_at(&log_text(), "WARN", QUEUED).len(), 1);

        // Wait for each attempt to actually finish (the debug line count to
        // grow) before pushing the next: two flushes fired back to back with
        // no yield in between would both see `draining` already held by the
        // first and collapse into a single drain attempt, which is not what
        // "two more flush() each with one fresh record" is testing.
        for (i, want) in [(0, 2usize), (1, 3)] {
            sink.record(record_named(&format!("extra-{i}")));
            sink.flush();
            wait_for(&format!("{want} debug push-failed lines"), || {
                log_text()
                    .lines()
                    .filter(|l| l.contains("DEBUG") && l.contains("cloud telemetry push failed"))
                    .count()
                    == want
            })
            .await;
        }
        assert_eq!(lines_at(&log_text(), "WARN", QUEUED).len(), 1);

        toggle.set(Plane::Up);
        sink.flush();
        wait_for("the queue to drain", || log_text().contains(DRAINED)).await;

        toggle.set(Plane::Down);
        sink.record(record_named("after-recovery"));
        sink.flush();
        wait_for("a fourth debug push-failed line", || {
            log_text()
                .lines()
                .filter(|l| l.contains("DEBUG") && l.contains("cloud telemetry push failed"))
                .count()
                == 4
        })
        .await;
        assert_eq!(lines_at(&log_text(), "WARN", QUEUED).len(), 2);
    }

    /// A full queue drops the oldest records, and says so once, at the real
    /// cap (10 000), not a scaled-down stand-in.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn the_cap_drops_the_oldest_and_says_so_once() {
        let _g = log_lock();
        clear_log();

        let (base, toggle) = toggle_control_plane(Plane::Down).await;
        let sink = CloudSink::new(base, "k");

        for i in 1..=20 {
            sink.record(record_named(&format!("r{i:05}")));
        }
        sink.flush();
        wait_for("the first batch to queue", || sink.queued() == 20).await;

        let mut i = 21;
        while i <= 10_025 {
            let end = (i + 19).min(10_025);
            for n in i..=end {
                sink.record(record_named(&format!("r{n:05}")));
            }
            sink.flush();
            i = end + 1;
        }
        wait_long("the queue to settle at the cap", || {
            sink.queued() == QUEUE_CAP
        })
        .await;
        // The 500-odd concurrent drain attempts this loop provoked (each one
        // popping the front chunk, failing, and pushing it back) are still
        // settling in the background; give the last of them time to log
        // before reading what they wrote.
        wait_long("a debug-level drop past the first warning", || {
            !lines_at(&log_text(), "DEBUG", DROPPING).is_empty()
        })
        .await;

        {
            let log = log_text();
            let dropping_warns = lines_at(&log, "WARN", DROPPING);
            assert_eq!(dropping_warns.len(), 1, "one warning for the outage: {log}");
            assert!(dropping_warns[0].contains("cap=10000"), "{log}");
        }

        toggle.up_for(usize::MAX);
        sink.flush();
        wait_long("all 10 000 surviving records to arrive", || {
            toggle.received_run_ids().len() == 10_000
        })
        .await;

        let received = toggle.received_run_ids();
        assert_eq!(received.first().unwrap(), "r00026");
        assert_eq!(received.last().unwrap(), "r10025");
        assert!(
            received.windows(2).all(|w| w[0] < w[1]),
            "must arrive strictly in order"
        );

        wait_for("the drained line", || log_text().contains(DRAINED)).await;
        let log = log_text();
        let drained = log.lines().find(|l| l.contains(DRAINED)).unwrap();
        assert!(drained.contains("replayed=10000"), "{drained}");
        assert!(drained.contains("dropped=25"), "{drained}");
    }

    /// The invariant-13 boundary, restated against the restructured sink: a
    /// status answer is a refusal and is never queued.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_refusal_is_never_queued() {
        let _g = log_lock();
        clear_log();

        let (base, received) = stub_control_plane(vec![403]).await;
        let sink = CloudSink::new(base, "a-key-without-the-role");
        push_one(&sink, &received, 1).await;
        push_one(&sink, &received, 2).await;

        // The stub's own counter (what `push_one` waits on) advances as soon
        // as the SERVER has the request, which can be a hair before the
        // CLIENT's `send().await` resolves and the `Refused` arm runs; wait
        // for that arm's own observable effect (the log line) before reading
        // what it did to the queue, or this is racy against its own mutant.
        wait_for("the refusal to reach the log", || {
            !refusals_at(&log_text(), "WARN").is_empty()
        })
        .await;
        assert_eq!(sink.queued(), 0);
        let log = log_text();
        assert_eq!(refusals_at(&log, "WARN").len(), 1, "{log}");
        assert!(
            !log.contains(QUEUED),
            "a refusal must never be reported as an outage: {log}"
        );
    }

    /// A push that gets no answer at all is bounded by `PUSH_TIMEOUT` rather
    /// than hanging on the operating system's connect timeout, and once it
    /// times out it is queued exactly like a connection refused.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_push_that_never_gets_an_answer_is_bounded_and_queued() {
        let _g = log_lock();
        clear_log();

        let (base, toggle) = toggle_control_plane(Plane::Stall).await;
        let sink = CloudSink::with_options(base, "k", Duration::from_millis(200));

        sink.record(record_named("stalled-1"));
        sink.flush();
        wait_for("the timed-out push to queue", || sink.queued() == 1).await;

        wait_for("the queued warning to reach the log", || {
            log_text().contains(QUEUED)
        })
        .await;
        let log = log_text();
        let warn = log
            .lines()
            .find(|l| l.contains("WARN") && l.contains(QUEUED))
            .unwrap_or_else(|| panic!("no QUEUED warning: {log}"));
        assert!(warn.contains("error="), "{warn}");
        assert!(
            warn.to_lowercase().contains("time"),
            "the warning must name a timeout: {warn}"
        );

        toggle.set(Plane::Up);
        sink.flush();
        wait_for("the body to arrive", || {
            !toggle.bodies.lock().unwrap().is_empty()
        })
        .await;
        wait_for("the drained line", || log_text().contains(DRAINED)).await;
        let log = log_text();
        let drained = log.lines().find(|l| l.contains(DRAINED)).unwrap();
        assert!(drained.contains("replayed=1"), "{drained}");
    }

    /// A relapse mid-replay keeps what is left, in order, for the next attempt.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_drain_that_fails_midway_keeps_the_rest_in_order() {
        let _g = log_lock();
        clear_log();

        let (base, toggle) = toggle_control_plane(Plane::Down).await;
        let sink = CloudSink::new(base, "k");

        let mut expected = Vec::new();
        for i in 1..=20 {
            let id = format!("a-{i:02}");
            sink.record(record_named(&id));
            expected.push(id);
        }
        sink.flush();
        wait_for("batch A to queue", || sink.queued() == 20).await;

        for prefix in ["b", "c"] {
            for i in 1..=20 {
                let id = format!("{prefix}-{i:02}");
                sink.record(record_named(&id));
                expected.push(id);
            }
            sink.flush();
        }
        wait_for("batches B and C to queue", || sink.queued() == 60).await;

        toggle.up_for(1);
        sink.flush();
        wait_for("batch A's ids to arrive", || {
            toggle.received_run_ids().len() == 20
        })
        .await;
        assert_eq!(toggle.received_run_ids(), expected[..20].to_vec());
        wait_for("B and C to be back in the queue", || sink.queued() == 40).await;
        assert!(
            !log_text().contains(DRAINED),
            "the plane went back down before the queue emptied: {}",
            log_text()
        );

        toggle.set(Plane::Up);
        sink.flush();
        wait_for("all 60 to arrive in order", || {
            toggle.received_run_ids().len() == 60
        })
        .await;
        assert_eq!(toggle.received_run_ids(), expected);

        wait_for("the drained line", || log_text().contains(DRAINED)).await;
        let log = log_text();
        let drained = log.lines().find(|l| l.contains(DRAINED)).unwrap();
        assert!(drained.contains("replayed=60"), "{drained}");
    }

    /// The guard that the restructure did not put an await on the request
    /// path: `record`/`flush` must return long before a 10 s stall resolves.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn record_and_flush_return_without_waiting_for_the_control_plane() {
        let (base, _toggle) = toggle_control_plane(Plane::Stall).await;
        let sink = Arc::new(CloudSink::new(base, "k"));

        let s = Arc::clone(&sink);
        let handle = tokio::task::spawn_blocking(move || {
            for i in 0..45 {
                s.record(record_named(&format!("blocking-{i}")));
            }
            s.flush();
            s.flush();
        });

        tokio::time::timeout(Duration::from_secs(2), handle)
            .await
            .expect("the request path waited for the control plane")
            .unwrap();

        assert_eq!(
            sink.queued(),
            0,
            "the stalled pushes are in flight in the background, not failed yet"
        );
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
    ///
    /// Since invariant 53 the first unreachable push of an outage writes the
    /// queue's own warning, which is not a refusal and is not counted here;
    /// the attempts themselves still log at debug, which is what this waits on.
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
