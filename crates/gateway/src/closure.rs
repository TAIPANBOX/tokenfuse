//! D8, the gateway side: a person closes one retained reservation (invariant 50, D7) with
//! evidence, and nothing else does.
//!
//! `@decided 2026-10-11` fixes who and what: closing is a person's act, taken with a passkey
//! signature in the operator console; the console mints a short-lived token bound to one
//! reservation id and its revision only after that assertion; the gateway verifies the token
//! with a secret it shares with the console and refuses a stale revision. A closure is observed
//! (the usage the provider returned, or the covering invoice line) or no-charge (the provider
//! confirms nothing was billed). Nothing here releases a reservation on a timer, settles one at
//! the estimate by default, or takes an administrative adjustment.
//!
//! **The token** is `v1.<reservation id>.<revision>.<expiry>.<signature>`: the id in decimal,
//! the revision as the 16 lowercase hex digits `GET /v1/retained` lists, the expiry in Unix
//! milliseconds, and the signature the lowercase hex HMAC-SHA256, under
//! `TOKENFUSE_CLOSURE_SECRET`, of `tokenfuse-closure-v1\n<id>\n<revision>\n<expiry>`. It rides
//! in [`TOKEN_HEADER`], not `Authorization`, because the admin gate (invariant 41) already
//! reads that header for its own bearer key and both may be required at once. The signature
//! is checked before anything else is read from the token, in constant time; a token that
//! expires more than [`MAX_TOKEN_TTL_MILLIS`] from now is refused as not short-lived, so a
//! console bug that mints a year-long token is a refusal rather than a standing credential.
//!
//! **Effects, exactly once.** The entry is taken out of the registry under one lock, so two
//! closures cannot both take it; the closure record is appended to the retained journal and
//! synced BEFORE either ledger moves, so a crash between the two leaves the reservation closed
//! on disk and the next start does not restore it; then the run half is settled on the chain
//! it was admitted against (`LedgerBackend::settle`, invariant 49's exactly-once behind it)
//! and the unit half in its own window. Observed settles at the given cost, no-charge at zero.
//!
//! **Idempotency.** An operation id that already closed something answers the recorded
//! result when the request carries the same content, and `409 closure_conflict` with nothing
//! changed when it does not. A different operation id for a reservation already closed is
//! `409 already_closed`. The books live in this process, and startup loads the closures the
//! journal still holds, so a retry answers across one restart; the startup rewrite then drops
//! them with the records they closed (D-3), and a retry across a second restart answers
//! `404 not_retained`, never a second charge.
//!
//! **Spend reaches the Cloud (D8.1).** An observed closure writes the `allow` row a settled
//! call writes (`settle::allow_record`), through the same sink, so the Parquet trace and, in
//! Cloud mode, the control plane see the observed cost, and the run and unit seeds a restarted
//! gateway takes from the Cloud (invariants 70 and 52) include it. One row per closure: it is
//! written on the first application only, never on a replay. A no-charge closure writes none.
//!
//! **On the event stream (D10, invariant 90).** One `retained_closed` (high) per closure
//! applied, written after the closure record is synced and the money settled, under the
//! `agent_id` the journal recorded for the call (D8.1); a record journaled before that carries
//! none, and its event is skipped and counted (SPEC 6.1 forbids inventing one). A refusal and a
//! replay of an applied operation write none. Who closed it is not on the event: the gateway
//! verifies a token, not a person, and the console's own record names the person.

use crate::events::EventType;
use crate::retainedjournal::{ClosureRecord, KIND_CLOSURE};
use crate::state::AppState;
use axum::body::Bytes;
use axum::extract::State;
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::Json;
use hmac::{Hmac, Mac};
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use std::collections::HashMap;
use std::sync::Mutex;
use tokenfuse_core::Microusd;

/// The variable that turns the route on and holds the shared secret.
pub const SECRET_ENV: &str = "TOKENFUSE_CLOSURE_SECRET";
/// The request header that carries the closure token.
pub const TOKEN_HEADER: &str = "x-fuse-closure-token";
/// The shortest secret accepted: 32 bytes, the HMAC-SHA256 output size.
pub const MIN_SECRET_BYTES: usize = 32;
/// The longest a token may live, measured from the moment it is presented.
pub const MAX_TOKEN_TTL_MILLIS: i64 = 300_000;
/// Bounds on caller-chosen strings, which reach the journal and the log.
pub const MAX_OPERATION_ID_BYTES: usize = 128;
pub const MAX_EVIDENCE_REF_BYTES: usize = 512;
const MAX_TOKEN_BYTES: usize = 256;
const MAC_DOMAIN: &str = "tokenfuse-closure-v1";

/// The two forms a closure may take (`@decided 2026-10-11`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EvidenceKind {
    /// The provider's returned usage, or the invoice line covering the call: settles at
    /// `observed_microusd`.
    Observed,
    /// The provider confirms nothing was billed: releases at zero.
    NoCharge,
}

impl EvidenceKind {
    fn as_str(self) -> &'static str {
        match self {
            EvidenceKind::Observed => "observed",
            EvidenceKind::NoCharge => "no_charge",
        }
    }
}

/// `POST /v1/retained/close`. Unknown fields are refused, so a misspelt member is never
/// silently read as absent.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CloseRequest {
    pub reservation_id: u64,
    pub expected_revision: String,
    pub operation_id: String,
    pub evidence_kind: EvidenceKind,
    #[serde(default)]
    pub observed_microusd: Option<i64>,
    pub evidence_ref: String,
}

/// What an operation id is bound to: the request content that closed something.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Content {
    reservation_id: u64,
    revision: String,
    evidence_kind: String,
    observed_microusd: Option<i64>,
    evidence_ref: String,
}

impl Content {
    fn of(req: &CloseRequest) -> Self {
        Content {
            reservation_id: req.reservation_id,
            revision: req.expected_revision.clone(),
            evidence_kind: req.evidence_kind.as_str().into(),
            observed_microusd: req.observed_microusd,
            evidence_ref: req.evidence_ref.clone(),
        }
    }
    fn of_record(c: &ClosureRecord) -> Self {
        Content {
            reservation_id: c.reservation_id,
            revision: c.revision.clone(),
            evidence_kind: c.evidence_kind.clone(),
            observed_microusd: c.observed_microusd,
            evidence_ref: c.evidence_ref.clone(),
        }
    }
}

#[derive(Debug, Default)]
struct Books {
    /// Operation id to the content it closed with and the record it wrote.
    by_operation: HashMap<String, (Content, ClosureRecord)>,
    /// (reservation id, revision) to the operation id that closed it.
    closed: HashMap<(u64, String), String>,
}

impl Books {
    fn note(&mut self, record: &ClosureRecord) {
        self.closed.insert(
            (record.reservation_id, record.revision.clone()),
            record.operation_id.clone(),
        );
        self.by_operation.insert(
            record.operation_id.clone(),
            (Content::of_record(record), record.clone()),
        );
    }
}

/// The closure route's configuration and books, present only when [`SECRET_ENV`] is set.
pub struct ClosureDoor {
    secret: Vec<u8>,
    books: Mutex<Books>,
}

impl std::fmt::Debug for ClosureDoor {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ClosureDoor").finish_non_exhaustive()
    }
}

/// Why a token was refused. Deliberately coarse: the caller learns expired or not, never which
/// part of an invalid token was wrong.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TokenError {
    Invalid,
    Expired,
}

impl ClosureDoor {
    pub fn new(secret: &[u8]) -> Self {
        ClosureDoor {
            secret: secret.to_vec(),
            books: Mutex::new(Books::default()),
        }
    }

    /// `None` (the route is off) when unset or empty; an error naming the variable when set
    /// and shorter than [`MIN_SECRET_BYTES`], so a secret nobody could rely on stops the
    /// gateway rather than serving a weak door.
    pub fn from_value(value: Option<&str>) -> Result<Option<Self>, String> {
        match value {
            None | Some("") => Ok(None),
            Some(s) if s.len() < MIN_SECRET_BYTES => Err(format!(
                "{SECRET_ENV} is set but is {} bytes; it must be at least {MIN_SECRET_BYTES} bytes, or unset to turn the closure route off",
                s.len()
            )),
            Some(s) => Ok(Some(ClosureDoor::new(s.as_bytes()))),
        }
    }

    pub fn from_env() -> Result<Option<Self>, String> {
        ClosureDoor::from_value(std::env::var(SECRET_ENV).ok().as_deref())
    }

    /// Load closures a previous process recorded, so their operation ids answer again.
    pub fn remember(&self, closures: &[ClosureRecord]) {
        let mut books = self.books.lock().unwrap_or_else(|p| p.into_inner());
        for c in closures {
            books.note(c);
        }
    }

    /// Check a token's signature, then its expiry, and return the id and revision it binds.
    pub fn verify(&self, token: &str, now_millis: i64) -> Result<(u64, String), TokenError> {
        if token.len() > MAX_TOKEN_BYTES {
            return Err(TokenError::Invalid);
        }
        let parts: Vec<&str> = token.split('.').collect();
        let [version, id, revision, exp, sig] = parts.as_slice() else {
            return Err(TokenError::Invalid);
        };
        if *version != "v1" || !is_decimal(id) || !is_decimal(exp) || !is_revision(revision) {
            return Err(TokenError::Invalid);
        }
        let Some(sig) = decode_hex(sig).filter(|s| s.len() == 32) else {
            return Err(TokenError::Invalid);
        };
        let mut mac = self.mac();
        mac.update(message(id, revision, exp).as_bytes());
        mac.verify_slice(&sig).map_err(|_| TokenError::Invalid)?;
        let (Ok(id), Ok(exp)) = (id.parse::<u64>(), exp.parse::<i64>()) else {
            return Err(TokenError::Invalid);
        };
        if exp <= now_millis {
            return Err(TokenError::Expired);
        }
        if exp.saturating_sub(now_millis) > MAX_TOKEN_TTL_MILLIS {
            return Err(TokenError::Invalid);
        }
        Ok((id, (*revision).to_string()))
    }

    fn mac(&self) -> Hmac<Sha256> {
        Hmac::<Sha256>::new_from_slice(&self.secret).expect("hmac takes any key length")
    }
}

/// Mint a token the way the console does. For tests and as the reference for the format.
pub fn mint(secret: &[u8], id: u64, revision: &str, exp_millis: i64) -> String {
    let mut mac = Hmac::<Sha256>::new_from_slice(secret).expect("hmac takes any key length");
    mac.update(message(&id.to_string(), revision, &exp_millis.to_string()).as_bytes());
    let sig: String = mac
        .finalize()
        .into_bytes()
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect();
    format!("v1.{id}.{revision}.{exp_millis}.{sig}")
}

fn message(id: &str, revision: &str, exp: &str) -> String {
    format!("{MAC_DOMAIN}\n{id}\n{revision}\n{exp}")
}

fn is_decimal(s: &str) -> bool {
    !s.is_empty() && s.len() <= 19 && s.bytes().all(|b| b.is_ascii_digit())
}

fn is_revision(s: &str) -> bool {
    s.len() == 16 && s.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
}

fn decode_hex(s: &str) -> Option<Vec<u8>> {
    if !s.len().is_multiple_of(2) {
        return None;
    }
    (0..s.len())
        .step_by(2)
        .map(|i| {
            let pair = s.get(i..i + 2)?;
            if !pair.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f')) {
                return None;
            }
            u8::from_str_radix(pair, 16).ok()
        })
        .collect()
}

fn refuse(status: StatusCode, kind: &str, message: impl Into<String>) -> Response {
    (
        status,
        Json(serde_json::json!({
            "type": "error",
            "error": { "type": kind, "message": message.into() },
        })),
    )
        .into_response()
}

/// Request fields that are malformed on their own, before any token or state is consulted.
fn invalid_request(req: &CloseRequest) -> Option<String> {
    let op = &req.operation_id;
    if op.is_empty()
        || op.len() > MAX_OPERATION_ID_BYTES
        || !op.bytes().all(|b| b.is_ascii_graphic())
    {
        return Some(format!(
            "operation_id must be 1 to {MAX_OPERATION_ID_BYTES} visible ASCII bytes"
        ));
    }
    let ev = &req.evidence_ref;
    if ev.trim().is_empty() || ev.len() > MAX_EVIDENCE_REF_BYTES || ev.chars().any(char::is_control)
    {
        return Some(format!(
            "evidence_ref must name the evidence in 1 to {MAX_EVIDENCE_REF_BYTES} bytes with no control characters"
        ));
    }
    if !is_revision(&req.expected_revision) {
        return Some("expected_revision must be the 16 hex digits GET /v1/retained lists".into());
    }
    match (req.evidence_kind, req.observed_microusd) {
        (EvidenceKind::Observed, None) => {
            Some("an observed closure needs observed_microusd, the cost the evidence shows".into())
        }
        (EvidenceKind::Observed, Some(c)) if c < 0 => {
            Some("observed_microusd cannot be negative".into())
        }
        (EvidenceKind::NoCharge, Some(_)) => {
            Some("a no_charge closure carries no observed_microusd: it releases at zero".into())
        }
        _ => None,
    }
}

fn result_body(record: &ClosureRecord, replayed: bool) -> serde_json::Value {
    serde_json::json!({
        "closed": true,
        "replayed": replayed,
        "reservation_id": record.reservation_id,
        "revision": record.revision,
        "operation_id": record.operation_id,
        "evidence_kind": record.evidence_kind,
        "evidence_ref": record.evidence_ref,
        "settled_microusd": record.settled_microusd,
        "run_id": record.run_id,
        "unit": record.unit,
        "closed_at_millis": record.closed_at_millis,
    })
}

/// `POST /v1/retained/close`, behind the admin gate, registered only when the door is
/// configured.
pub async fn close(State(st): State<AppState>, headers: HeaderMap, body: Bytes) -> Response {
    let Some(door) = st.closure.clone() else {
        return StatusCode::NOT_FOUND.into_response();
    };
    let req: CloseRequest = match serde_json::from_slice(&body) {
        Ok(r) => r,
        Err(e) => {
            return refuse(
                StatusCode::BAD_REQUEST,
                "invalid_request",
                format!("the closure request could not be read: {e}"),
            )
        }
    };
    if let Some(why) = invalid_request(&req) {
        return refuse(StatusCode::BAD_REQUEST, "invalid_request", why);
    }
    let now = crate::sink::now_millis();
    let Some(token) = headers.get(TOKEN_HEADER).and_then(|v| v.to_str().ok()) else {
        return refuse(
            StatusCode::UNAUTHORIZED,
            "closure_token_required",
            format!("a closure needs a token from the operator console in {TOKEN_HEADER}"),
        );
    };
    let (token_id, token_revision) = match door.verify(token.trim(), now) {
        Ok(bound) => bound,
        Err(TokenError::Expired) => {
            return refuse(
                StatusCode::UNAUTHORIZED,
                "closure_token_expired",
                "the closure token has expired; mint a new one",
            )
        }
        Err(TokenError::Invalid) => {
            return refuse(
                StatusCode::UNAUTHORIZED,
                "closure_token_invalid",
                format!(
                    "the closure token is not one this gateway accepts (signature, format, or a lifetime over {} seconds)",
                    MAX_TOKEN_TTL_MILLIS / 1000
                ),
            )
        }
    };
    if token_id != req.reservation_id || token_revision != req.expected_revision {
        return refuse(
            StatusCode::FORBIDDEN,
            "closure_token_mismatch",
            "the closure token is bound to another reservation or revision",
        );
    }
    let (status, value) = apply(&st, &door, &req, now);
    (status, Json(value)).into_response()
}

/// The closure itself, under the books' lock. Pure of HTTP, so tests can drive it directly.
pub fn apply(
    st: &AppState,
    door: &ClosureDoor,
    req: &CloseRequest,
    now: i64,
) -> (StatusCode, serde_json::Value) {
    let err = |status: StatusCode, kind: &str, message: String| {
        (
            status,
            serde_json::json!({ "type": "error", "error": { "type": kind, "message": message } }),
        )
    };
    let mut books = door.books.lock().unwrap_or_else(|p| p.into_inner());
    let content = Content::of(req);
    if let Some((recorded, record)) = books.by_operation.get(&req.operation_id) {
        if *recorded == content {
            return (StatusCode::OK, result_body(record, true));
        }
        return err(
            StatusCode::CONFLICT,
            "closure_conflict",
            format!(
                "operation {} already closed reservation {} with different content; nothing changed",
                req.operation_id, record.reservation_id
            ),
        );
    }
    if let Some(op) = books
        .closed
        .get(&(req.reservation_id, req.expected_revision.clone()))
    {
        return err(
            StatusCode::CONFLICT,
            "already_closed",
            format!(
                "reservation {} was already closed by operation {op}",
                req.reservation_id
            ),
        );
    }
    let Some(current) = st.retained.find(req.reservation_id) else {
        return err(
            StatusCode::NOT_FOUND,
            "not_retained",
            format!(
                "reservation {} is not a retained reservation this gateway lists",
                req.reservation_id
            ),
        );
    };
    if current.revision != req.expected_revision {
        return err(
            StatusCode::CONFLICT,
            "stale_revision",
            format!(
                "reservation {} is at revision {}, not {}",
                req.reservation_id, current.revision, req.expected_revision
            ),
        );
    }
    let settled = match req.evidence_kind {
        EvidenceKind::Observed => Microusd(req.observed_microusd.unwrap_or(0)),
        EvidenceKind::NoCharge => Microusd::ZERO,
    };
    let record = ClosureRecord {
        v: 1,
        kind: KIND_CLOSURE.into(),
        reservation_id: req.reservation_id,
        revision: req.expected_revision.clone(),
        operation_id: req.operation_id.clone(),
        evidence_kind: req.evidence_kind.as_str().into(),
        observed_microusd: req.observed_microusd,
        evidence_ref: req.evidence_ref.clone(),
        settled_microusd: settled.0,
        run_id: current.run.run_id.clone(),
        unit: current.unit.as_ref().map(|u| u.unit.clone()),
        closed_at_millis: now,
    };
    // Written and synced before anything moves: a closure that is not on disk has not
    // happened, so a failed write changes nothing.
    if let Some(journal) = st.retained.journal() {
        if let Err(e) = journal.append_closure(&record) {
            tracing::error!(
                path = %journal.path().display(),
                reservation = req.reservation_id,
                error = %e,
                "the closure could not be written to the retained journal; nothing was closed"
            );
            return err(
                StatusCode::INTERNAL_SERVER_ERROR,
                "journal_write_failed",
                "the closure could not be made durable; nothing was closed".into(),
            );
        }
    }
    let Some(entry) = st.retained.take(req.reservation_id, &req.expected_revision) else {
        // Unreachable while the books' lock is held (`find` saw it a moment ago and only a
        // closure takes an entry); answered rather than assumed.
        return err(
            StatusCode::CONFLICT,
            "already_closed",
            format!(
                "reservation {} was taken by another closure",
                req.reservation_id
            ),
        );
    };
    st.ledger.settle(&entry.run, settled);
    if let Some(u) = &entry.unit {
        st.units.settle(u, settled, now);
    }
    // D8.1: an observed cost is spend, so it takes the path a settled call's spend takes, the
    // `allow` row through the sink (the Parquet trace and, in Cloud mode, the cloud sink), and
    // a restarted gateway's run and unit seeds (invariants 70 and 52) count it. Written here,
    // once, after the closure is durable and before the books note it, so a replay of the
    // same operation (answered above from the books, in this process or after a restart)
    // never writes a second row. A no-charge closure is a release, and a release writes no row.
    if req.evidence_kind == EvidenceKind::Observed {
        st.sink.record(closure_row(&entry, settled, now));
    }
    // D10, invariant 90: one `retained_closed` per closure applied, from here and nowhere else.
    // Every refusal above has already returned, and a replay of the same operation is answered
    // from the books before this point, so neither reaches the bus. The subject is the agent
    // the journal recorded for the call; a record with none is skipped and counted by the
    // exporter, never given one.
    let outcome = st.events.emit(
        EventType::RetainedClosed,
        now,
        entry.attribution.as_ref().map(|a| a.agent_id.as_str()),
        Some(record.run_id.as_str()),
        None,
        tokenfuse_core::agent_event::retained_closed_data(
            record.reservation_id,
            &record.revision,
            &record.operation_id,
            &record.evidence_kind,
            record.settled_microusd,
            &record.evidence_ref,
            record.unit.as_deref(),
        ),
    );
    crate::events::log_outcome(EventType::RetainedClosed, outcome);
    books.note(&record);
    tracing::info!(
        reservation = record.reservation_id,
        revision = %record.revision,
        run = %record.run_id,
        operation = %record.operation_id,
        evidence_kind = %record.evidence_kind,
        evidence_ref = %record.evidence_ref,
        settled_microusd = record.settled_microusd,
        reserved_microusd = entry.run.amount.0,
        unit = record.unit.as_deref().unwrap_or(""),
        "retained reservation closed with evidence (D8): settled on the run chain it was admitted against and on its unit"
    );
    (StatusCode::OK, result_body(&record, false))
}

/// The `allow` row an observed closure writes: `settle::allow_record`, the shape a settled
/// call's row has, with the attribution the retained record journaled, the observed cost, no
/// token counts (the evidence is a cost, not a usage record) and no router savings. A record
/// from a journal line older than the attribution field names no agent or key; its unit is
/// taken from the unit half when it has one, so the Cloud's unit month still counts it.
fn closure_row(
    entry: &crate::settle::RetainedReservation,
    settled: Microusd,
    now: i64,
) -> crate::sink::CallRecord {
    let journaled = entry.attribution.clone().unwrap_or_default();
    let unit = if journaled.unit.is_empty() {
        entry
            .unit
            .as_ref()
            .map(|u| u.unit.clone())
            .unwrap_or_default()
    } else {
        journaled.unit
    };
    let attribution = crate::settle::CallAttribution {
        model: entry.model.clone(),
        agent_id: journaled.agent_id,
        parent_run_id: journaled.parent_run_id,
        on_behalf_of: journaled.on_behalf_of,
        outcome: journaled.outcome,
        key_id: journaled.key_id,
        unit,
        identity_reason: journaled.identity_reason,
        ..Default::default()
    };
    crate::settle::allow_record(
        &entry.run,
        &attribution,
        settled,
        &tokenfuse_core::Usage::default(),
        Microusd::ZERO,
        now,
    )
}

/// One row of `GET /v1/retained`.
#[derive(Debug, Serialize)]
pub struct RetainedView {
    pub reservation_id: u64,
    pub revision: String,
    pub run_id: String,
    pub chain: Vec<String>,
    pub amount_microusd: i64,
    pub unit: Option<String>,
    pub model: String,
    pub retained_at_millis: i64,
}

/// `GET /v1/retained`: every listed retained reservation, by id, with the revision a token
/// must bind. Behind the admin gate, registered only when the door is configured.
pub async fn list(State(st): State<AppState>) -> Json<Vec<RetainedView>> {
    let mut rows: Vec<RetainedView> = st
        .retained
        .all()
        .into_iter()
        .map(|e| RetainedView {
            reservation_id: e.run.id,
            revision: e.revision,
            chain: e.run.chain.iter().map(|l| l.run_id.clone()).collect(),
            run_id: e.run.run_id,
            amount_microusd: e.run.amount.0,
            unit: e.unit.map(|u| u.unit),
            model: e.model,
            retained_at_millis: e.retained_at_millis,
        })
        .collect();
    rows.sort_by_key(|r| r.reservation_id);
    Json(rows)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::retainedjournal::{self, Journal, Record};
    use crate::settle::{Retained, RetainedReservation};
    use crate::unitledger::UnitLedger;
    use std::sync::Arc;
    use tokenfuse_core::Ledger;

    const SECRET: &[u8] = b"unit-test-closure-secret-0123456789abcdef";

    fn scratch(name: &str) -> std::path::PathBuf {
        let d = std::env::temp_dir().join(format!("tf-closure-unit-{}-{name}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        d
    }

    struct Rig {
        state: AppState,
        ledger: Arc<Ledger>,
        units: Arc<UnitLedger>,
        door: ClosureDoor,
        now: i64,
        rows: Arc<Rows>,
    }

    /// Every row the closure hands the sink, the stand-in for the Parquet trace and the cloud
    /// sink (`TeeSink` hands both the same record).
    #[derive(Default)]
    struct Rows(Mutex<Vec<crate::sink::CallRecord>>);
    impl crate::sink::EventSink for Rows {
        fn record(&self, rec: crate::sink::CallRecord) {
            self.0.lock().unwrap().push(rec);
        }
        fn flush(&self) {}
    }
    impl Rows {
        fn all(&self) -> Vec<crate::sink::CallRecord> {
            self.0.lock().unwrap().clone()
        }
    }

    fn attributed() -> Option<retainedjournal::RowAttribution> {
        Some(retainedjournal::RowAttribution {
            agent_id: "agent://acme/bot".into(),
            key_id: "k-ops".into(),
            unit: "ops".into(),
            parent_run_id: "parent".into(),
            on_behalf_of: "user://acme/alice".into(),
            ..Default::default()
        })
    }

    /// A state whose registry (and journal, with `dir`) holds one retained reservation of
    /// `amount` on `child` under `parent`, with a unit half on `ops`, taken the way
    /// `SettleGuard::retain` takes it.
    fn rig(dir: Option<&std::path::Path>, amount: Microusd) -> (Rig, RetainedReservation) {
        rig_with(dir, amount, attributed())
    }

    fn rig_with(
        dir: Option<&std::path::Path>,
        amount: Microusd,
        attribution: Option<retainedjournal::RowAttribution>,
    ) -> (Rig, RetainedReservation) {
        let ledger = Arc::new(Ledger::new());
        let units = Arc::new(UnitLedger::new(HashMap::from([(
            "ops".to_string(),
            Microusd::from_usd(10.0),
        )])));
        let now = crate::sink::now_millis();
        ledger
            .open_run("parent", Microusd::from_usd(5.0), None)
            .unwrap();
        ledger
            .open_run("child", Microusd::from_usd(5.0), Some("parent"))
            .unwrap();
        let run = ledger.reserve("child", amount).unwrap();
        let unit = units.try_reserve("ops", amount, now).unwrap();
        let tail = ledger.tail_parent(&run);
        let mut entry = RetainedReservation {
            run,
            unit,
            model: "m".into(),
            retained_at_millis: now,
            revision: String::new(),
            attribution,
        };
        let record = Record::retained(&entry, tail);
        entry.revision = record.revision();
        let retained = match dir {
            Some(d) => Retained::with_journal(Journal::open(d).unwrap()),
            None => Retained::default(),
        };
        retained.journal_retained(&entry, &record);
        assert!(retained.push(entry.clone()));
        let mut state = AppState::new(
            ledger.clone(),
            Arc::new(tokenfuse_core::PriceBook::new()),
            Arc::new(tokenfuse_core::Policy::default()),
            Arc::new(crate::provider::StubProvider::default()),
            "t",
        )
        .with_retained(Arc::new(retained));
        state.units = units.clone();
        let rows = Arc::new(Rows::default());
        let state = state.with_sink(rows.clone());
        (
            Rig {
                state,
                ledger,
                units,
                door: ClosureDoor::new(SECRET),
                now,
                rows,
            },
            entry,
        )
    }

    fn request(
        e: &RetainedReservation,
        op: &str,
        kind: EvidenceKind,
        cost: Option<i64>,
    ) -> CloseRequest {
        CloseRequest {
            reservation_id: e.run.id,
            expected_revision: e.revision.clone(),
            operation_id: op.into(),
            evidence_kind: kind,
            observed_microusd: cost,
            evidence_ref: "provider usage msg_1".into(),
        }
    }

    #[test]
    fn an_observed_closure_settles_both_ledgers_at_the_cost_on_every_link() {
        let (r, e) = rig(None, Microusd(8_000));
        let (status, body) = apply(
            &r.state,
            &r.door,
            &request(&e, "op", EvidenceKind::Observed, Some(5_500)),
            r.now,
        );
        assert_eq!(status, StatusCode::OK, "{body}");
        for run in ["child", "parent"] {
            let s = r.ledger.snapshot(run).unwrap();
            assert_eq!(
                (s.reserved, s.spent),
                (Microusd::ZERO, Microusd(5_500)),
                "{run}"
            );
        }
        assert_eq!(r.units.reserved("ops", r.now), Microusd::ZERO);
        assert_eq!(r.units.spent("ops", r.now), Microusd(5_500));
        assert!(r.state.retained.is_empty());
        assert_eq!(body["unit"], "ops");
    }

    #[test]
    fn a_no_charge_closure_releases_both_ledgers_at_zero() {
        let (r, e) = rig(None, Microusd(8_000));
        let (status, _) = apply(
            &r.state,
            &r.door,
            &request(&e, "op", EvidenceKind::NoCharge, None),
            r.now,
        );
        assert_eq!(status, StatusCode::OK);
        for run in ["child", "parent"] {
            let s = r.ledger.snapshot(run).unwrap();
            assert_eq!(
                (s.reserved, s.spent),
                (Microusd::ZERO, Microusd::ZERO),
                "{run}"
            );
        }
        assert_eq!(r.units.reserved("ops", r.now), Microusd::ZERO);
        assert_eq!(r.units.spent("ops", r.now), Microusd::ZERO);
    }

    /// Two closures of one reservation under different operation ids, raced: exactly one
    /// applies, and both ledgers move once.
    #[test]
    fn racing_closures_of_one_reservation_apply_exactly_once() {
        let (r, e) = rig(None, Microusd(8_000));
        let r = Arc::new(r);
        let handles: Vec<_> = (0..16)
            .map(|i| {
                let (r, e) = (r.clone(), e.clone());
                std::thread::spawn(move || {
                    apply(
                        &r.state,
                        &r.door,
                        &request(&e, &format!("op-{i}"), EvidenceKind::Observed, Some(1_000)),
                        r.now,
                    )
                    .0
                })
            })
            .collect();
        let statuses: Vec<StatusCode> = handles.into_iter().map(|h| h.join().unwrap()).collect();
        assert_eq!(statuses.iter().filter(|s| **s == StatusCode::OK).count(), 1);
        assert_eq!(
            statuses
                .iter()
                .filter(|s| **s == StatusCode::CONFLICT)
                .count(),
            15
        );
        assert_eq!(r.ledger.snapshot("child").unwrap().spent, Microusd(1_000));
        assert_eq!(r.ledger.snapshot("parent").unwrap().spent, Microusd(1_000));
        assert_eq!(r.units.spent("ops", r.now), Microusd(1_000));
        assert_eq!(r.rows.all().len(), 1, "one closure, one row");
    }

    #[test]
    fn a_replay_answers_the_recorded_result_and_a_conflict_changes_nothing() {
        let (r, e) = rig(None, Microusd(8_000));
        let req = request(&e, "op", EvidenceKind::Observed, Some(700));
        let first = apply(&r.state, &r.door, &req, r.now);
        let again = apply(&r.state, &r.door, &req, r.now + 5);
        let mut other = req.clone();
        other.evidence_ref = "a different invoice".into();
        let conflict = apply(&r.state, &r.door, &other, r.now);
        assert_eq!(first.0, StatusCode::OK);
        assert_eq!(again.0, StatusCode::OK);
        assert_eq!(again.1["replayed"], true);
        assert_eq!(again.1["closed_at_millis"], first.1["closed_at_millis"]);
        assert_eq!(again.1["unit"], "ops");
        assert_eq!(conflict.0, StatusCode::CONFLICT);
        assert_eq!(conflict.1["error"]["type"], "closure_conflict");
        assert_eq!(r.ledger.snapshot("child").unwrap().spent, Microusd(700));
        assert_eq!(r.units.spent("ops", r.now), Microusd(700));
        assert_eq!(
            r.rows.all().len(),
            1,
            "the replay and the conflict write no row"
        );
    }

    /// The closure record is written before anything moves; a write that fails closes nothing.
    #[test]
    fn a_closure_the_journal_cannot_take_changes_nothing() {
        let dir = scratch("unwritable");
        let (r, e) = rig(Some(&dir), Microusd(8_000));
        let mut req = request(&e, "op", EvidenceKind::Observed, Some(700));
        // A record over the journal's line bound is refused by the writer, whole.
        req.evidence_ref = "x".repeat(retainedjournal::MAX_LINE_BYTES);
        let (status, body) = apply(&r.state, &r.door, &req, r.now);
        assert_eq!(status, StatusCode::INTERNAL_SERVER_ERROR, "{body}");
        assert_eq!(
            r.ledger.snapshot("child").unwrap().reserved,
            Microusd(8_000)
        );
        assert_eq!(r.units.reserved("ops", r.now), Microusd(8_000));
        assert_eq!(r.state.retained.len(), 1);
        assert!(r.rows.all().is_empty(), "nothing closed, nothing spent");
        assert!(retainedjournal::read(&dir).unwrap().closures.is_empty());
        std::fs::remove_dir_all(&dir).ok();
    }

    /// A crash between the closure record and the ledgers: the record is on disk, so a fresh
    /// process restores everything but the closed reservation, and its operation still
    /// answers the recorded result.
    #[test]
    fn a_closure_on_disk_is_never_restored_and_its_operation_answers_after_a_restart() {
        let dir = scratch("restart");
        let (r, e) = rig(Some(&dir), Microusd(8_000));
        let req = request(&e, "op", EvidenceKind::Observed, Some(700));
        assert_eq!(apply(&r.state, &r.door, &req, r.now).0, StatusCode::OK);

        let report = retainedjournal::read(&dir).unwrap();
        assert_eq!((report.records.len(), report.closures.len()), (1, 1));
        let ledger = Arc::new(Ledger::new());
        let registry = Retained::default();
        let units = UnitLedger::default();
        let replayed = retainedjournal::replay(
            report,
            &crate::ledger_backend::LocalLedger(ledger.clone()),
            &units,
            &registry,
            r.now,
        );
        assert_eq!(replayed.closed, 1);
        assert!(replayed.keep.is_empty());
        assert!(ledger.snapshot("child").is_none());
        assert!(registry.is_empty());

        let door = ClosureDoor::new(SECRET);
        door.remember(&replayed.read.closures);
        let (r2, _) = rig(None, Microusd(1));
        let again = apply(&r2.state, &door, &req, r.now);
        assert_eq!(again.0, StatusCode::OK);
        assert_eq!(again.1["replayed"], true);
        assert_eq!(again.1["settled_microusd"], 700);
        assert!(
            r2.rows.all().is_empty(),
            "a replay after a restart writes no second row"
        );
        std::fs::remove_dir_all(&dir).ok();
    }

    /// D8.1: the observed cost is spend, so it is written as the `allow` row a settled call
    /// writes, once, under the attribution the retained record journaled.
    #[test]
    fn an_observed_closure_writes_one_allow_row_with_the_calls_attribution() {
        let (r, e) = rig(None, Microusd(8_000));
        let req = request(&e, "op", EvidenceKind::Observed, Some(5_500));
        assert_eq!(apply(&r.state, &r.door, &req, r.now).0, StatusCode::OK);
        let rows = r.rows.all();
        assert_eq!(rows.len(), 1, "{rows:?}");
        let row = &rows[0];
        assert_eq!(row.decision, "allow");
        assert_eq!(row.run_id, "child");
        assert_eq!(row.cost_microusd, 5_500);
        assert_eq!(row.step, e.run.step);
        assert_eq!(row.model, "m");
        assert_eq!(row.agent_id, "agent://acme/bot");
        assert_eq!(row.key_id, "k-ops");
        assert_eq!(row.unit, "ops");
        assert_eq!(row.parent_run_id, "parent");
        assert_eq!(row.on_behalf_of, "user://acme/alice");
        assert_eq!((row.input_tokens, row.output_tokens), (0, 0));
        assert_eq!(row.saved_microusd, 0);
        assert_eq!(row.ts_millis, r.now);
    }

    #[test]
    fn a_no_charge_closure_writes_no_row() {
        let (r, e) = rig(None, Microusd(8_000));
        let req = request(&e, "op", EvidenceKind::NoCharge, None);
        assert_eq!(apply(&r.state, &r.door, &req, r.now).0, StatusCode::OK);
        assert!(r.rows.all().is_empty(), "{:?}", r.rows.all());
    }

    /// A reservation journaled before the attribution field existed: the row names no agent
    /// or key, and takes its unit from the unit half, so the Cloud's unit month still counts it.
    #[test]
    fn a_record_from_before_the_attribution_field_files_its_unit_from_the_unit_half() {
        let (r, e) = rig_with(None, Microusd(8_000), None);
        let req = request(&e, "op", EvidenceKind::Observed, Some(300));
        assert_eq!(apply(&r.state, &r.door, &req, r.now).0, StatusCode::OK);
        let rows = r.rows.all();
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].unit, "ops");
        assert_eq!(rows[0].agent_id, "");
        assert_eq!(rows[0].cost_microusd, 300);
    }

    // -- D10: a closure reaches the bus (invariant 90) ----------------------
    //
    // agent-passport SPEC 6.2 registers `retained_closed` (high): a person
    // closing a retained reservation with evidence, raised once per closure the
    // gateway applies, never for a refused attempt and never for a retry of an
    // operation already applied.

    /// A real exporter on a private file: it is the serialization point that
    /// enforces `agent_id`, so a test reads what reached the bus, not what a
    /// double was handed.
    fn bus(name: &str) -> (Arc<crate::events::EventExporter>, std::path::PathBuf) {
        let dir = scratch(&format!("bus-{name}"));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("events.ndjson");
        let exporter = crate::events::EventExporter::open(path.to_str().unwrap()).unwrap();
        (Arc::new(exporter), path)
    }

    fn closed_on_bus(path: &std::path::Path) -> Vec<serde_json::Value> {
        std::fs::read_to_string(path)
            .unwrap_or_default()
            .lines()
            .filter(|l| !l.trim().is_empty())
            .map(|l| serde_json::from_str::<serde_json::Value>(l).unwrap())
            .filter(|e| e["type"] == "retained_closed")
            .collect()
    }

    #[test]
    fn an_applied_closure_writes_one_retained_closed_with_its_evidence() {
        let (r, e) = rig(None, Microusd(8_000));
        let (events, path) = bus("observed");
        let st = r.state.clone().with_events(events);
        let (status, body) = apply(
            &st,
            &r.door,
            &request(&e, "op", EvidenceKind::Observed, Some(5_500)),
            r.now,
        );
        let on_bus = closed_on_bus(&path);
        std::fs::remove_dir_all(path.parent().unwrap()).ok();
        assert_eq!(status, StatusCode::OK, "{body}");
        assert_eq!(on_bus.len(), 1, "one closure, one event: {on_bus:?}");
        let ev = &on_bus[0];
        assert_eq!(ev["schema"], "taipanbox.dev/agent-event/v0.2", "{ev}");
        assert_eq!(ev["source"], "tokenfuse", "{ev}");
        assert_eq!(ev["severity"], "high", "{ev}");
        assert_eq!(
            ev["agent_id"], "agent://acme/bot",
            "the journaled call's agent: {ev}"
        );
        assert_eq!(ev["run_id"], "child", "{ev}");
        assert!(
            ev.get("on_behalf_of").is_none(),
            "SPEC 6.2 puts agent_id and run_id on this envelope, nothing else: {ev}"
        );
        assert_eq!(
            ev["data"],
            serde_json::json!({
                "reservation_id": e.run.id,
                "revision": e.revision,
                "operation_id": "op",
                "evidence_kind": "observed",
                "settled_microusd": 5_500,
                "evidence_ref": "provider usage msg_1",
                "unit": "ops",
            }),
            "{ev}"
        );
    }

    #[test]
    fn a_no_charge_closure_writes_one_retained_closed_settled_at_zero() {
        let (r, e) = rig(None, Microusd(8_000));
        let (events, path) = bus("no-charge");
        let st = r.state.clone().with_events(events);
        let (status, _) = apply(
            &st,
            &r.door,
            &request(&e, "op-nc", EvidenceKind::NoCharge, None),
            r.now,
        );
        let on_bus = closed_on_bus(&path);
        std::fs::remove_dir_all(path.parent().unwrap()).ok();
        assert_eq!(status, StatusCode::OK);
        assert_eq!(on_bus.len(), 1, "{on_bus:?}");
        assert_eq!(on_bus[0]["severity"], "high");
        assert_eq!(on_bus[0]["data"]["evidence_kind"], "no_charge");
        assert_eq!(on_bus[0]["data"]["settled_microusd"], 0);
        assert_eq!(on_bus[0]["data"]["operation_id"], "op-nc");
    }

    /// Asked again with the same operation, with different content, or by a
    /// second operation: the books answer, nothing moves, and no second
    /// `retained_closed` is written.
    #[test]
    fn a_replay_a_conflict_and_a_second_operation_write_no_second_retained_closed() {
        let (r, e) = rig(None, Microusd(8_000));
        let (events, path) = bus("replay");
        let st = r.state.clone().with_events(events);
        let req = request(&e, "op", EvidenceKind::Observed, Some(700));
        let first = apply(&st, &r.door, &req, r.now);
        let again = apply(&st, &r.door, &req, r.now + 5);
        let mut changed = req.clone();
        changed.evidence_ref = "a different invoice".into();
        let conflict = apply(&st, &r.door, &changed, r.now);
        let second = apply(
            &st,
            &r.door,
            &request(&e, "op-2", EvidenceKind::Observed, Some(700)),
            r.now,
        );
        let on_bus = closed_on_bus(&path);
        std::fs::remove_dir_all(path.parent().unwrap()).ok();
        assert_eq!(first.0, StatusCode::OK);
        assert_eq!(again.0, StatusCode::OK);
        assert_eq!(again.1["replayed"], true);
        assert_eq!(conflict.1["error"]["type"], "closure_conflict");
        assert_eq!(second.1["error"]["type"], "already_closed");
        assert_eq!(on_bus.len(), 1, "applied once, written once: {on_bus:?}");
        assert_eq!(on_bus[0]["data"]["operation_id"], "op");
    }

    /// A stale revision and a closure the journal cannot take close nothing,
    /// so neither is on the bus; the closure applied after them is, alone.
    #[test]
    fn a_stale_revision_or_an_unwritable_journal_writes_no_retained_closed() {
        let dir = scratch("bus-refusals-journal");
        let (r, e) = rig(Some(&dir), Microusd(8_000));
        let (events, path) = bus("refusals");
        let st = r.state.clone().with_events(events);
        let mut stale = request(&e, "op-stale", EvidenceKind::Observed, Some(700));
        stale.expected_revision = if e.revision == "0000000000000000" {
            "1111111111111111".into()
        } else {
            "0000000000000000".into()
        };
        let stale = apply(&st, &r.door, &stale, r.now);
        let mut too_big = request(&e, "op-big", EvidenceKind::Observed, Some(700));
        too_big.evidence_ref = "x".repeat(retainedjournal::MAX_LINE_BYTES);
        let too_big = apply(&st, &r.door, &too_big, r.now);
        let applied = apply(
            &st,
            &r.door,
            &request(&e, "op-ok", EvidenceKind::Observed, Some(700)),
            r.now,
        );
        let on_bus = closed_on_bus(&path);
        std::fs::remove_dir_all(path.parent().unwrap()).ok();
        std::fs::remove_dir_all(&dir).ok();
        assert_eq!(stale.1["error"]["type"], "stale_revision", "{}", stale.1);
        assert_eq!(
            too_big.0,
            StatusCode::INTERNAL_SERVER_ERROR,
            "{}",
            too_big.1
        );
        assert_eq!(applied.0, StatusCode::OK, "{}", applied.1);
        assert_eq!(on_bus.len(), 1, "only the applied closure: {on_bus:?}");
        assert_eq!(on_bus[0]["data"]["operation_id"], "op-ok");
    }

    /// The operation answered again after a restart (the books loaded from the
    /// journal) is a replay, and writes nothing to the bus.
    #[test]
    fn a_closure_answered_again_after_a_restart_writes_no_second_retained_closed() {
        let dir = scratch("bus-restart");
        let (r, e) = rig(Some(&dir), Microusd(8_000));
        let (events, path) = bus("restart-first");
        let st = r.state.clone().with_events(events);
        let req = request(&e, "op", EvidenceKind::Observed, Some(700));
        assert_eq!(apply(&st, &r.door, &req, r.now).0, StatusCode::OK);

        let door = ClosureDoor::new(SECRET);
        door.remember(&retainedjournal::read(&dir).unwrap().closures);
        let (r2, _) = rig(None, Microusd(1));
        let (events2, path2) = bus("restart-second");
        let st2 = r2.state.clone().with_events(events2);
        let again = apply(&st2, &door, &req, r.now);
        let (before, after) = (closed_on_bus(&path), closed_on_bus(&path2));
        std::fs::remove_dir_all(path.parent().unwrap()).ok();
        std::fs::remove_dir_all(path2.parent().unwrap()).ok();
        std::fs::remove_dir_all(&dir).ok();
        assert_eq!(before.len(), 1, "the closure itself: {before:?}");
        assert_eq!(again.0, StatusCode::OK);
        assert_eq!(again.1["replayed"], true);
        assert!(after.is_empty(), "the replay wrote {after:?}");
    }

    /// SPEC 6.1: a record that names no agent (journaled before the attribution
    /// field existed) still closes, and its `retained_closed` is skipped and
    /// counted rather than filed under an invented subject.
    #[test]
    fn a_closure_of_a_record_that_names_no_agent_is_skipped_and_counted() {
        let (r, e) = rig_with(None, Microusd(8_000), None);
        let (events, path) = bus("no-agent");
        let st = r.state.clone().with_events(Arc::clone(&events));
        let (status, _) = apply(
            &st,
            &r.door,
            &request(&e, "op", EvidenceKind::Observed, Some(300)),
            r.now,
        );
        let on_bus = closed_on_bus(&path);
        std::fs::remove_dir_all(path.parent().unwrap()).ok();
        assert_eq!(status, StatusCode::OK);
        assert!(on_bus.is_empty(), "{on_bus:?}");
        assert_eq!(
            events.skipped_count(),
            1,
            "the closure with no subject is skipped AND counted"
        );
    }

    #[test]
    fn malformed_requests_are_refused_before_anything_is_read() {
        let (_, e) = rig(None, Microusd(100));
        let ok = request(&e, "op", EvidenceKind::Observed, Some(1));
        assert!(invalid_request(&ok).is_none());
        let mut bad: Vec<CloseRequest> = vec![
            request(&e, "op", EvidenceKind::Observed, None),
            request(&e, "op", EvidenceKind::Observed, Some(-1)),
            request(&e, "op", EvidenceKind::NoCharge, Some(0)),
            request(&e, "", EvidenceKind::NoCharge, None),
            request(&e, "op id", EvidenceKind::NoCharge, None),
            request(
                &e,
                &"o".repeat(MAX_OPERATION_ID_BYTES + 1),
                EvidenceKind::NoCharge,
                None,
            ),
        ];
        let mut r = request(&e, "op", EvidenceKind::NoCharge, None);
        r.evidence_ref = " ".into();
        bad.push(r);
        let mut r = request(&e, "op", EvidenceKind::NoCharge, None);
        r.evidence_ref = "line\nbreak".into();
        bad.push(r);
        let mut r = request(&e, "op", EvidenceKind::NoCharge, None);
        r.expected_revision = "ABCDEF0123456789".into();
        bad.push(r);
        for (i, b) in bad.iter().enumerate() {
            assert!(invalid_request(b).is_some(), "case {i} accepted: {b:?}");
        }
        assert!(serde_json::from_str::<CloseRequest>(
            r#"{"reservation_id":1,"expected_revision":"0000000000000000","operation_id":"o","evidence_kind":"observed","observed_microusd":1,"evidence_ref":"e","note":"x"}"#
        )
        .is_err());
        assert!(serde_json::from_str::<CloseRequest>(
            r#"{"reservation_id":1,"expected_revision":"0000000000000000","operation_id":"o","evidence_kind":"adjustment","evidence_ref":"e"}"#
        )
        .is_err());
    }

    #[test]
    fn the_secret_is_off_when_unset_and_refused_when_shorter_than_32_bytes() {
        assert!(ClosureDoor::from_value(None).unwrap().is_none());
        assert!(ClosureDoor::from_value(Some("")).unwrap().is_none());
        let err = ClosureDoor::from_value(Some(&"s".repeat(31))).unwrap_err();
        assert!(err.contains(SECRET_ENV) && err.contains("31"), "{err}");
        assert!(ClosureDoor::from_value(Some(&"s".repeat(32)))
            .unwrap()
            .is_some());
    }

    #[test]
    fn a_token_is_bound_signed_and_short_lived_at_its_exact_boundaries() {
        let door = ClosureDoor::new(SECRET);
        let now = 1_800_000_000_000;
        let rev = "0123456789abcdef";
        assert_eq!(
            door.verify(&mint(SECRET, 7, rev, now + 1), now),
            Ok((7, rev.to_string()))
        );
        assert_eq!(
            door.verify(&mint(SECRET, 7, rev, now), now),
            Err(TokenError::Expired)
        );
        assert!(door
            .verify(&mint(SECRET, 7, rev, now + MAX_TOKEN_TTL_MILLIS), now)
            .is_ok());
        assert_eq!(
            door.verify(&mint(SECRET, 7, rev, now + MAX_TOKEN_TTL_MILLIS + 1), now),
            Err(TokenError::Invalid)
        );
        assert_eq!(
            door.verify(
                &mint(b"some-other-secret-of-32-bytes-or-more!!", 7, rev, now + 1),
                now
            ),
            Err(TokenError::Invalid)
        );
        // Every field is under the signature: change one and it no longer verifies.
        let good = mint(SECRET, 7, rev, now + 1000);
        let parts: Vec<&str> = good.split('.').collect();
        for (i, swap) in [
            (1, "8"),
            (2, "0123456789abcdee"),
            (3, &*(now + 999).to_string()),
        ] {
            let mut p = parts.clone();
            p[i] = swap;
            assert_eq!(
                door.verify(&p.join("."), now),
                Err(TokenError::Invalid),
                "field {i}"
            );
        }
        assert_eq!(
            door.verify(&good.to_uppercase(), now),
            Err(TokenError::Invalid)
        );
    }

    /// Seeded sweep: arbitrary token strings and every truncation and byte flip of a real
    /// token never panic and never verify.
    #[test]
    fn hostile_tokens_never_panic_and_never_verify() {
        let door = ClosureDoor::new(SECRET);
        let now = 1_800_000_000_000;
        let good = mint(SECRET, 42, "fedcba9876543210", now + 60_000);
        assert!(door.verify(&good, now).is_ok());
        let mut x: u64 = 0x9e37_79b9_7f4a_7c15;
        let mut next = move || {
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            x
        };
        for _ in 0..200 {
            let mut bytes = good.clone().into_bytes();
            match next() % 4 {
                0 => bytes.truncate((next() as usize) % bytes.len()),
                1 => {
                    let i = (next() as usize) % bytes.len();
                    bytes[i] ^= 1 + (next() % 255) as u8;
                }
                2 => bytes.extend((0..next() % 400).map(|_| (next() % 128) as u8)),
                _ => bytes = (0..next() % 300).map(|_| (next() % 256) as u8).collect(),
            }
            let s = String::from_utf8_lossy(&bytes);
            if s != good {
                assert!(door.verify(&s, now).is_err(), "{s:?} verified");
            }
        }
    }
}
