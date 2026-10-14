//! The retained-reservation journal (W03): what makes a retained reservation (invariant 50,
//! D7) survive a gateway restart.
//!
//! A call handed to the provider that ended before any status line came back is neither
//! settled nor released: its run reservation (on every link of the chain it was admitted
//! against) and its unit reservation stay outstanding until somebody reconciles them. Until
//! this module that liability lived only in this process's ledgers, so a restart forgot it and
//! the next call was admitted against room the provider may already have billed.
//!
//! Each retain appends one NDJSON line to `<TOKENFUSE_DATA_DIR>/retained-reservations.ndjson`
//! and syncs it to disk before the guard returns; startup reads the file and puts every
//! reservation back: on the run ledger with its original id, chain and generations
//! (`tokenfuse_core::Ledger::restore_outstanding`), on the unit ledger in the window it was
//! taken in and only if that window is still the current month (`UnitLedger::restore`), and in
//! the registry `GET /v1/runs` reads. Liability is rebuilt from these records alone, never
//! from settled-spend totals.
//!
//! Append-only while the process runs. Closing a retained reservation (D8, `crate::closure`)
//! appends a `closure` record naming the reservation's id and revision, synced before the
//! closure is applied, so a restart never puts a closed reservation back. Startup then rewrites
//! the file with only the records still open (D-3): a temp file beside it, synced, renamed over
//! it, the directory synced, and the append handle reopened on the new file. A record of a
//! `kind` this version does not know is counted, never read as a closure, and kept verbatim by
//! the rewrite, so a later version's records survive a downgrade.
//!
//! The file is ours, but it is still read as hostile input: a line over [`MAX_LINE_BYTES`] is
//! skipped without being held in memory, a line that does not parse is skipped and counted,
//! and a torn final line (a crash mid-append) is one of those. [`Journal::open`] terminates a
//! torn final line before appending, so a record written after a crash never fuses with it.

use crate::ledger_backend::LedgerBackend;
use crate::settle::{Retained, RetainedReservation};
use crate::unitledger::{RestoreOutcome, UnitLedger, UnitReservation};
use serde::{Deserialize, Serialize};
use std::fs::{File, OpenOptions};
use std::io::{self, BufRead, BufReader, Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use tokenfuse_core::{Outstanding, Reservation};

/// The journal's file name inside the data directory. Not `.parquet`, so the trace readers
/// (`tokenfuse sql`, the sink's own listing) never see it.
pub const FILE_NAME: &str = "retained-reservations.ndjson";

/// The longest line written or read. A chain holds at most 64 links, but run ids are chosen
/// by the caller and bounded only by the HTTP header limit, so this is generous on purpose: a
/// line the reader would skip is a liability lost, and the writer refuses the same bound so
/// the two can never disagree.
pub const MAX_LINE_BYTES: usize = 16 * 1024 * 1024;

/// The `kind` of a retained reservation, restored at startup.
pub const KIND_RETAINED: &str = "retained";

/// The `kind` of a closure (D8): the reservation it names is not restored.
pub const KIND_CLOSURE: &str = "closure";

/// The name of the temp file a startup rewrite builds before renaming it over the journal.
pub const TEMP_FILE_NAME: &str = "retained-reservations.ndjson.tmp";

/// One journal line.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Record {
    /// Format version, written as 1. Not checked on read: a later version's `retained`
    /// record that still parses is restored rather than dropped, the conservative direction.
    pub v: u32,
    pub kind: String,
    /// The run reservation exactly as admitted: id, leaf, amount, step, generation, chain.
    pub run: Reservation,
    /// The parent the ledger held for the chain's last link (`Outstanding::tail_parent`).
    #[serde(default)]
    pub tail_parent: Option<String>,
    /// The unit reservation with the window (`YYYY-MM`) it was taken in.
    #[serde(default)]
    pub unit: Option<UnitReservation>,
    #[serde(default)]
    pub model: String,
    pub retained_at_millis: i64,
    /// Who the call was attributed to (D8.1): what an observed closure's `allow` row carries,
    /// so the row reaches the Cloud under the same agent, key and unit a settled call would.
    /// Absent on a line written before this field existed, and never serialized when absent,
    /// so such a line keeps its canonical bytes and therefore its revision.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub attribution: Option<RowAttribution>,
}

/// The request-scoped fields of a retained call that its eventual `allow` row needs, a subset
/// of `settle::CallAttribution`. Every member is skipped when empty, so the journal line grows
/// only by what the call actually carried.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct RowAttribution {
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub agent_id: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub key_id: String,
    /// The unit the identity map resolved, capped or not (a unit with no cap holds no unit
    /// reservation, and the Cloud's unit month still needs the name).
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub unit: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub parent_run_id: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub on_behalf_of: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub outcome: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub identity_reason: Option<String>,
}

impl RowAttribution {
    pub fn of(a: &crate::settle::CallAttribution) -> Self {
        RowAttribution {
            agent_id: a.agent_id.clone(),
            key_id: a.key_id.clone(),
            unit: a.unit.clone(),
            parent_run_id: a.parent_run_id.clone(),
            on_behalf_of: a.on_behalf_of.clone(),
            outcome: a.outcome.clone(),
            identity_reason: a.identity_reason.clone(),
        }
    }
}

impl Record {
    /// The record's revision: the first 8 bytes of SHA-256 over a domain tag and the record's
    /// canonical serialization, as 16 lowercase hex digits. A closure token binds it, so a
    /// token minted for one record never closes another that reuses its id (ids are unique
    /// only within one lineage of the journal: a restart moves the counter past the records
    /// still open, not past the closed ones a rewrite dropped). Stable across a restart,
    /// because the rewrite writes the same canonical bytes this hashes.
    pub fn revision(&self) -> String {
        use sha2::{Digest, Sha256};
        let canonical = serde_json::to_vec(self).unwrap_or_default();
        let mut h = Sha256::new();
        h.update(b"tokenfuse-retained-revision-v1\n");
        h.update(&canonical);
        h.finalize()[..8]
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect()
    }

    pub fn retained(entry: &RetainedReservation, tail_parent: Option<String>) -> Self {
        Record {
            v: 1,
            kind: KIND_RETAINED.into(),
            run: entry.run.clone(),
            tail_parent,
            unit: entry.unit.clone(),
            model: entry.model.clone(),
            retained_at_millis: entry.retained_at_millis,
            attribution: entry.attribution.clone(),
        }
    }
}

/// One closure line (D8). Written before the closure is applied, so a crash between the two
/// leaves the reservation closed on disk and still outstanding in nothing: the next start
/// restores everything but this reservation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ClosureRecord {
    pub v: u32,
    pub kind: String,
    pub reservation_id: u64,
    pub revision: String,
    pub operation_id: String,
    /// `observed` or `no_charge`.
    pub evidence_kind: String,
    #[serde(default)]
    pub observed_microusd: Option<i64>,
    pub evidence_ref: String,
    /// What the closure settled both halves at: the observed cost, or zero.
    pub settled_microusd: i64,
    pub run_id: String,
    /// The unit the reservation's unit half was on, if it had one.
    #[serde(default)]
    pub unit: Option<String>,
    pub closed_at_millis: i64,
}

/// An open, append-only journal file.
#[derive(Debug)]
pub struct Journal {
    path: PathBuf,
    file: Mutex<File>,
}

impl Journal {
    /// Open (creating) `<dir>/retained-reservations.ndjson` for appending. If the file ends in
    /// a torn line, a newline is written first so the next record starts a line of its own.
    pub fn open(dir: &Path) -> io::Result<Journal> {
        std::fs::create_dir_all(dir)?;
        let path = dir.join(FILE_NAME);
        let mut file = OpenOptions::new()
            .create(true)
            .read(true)
            .append(true)
            .open(&path)?;
        let len = file.metadata()?.len();
        if len > 0 {
            file.seek(SeekFrom::Start(len - 1))?;
            let mut last = [0u8; 1];
            file.read_exact(&mut last)?;
            if last[0] != b'\n' {
                file.write_all(b"\n")?;
                file.sync_data()?;
            }
        } else {
            // A file just created is durable only once its directory entry is; best effort,
            // since not every platform lets a directory be opened for this.
            if let Ok(d) = File::open(dir) {
                let _ = d.sync_all();
            }
        }
        Ok(Journal {
            path,
            file: Mutex::new(file),
        })
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Append one record and sync it to disk before returning. One `write_all` of the whole
    /// line, under the lock, so concurrent appends never interleave. Synchronous by design:
    /// it runs from `SettleGuard::drop`, which cannot await, and only on the rare call whose
    /// outcome is unknown.
    pub fn append(&self, record: &Record) -> io::Result<()> {
        self.append_line(record)
    }

    /// Append one closure record, synced before returning, under the same bound and lock.
    pub fn append_closure(&self, record: &ClosureRecord) -> io::Result<()> {
        self.append_line(record)
    }

    fn append_line<T: Serialize>(&self, record: &T) -> io::Result<()> {
        let mut line = serde_json::to_vec(record).map_err(io::Error::other)?;
        line.push(b'\n');
        if line.len() > MAX_LINE_BYTES {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!(
                    "record is {} bytes, over the {MAX_LINE_BYTES}-byte line limit",
                    line.len()
                ),
            ));
        }
        let mut file = self.file.lock().unwrap_or_else(|p| p.into_inner());
        file.write_all(&line)?;
        file.sync_data()
    }

    /// D-3: replace the journal with exactly `lines` (each written as one line), atomically. A
    /// temp file in the same directory is written and synced, renamed over the journal, the
    /// directory is synced, and the append handle is reopened on the new file, all under the
    /// append lock so no record lands on the replaced file. On any error the journal is left
    /// as it was (the rename is the only step that changes it) and the handle keeps appending
    /// to it.
    pub fn rewrite(&self, lines: &[Vec<u8>]) -> io::Result<()> {
        let dir = self.path.parent().unwrap_or(Path::new("."));
        let temp = dir.join(TEMP_FILE_NAME);
        let mut file = self.file.lock().unwrap_or_else(|p| p.into_inner());
        {
            let mut t = OpenOptions::new()
                .create(true)
                .write(true)
                .truncate(true)
                .open(&temp)?;
            for line in lines {
                t.write_all(line)?;
                t.write_all(b"\n")?;
            }
            t.sync_all()?;
        }
        std::fs::rename(&temp, &self.path)?;
        if let Ok(d) = File::open(dir) {
            let _ = d.sync_all();
        }
        *file = OpenOptions::new()
            .create(true)
            .read(true)
            .append(true)
            .open(&self.path)?;
        Ok(())
    }
}

/// What reading a journal found, every skip counted.
#[derive(Debug, Default)]
pub struct ReadReport {
    pub records: Vec<Record>,
    /// Closure records (D8), in file order.
    pub closures: Vec<ClosureRecord>,
    /// The raw bytes of every well-formed record of an unknown kind, kept by the rewrite.
    pub other_kind_lines: Vec<Vec<u8>>,
    /// Lines that are not a record (a torn final line among them).
    pub malformed: usize,
    /// Lines over [`MAX_LINE_BYTES`], skipped unread.
    pub oversized: usize,
    /// Well-formed records of a `kind` this version does not know.
    pub other_kind: usize,
}

/// Read `<dir>/retained-reservations.ndjson`. A missing file is an empty report.
pub fn read(dir: &Path) -> io::Result<ReadReport> {
    match File::open(dir.join(FILE_NAME)) {
        Ok(f) => parse(BufReader::new(f)),
        Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(ReadReport::default()),
        Err(e) => Err(e),
    }
}

/// Parse journal lines from any reader, bounded per line.
pub fn parse<R: BufRead>(mut reader: R) -> io::Result<ReadReport> {
    let mut report = ReadReport::default();
    let mut line = Vec::new();
    while let Some(oversized) = next_line(&mut reader, &mut line)? {
        if oversized {
            report.oversized += 1;
            continue;
        }
        let trimmed = line.trim_ascii();
        if trimmed.is_empty() {
            continue;
        }
        #[derive(Deserialize)]
        struct Kind {
            kind: String,
        }
        match serde_json::from_slice::<Kind>(trimmed) {
            Ok(k) if k.kind == KIND_RETAINED => match serde_json::from_slice::<Record>(trimmed) {
                Ok(r) => report.records.push(r),
                Err(_) => report.malformed += 1,
            },
            Ok(k) if k.kind == KIND_CLOSURE => {
                match serde_json::from_slice::<ClosureRecord>(trimmed) {
                    Ok(c) => report.closures.push(c),
                    Err(_) => report.malformed += 1,
                }
            }
            Ok(_) => {
                report.other_kind += 1;
                report.other_kind_lines.push(trimmed.to_vec());
            }
            Err(_) => report.malformed += 1,
        }
    }
    Ok(report)
}

/// Read the next line into `buf` without ever holding more than [`MAX_LINE_BYTES`] of it.
/// `None` at end of input; `Some(true)` for a line that was over the bound (its bytes are
/// discarded, `buf` is empty).
fn next_line<R: BufRead>(reader: &mut R, buf: &mut Vec<u8>) -> io::Result<Option<bool>> {
    buf.clear();
    let mut oversized = false;
    let mut any = false;
    loop {
        let avail = match reader.fill_buf() {
            Ok(a) => a,
            Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
            Err(e) => return Err(e),
        };
        if avail.is_empty() {
            return Ok(any.then_some(oversized));
        }
        any = true;
        let (chunk, done) = match avail.iter().position(|&b| b == b'\n') {
            Some(i) => (&avail[..i], Some(i + 1)),
            None => (avail, None),
        };
        if !oversized {
            if buf.len() + chunk.len() > MAX_LINE_BYTES {
                oversized = true;
                buf.clear();
            } else {
                buf.extend_from_slice(chunk);
            }
        }
        let used = done.unwrap_or(avail.len());
        reader.consume(used);
        if done.is_some() {
            return Ok(Some(oversized));
        }
    }
}

/// What startup's replay did.
#[derive(Debug, Default)]
pub struct ReplayReport {
    pub read: ReadReport,
    /// `None` when the ledger backend cannot restore (raft): then nothing was restored on any
    /// ledger and nothing was listed.
    pub runs: Option<tokenfuse_core::Restored>,
    pub units_restored: usize,
    /// Unit halves from a window that is no longer the current month.
    pub units_other_month: usize,
    pub units_refused: usize,
    /// Restored reservations the registry did not list (past `MAX_RETAINED`); still held.
    pub unlisted: usize,
    /// Retained records a closure in the same journal names (id and revision): not restored.
    pub closed: usize,
    /// What a startup rewrite keeps: each still-open retained record once, in its canonical
    /// bytes, then every record of an unknown kind verbatim.
    pub keep: Vec<Vec<u8>>,
}

/// Put every retained reservation in the journal back on the ledgers and in the registry.
/// Called once at startup, before the listener binds and after the Cloud seeds (a unit seed is
/// refused once anything is outstanding on the unit).
pub fn replay(
    report: ReadReport,
    ledger: &dyn LedgerBackend,
    units: &UnitLedger,
    retained: &Retained,
    now_millis: i64,
) -> ReplayReport {
    let mut out = ReplayReport::default();
    let closed: std::collections::HashSet<(u64, &str)> = report
        .closures
        .iter()
        .map(|c| (c.reservation_id, c.revision.as_str()))
        .collect();
    let mut open: Vec<Record> = Vec::new();
    let mut kept = std::collections::HashSet::new();
    for r in &report.records {
        let revision = r.revision();
        if closed.contains(&(r.run.id, revision.as_str())) {
            out.closed += 1;
            continue;
        }
        if kept.insert(revision) {
            out.keep
                .push(serde_json::to_vec(r).expect("a record that was read serializes"));
        }
        open.push(r.clone());
    }
    out.keep.extend(report.other_kind_lines.iter().cloned());
    let entries: Vec<Outstanding> = open
        .iter()
        .map(|r| Outstanding {
            reservation: r.run.clone(),
            tail_parent: r.tail_parent.clone(),
        })
        .collect();
    let Some(runs) = ledger.restore_outstanding(&entries) else {
        out.read = report;
        return out;
    };
    let restored: std::collections::HashSet<u64> = runs.restored.iter().copied().collect();
    let mut listed_ids = std::collections::HashSet::new();
    for r in &open {
        // Only a record the run ledger took back is credited anywhere else, so a duplicate
        // line never counts its unit half twice.
        if !restored.contains(&r.run.id) || !listed_ids.insert(r.run.id) {
            continue;
        }
        if let Some(u) = &r.unit {
            match units.restore(u, now_millis) {
                RestoreOutcome::Applied => out.units_restored += 1,
                RestoreOutcome::OtherMonth => out.units_other_month += 1,
                RestoreOutcome::Negative => out.units_refused += 1,
            }
        }
        let listed = retained.push(RetainedReservation {
            run: r.run.clone(),
            unit: r.unit.clone(),
            model: r.model.clone(),
            retained_at_millis: r.retained_at_millis,
            revision: r.revision(),
            attribution: r.attribution.clone(),
        });
        if !listed {
            out.unlisted += 1;
        }
    }
    out.runs = Some(runs);
    out.read = report;
    out
}

/// Startup, once, before the listener binds: read the journal in `dir`, put its reservations
/// back on `state`'s ledgers and registry, credit a staged Cloud run seed (invariant 70) to
/// every run the restore created (the restore makes those runs exist, so the first request
/// would no longer see them as fresh and the seed would never land), and say what happened in
/// one line. A journal that exists and cannot be read is returned as the error, and the caller
/// refuses to start ([`startup_refusal`]): serving without the restored liability, with the id
/// and generation counters starting from zero while new retains keep being appended, would let
/// a later restart drop records as duplicate or superseded. A missing journal reads as empty.
pub async fn replay_at_startup(
    state: &crate::state::AppState,
    dir: &Path,
    now_millis: i64,
) -> io::Result<ReplayReport> {
    let read = read(dir)?;
    let records = read.records.len();
    let report = replay(
        read,
        state.ledger.as_ref(),
        &state.units,
        &state.retained,
        now_millis,
    );
    // D8: closures recorded in this journal keep answering their operation id after the
    // restart (one restart: the rewrite below drops them with the records they closed).
    if let Some(door) = state.closure.as_ref() {
        door.remember(&report.read.closures);
    }
    // D-3: the journal is rewritten with only what is still open. A failed rewrite leaves the
    // old file in place, which reads the same way (its closures still exclude what they close),
    // so it is an error line, not a refusal.
    if let Some(journal) = state.retained.journal() {
        match journal.rewrite(&report.keep) {
            Ok(()) => tracing::info!(
                path = %journal.path().display(),
                kept = report.keep.len(),
                closed = report.closed,
                "retained-reservation journal rewritten with only the records still open"
            ),
            Err(e) => tracing::error!(
                path = %journal.path().display(),
                error = %e,
                "the retained-reservation journal could not be rewritten; it keeps its closed records until the next start"
            ),
        }
    }
    let Some(runs) = report.runs.as_ref() else {
        if records > 0 {
            tracing::warn!(
                records,
                "this ledger backend cannot restore retained reservations (raft); the journal's records were left unrestored"
            );
        }
        return Ok(report);
    };
    // The restore leaves each recreated run's budget at zero. A run that later calls opens
    // itself with a budget, but a parent whose budget lives in the Cloud may never call, so
    // the proxy gives it that budget on a child's call, as it does for an unopened parent.
    state.note_restored_unbudgeted(runs.runs_created.iter().map(|(run, _)| run.clone()));
    let mut seeded = 0;
    let mut unseeded = Vec::new();
    for (run, generation) in &runs.runs_created {
        if let Some(seed) = state.take_run_seed(run) {
            if state.ledger.seed_spend(run, seed, *generation).await {
                seeded += 1;
            }
        } else if !state.seed.is_open() {
            unseeded.push((run.clone(), *generation));
        }
    }
    // Invariant 103: the control plane has not answered the seed yet, so these runs had none to
    // take; the retry that opens the gate credits them before it does.
    state.note_replayed_unseeded(unseeded);
    let skipped =
        report.read.malformed + report.read.oversized + runs.invalid + report.units_refused;
    let line = format!(
        "retained-reservation journal replayed: {} closed by D8 and not restored, {} restored, {} runs recreated ({seeded} with their Cloud seed), {} unit halves outstanding again, {} unit halves from a past month, {} duplicate, {} links on a superseded generation, {} unlisted past the registry cap; skipped {} malformed, {} oversized, {} invalid, {} of an unknown kind, {} negative unit halves",
        report.closed,
        runs.restored.len(),
        runs.runs_created.len(),
        report.units_restored,
        report.units_other_month,
        runs.duplicate,
        runs.links_dropped,
        report.unlisted,
        report.read.malformed,
        report.read.oversized,
        runs.invalid,
        report.read.other_kind,
        report.units_refused,
    );
    if skipped > 0 {
        tracing::warn!(path = %dir.join(FILE_NAME).display(), "{line}");
    } else {
        tracing::info!(path = %dir.join(FILE_NAME).display(), "{line}");
    }
    Ok(report)
}

/// The line `serve` prints before it exits 2 on a journal that exists and cannot be opened or
/// read: the path, the operating system's error, and why the gateway does not serve without it.
pub fn startup_refusal(path: &Path, error: &io::Error) -> String {
    format!(
        "the retained-reservation journal {} exists and cannot be read ({error}); refusing to start, because serving without it would admit calls against liability it holds and could later drop its records as duplicate. Fix the file so it can be read. Moving it away is not a fix: the gateway then starts with none of the retained liability it holds",
        path.display()
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ledger_backend::LocalLedger;
    use std::collections::HashMap;
    use std::sync::Arc;
    use tokenfuse_core::{Ledger, Microusd};

    fn scratch(name: &str) -> PathBuf {
        let d =
            std::env::temp_dir().join(format!("tf-retained-journal-{}-{name}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        d
    }

    /// Takes a real reservation pair the way a call does, so the record carries what the
    /// guard would hand the journal.
    fn retained_pair(
        ledger: &Ledger,
        units: &UnitLedger,
        run: &str,
        parent: Option<&str>,
        amount: Microusd,
        now: i64,
    ) -> (RetainedReservation, Option<String>) {
        if let Some(p) = parent {
            ledger.open_run(p, Microusd::from_usd(5.0), None).ok();
        }
        ledger
            .open_run(run, Microusd::from_usd(5.0), parent)
            .expect("opens");
        let r = ledger.reserve(run, amount).unwrap();
        let u = units.try_reserve("ops", amount, now).unwrap();
        let tail = ledger.tail_parent(&r);
        (
            RetainedReservation {
                run: r,
                unit: u,
                model: "m".into(),
                retained_at_millis: now,
                revision: String::new(),
                attribution: None,
            },
            tail,
        )
    }

    fn capped() -> UnitLedger {
        UnitLedger::new(HashMap::from([(
            "ops".to_string(),
            Microusd::from_usd(10.0),
        )]))
    }

    #[test]
    fn a_journal_round_trips_and_replays_onto_fresh_ledgers() {
        let dir = scratch("round-trip");
        let now = crate::sink::now_millis();
        let (old, old_units) = (Ledger::new(), capped());
        let (entry, tail) = retained_pair(
            &old,
            &old_units,
            "child",
            Some("parent"),
            Microusd(8_657),
            now,
        );
        Journal::open(&dir)
            .unwrap()
            .append(&Record::retained(&entry, tail))
            .unwrap();

        let ledger = Arc::new(Ledger::new());
        let units = capped();
        let registry = Retained::default();
        let report = replay(
            read(&dir).unwrap(),
            &LocalLedger(ledger.clone()),
            &units,
            &registry,
            now,
        );
        assert_eq!(report.runs.as_ref().unwrap().restored, vec![entry.run.id]);
        assert_eq!(report.units_restored, 1);
        assert_eq!(ledger.snapshot("child").unwrap().reserved, Microusd(8_657));
        assert_eq!(ledger.snapshot("parent").unwrap().reserved, Microusd(8_657));
        assert_eq!(units.reserved("ops", now), Microusd(8_657));
        assert_eq!(units.spent("ops", now), Microusd::ZERO);
        let listed = registry.for_run("child");
        assert_eq!(listed.len(), 1);
        assert_eq!(listed[0].run, entry.run);
        assert_eq!(listed[0].unit, entry.unit);
        assert_eq!(listed[0].retained_at_millis, now);
        std::fs::remove_dir_all(&dir).ok();
    }

    /// A unit half taken in a month that has since rolled over is not put back: the
    /// counters it belonged to are gone, exactly as `settle` treats it. The run half stays.
    #[test]
    fn a_unit_half_from_a_past_month_is_not_restored_and_the_run_half_is() {
        let july = 1_784_073_600_000; // 2026-07-15
        let august = july + 17 * 86_400_000;
        let (old, old_units) = (Ledger::new(), capped());
        let (entry, tail) = retained_pair(&old, &old_units, "r", None, Microusd(500), july);
        let ledger = Arc::new(Ledger::new());
        let units = capped();
        let registry = Retained::default();
        let report = replay(
            ReadReport {
                records: vec![Record::retained(&entry, tail)],
                ..Default::default()
            },
            &LocalLedger(ledger.clone()),
            &units,
            &registry,
            august,
        );
        assert_eq!((report.units_restored, report.units_other_month), (0, 1));
        assert_eq!(units.reserved("ops", august), Microusd::ZERO);
        assert_eq!(ledger.snapshot("r").unwrap().reserved, Microusd(500));
        assert_eq!(registry.len(), 1);
    }

    #[test]
    fn a_duplicated_line_is_restored_once_on_both_ledgers() {
        let now = crate::sink::now_millis();
        let (old, old_units) = (Ledger::new(), capped());
        let (entry, tail) = retained_pair(&old, &old_units, "r", None, Microusd(500), now);
        let rec = Record::retained(&entry, tail);
        let ledger = Arc::new(Ledger::new());
        let units = capped();
        let registry = Retained::default();
        let report = replay(
            ReadReport {
                records: vec![rec.clone(), rec],
                ..Default::default()
            },
            &LocalLedger(ledger.clone()),
            &units,
            &registry,
            now,
        );
        assert_eq!(report.runs.unwrap().duplicate, 1);
        assert_eq!(ledger.snapshot("r").unwrap().reserved, Microusd(500));
        assert_eq!(units.reserved("ops", now), Microusd(500));
        assert_eq!(registry.len(), 1);
    }

    /// A crash mid-append leaves a torn last line. Reading skips it and keeps every whole
    /// record; reopening terminates it, so the next record is a line of its own and parses.
    #[test]
    fn a_torn_final_line_is_skipped_and_never_fuses_with_the_next_record() {
        let dir = scratch("torn");
        let now = crate::sink::now_millis();
        let (old, old_units) = (Ledger::new(), capped());
        let (a, ta) = retained_pair(&old, &old_units, "a", None, Microusd(100), now);
        let (b, tb) = retained_pair(&old, &old_units, "b", None, Microusd(200), now);
        Journal::open(&dir)
            .unwrap()
            .append(&Record::retained(&a, ta))
            .unwrap();
        let mut half = serde_json::to_vec(&Record::retained(&b, tb.clone())).unwrap();
        half.truncate(half.len() / 2);
        OpenOptions::new()
            .append(true)
            .open(dir.join(FILE_NAME))
            .unwrap()
            .write_all(&half)
            .unwrap();
        let torn = read(&dir).unwrap();
        assert_eq!((torn.records.len(), torn.malformed), (1, 1));

        Journal::open(&dir)
            .unwrap()
            .append(&Record::retained(&b, tb))
            .unwrap();
        let healed = read(&dir).unwrap();
        assert_eq!((healed.records.len(), healed.malformed), (2, 1));
        assert_eq!(healed.records[1].run.run_id, "b");
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn a_missing_journal_is_empty_and_an_unknown_kind_is_counted_not_restored() {
        let dir = scratch("missing");
        let r = read(&dir).unwrap();
        assert!(r.records.is_empty() && r.malformed == 0);

        let now = crate::sink::now_millis();
        let (old, old_units) = (Ledger::new(), capped());
        let (entry, tail) = retained_pair(&old, &old_units, "r", None, Microusd(100), now);
        let mut other = Record::retained(&entry, tail);
        other.kind = "closed".into();
        let line = serde_json::to_string(&other).unwrap();
        let r = parse(io::Cursor::new(format!("{line}\n\n"))).unwrap();
        assert_eq!((r.records.len(), r.other_kind, r.malformed), (0, 1, 0));
    }

    #[test]
    fn a_line_over_the_bound_is_skipped_without_losing_its_neighbours() {
        let now = crate::sink::now_millis();
        let (old, old_units) = (Ledger::new(), capped());
        let (entry, tail) = retained_pair(&old, &old_units, "r", None, Microusd(100), now);
        let good = serde_json::to_string(&Record::retained(&entry, tail)).unwrap();
        let mut bytes = Vec::new();
        bytes.extend_from_slice(good.as_bytes());
        bytes.push(b'\n');
        bytes.extend(std::iter::repeat_n(b'x', MAX_LINE_BYTES + 10));
        bytes.push(b'\n');
        bytes.extend_from_slice(good.as_bytes());
        // A reader whose buffer is far smaller than the line, so the bound is crossed across
        // many `fill_buf` calls rather than once.
        let r = parse(BufReader::with_capacity(4096, io::Cursor::new(bytes))).unwrap();
        assert_eq!((r.records.len(), r.oversized, r.malformed), (2, 1, 0));
    }

    #[test]
    fn an_over_long_record_is_refused_by_the_writer_and_not_half_written() {
        let dir = scratch("over-long");
        let journal = Journal::open(&dir).unwrap();
        let now = crate::sink::now_millis();
        let (old, old_units) = (Ledger::new(), capped());
        let (mut entry, tail) = retained_pair(&old, &old_units, "r", None, Microusd(100), now);
        entry.model = "m".repeat(MAX_LINE_BYTES);
        assert!(journal.append(&Record::retained(&entry, tail)).is_err());
        assert_eq!(std::fs::metadata(journal.path()).unwrap().len(), 0);
        std::fs::remove_dir_all(&dir).ok();
    }

    /// Seeded sweep: arbitrary bytes, real records cut at random points, CR/LF noise and long
    /// runs. Parsing never panics, every whole record between the noise is found, and nothing
    /// that is not one is.
    #[test]
    fn hostile_journal_bytes_never_panic_and_never_invent_a_record() {
        let now = crate::sink::now_millis();
        let (old, old_units) = (Ledger::new(), capped());
        let (entry, tail) = retained_pair(&old, &old_units, "r", None, Microusd(100), now);
        let good = serde_json::to_vec(&Record::retained(&entry, tail)).unwrap();
        let mut x: u64 = 0x2545_f491_4f6c_dd1d;
        let mut next = move || {
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            x
        };
        for _ in 0..200 {
            let mut bytes = Vec::new();
            let mut whole = 0;
            for _ in 0..(next() % 10) {
                match next() % 5 {
                    0 => {
                        bytes.extend_from_slice(&good);
                        bytes.push(b'\n');
                        whole += 1;
                    }
                    1 => {
                        let cut = (next() as usize) % good.len();
                        bytes.extend_from_slice(&good[..cut]);
                        bytes.push(b'\n');
                    }
                    2 => {
                        for _ in 0..(next() % 300) {
                            let b = (next() % 256) as u8;
                            bytes.push(if b == b'\n' { b'x' } else { b });
                        }
                        bytes.push(b'\n');
                    }
                    3 => bytes.extend_from_slice(b"\r\n\n  \n"),
                    _ => bytes.extend_from_slice(b"{\"kind\":\"retained\"}\n"),
                }
            }
            let cap = 1 + (next() % 64) as usize;
            let r = parse(BufReader::with_capacity(cap, io::Cursor::new(bytes))).unwrap();
            assert_eq!(r.records.len(), whole);
            assert!(r.records.iter().all(|rec| rec.run == entry.run));
        }
    }

    /// Invariant 70 credits a staged Cloud run seed when the first request opens a run fresh.
    /// A restore makes the run exist before that request, so `replay_at_startup` credits the
    /// seed itself, at the generation the run came back at; without it the seed would never
    /// land and the run would restart its spend from zero.
    #[tokio::test]
    async fn a_restored_run_still_gets_its_staged_cloud_seed() {
        let dir = scratch("seed");
        let now = crate::sink::now_millis();
        let (old, old_units) = (Ledger::new(), capped());
        let (entry, tail) = retained_pair(&old, &old_units, "child", None, Microusd(300), now);
        Journal::open(&dir)
            .unwrap()
            .append(&Record::retained(&entry, tail))
            .unwrap();
        let ledger = Arc::new(Ledger::new());
        let state = crate::state::AppState::new(
            ledger.clone(),
            Arc::new(tokenfuse_core::PriceBook::new()),
            Arc::new(tokenfuse_core::Policy::default()),
            Arc::new(crate::provider::StubProvider::default()),
            "t",
        );
        state.set_run_seed(HashMap::from([
            ("child".to_string(), Microusd(5_000)),
            ("elsewhere".to_string(), Microusd(7)),
        ]));
        let report = replay_at_startup(&state, &dir, now).await.unwrap();
        assert_eq!(report.runs.unwrap().restored, vec![entry.run.id]);
        let child = ledger.snapshot("child").unwrap();
        assert_eq!(child.reserved, Microusd(300));
        assert_eq!(child.spent, Microusd(5_000));
        assert_eq!(state.take_run_seed("child"), None, "taken, at most once");
        assert_eq!(state.take_run_seed("elsewhere"), Some(Microusd(7)));
        std::fs::remove_dir_all(&dir).ok();
    }

    /// D-2: a journal that exists and cannot be read is the caller's error to refuse on, never
    /// an empty restore; a missing journal is an empty one.
    #[tokio::test]
    async fn an_unreadable_journal_is_an_error_and_a_missing_one_is_empty() {
        let state = crate::state::AppState::new(
            Arc::new(Ledger::new()),
            Arc::new(tokenfuse_core::PriceBook::new()),
            Arc::new(tokenfuse_core::Policy::default()),
            Arc::new(crate::provider::StubProvider::default()),
            "t",
        );
        let missing = scratch("missing");
        std::fs::create_dir_all(&missing).unwrap();
        let report = replay_at_startup(&state, &missing, 0).await.unwrap();
        assert!(report.read.records.is_empty());

        let unreadable = scratch("unreadable");
        std::fs::create_dir_all(unreadable.join(FILE_NAME)).unwrap();
        let err = replay_at_startup(&state, &unreadable, 0)
            .await
            .expect_err("a journal that cannot be read must not replay as empty");
        let line = startup_refusal(&unreadable.join(FILE_NAME), &err);
        assert!(line.contains(&unreadable.join(FILE_NAME).display().to_string()));
        assert!(line.contains(&err.to_string()));
        std::fs::remove_dir_all(&missing).ok();
        std::fs::remove_dir_all(&unreadable).ok();
    }

    fn closure_of(entry: &RetainedReservation, revision: &str) -> ClosureRecord {
        ClosureRecord {
            v: 1,
            kind: KIND_CLOSURE.into(),
            reservation_id: entry.run.id,
            revision: revision.into(),
            operation_id: "op".into(),
            evidence_kind: "no_charge".into(),
            observed_microusd: None,
            evidence_ref: "invoice".into(),
            settled_microusd: 0,
            run_id: entry.run.run_id.clone(),
            unit: None,
            closed_at_millis: 1,
        }
    }

    /// D-3. The rewrite keeps each still-open record once and every record of a kind this
    /// version does not know, verbatim; it drops closed records, their closures, torn lines
    /// and duplicates. The file then reads back to the same open set with the same revisions,
    /// and the append handle writes to the new file.
    #[test]
    fn a_rewrite_keeps_only_open_records_and_unknown_kinds_with_stable_revisions() {
        let dir = scratch("rewrite");
        let now = crate::sink::now_millis();
        let (old, old_units) = (Ledger::new(), capped());
        let (a, ta) = retained_pair(&old, &old_units, "a", None, Microusd(100), now);
        let (b, tb) = retained_pair(&old, &old_units, "b", None, Microusd(200), now);
        let (ra, rb) = (Record::retained(&a, ta), Record::retained(&b, tb));
        let journal = Journal::open(&dir).unwrap();
        journal.append(&ra).unwrap();
        journal.append(&rb).unwrap();
        journal.append(&rb).unwrap();
        journal
            .append_closure(&closure_of(&a, &ra.revision()))
            .unwrap();
        let future = br#"{"v":9,"kind":"from_a_later_version","x":1}"#;
        let mut raw = OpenOptions::new()
            .append(true)
            .open(dir.join(FILE_NAME))
            .unwrap();
        raw.write_all(future).unwrap();
        raw.write_all(b"\n{\"kind\":\"retained\",\"v\":1,\"ru")
            .unwrap();
        drop(raw);

        let ledger = Arc::new(Ledger::new());
        let units = capped();
        let report = replay(
            read(&dir).unwrap(),
            &LocalLedger(ledger.clone()),
            &units,
            &Retained::default(),
            now,
        );
        assert_eq!(report.closed, 1);
        assert!(
            ledger.snapshot("a").is_none(),
            "the closed record is not restored"
        );
        assert_eq!(ledger.snapshot("b").unwrap().reserved, Microusd(200));
        journal.rewrite(&report.keep).unwrap();
        let text = std::fs::read_to_string(dir.join(FILE_NAME)).unwrap();
        assert_eq!(text.lines().count(), 2, "{text}");
        assert!(text.lines().any(|l| l.as_bytes() == future), "{text}");
        assert!(!dir.join(TEMP_FILE_NAME).exists());

        let again = read(&dir).unwrap();
        assert_eq!(again.records, vec![rb.clone()]);
        assert_eq!(again.records[0].revision(), rb.revision());
        assert_eq!(
            (again.closures.len(), again.malformed, again.other_kind),
            (0, 0, 1)
        );
        let (c, tc) = retained_pair(&old, &old_units, "c", None, Microusd(300), now);
        journal.append(&Record::retained(&c, tc)).unwrap();
        assert_eq!(
            read(&dir).unwrap().records.len(),
            2,
            "appends land on the new file"
        );
        std::fs::remove_dir_all(&dir).ok();
    }

    /// A closure names a revision, not only an id: a record that reuses a closed record's id
    /// (ids are unique only within one lineage of the journal) is still restored.
    #[test]
    fn a_closure_excludes_only_the_revision_it_names() {
        let now = crate::sink::now_millis();
        let (old, old_units) = (Ledger::new(), capped());
        let (a, ta) = retained_pair(&old, &old_units, "a", None, Microusd(100), now);
        let ra = Record::retained(&a, ta);
        let ledger = Arc::new(Ledger::new());
        let report = replay(
            ReadReport {
                records: vec![ra.clone()],
                closures: vec![closure_of(&a, "0000000000000000")],
                ..Default::default()
            },
            &LocalLedger(ledger.clone()),
            &capped(),
            &Retained::default(),
            now,
        );
        assert_eq!(report.closed, 0);
        assert_eq!(ledger.snapshot("a").unwrap().reserved, Microusd(100));
        assert_eq!(report.keep.len(), 1);
    }

    /// D8.1. A line written before `attribution` existed carries exactly the seven older
    /// members; it reads with no attribution, and its revision is still the hash of the bytes
    /// on disk, so a closure (or a token) minted against it still names it after the upgrade.
    /// A line that does carry an attribution round-trips it.
    #[test]
    fn a_line_from_before_the_attribution_field_keeps_its_revision() {
        use sha2::{Digest, Sha256};
        let now = crate::sink::now_millis();
        let (old, old_units) = (Ledger::new(), capped());
        let (a, ta) = retained_pair(&old, &old_units, "a", None, Microusd(100), now);
        let mut record = Record::retained(&a, ta);
        record.attribution = None;
        let line = serde_json::to_vec(&record).unwrap();
        let keys: Vec<String> = serde_json::from_slice::<serde_json::Value>(&line)
            .unwrap()
            .as_object()
            .unwrap()
            .keys()
            .cloned()
            .collect();
        let mut expected = vec![
            "kind",
            "model",
            "retained_at_millis",
            "run",
            "tail_parent",
            "unit",
            "v",
        ];
        expected.sort();
        assert_eq!(keys, expected, "the older line shape, member for member");

        let mut h = Sha256::new();
        h.update(b"tokenfuse-retained-revision-v1\n");
        h.update(&line);
        let on_disk: String = h.finalize()[..8]
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect();
        let parsed: Record = serde_json::from_slice(&line).unwrap();
        assert_eq!(parsed.attribution, None);
        assert_eq!(parsed.revision(), on_disk);

        let ledger = Arc::new(Ledger::new());
        let report = replay(
            ReadReport {
                records: vec![parsed],
                closures: vec![closure_of(&a, &on_disk)],
                ..Default::default()
            },
            &LocalLedger(ledger.clone()),
            &capped(),
            &Retained::default(),
            now,
        );
        assert_eq!(report.closed, 1, "the closure still names the older line");
        assert!(ledger.snapshot("a").is_none());

        record.attribution = Some(RowAttribution {
            agent_id: "agent://acme/bot".into(),
            unit: "ops".into(),
            ..Default::default()
        });
        let line = serde_json::to_vec(&record).unwrap();
        let back: Record = serde_json::from_slice(&line).unwrap();
        assert_eq!(back, record);
        assert_ne!(
            back.revision(),
            on_disk,
            "the attribution is part of what a token binds"
        );
    }

    /// A rewrite that fails before its rename leaves the journal exactly as it was, and the
    /// append handle still writes to it.
    #[test]
    fn a_rewrite_that_fails_leaves_the_journal_as_it_was() {
        let dir = scratch("rewrite-fails");
        let now = crate::sink::now_millis();
        let (old, old_units) = (Ledger::new(), capped());
        let (a, ta) = retained_pair(&old, &old_units, "a", None, Microusd(100), now);
        let journal = Journal::open(&dir).unwrap();
        journal.append(&Record::retained(&a, ta.clone())).unwrap();
        let before = std::fs::read(dir.join(FILE_NAME)).unwrap();
        std::fs::create_dir_all(dir.join(TEMP_FILE_NAME)).unwrap();
        assert!(journal.rewrite(&[]).is_err());
        assert_eq!(std::fs::read(dir.join(FILE_NAME)).unwrap(), before);
        journal.append(&Record::retained(&a, ta)).unwrap();
        assert_eq!(read(&dir).unwrap().records.len(), 2);
        std::fs::remove_dir_all(&dir).ok();
    }
}
