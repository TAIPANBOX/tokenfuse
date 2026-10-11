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
//! Append-only. Nothing here removes a line: closing a retained reservation is D8, decided
//! (`@decided 2026-10-11`) and not built, and until it is every retained reservation is
//! outstanding for good, so every line stays true. A record of a `kind` this version does not
//! know is counted and skipped, never read as a closure.
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

/// The one `kind` this version writes and restores.
pub const KIND_RETAINED: &str = "retained";

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
}

impl Record {
    pub fn retained(entry: &RetainedReservation, tail_parent: Option<String>) -> Self {
        Record {
            v: 1,
            kind: KIND_RETAINED.into(),
            run: entry.run.clone(),
            tail_parent,
            unit: entry.unit.clone(),
            model: entry.model.clone(),
            retained_at_millis: entry.retained_at_millis,
        }
    }
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
}

/// What reading a journal found, every skip counted.
#[derive(Debug, Default)]
pub struct ReadReport {
    pub records: Vec<Record>,
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
        match serde_json::from_slice::<Record>(trimmed) {
            Ok(r) if r.kind == KIND_RETAINED => report.records.push(r),
            Ok(_) => report.other_kind += 1,
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
    let entries: Vec<Outstanding> = report
        .records
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
    for r in &report.records {
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
    for (run, generation) in &runs.runs_created {
        if let Some(seed) = state.take_run_seed(run) {
            if state.ledger.seed_spend(run, seed, *generation).await {
                seeded += 1;
            }
        }
    }
    let skipped =
        report.read.malformed + report.read.oversized + runs.invalid + report.units_refused;
    let line = format!(
        "retained-reservation journal replayed: {} restored, {} runs recreated ({seeded} with their Cloud seed), {} unit halves outstanding again, {} unit halves from a past month, {} duplicate, {} links on a superseded generation, {} unlisted past the registry cap; skipped {} malformed, {} oversized, {} invalid, {} of an unknown kind, {} negative unit halves",
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
        "the retained-reservation journal {} exists and cannot be read ({error}); refusing to start, because serving without it would admit calls against liability it holds and could later drop its records as duplicate. Fix or move the file; a missing journal starts empty",
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
}
