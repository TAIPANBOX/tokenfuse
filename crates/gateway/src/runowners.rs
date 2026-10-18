//! Who opened a run (CLAUDE.md invariant 120).
//!
//! A run id is chosen by the caller, so possession of one proves nothing: until 2026-10-18 a
//! caller holding client key B could name a run key A had opened, spend in it, read its labels
//! in a taint `403`, and declare it as the parent of a run of its own, which rolled B's spend
//! into A's budget and gave B's run A's labels. The tool-call check already answered a caller
//! only about its own runs (invariant 118); the metered door recorded the owner and checked
//! nothing.
//!
//! A run belongs to the PRINCIPAL whose metered call first named it. A principal is the
//! credential the door verified, never anything the caller wrote: `key:<key_id>` for a static
//! client key, `tok:<sub>` for an agent token (the token door is a later change; the namespace
//! is fixed here so a key and a token that happen to share a name can never be one owner). With
//! client keys off the principal is empty and nothing is recorded, so a gateway that
//! authenticates nobody behaves exactly as before.
//!
//! With `TOKENFUSE_DATA_DIR` set, each first claim of a run appends one NDJSON line to
//! `<dir>/run-owners.ndjson` and syncs it before the call goes on, and startup reads the file
//! back before the listener binds, so a restart does not hand every run to whoever names it
//! first afterwards. The file is read as hostile input, the shape of the retained-reservation
//! journal (`crate::retainedjournal`, whose bounded line reader this shares): a line over the
//! bound is skipped unread, a line that does not parse or names no principal is skipped and
//! counted, a torn final line is terminated on open so it never fuses with the next record, and
//! the first record for a run wins, as the first claim did. Startup rewrites the file with one
//! line per run. A journal that exists and cannot be read refuses to start.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs::{File, OpenOptions};
use std::io::{self, BufRead, BufReader, Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use std::sync::Mutex;

/// The journal's file name inside the data directory.
pub const FILE_NAME: &str = "run-owners.ndjson";

/// The temp file a startup rewrite builds before renaming it over the journal.
pub const TEMP_FILE_NAME: &str = "run-owners.ndjson.tmp";

/// The namespace of a static client key's principal.
pub const KEY_PREFIX: &str = "key:";

/// The namespace of an agent token's principal (the subject the token names).
pub const TOKEN_PREFIX: &str = "tok:";

/// The startup line when client keys are configured and no data dir is.
pub const PROCESS_LOCAL_LINE: &str = "run ownership is process-local: TOKENFUSE_DATA_DIR is not set, so a restart forgets which principal opened each run and the first caller to name a run after it owns it";

/// The startup line when client keys are not configured.
pub const OFF_LINE: &str = "run ownership off: TOKENFUSE_CLIENT_KEYS is not set, so no run has an owner and any caller may name any run or parent";

/// The principal a static client key authenticates as, or empty when there is no key (client
/// authentication off).
pub fn key_principal(key_id: &str) -> String {
    if key_id.is_empty() {
        String::new()
    } else {
        format!("{KEY_PREFIX}{key_id}")
    }
}

/// The principal an agent token authenticates as, from its subject, or empty for none.
pub fn token_principal(subject: &str) -> String {
    if subject.is_empty() {
        String::new()
    } else {
        format!("{TOKEN_PREFIX}{subject}")
    }
}

/// The client key id a `key:` principal names, or `None` for any other principal.
pub fn key_of(principal: &str) -> Option<&str> {
    principal
        .strip_prefix(KEY_PREFIX)
        .filter(|rest| !rest.is_empty())
}

/// Whether `s` is a principal this module can have written: a known namespace and a name.
pub fn is_principal(s: &str) -> bool {
    [KEY_PREFIX, TOKEN_PREFIX]
        .iter()
        .any(|p| s.strip_prefix(p).is_some_and(|rest| !rest.is_empty()))
}

/// What [`RunOwners::claim`] found.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Claim {
    /// The caller has no principal (client authentication off): nothing is recorded.
    Unowned,
    /// No principal had named the run; the caller owns it now.
    Opened,
    /// The run was already the caller's.
    Own,
    /// The run belongs to the principal named here. For the operator's log, never the caller's
    /// answer.
    Elsewhere(String),
}

/// One journal line: a run and the principal that opened it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Record {
    /// Format version, written as 1. Not checked on read.
    pub v: u32,
    pub run_id: String,
    pub owner: String,
    pub at_millis: i64,
}

impl Record {
    fn is_valid(&self) -> bool {
        !self.run_id.is_empty() && is_principal(&self.owner)
    }
}

/// Run id to the principal that opened it, first claim wins.
#[derive(Debug, Default)]
pub struct RunOwners {
    owners: Mutex<HashMap<String, String>>,
    journal: Option<Journal>,
}

impl RunOwners {
    /// An owner map whose first claims are appended to `journal`.
    pub fn with_journal(journal: Journal) -> Self {
        RunOwners {
            owners: Mutex::new(HashMap::new()),
            journal: Some(journal),
        }
    }

    pub fn journal(&self) -> Option<&Journal> {
        self.journal.as_ref()
    }

    /// Claim `run_id` for `principal`, or say whose it is.
    ///
    /// First claim wins: a later principal naming the same run never takes it over. A first
    /// claim is appended to the journal and synced before this returns, outside the map's
    /// lock, so one slow disk does not hold every other caller's lookup. A write that fails is
    /// one error line and the claim stands for this process.
    pub fn claim(&self, run_id: &str, principal: &str) -> Claim {
        if run_id.is_empty() || principal.is_empty() {
            return Claim::Unowned;
        }
        {
            let mut owners = self.owners.lock().unwrap_or_else(|p| p.into_inner());
            match owners.get(run_id) {
                Some(o) if o == principal => return Claim::Own,
                Some(o) => return Claim::Elsewhere(o.clone()),
                None => {
                    owners.insert(run_id.to_string(), principal.to_string());
                }
            }
        }
        if let Some(journal) = &self.journal {
            let record = Record {
                v: 1,
                run_id: run_id.to_string(),
                owner: principal.to_string(),
                at_millis: crate::sink::now_millis(),
            };
            if let Err(e) = journal.append(&record) {
                tracing::error!(
                    path = %journal.path().display(),
                    run = %run_id,
                    error = %e,
                    "the run-owner journal could not take this run's owner; the run is owned in this process only"
                );
            }
        }
        Claim::Opened
    }

    /// The principal that owns `run_id`, if any keyed call has named it.
    pub fn owner(&self, run_id: &str) -> Option<String> {
        self.owners
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .get(run_id)
            .cloned()
    }

    /// Load replayed records, first per run wins, without journaling them again. Returns how
    /// many runs were loaded.
    pub fn load(&self, records: &[Record]) -> usize {
        let mut owners = self.owners.lock().unwrap_or_else(|p| p.into_inner());
        let mut loaded = 0;
        for r in records.iter().filter(|r| r.is_valid()) {
            if let std::collections::hash_map::Entry::Vacant(e) = owners.entry(r.run_id.clone()) {
                e.insert(r.owner.clone());
                loaded += 1;
            }
        }
        loaded
    }

    pub fn len(&self) -> usize {
        self.owners.lock().unwrap_or_else(|p| p.into_inner()).len()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

/// An open, append-only run-owner journal.
#[derive(Debug)]
pub struct Journal {
    path: PathBuf,
    file: Mutex<File>,
}

impl Journal {
    /// Open (creating) `<dir>/run-owners.ndjson` for appending. A file that ends in a torn
    /// line gets a newline first, so the next record starts a line of its own.
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
        } else if let Ok(d) = File::open(dir) {
            let _ = d.sync_all();
        }
        Ok(Journal {
            path,
            file: Mutex::new(file),
        })
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Append one record and sync it before returning, one `write_all` under the lock.
    pub fn append(&self, record: &Record) -> io::Result<()> {
        let mut line = serde_json::to_vec(record).map_err(io::Error::other)?;
        line.push(b'\n');
        if line.len() > crate::retainedjournal::MAX_LINE_BYTES {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!(
                    "record is {} bytes, over the {}-byte line limit",
                    line.len(),
                    crate::retainedjournal::MAX_LINE_BYTES
                ),
            ));
        }
        let mut file = self.file.lock().unwrap_or_else(|p| p.into_inner());
        file.write_all(&line)?;
        file.sync_data()
    }

    /// Replace the journal with exactly `records`, atomically: a temp file beside it, synced,
    /// renamed over it, the directory synced, the append handle reopened, all under the append
    /// lock. On any error the journal is left as it was.
    pub fn rewrite(&self, records: &[Record]) -> io::Result<()> {
        let dir = self.path.parent().unwrap_or(Path::new("."));
        let temp = dir.join(TEMP_FILE_NAME);
        let mut file = self.file.lock().unwrap_or_else(|p| p.into_inner());
        {
            let mut t = OpenOptions::new()
                .create(true)
                .write(true)
                .truncate(true)
                .open(&temp)?;
            for r in records {
                let mut line = serde_json::to_vec(r).map_err(io::Error::other)?;
                line.push(b'\n');
                t.write_all(&line)?;
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
    /// Every valid record, in file order, duplicates included.
    pub records: Vec<Record>,
    /// Lines that are not a record (a torn final line among them).
    pub malformed: usize,
    /// Lines over the bound, skipped unread.
    pub oversized: usize,
    /// Records that parse and name no run or no known principal.
    pub invalid: usize,
}

/// Read `<dir>/run-owners.ndjson`. A missing file is an empty report.
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
    while let Some(oversized) = crate::retainedjournal::next_line(&mut reader, &mut line)? {
        if oversized {
            report.oversized += 1;
            continue;
        }
        let trimmed = line.trim_ascii();
        if trimmed.is_empty() {
            continue;
        }
        match serde_json::from_slice::<Record>(trimmed) {
            Ok(r) if r.is_valid() => report.records.push(r),
            Ok(_) => report.invalid += 1,
            Err(_) => report.malformed += 1,
        }
    }
    Ok(report)
}

/// The first record per run, in file order, and how many later ones were dropped.
pub fn distinct(records: &[Record]) -> (Vec<Record>, usize) {
    let mut seen = std::collections::HashSet::new();
    let mut out = Vec::new();
    let mut duplicate = 0;
    for r in records {
        if seen.insert(r.run_id.clone()) {
            out.push(r.clone());
        } else {
            duplicate += 1;
        }
    }
    (out, duplicate)
}

/// What startup's replay did.
#[derive(Debug, Default)]
pub struct ReplayReport {
    pub read: ReadReport,
    pub loaded: usize,
    pub duplicate: usize,
}

/// Put every owner the journal holds back into `owners`, then rewrite the journal with one line
/// per run. Called once, before the listener binds. A journal that exists and cannot be read is
/// the error, and the caller refuses to start ([`startup_refusal`]): serving without it would
/// hand every run it names to the first caller after the restart. A failed rewrite leaves the
/// old file, which reads the same way, and is one error line.
pub fn replay_at_startup(owners: &RunOwners, dir: &Path) -> io::Result<ReplayReport> {
    let read = read(dir)?;
    let (kept, duplicate) = distinct(&read.records);
    let loaded = owners.load(&kept);
    if let Some(journal) = owners.journal() {
        if let Err(e) = journal.rewrite(&kept) {
            tracing::error!(
                path = %journal.path().display(),
                error = %e,
                "the run-owner journal could not be rewritten; it keeps its duplicate lines until the next start"
            );
        }
    }
    let line = format!(
        "run-owner journal replayed: {loaded} runs owned, {duplicate} duplicate lines dropped; skipped {} malformed, {} oversized, {} naming no principal",
        read.malformed, read.oversized, read.invalid
    );
    if read.malformed + read.oversized + read.invalid > 0 {
        tracing::warn!(path = %dir.join(FILE_NAME).display(), "{line}");
    } else {
        tracing::info!(path = %dir.join(FILE_NAME).display(), "{line}");
    }
    Ok(ReplayReport {
        read,
        loaded,
        duplicate,
    })
}

/// The line `serve` prints before it exits 2 on a run-owner journal that exists and cannot be
/// opened or read.
pub fn startup_refusal(path: &Path, error: &io::Error) -> String {
    format!(
        "the run-owner journal {} exists and cannot be read ({error}); refusing to start, because serving without it would let the first caller after this restart own every run it names. Fix the file so it can be read. Moving it away is not a fix: the gateway then starts with no run owned by anybody",
        path.display()
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn scratch(name: &str) -> PathBuf {
        let d = std::env::temp_dir().join(format!("tf-run-owners-{}-{name}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    fn record(run: &str, owner: &str) -> Record {
        Record {
            v: 1,
            run_id: run.into(),
            owner: owner.into(),
            at_millis: 1_700_000_000_000,
        }
    }

    fn line(r: &Record) -> Vec<u8> {
        let mut l = serde_json::to_vec(r).unwrap();
        l.push(b'\n');
        l
    }

    #[test]
    fn a_key_and_a_token_with_the_same_name_are_different_principals() {
        assert_eq!(key_principal("ops"), "key:ops");
        assert_eq!(token_principal("ops"), "tok:ops");
        assert_ne!(key_principal("ops"), token_principal("ops"));
        assert_eq!(key_principal(""), "", "no key is no principal");
        assert_eq!(token_principal(""), "", "no subject is no principal");
        assert_eq!(key_of("key:ops"), Some("ops"));
        assert_eq!(key_of("tok:ops"), None, "a token is not a client key");
        assert_eq!(key_of("key:"), None);
        assert!(is_principal("key:a") && is_principal("tok:a"));
        assert!(!is_principal("ops"));
        assert!(!is_principal("key:"));
        assert!(!is_principal(""));
    }

    #[test]
    fn a_first_claim_owns_the_run_and_a_second_principal_is_elsewhere() {
        let owners = RunOwners::default();
        assert_eq!(owners.claim("r", "key:a"), Claim::Opened);
        assert_eq!(owners.claim("r", "key:a"), Claim::Own);
        assert_eq!(
            owners.claim("r", "key:b"),
            Claim::Elsewhere("key:a".into()),
            "a second principal never takes a run over"
        );
        assert_eq!(
            owners.claim("r", "tok:a"),
            Claim::Elsewhere("key:a".into()),
            "a token named like the key is another principal"
        );
        assert_eq!(owners.owner("r").as_deref(), Some("key:a"));
    }

    #[test]
    fn an_empty_principal_claims_nothing() {
        let owners = RunOwners::default();
        assert_eq!(owners.claim("r", ""), Claim::Unowned);
        assert_eq!(owners.owner("r"), None, "client auth off records no owner");
        assert_eq!(owners.claim("r", "key:a"), Claim::Opened);
        assert_eq!(
            owners.claim("r", ""),
            Claim::Unowned,
            "an unauthenticated caller is not refused here: with keys off nobody is"
        );
    }

    #[test]
    fn a_claim_is_journaled_and_replayed_first_owner_wins() {
        let dir = scratch("replay");
        {
            let owners = RunOwners::with_journal(Journal::open(&dir).unwrap());
            assert_eq!(owners.claim("r1", "key:a"), Claim::Opened);
            assert_eq!(owners.claim("r2", "key:b"), Claim::Opened);
            assert!(matches!(owners.claim("r1", "key:b"), Claim::Elsewhere(_)));
        }
        let after = RunOwners::with_journal(Journal::open(&dir).unwrap());
        let report = replay_at_startup(&after, &dir).unwrap();
        assert_eq!(report.loaded, 2, "{report:?}");
        assert_eq!(after.owner("r1").as_deref(), Some("key:a"));
        assert_eq!(after.owner("r2").as_deref(), Some("key:b"));
        assert_eq!(
            after.claim("r1", "key:b"),
            Claim::Elsewhere("key:a".into()),
            "the owner survived the restart"
        );
        assert_eq!(after.claim("r1", "key:a"), Claim::Own);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn startup_rewrites_the_journal_with_one_line_per_run() {
        let dir = scratch("compact");
        let mut bytes = Vec::new();
        bytes.extend(line(&record("r1", "key:a")));
        bytes.extend(line(&record("r1", "key:b")));
        bytes.extend(b"not json\n");
        bytes.extend(line(&record("r2", "tok:agent")));
        bytes.extend(line(&record("r3", "nobody")));
        std::fs::write(dir.join(FILE_NAME), &bytes).unwrap();

        let owners = RunOwners::with_journal(Journal::open(&dir).unwrap());
        let report = replay_at_startup(&owners, &dir).unwrap();
        assert_eq!(
            (
                report.loaded,
                report.duplicate,
                report.read.malformed,
                report.read.invalid
            ),
            (2, 1, 1, 1),
            "{report:?}"
        );
        assert_eq!(
            owners.owner("r1").as_deref(),
            Some("key:a"),
            "the first line for a run wins, as the first claim did"
        );
        assert_eq!(
            owners.owner("r3"),
            None,
            "a record naming no principal is skipped"
        );

        let rewritten = read(&dir).unwrap();
        assert_eq!(
            rewritten.records,
            vec![record("r1", "key:a"), record("r2", "tok:agent")],
            "one line per run, nothing malformed kept"
        );
        assert_eq!(rewritten.malformed + rewritten.invalid, 0);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_truncated_journal_replays_every_whole_line_and_never_a_torn_one() {
        let records = [
            record("run-1", "key:alpha"),
            record("run-two", "key:b"),
            record("r3", "tok:agent://acme/x"),
            record("run-1", "key:b"),
            record("a-much-longer-run-identifier-0123456789", "key:alpha"),
        ];
        let mut bytes = Vec::new();
        let mut ends = Vec::new();
        for r in &records {
            bytes.extend(line(r));
            ends.push(bytes.len() - 1);
        }
        let dir = scratch("truncate");
        for cut in 0..=bytes.len() {
            std::fs::write(dir.join(FILE_NAME), &bytes[..cut]).unwrap();
            let journal = Journal::open(&dir).unwrap();
            let report = read(&dir).unwrap();
            let whole: Vec<Record> = records
                .iter()
                .zip(&ends)
                .filter(|(_, end)| **end <= cut)
                .map(|(r, _)| r.clone())
                .collect();
            assert_eq!(
                report.records, whole,
                "cut at {cut}: every whole line and nothing else"
            );
            assert!(report.malformed <= 1, "cut at {cut}: at most the torn line");

            journal.append(&record("after-the-cut", "key:z")).unwrap();
            let again = read(&dir).unwrap();
            let mut expected = whole.clone();
            expected.push(record("after-the-cut", "key:z"));
            assert_eq!(
                again.records, expected,
                "cut at {cut}: a record written after the cut never fuses with the torn line"
            );
            assert_eq!(
                again.invalid, 0,
                "cut at {cut}: no line became a different, valid-looking record"
            );
        }
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn hostile_journal_bytes_never_panic_and_never_invent_an_owner() {
        let mut seed: u64 = 0x5eed_0f0e_4e45;
        let mut next = || {
            seed ^= seed << 13;
            seed ^= seed >> 7;
            seed ^= seed << 17;
            seed
        };
        let alphabet: &[u8] = b"{}[]\":,\n\r\\ key:tok:run_idowneratv1-0123456789abc\x00\xff\xc3";
        for round in 0..200 {
            let len = (next() % 512) as usize;
            let mut bytes: Vec<u8> = (0..len)
                .map(|_| alphabet[(next() % alphabet.len() as u64) as usize])
                .collect();
            if round % 3 == 0 {
                bytes.push(b'\n');
                bytes.extend(line(&record("real", "key:real")));
            }
            let report = parse(&bytes[..]).unwrap();
            for r in &report.records {
                assert!(
                    is_principal(&r.owner) && !r.run_id.is_empty(),
                    "round {round}: a record with no principal was read: {r:?}"
                );
            }
            if round % 3 == 0 {
                assert!(
                    report.records.contains(&record("real", "key:real")),
                    "round {round}: a whole line after hostile bytes is still read"
                );
            }
        }
    }

    #[test]
    fn an_unreadable_journal_is_an_error_and_a_missing_one_is_empty() {
        let missing = scratch("missing");
        let report = read(&missing).unwrap();
        assert!(report.records.is_empty());
        let _ = std::fs::remove_dir_all(&missing);

        let broken = scratch("is-a-directory");
        std::fs::create_dir(broken.join(FILE_NAME)).unwrap();
        assert!(
            read(&broken).is_err(),
            "a journal that exists and cannot be read is an error, never an empty journal"
        );
        assert!(Journal::open(&broken).is_err());
        let line = startup_refusal(&broken.join(FILE_NAME), &io::Error::other("boom"));
        assert!(line.contains(FILE_NAME) && line.contains("boom"), "{line}");
        let _ = std::fs::remove_dir_all(&broken);
    }
}
