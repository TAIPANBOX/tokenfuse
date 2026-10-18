//! Who opened a run (CLAUDE.md invariant 120).
//!
//! SCAFFOLD for the red-first commit: the names the tests use exist and keep
//! today's behaviour (the owner is the raw key id, first write wins, nobody is
//! refused, nothing is journaled). The next commit fills them in.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs::{File, OpenOptions};
use std::io::{self, BufRead};
use std::path::{Path, PathBuf};
use std::sync::Mutex;

pub const FILE_NAME: &str = "run-owners.ndjson";
pub const TEMP_FILE_NAME: &str = "run-owners.ndjson.tmp";
pub const KEY_PREFIX: &str = "key:";
pub const TOKEN_PREFIX: &str = "tok:";
pub const PROCESS_LOCAL_LINE: &str = "";
pub const OFF_LINE: &str = "";

pub fn key_principal(key_id: &str) -> String {
    key_id.to_string()
}

pub fn token_principal(subject: &str) -> String {
    subject.to_string()
}

pub fn key_of(principal: &str) -> Option<&str> {
    Some(principal).filter(|p| !p.is_empty())
}

pub fn is_principal(s: &str) -> bool {
    !s.is_empty()
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Claim {
    Unowned,
    Opened,
    Own,
    Elsewhere(String),
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Record {
    pub v: u32,
    pub run_id: String,
    pub owner: String,
    pub at_millis: i64,
}

#[derive(Debug, Default)]
pub struct RunOwners {
    owners: Mutex<HashMap<String, String>>,
    journal: Option<Journal>,
}

impl RunOwners {
    pub fn with_journal(journal: Journal) -> Self {
        RunOwners {
            owners: Mutex::new(HashMap::new()),
            journal: Some(journal),
        }
    }

    pub fn journal(&self) -> Option<&Journal> {
        self.journal.as_ref()
    }

    pub fn claim(&self, run_id: &str, principal: &str) -> Claim {
        if run_id.is_empty() || principal.is_empty() {
            return Claim::Unowned;
        }
        self.owners
            .lock()
            .unwrap()
            .entry(run_id.to_string())
            .or_insert_with(|| principal.to_string());
        Claim::Own
    }

    pub fn owner(&self, run_id: &str) -> Option<String> {
        self.owners.lock().unwrap().get(run_id).cloned()
    }

    pub fn load(&self, _records: &[Record]) -> usize {
        0
    }

    pub fn len(&self) -> usize {
        self.owners.lock().unwrap().len()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

#[derive(Debug)]
pub struct Journal {
    path: PathBuf,
    #[allow(dead_code)]
    file: Mutex<File>,
}

impl Journal {
    pub fn open(dir: &Path) -> io::Result<Journal> {
        std::fs::create_dir_all(dir)?;
        let path = dir.join(FILE_NAME);
        let file = OpenOptions::new().create(true).append(true).open(&path)?;
        Ok(Journal {
            path,
            file: Mutex::new(file),
        })
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    pub fn append(&self, _record: &Record) -> io::Result<()> {
        Ok(())
    }

    pub fn rewrite(&self, _records: &[Record]) -> io::Result<()> {
        Ok(())
    }
}

#[derive(Debug, Default)]
pub struct ReadReport {
    pub records: Vec<Record>,
    pub malformed: usize,
    pub oversized: usize,
    pub invalid: usize,
}

pub fn read(_dir: &Path) -> io::Result<ReadReport> {
    Ok(ReadReport::default())
}

pub fn parse<R: BufRead>(_reader: R) -> io::Result<ReadReport> {
    Ok(ReadReport::default())
}

pub fn distinct(records: &[Record]) -> (Vec<Record>, usize) {
    (records.to_vec(), 0)
}

#[derive(Debug, Default)]
pub struct ReplayReport {
    pub read: ReadReport,
    pub loaded: usize,
    pub duplicate: usize,
}

pub fn replay_at_startup(_owners: &RunOwners, _dir: &Path) -> io::Result<ReplayReport> {
    Ok(ReplayReport::default())
}

pub fn startup_refusal(path: &Path, _error: &io::Error) -> String {
    path.display().to_string()
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
        let mut seed: u64 = 0x5eed_0f_0e4e_45;
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
