//! The checkpoint sidecar of agent-passport SPEC 6.5.1, format v1: signed
//! checkpoints of this process's own agent-event stream, so that a witness
//! (keyryx) can later prove that no byte a checkpoint covers was rewritten
//! (CLAUDE.md invariant 128).
//!
//! A record names how many lines the stream held (`count`), the SPEC 6.5
//! chain hash of the last of them (`head`), and the SHA-256 of every byte
//! through that line's LF (`prefix`), and chains to the record before it
//! (`prev`). It is signed ES256 when a key certified by keyryx is valid at the
//! record's `at`; when none is, it is written unsigned with `unsigned_reason`
//! and never dropped.
//!
//! # What lives here and what does not
//!
//! The bytes of a record, the running prefix, the chain of records and when a
//! record is due all live in this crate, because the exporter that writes the
//! stream ([`crate::agent_event::Exporter`]) lives here and a record has to be
//! taken under the same lock that orders the stream's lines. The key does not:
//! ECDSA and the keyryx client need `p256` and an HTTP client, which this
//! crate may not depend on (invariant 1). A key reaches this module only as a
//! [`CheckpointSigner`], which the gateway implements.
//!
//! # The rules this file holds
//!
//! - A record is the RFC 8785 serialization of its own object
//!   ([`crate::jcs`]), followed by one LF, so a Go writer and this one agree on
//!   the bytes. Pinned against agent-passport's `checkpoint-vectors.json`
//!   (vendored byte-identical in `crates/core/testdata`).
//! - `prefix` is hashed from the stream as it stands: a line this writer
//!   appended is fed into the running hash only when the file grew by exactly
//!   that line, and anything else (another writer, a torn append) is read back
//!   from the file. A stream found shorter than what was hashed is hashed again
//!   from byte zero before any record is written.
//! - A line is named as a `head` only when agent-stack-go's verifier would call
//!   it a well-formed event ([`head_of_line`]); a record naming any other line
//!   is one that verifier refuses.
//! - The key is chosen for the record's own `at`, so the record a witness checks
//!   against a key statement is signed by a key that statement certifies at
//!   that instant.

use std::collections::VecDeque;
use std::fs::{File, OpenOptions};
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use std::sync::Arc;

use serde_json::{Map, Value};
use sha2::{Digest, Sha256};

/// The format version, `v`.
pub const FORMAT_VERSION: u64 = 1;
/// Lines between two `checkpoint` records (SPEC 6.5.1).
pub const EVERY_LINES: u64 = 64;
/// The longest time a written line waits for a record (SPEC 6.5.1).
pub const INTERVAL_MILLIS: i64 = 10_000;
/// The `prev` of the first record of a file.
pub const GENESIS: &str = "sha256:0000000000000000000000000000000000000000000000000000000000000000";
/// The one algorithm v1 signs with.
pub const ALG: &str = "ES256";
/// The one `unsigned_reason` value format v1 lists.
pub const KEY_EXPIRED: &str = "key_expired";
/// A stream's sidecar is `<stream>` followed by this.
pub const SIDECAR_SUFFIX: &str = ".ckpt.ndjson";
/// A line longer than this is never named as a head: agent-stack-go's
/// `resumeWindow`, past which its verifier calls a line not well-formed.
pub const LINE_CAP: usize = 4 << 20;
/// keyryx's `MaxRecord`: a longer record line is refused by the witness, so
/// one is never written.
pub const RECORD_CAP: usize = 4096;
/// How many of a stream's last lines are kept at open to find the line a
/// `resume` record names.
const RESUME_WINDOW: usize = 4096;
/// The longest last line of a sidecar this writer will read to chain from.
const SIDECAR_TAIL_CAP: u64 = 16 << 20;

/// A clock in milliseconds since the Unix epoch. Tests inject one.
pub type Clock = Arc<dyn Fn() -> i64 + Send + Sync>;

/// The wall clock.
pub fn system_clock() -> Clock {
    Arc::new(|| {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_millis() as i64)
            .unwrap_or(0)
    })
}

/// The kind of a record.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Kind {
    /// Every [`EVERY_LINES`] lines or [`INTERVAL_MILLIS`], whichever first.
    Checkpoint,
    /// On a clean close.
    Close,
    /// When the writer reopened a stream whose tail it could not chain from.
    Resume,
}

impl Kind {
    pub fn as_str(self) -> &'static str {
        match self {
            Kind::Checkpoint => "checkpoint",
            Kind::Close => "close",
            Kind::Resume => "resume",
        }
    }
}

/// A key that may sign records. Implemented outside this crate.
pub trait CheckpointKey: Send + Sync {
    /// The RFC 7638 thumbprint of the key, base64url without padding.
    fn kid(&self) -> &str;
    /// ES256 over SHA-256 of `signing_input`: r then s, 32 big-endian bytes
    /// each (RFC 7518 section 3.4).
    fn sign(&self, signing_input: &[u8]) -> Result<[u8; 64], String>;
}

/// Why no key could sign at an instant. Format v1 has one word for all three,
/// `key_expired`; the three are kept apart for the operator's log only.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NoKey {
    /// keyryx has not certified a key for this process yet.
    NeverCertified,
    /// A key is certified, and its statement starts after this instant.
    NotYetValid,
    /// Every key certified so far ran out before this instant.
    Expired,
}

impl NoKey {
    pub fn describe(self) -> &'static str {
        match self {
            NoKey::NeverCertified => "no key has been certified by keyryx yet",
            NoKey::NotYetValid => "the certified key's statement has not started yet",
            NoKey::Expired => "every certified key's statement has run out",
        }
    }
}

/// The source of keys, asked once per record for the key valid at its `at`.
pub trait CheckpointSigner: Send + Sync {
    fn key_at(&self, at_millis: i64) -> Result<Arc<dyn CheckpointKey>, NoKey>;
}

/// The members of one record before its key is chosen.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Fields {
    pub kind: Kind,
    pub stream: String,
    pub count: u64,
    pub head: String,
    pub prefix: String,
    /// The record's time; `at` is formatted from it, and the key is chosen for it.
    pub at_millis: i64,
    pub prev: String,
}

/// One encoded record, without its LF.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Encoded {
    Signed {
        kid: String,
        /// The JCS serialization of the record with `sig` removed.
        signing_input: Vec<u8>,
        record: Vec<u8>,
    },
    Unsigned {
        reason: NoKey,
        record: Vec<u8>,
    },
}

impl Encoded {
    pub fn record(&self) -> &[u8] {
        match self {
            Encoded::Signed { record, .. } | Encoded::Unsigned { record, .. } => record,
        }
    }

    pub fn is_signed(&self) -> bool {
        matches!(self, Encoded::Signed { .. })
    }
}

/// `at` in the one form v1 allows, `YYYY-MM-DDTHH:MM:SS.sssZ`.
pub fn format_at(at_millis: i64) -> String {
    crate::timefmt::ts_millis_to_rfc3339_millis(at_millis)
}

fn body(f: &Fields) -> Map<String, Value> {
    let mut m = Map::new();
    m.insert("v".into(), Value::from(FORMAT_VERSION));
    m.insert("kind".into(), Value::from(f.kind.as_str()));
    m.insert("stream".into(), Value::from(f.stream.as_str()));
    m.insert("count".into(), Value::from(f.count));
    m.insert("head".into(), Value::from(f.head.as_str()));
    m.insert("prefix".into(), Value::from(f.prefix.as_str()));
    m.insert("at".into(), Value::from(format_at(f.at_millis)));
    m.insert("prev".into(), Value::from(f.prev.as_str()));
    m
}

fn canonical(m: &Map<String, Value>) -> Vec<u8> {
    crate::jcs::canonicalize(&Value::Object(m.clone())).into_bytes()
}

/// Encode one record: signed by the key valid at `fields.at_millis`, or
/// unsigned with `unsigned_reason` when there is none. An error means the key
/// could not sign, and no record should be written.
pub fn encode(fields: &Fields, signer: &dyn CheckpointSigner) -> Result<Encoded, String> {
    let mut m = body(fields);
    match signer.key_at(fields.at_millis) {
        Err(reason) => {
            m.insert("unsigned_reason".into(), Value::from(KEY_EXPIRED));
            Ok(Encoded::Unsigned {
                reason,
                record: canonical(&m),
            })
        }
        Ok(key) => {
            let kid = key.kid().to_string();
            m.insert("alg".into(), Value::from(ALG));
            m.insert("kid".into(), Value::from(kid.as_str()));
            let signing_input = canonical(&m);
            let sig = key.sign(&signing_input)?;
            m.insert("sig".into(), Value::from(base64url(&sig)));
            Ok(Encoded::Signed {
                kid,
                signing_input,
                record: canonical(&m),
            })
        }
    }
}

/// `sha256:` and the lowercase hex of SHA-256 over `bytes`.
pub fn sha256_hex(bytes: &[u8]) -> String {
    hex_digest(Sha256::digest(bytes).as_slice())
}

fn hex_digest(digest: &[u8]) -> String {
    use std::fmt::Write as _;
    let mut s = String::with_capacity(7 + 64);
    s.push_str("sha256:");
    for b in digest {
        let _ = write!(s, "{b:02x}");
    }
    s
}

/// Unpadded base64url (RFC 4648 section 5).
pub fn base64url(bytes: &[u8]) -> String {
    const T: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    let mut out = String::with_capacity(bytes.len().div_ceil(3) * 4);
    for chunk in bytes.chunks(3) {
        let b1 = chunk.get(1).copied().unwrap_or(0);
        let b2 = chunk.get(2).copied().unwrap_or(0);
        let n = (u32::from(chunk[0]) << 16) | (u32::from(b1) << 8) | u32::from(b2);
        out.push(T[((n >> 18) & 63) as usize] as char);
        out.push(T[((n >> 12) & 63) as usize] as char);
        if chunk.len() > 1 {
            out.push(T[((n >> 6) & 63) as usize] as char);
        }
        if chunk.len() > 2 {
            out.push(T[(n & 63) as usize] as char);
        }
    }
    out
}

/// The sidecar file name of a stream: `<stream>.ckpt.ndjson`.
pub fn sidecar_name(stream: &str) -> String {
    format!("{stream}{SIDECAR_SUFFIX}")
}

/// Whether `name` is a stream name keyryx accepts in a record:
/// `^[A-Za-z0-9][A-Za-z0-9._-]{0,250}\.ndjson$`.
pub fn stream_name_is_valid(name: &str) -> bool {
    let Some(stem) = name.strip_suffix(".ndjson") else {
        return false;
    };
    let b = stem.as_bytes();
    !b.is_empty()
        && b.len() <= 251
        && b[0].is_ascii_alphanumeric()
        && b.iter()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, b'.' | b'_' | b'-'))
}

/// The SPEC 6.5 chain hash of one stream line (without its LF), when
/// agent-stack-go's verifier would call it a well-formed event; `None`
/// otherwise.
///
/// Its rule, followed here: at most [`LINE_CAP`] bytes; after trimming, an
/// object whose `schema`, `ts`, `source`, `type` and `agent_id` are non-empty
/// strings, and whose typed optional members (`severity`, `run_id`,
/// `prev_hash` strings, `on_behalf_of` a list of strings, `data` an object)
/// have their types. Go matches a key to a field in any case; a key that
/// differs from a field name only in case is refused here, so this is never
/// more lenient than the verifier, only possibly stricter.
pub fn head_of_line(line: &[u8]) -> Option<String> {
    if line.len() > LINE_CAP {
        return None;
    }
    let value: Value = serde_json::from_slice(line.trim_ascii()).ok()?;
    if !is_event(&value) {
        return None;
    }
    Some(crate::agent_event::chain_hash_value(value))
}

fn is_event(value: &Value) -> bool {
    const REQUIRED: [&str; 5] = ["schema", "ts", "source", "type", "agent_id"];
    const STRINGS: [&str; 3] = ["severity", "run_id", "prev_hash"];
    let Some(obj) = value.as_object() else {
        return false;
    };
    for key in obj.keys() {
        let lower = key.to_ascii_lowercase();
        let known = REQUIRED.contains(&lower.as_str())
            || STRINGS.contains(&lower.as_str())
            || lower == "on_behalf_of"
            || lower == "data";
        if known && lower != *key {
            return false;
        }
    }
    let required = REQUIRED.iter().all(|k| {
        obj.get(*k)
            .and_then(Value::as_str)
            .is_some_and(|s| !s.is_empty())
    });
    let strings = STRINGS.iter().all(|k| {
        matches!(
            obj.get(*k),
            None | Some(Value::Null) | Some(Value::String(_))
        )
    });
    let chain = match obj.get("on_behalf_of") {
        None | Some(Value::Null) => true,
        Some(Value::Array(items)) => items
            .iter()
            .all(|i| matches!(i, Value::Null | Value::String(_))),
        Some(_) => false,
    };
    let data = matches!(
        obj.get("data"),
        None | Some(Value::Null) | Some(Value::Object(_))
    );
    required && strings && chain && data
}

/// What a writer is told to do, when its sidecar is attached.
#[derive(Clone)]
pub struct CheckpointConfig {
    /// The checkpoints directory, separate from the stream's own directory.
    pub dir: PathBuf,
    pub signer: Arc<dyn CheckpointSigner>,
    pub clock: Clock,
}

/// What attaching the sidecar found.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Opened {
    pub sidecar: PathBuf,
    /// Lines the stream held, every LF-terminated line counted.
    pub stream_lines: u64,
    /// Whether the sidecar already held records, so the first one written now
    /// chains to the last of them rather than starting at the genesis value.
    pub continued: bool,
    /// Bytes of a torn final record cut from the sidecar.
    pub cut_torn_bytes: u64,
    /// The line a `resume` record named, when one was written.
    pub resume: Option<u64>,
    /// The writer could not chain from the stream's tail and found no
    /// well-formed line among the last lines it kept, so no `resume` was
    /// written.
    pub resume_unfound: bool,
}

/// Counters a process logs from, read with [`Checkpointer::stats`].
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct CheckpointStats {
    pub signed: u64,
    pub unsigned: u64,
    pub errors: u64,
    /// Whether the last record written was signed.
    pub last_signed: Option<bool>,
    /// Why the last unsigned record was unsigned.
    pub last_unsigned_reason: Option<NoKey>,
    pub last_error: Option<String>,
}

/// One LF-terminated line seen by a scan.
#[derive(Clone)]
struct Mark {
    line: u64,
    start: u64,
    end: u64,
    /// The running hash through this line's LF.
    sum: Sha256,
}

struct Scanned {
    sum: Sha256,
    off: u64,
    count: u64,
    marks: VecDeque<Mark>,
}

/// Hash `file` from `start` to its current end, through the last LF, keeping
/// the last `keep` lines' marks. `sum` holds the bytes before `start`.
fn scan(file: &File, start: u64, sum: Sha256, count: u64, keep: usize) -> std::io::Result<Scanned> {
    let mut f = file;
    let len = f.metadata()?.len();
    f.seek(SeekFrom::Start(start))?;
    let mut reader = f.take(len.saturating_sub(start));
    let mut buf = vec![0u8; 64 << 10];
    let mut running = sum;
    let mut at_off = running.clone();
    let (mut pos, mut off, mut count) = (start, start, count);
    let mut line_start = start;
    let mut marks = VecDeque::new();
    loop {
        let n = reader.read(&mut buf)?;
        if n == 0 {
            break;
        }
        let mut p = &buf[..n];
        while !p.is_empty() {
            match p.iter().position(|b| *b == b'\n') {
                None => {
                    running.update(p);
                    pos += p.len() as u64;
                    p = &[];
                }
                Some(i) => {
                    running.update(&p[..=i]);
                    pos += i as u64 + 1;
                    count += 1;
                    off = pos;
                    at_off = running.clone();
                    if keep > 0 {
                        marks.push_back(Mark {
                            line: count,
                            start: line_start,
                            end: off,
                            sum: at_off.clone(),
                        });
                        if marks.len() > keep {
                            marks.pop_front();
                        }
                    }
                    line_start = off;
                    p = &p[i + 1..];
                }
            }
        }
    }
    Ok(Scanned {
        sum: at_off,
        off,
        count,
        marks,
    })
}

/// The head of the line a mark names, read back from the file.
fn head_at(file: &File, m: &Mark) -> Option<String> {
    let len = (m.end - 1).checked_sub(m.start)?;
    if len > LINE_CAP as u64 {
        return None;
    }
    let mut f = file;
    f.seek(SeekFrom::Start(m.start)).ok()?;
    let mut line = vec![0u8; len as usize];
    f.read_exact(&mut line).ok()?;
    head_of_line(&line)
}

/// The `prev` the next record carries, the length of the sidecar's complete
/// records, and its whole length.
fn sidecar_tail(file: &File) -> Result<(String, u64, u64), String> {
    let mut f = file;
    let total = f
        .metadata()
        .map_err(|e| format!("cannot read the checkpoint file: {e}"))?
        .len();
    if total == 0 {
        return Ok((GENESIS.to_string(), 0, 0));
    }
    let mut window: u64 = 8192;
    loop {
        let start = total.saturating_sub(window);
        let mut buf = vec![0u8; (total - start) as usize];
        f.seek(SeekFrom::Start(start))
            .and_then(|_| f.read_exact(&mut buf))
            .map_err(|e| format!("cannot read the checkpoint file: {e}"))?;
        let Some(last) = buf.iter().rposition(|b| *b == b'\n') else {
            if start == 0 {
                // No complete record at all: everything there is torn.
                return Ok((GENESIS.to_string(), 0, total));
            }
            if window >= SIDECAR_TAIL_CAP {
                return Err(format!(
                    "the checkpoint file ends in more than {SIDECAR_TAIL_CAP} bytes with no line end; \
                     it is not a file this writer wrote"
                ));
            }
            window *= 2;
            continue;
        };
        let complete = start + last as u64 + 1;
        match buf[..last].iter().rposition(|b| *b == b'\n') {
            Some(j) => return Ok((sha256_hex(&buf[j + 1..last]), complete, total)),
            None if start == 0 => return Ok((sha256_hex(&buf[..last]), complete, total)),
            None => {
                if window >= SIDECAR_TAIL_CAP {
                    return Err(format!(
                        "the checkpoint file's last record is over {SIDECAR_TAIL_CAP} bytes; \
                         it is not a file this writer wrote"
                    ));
                }
                window *= 2;
            }
        }
    }
}

fn open_sidecar(path: &Path) -> std::io::Result<File> {
    let mut o = OpenOptions::new();
    o.create(true).read(true).append(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        o.mode(0o640);
    }
    o.open(path)
}

/// The sidecar writer of one stream. Every method runs under the exporter's
/// sink lock, the stream's single serialization point.
pub struct Checkpointer {
    stream: String,
    sidecar_path: PathBuf,
    sidecar: File,
    /// The length of the sidecar's complete records, to cut a torn append.
    sidecar_len: u64,
    signer: Arc<dyn CheckpointSigner>,
    clock: Clock,
    /// SHA-256 over the stream's bytes `[0, off)`.
    sum: Sha256,
    /// The offset just after the last LF hashed.
    off: u64,
    /// Lines through `off`.
    count: u64,
    /// The head of line `count`, when it is a well-formed event.
    head: Option<String>,
    prev: String,
    /// Lines hashed since the last record.
    pending: u64,
    last_at: i64,
    stats: CheckpointStats,
}

impl std::fmt::Debug for Checkpointer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Checkpointer")
            .field("stream", &self.stream)
            .field("sidecar", &self.sidecar_path)
            .field("off", &self.off)
            .field("count", &self.count)
            .field("pending", &self.pending)
            .finish_non_exhaustive()
    }
}

impl Checkpointer {
    /// Open the sidecar of the stream at `stream_path`, whose open file is
    /// `stream`, hashing the stream once from byte zero. `fresh_chain` says
    /// whether the exporter could not chain from the stream's tail, in which
    /// case a `resume` record names the last well-formed line found there.
    pub fn open(
        cfg: CheckpointConfig,
        stream_path: &Path,
        stream: &File,
        fresh_chain: bool,
    ) -> Result<(Self, Opened), String> {
        let name = stream_path
            .file_name()
            .and_then(|n| n.to_str())
            .ok_or_else(|| format!("the stream path '{}' names no file", stream_path.display()))?;
        if !stream_name_is_valid(name) {
            return Err(format!(
                "the stream's file name '{name}' is not one a checkpoint record may name \
                 (a letter or digit, then letters, digits, '.', '_' or '-', ending in .ndjson, \
                 at most 258 characters)"
            ));
        }
        let stream_dir = stream_path
            .parent()
            .filter(|p| !p.as_os_str().is_empty())
            .unwrap_or_else(|| Path::new("."));
        let same = match (stream_dir.canonicalize(), cfg.dir.canonicalize()) {
            (Ok(a), Ok(b)) => a == b,
            _ => stream_dir == cfg.dir,
        };
        if same {
            return Err(format!(
                "the checkpoints directory '{}' is the stream's own directory; SPEC 6.5.1 puts the \
                 sidecar in a directory of its own, because its name ends in .ndjson and a reader \
                 globbing for streams would take it for one",
                cfg.dir.display()
            ));
        }
        let sidecar_path = cfg.dir.join(sidecar_name(name));
        let sidecar = open_sidecar(&sidecar_path).map_err(|e| {
            format!(
                "cannot open the checkpoint file '{}': {e}",
                sidecar_path.display()
            )
        })?;
        match sidecar.try_lock() {
            Ok(()) => {}
            Err(std::fs::TryLockError::WouldBlock) => {
                return Err(format!(
                    "the checkpoint file '{}' is held by another process; only one writer may \
                     write a stream's checkpoints",
                    sidecar_path.display()
                ))
            }
            Err(std::fs::TryLockError::Error(e)) => {
                return Err(format!(
                    "cannot lock the checkpoint file '{}': {e}",
                    sidecar_path.display()
                ))
            }
        }
        let (prev, complete, total) = sidecar_tail(&sidecar)?;
        if total > complete {
            sidecar
                .set_len(complete)
                .map_err(|e| format!("cannot cut a torn record from the checkpoint file: {e}"))?;
        }
        let scanned = scan(stream, 0, Sha256::new(), 0, RESUME_WINDOW)
            .map_err(|e| format!("cannot read the stream to hash it: {e}"))?;
        let head = scanned.marks.back().and_then(|m| head_at(stream, m));
        let now = (cfg.clock)();
        let mut ck = Checkpointer {
            stream: name.to_string(),
            sidecar_path: sidecar_path.clone(),
            sidecar,
            sidecar_len: complete,
            signer: cfg.signer,
            clock: cfg.clock,
            sum: scanned.sum,
            off: scanned.off,
            count: scanned.count,
            head,
            prev,
            pending: 0,
            last_at: now,
            stats: CheckpointStats::default(),
        };
        let mut opened = Opened {
            sidecar: sidecar_path,
            stream_lines: scanned.count,
            continued: complete > 0,
            cut_torn_bytes: total - complete,
            resume: None,
            resume_unfound: false,
        };
        if fresh_chain && scanned.count > 0 {
            let found = scanned
                .marks
                .iter()
                .rev()
                .find_map(|m| head_at(stream, m).map(|h| (m.line, h, m.sum.clone())));
            match found {
                Some((line, head, sum)) => {
                    let prefix = hex_digest(sum.finalize().as_slice());
                    ck.write_record(Kind::Resume, line, head, prefix, now)?;
                    opened.resume = Some(line);
                }
                None => opened.resume_unfound = true,
            }
        }
        Ok((ck, opened))
    }

    /// The path of the sidecar.
    pub fn sidecar_path(&self) -> &Path {
        &self.sidecar_path
    }

    pub fn stats(&self) -> CheckpointStats {
        self.stats.clone()
    }

    /// Whether the next line must start with an LF because the stream ends in
    /// bytes after its last LF (a torn append, or a writer killed mid-line), so
    /// that the line is not glued onto the fragment.
    pub fn needs_newline(&self, stream: &File) -> bool {
        let Ok(len) = stream.metadata().map(|m| m.len()) else {
            return false;
        };
        if len == self.off || len == 0 {
            return false;
        }
        let mut f = stream;
        let mut last = [0u8; 1];
        f.seek(SeekFrom::Start(len - 1))
            .and_then(|_| f.read_exact(&mut last))
            .map(|_| last[0] != b'\n')
            .unwrap_or(false)
    }

    /// After the exporter appended `written` (one or more LF-terminated lines,
    /// the last of which is its own event, whose chain hash is `own_head`), hash
    /// what the stream gained and write a record when one is due. Never fails:
    /// an error is counted in [`Self::stats`], and the event is already on disk.
    pub fn after_append(&mut self, stream: &File, written: &[u8], own_head: Option<&str>) {
        let len = stream.metadata().map(|m| m.len());
        match len {
            Ok(len) if len == self.off + written.len() as u64 && written.ends_with(b"\n") => {
                self.sum.update(written);
                self.off = len;
                let lines = written.iter().filter(|b| **b == b'\n').count() as u64;
                self.count += lines;
                self.pending += lines;
                self.head = own_head.map(str::to_string);
            }
            _ => {
                if let Err(e) = self.advance(stream) {
                    self.note_error(format!("cannot read the stream to hash it: {e}"));
                    return;
                }
            }
        }
        let now = (self.clock)();
        self.maybe_write(now);
    }

    /// Hash what the stream gained since `off`, read from the file: lines
    /// another writer appended, or a fragment terminated since. A stream found
    /// shorter than `off` is hashed again from byte zero.
    fn advance(&mut self, stream: &File) -> std::io::Result<()> {
        let len = stream.metadata()?.len();
        if len < self.off {
            self.sum = Sha256::new();
            self.off = 0;
            self.count = 0;
            self.head = None;
        }
        if len == self.off {
            return Ok(());
        }
        let scanned = scan(stream, self.off, self.sum.clone(), self.count, 1)?;
        let added = scanned.count - self.count;
        if added > 0 {
            self.head = scanned.marks.back().and_then(|m| head_at(stream, m));
        }
        self.sum = scanned.sum;
        self.off = scanned.off;
        self.count = scanned.count;
        self.pending += added;
        Ok(())
    }

    /// Write a `checkpoint` when lines are waiting and the interval has passed.
    pub fn tick(&mut self) {
        let now = (self.clock)();
        self.maybe_write(now);
    }

    fn maybe_write(&mut self, now: i64) {
        if self.pending == 0 {
            return;
        }
        if self.pending < EVERY_LINES && now - self.last_at < INTERVAL_MILLIS {
            return;
        }
        // The last line is not an event, so there is no head to name. The next
        // line that is one will be checkpointed.
        let Some(head) = self.head.clone() else {
            return;
        };
        let prefix = self.prefix();
        let _ = self.write_record(Kind::Checkpoint, self.count, head, prefix, now);
    }

    /// The current `prefix`: SHA-256 of the stream through line `count`.
    fn prefix(&self) -> String {
        hex_digest(self.sum.clone().finalize().as_slice())
    }

    /// Write the `close` record, on a clean close. Returns the count it named,
    /// or `None` when the stream holds no event to name.
    pub fn close(&mut self, stream: &File) -> Result<Option<u64>, String> {
        self.advance(stream)
            .map_err(|e| format!("cannot read the stream to hash it: {e}"))?;
        let Some(head) = self.head.clone() else {
            return Ok(None);
        };
        if self.count == 0 {
            return Ok(None);
        }
        let now = (self.clock)();
        let prefix = self.prefix();
        self.write_record(Kind::Close, self.count, head, prefix, now)?;
        Ok(Some(self.count))
    }

    fn note_error(&mut self, message: String) {
        self.stats.errors += 1;
        self.stats.last_error = Some(message);
    }

    /// Build, sign and append one record, then chain the next one from it. A
    /// failed append is cut off again, so the sidecar never keeps a torn record.
    fn write_record(
        &mut self,
        kind: Kind,
        count: u64,
        head: String,
        prefix: String,
        now: i64,
    ) -> Result<(), String> {
        let fields = Fields {
            kind,
            stream: self.stream.clone(),
            count,
            head,
            prefix,
            at_millis: now,
            prev: self.prev.clone(),
        };
        let encoded = match encode(&fields, self.signer.as_ref()) {
            Ok(e) => e,
            Err(e) => {
                let msg = format!("the checkpoint key could not sign: {e}");
                self.note_error(msg.clone());
                return Err(msg);
            }
        };
        let record = encoded.record();
        if record.len() > RECORD_CAP {
            let msg = format!(
                "a checkpoint record of {} bytes is over keyryx's {RECORD_CAP}-byte cap",
                record.len()
            );
            self.note_error(msg.clone());
            return Err(msg);
        }
        let mut line = Vec::with_capacity(record.len() + 1);
        line.extend_from_slice(record);
        line.push(b'\n');
        if let Err(e) = self.sidecar.write_all(&line) {
            let _ = self.sidecar.set_len(self.sidecar_len);
            let msg = format!(
                "cannot append to the checkpoint file '{}': {e}",
                self.sidecar_path.display()
            );
            self.note_error(msg.clone());
            return Err(msg);
        }
        self.sidecar_len += line.len() as u64;
        self.prev = sha256_hex(record);
        self.last_at = now;
        self.pending = 0;
        match &encoded {
            Encoded::Signed { .. } => {
                self.stats.signed += 1;
                self.stats.last_signed = Some(true);
            }
            Encoded::Unsigned { reason, .. } => {
                self.stats.unsigned += 1;
                self.stats.last_signed = Some(false);
                self.stats.last_unsigned_reason = Some(*reason);
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests;
