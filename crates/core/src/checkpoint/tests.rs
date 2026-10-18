//! Tests for the checkpoint sidecar (invariant 128). Scenarios:
//! `features/signed-checkpoints-of-the-event-stream.feature`.
//!
//! The verifier below is written from SPEC 6.5.1's own steps and shares no
//! code with the writer beyond `crate::jcs`, which is pinned against the Go and
//! Python implementations elsewhere. It is checked first against agent-passport's
//! vectors, positive and negative, so that a record it accepts here is one the
//! SPEC accepts. Signatures are checked in the gateway, which has ECDSA.

use super::*;
use crate::agent_event::{EventType, Exporter};
use std::collections::HashMap;
use std::sync::atomic::{AtomicI64, Ordering};
use std::sync::Mutex;

const VECTORS: &str = include_str!("../../testdata/checkpoint-vectors.json");
/// SHA-256 of agent-passport's `examples/checkpoint-vectors.json` at
/// 1a98ca4c703931cfbb2cc51fad1c5b332647dbd6 (2026-10-18), the same bytes
/// agent-stack-go vendors.
const VECTORS_SHA256: &str =
    "sha256:7b6454853a48a3e20d0dd2c1be2bf9a25ddb88224205ea4211f0bc3bb5b76b63";

fn vectors() -> Value {
    serde_json::from_str(VECTORS).expect("the vendored vectors parse")
}

fn temp_dir(tag: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("tf-ckpt-{}-{tag}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(dir.join("events")).unwrap();
    std::fs::create_dir_all(dir.join("checkpoints")).unwrap();
    dir
}

// -- signers ---------------------------------------------------------------

/// A key that signs every input with a fixed, recognisable 64-byte value, so a
/// record is "signed" without ECDSA. Real signatures are checked in the gateway.
struct FakeKey {
    kid: String,
    fail: bool,
}

impl CheckpointKey for FakeKey {
    fn kid(&self) -> &str {
        &self.kid
    }
    fn sign(&self, signing_input: &[u8]) -> Result<[u8; 64], String> {
        if self.fail {
            return Err("the key refused".into());
        }
        let d = Sha256::digest(signing_input);
        let mut out = [0u8; 64];
        out[..32].copy_from_slice(&d);
        out[32..].copy_from_slice(&d);
        Ok(out)
    }
}

/// Answers a fake key, nothing, or a failing key, and remembers every instant
/// it was asked about.
struct TestSigner {
    answer: Mutex<Result<bool, NoKey>>,
    asked: Mutex<Vec<i64>>,
}

impl TestSigner {
    fn signing() -> Arc<Self> {
        Arc::new(TestSigner {
            answer: Mutex::new(Ok(false)),
            asked: Mutex::new(vec![]),
        })
    }
    fn none(reason: NoKey) -> Arc<Self> {
        Arc::new(TestSigner {
            answer: Mutex::new(Err(reason)),
            asked: Mutex::new(vec![]),
        })
    }
    fn set(&self, a: Result<bool, NoKey>) {
        *self.answer.lock().unwrap() = a;
    }
}

const TEST_KID: &str = "FXG0i91Nag8j0ITnQFhO8mLmW8ijBkZvamjNsS9g1dE";

impl CheckpointSigner for TestSigner {
    fn key_at(&self, at_millis: i64) -> Result<Arc<dyn CheckpointKey>, NoKey> {
        self.asked.lock().unwrap().push(at_millis);
        match *self.answer.lock().unwrap() {
            Ok(fail) => Ok(Arc::new(FakeKey {
                kid: TEST_KID.into(),
                fail,
            })),
            Err(r) => Err(r),
        }
    }
}

/// Signs exactly the vectors' signing inputs with the vectors' signatures, and
/// nothing else; from `expires_at` on it answers that the key ran out.
struct ReplaySigner {
    sigs: HashMap<Vec<u8>, [u8; 64]>,
    kid: String,
    expires_at: i64,
}

struct ReplayKey {
    sigs: HashMap<Vec<u8>, [u8; 64]>,
    kid: String,
}

impl CheckpointKey for ReplayKey {
    fn kid(&self) -> &str {
        &self.kid
    }
    fn sign(&self, signing_input: &[u8]) -> Result<[u8; 64], String> {
        self.sigs.get(signing_input).copied().ok_or_else(|| {
            format!(
                "asked to sign an input no vector carries: {}",
                String::from_utf8_lossy(signing_input)
            )
        })
    }
}

impl CheckpointSigner for ReplaySigner {
    fn key_at(&self, at_millis: i64) -> Result<Arc<dyn CheckpointKey>, NoKey> {
        if at_millis >= self.expires_at {
            return Err(NoKey::Expired);
        }
        Ok(Arc::new(ReplayKey {
            sigs: self.sigs.clone(),
            kid: self.kid.clone(),
        }))
    }
}

fn b64url_decode(s: &str) -> Vec<u8> {
    let val = |c: u8| -> u32 {
        match c {
            b'A'..=b'Z' => (c - b'A') as u32,
            b'a'..=b'z' => (c - b'a' + 26) as u32,
            b'0'..=b'9' => (c - b'0' + 52) as u32,
            b'-' => 62,
            b'_' => 63,
            _ => panic!("not base64url: {c}"),
        }
    };
    let mut out = vec![];
    for chunk in s.as_bytes().chunks(4) {
        let mut n = 0u32;
        for (i, c) in chunk.iter().enumerate() {
            n |= val(*c) << (18 - 6 * i);
        }
        out.push((n >> 16) as u8);
        if chunk.len() > 2 {
            out.push((n >> 8) as u8);
        }
        if chunk.len() > 3 {
            out.push(n as u8);
        }
    }
    out
}

fn replay_signer(expires_at: i64) -> ReplaySigner {
    let v = vectors();
    let mut sigs = HashMap::new();
    for c in v["checkpoints"].as_array().unwrap() {
        let Some(input) = c["signing_input"].as_str() else {
            continue;
        };
        let rec: Value = serde_json::from_str(c["record"].as_str().unwrap()).unwrap();
        let sig: [u8; 64] = b64url_decode(rec["sig"].as_str().unwrap())
            .try_into()
            .unwrap();
        sigs.insert(input.as_bytes().to_vec(), sig);
    }
    ReplaySigner {
        sigs,
        kid: v["key"]["kid"].as_str().unwrap().to_string(),
        expires_at,
    }
}

// -- an independent verifier, from SPEC 6.5.1's steps -----------------------

#[derive(Debug, Clone, PartialEq, Eq)]
enum Verdict {
    /// Every check passed; the signature is the gateway's to check.
    Valid,
    Unsigned,
    Refused(String),
}

fn lines_of(stream: &[u8]) -> Vec<(&[u8], usize)> {
    let mut out = vec![];
    let mut start = 0;
    for (i, b) in stream.iter().enumerate() {
        if *b == b'\n' {
            out.push((&stream[start..i], i + 1));
            start = i + 1;
        }
    }
    out
}

fn independent_head(line: &[u8]) -> Option<String> {
    let mut v: Value = serde_json::from_slice(line.trim_ascii()).ok()?;
    let obj = v.as_object_mut()?;
    for k in ["schema", "ts", "source", "type", "agent_id"] {
        if obj.get(k).and_then(Value::as_str).is_none_or(str::is_empty) {
            return None;
        }
    }
    obj.remove("prev_hash");
    Some(format!(
        "sha256:{}",
        Sha256::digest(crate::jcs::canonicalize(&v).as_bytes())
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect::<String>()
    ))
}

fn verify(stream: &[u8], sidecar: &[u8], name: &str) -> Vec<Verdict> {
    let lines = lines_of(stream);
    let mut prev = GENESIS.to_string();
    let mut out = vec![];
    for (raw, _) in lines_of(sidecar) {
        out.push(verify_one(raw, &lines, stream, &prev, name));
        prev = format!(
            "sha256:{}",
            Sha256::digest(raw)
                .iter()
                .map(|b| format!("{b:02x}"))
                .collect::<String>()
        );
    }
    out
}

fn verify_one(
    raw: &[u8],
    lines: &[(&[u8], usize)],
    stream: &[u8],
    prev: &str,
    name: &str,
) -> Verdict {
    let refuse = |s: &str| Verdict::Refused(s.to_string());
    let Ok(v) = serde_json::from_slice::<Value>(raw) else {
        return refuse("not JSON");
    };
    if crate::jcs::canonicalize(&v).as_bytes() != raw {
        return refuse("not canonical");
    }
    let Some(o) = v.as_object() else {
        return refuse("not an object");
    };
    let common = [
        "v", "kind", "stream", "count", "head", "prefix", "at", "prev",
    ];
    let mut keys: Vec<&str> = o.keys().map(String::as_str).collect();
    keys.sort();
    let mut signed: Vec<&str> = common
        .iter()
        .copied()
        .chain(["alg", "kid", "sig"])
        .collect();
    signed.sort();
    let mut unsigned: Vec<&str> = common.iter().copied().chain(["unsigned_reason"]).collect();
    unsigned.sort();
    let is_signed = keys == signed;
    if !is_signed && keys != unsigned {
        return refuse("members are not v1's");
    }
    if o["v"] != 1 {
        return refuse("v is not 1");
    }
    if !matches!(o["kind"].as_str(), Some("checkpoint" | "close" | "resume")) {
        return refuse("kind");
    }
    if o["stream"].as_str() != Some(name) {
        return refuse("stream");
    }
    let Some(count) = o["count"].as_u64().filter(|c| *c >= 1) else {
        return refuse("count");
    };
    if count as usize > lines.len() {
        return refuse("truncated");
    }
    let (line, end) = lines[count as usize - 1];
    if independent_head(line).as_deref() != o["head"].as_str() {
        return refuse("head does not match");
    }
    let prefix = format!(
        "sha256:{}",
        Sha256::digest(&stream[..end])
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect::<String>()
    );
    if o["prefix"].as_str() != Some(prefix.as_str()) {
        return refuse("prefix does not match");
    }
    if o["prev"].as_str() != Some(prev) {
        return refuse("prev does not chain");
    }
    let at = o["at"].as_str().unwrap_or("");
    let at_ok = at.len() == 24
        && at.bytes().enumerate().all(|(i, c)| match i {
            4 | 7 => c == b'-',
            10 => c == b'T',
            13 | 16 => c == b':',
            19 => c == b'.',
            23 => c == b'Z',
            _ => c.is_ascii_digit(),
        });
    if !at_ok {
        return refuse("at");
    }
    if !is_signed {
        return if o["unsigned_reason"] == KEY_EXPIRED {
            Verdict::Unsigned
        } else {
            refuse("unsigned_reason")
        };
    }
    if o["alg"] != ALG || o["sig"].as_str().map(str::len) != Some(86) {
        return refuse("alg or sig");
    }
    Verdict::Valid
}

fn vector_stream(lines: &[Value]) -> Vec<u8> {
    let mut s = vec![];
    for l in lines {
        s.extend_from_slice(l.as_str().unwrap().as_bytes());
        s.push(b'\n');
    }
    s
}

fn vector_sidecar() -> Vec<u8> {
    let v = vectors();
    let mut s = vec![];
    for c in v["checkpoints"].as_array().unwrap() {
        s.extend_from_slice(c["record"].as_str().unwrap().as_bytes());
        s.push(b'\n');
    }
    s
}

// -- the vectors -------------------------------------------------------------

#[test]
fn the_vendored_vectors_are_agent_passports_byte_for_byte() {
    assert_eq!(sha256_hex(VECTORS.as_bytes()), VECTORS_SHA256);
}

#[test]
fn the_independent_verifier_reads_the_vectors_as_the_spec_does() {
    let v = vectors();
    let name = v["stream"]["name"].as_str().unwrap();
    let stream = vector_stream(v["stream"]["lines"].as_array().unwrap());
    assert_eq!(
        verify(&stream, &vector_sidecar(), name),
        vec![
            Verdict::Valid,
            Verdict::Valid,
            Verdict::Valid,
            Verdict::Unsigned
        ]
    );
    let mut checked = 0;
    for (variant, spec) in v["negative_variants"].as_object().unwrap() {
        let stream = vector_stream(spec["lines"].as_array().unwrap());
        let got = verify(&stream, &vector_sidecar(), name);
        for (i, verdict) in got.iter().enumerate() {
            let refused = spec["refused"].get(i.to_string()).is_some();
            assert_eq!(
                refused,
                matches!(verdict, Verdict::Refused(_)),
                "{variant} record {i}: {verdict:?}"
            );
            checked += 1;
        }
    }
    assert_eq!(checked, 12, "three variants of four records each");
}

#[test]
fn the_vector_records_are_reproduced_byte_for_byte() {
    let v = vectors();
    let signer = replay_signer(i64::MAX);
    let mut checked = 0;
    for c in v["checkpoints"].as_array().unwrap() {
        let rec: Value = serde_json::from_str(c["record"].as_str().unwrap()).unwrap();
        let kind = match rec["kind"].as_str().unwrap() {
            "checkpoint" => Kind::Checkpoint,
            "close" => Kind::Close,
            _ => Kind::Resume,
        };
        let at = rec["at"].as_str().unwrap();
        let fields = Fields {
            kind,
            stream: rec["stream"].as_str().unwrap().into(),
            count: rec["count"].as_u64().unwrap(),
            head: rec["head"].as_str().unwrap().into(),
            prefix: rec["prefix"].as_str().unwrap().into(),
            at_millis: parse_at(at),
            prev: rec["prev"].as_str().unwrap().into(),
        };
        assert_eq!(format_at(fields.at_millis), at);
        let encoded = if rec.get("unsigned_reason").is_some() {
            encode(&fields, TestSigner::none(NoKey::Expired).as_ref()).unwrap()
        } else {
            encode(&fields, &signer).unwrap()
        };
        assert_eq!(
            String::from_utf8_lossy(encoded.record()),
            c["record"].as_str().unwrap()
        );
        if let Encoded::Signed { signing_input, .. } = &encoded {
            assert_eq!(
                String::from_utf8_lossy(signing_input),
                c["signing_input"].as_str().unwrap()
            );
        }
        checked += 1;
    }
    assert_eq!(checked, 4);
}

/// Milliseconds since the epoch of an `at` the vectors carry (all 2026-10-18).
fn parse_at(at: &str) -> i64 {
    let day = crate::timefmt::days_from_civil(
        at[0..4].parse().unwrap(),
        at[5..7].parse().unwrap(),
        at[8..10].parse().unwrap(),
    );
    let h: i64 = at[11..13].parse().unwrap();
    let m: i64 = at[14..16].parse().unwrap();
    let s: i64 = at[17..19].parse().unwrap();
    let ms: i64 = at[20..23].parse().unwrap();
    ((day * 86_400 + h * 3600 + m * 60 + s) * 1000) + ms
}

/// The whole vector sidecar, written by the writer from the vector stream:
/// every `head`, `prefix` and `prev` is computed here from the stream's bytes
/// and the records before it, never copied from the vectors.
#[test]
fn a_writer_over_the_vector_stream_writes_the_vector_sidecar_byte_for_byte() {
    let v = vectors();
    let dir = temp_dir("vector-sidecar");
    let lines = v["stream"]["lines"].as_array().unwrap();
    let path = dir.join("events").join("wardryx.ndjson");
    std::fs::write(&path, vector_stream(&lines[..2])).unwrap();
    let stream = OpenOptions::new()
        .read(true)
        .append(true)
        .open(&path)
        .unwrap();

    let at = |s: &str| parse_at(&format!("2026-10-18T09:00:{s}.000Z"));
    let clock_ms = Arc::new(AtomicI64::new(at("10")));
    let c = Arc::clone(&clock_ms);
    let cfg = CheckpointConfig {
        dir: dir.join("checkpoints"),
        signer: Arc::new(replay_signer(at("40"))),
        clock: Arc::new(move || c.load(Ordering::SeqCst)),
    };
    let (mut ck, opened) = Checkpointer::open(cfg, &path, &stream, false).unwrap();
    assert_eq!(opened.stream_lines, 2);
    assert_eq!(opened.resume, None);

    // Record 1: a checkpoint of the two lines.
    let (head, prefix) = (ck.head.clone().unwrap(), ck.prefix());
    ck.write_record(Kind::Checkpoint, ck.count, head, prefix, at("10"))
        .unwrap();
    // Line 3 is appended; record 2 is a resume naming it.
    let mut line3 = lines[2].as_str().unwrap().as_bytes().to_vec();
    line3.push(b'\n');
    (&stream).write_all(&line3).unwrap();
    clock_ms.store(at("15"), Ordering::SeqCst);
    let own = head_of_line(&line3[..line3.len() - 1]);
    ck.after_append(&stream, &line3, own.as_deref());
    assert_eq!(ck.count, 3);
    let (head, prefix) = (ck.head.clone().unwrap(), ck.prefix());
    ck.write_record(Kind::Resume, 3, head, prefix, at("20"))
        .unwrap();
    // Record 3: the close.
    clock_ms.store(at("30"), Ordering::SeqCst);
    assert_eq!(ck.close(&stream).unwrap(), Some(3));
    // Record 4: unsigned, the key having run out.
    let (head, prefix) = (ck.head.clone().unwrap(), ck.prefix());
    ck.write_record(Kind::Checkpoint, 3, head, prefix, at("40"))
        .unwrap();

    let sidecar = std::fs::read(dir.join("checkpoints/wardryx.ndjson.ckpt.ndjson")).unwrap();
    assert_eq!(
        String::from_utf8(sidecar).unwrap(),
        String::from_utf8(vector_sidecar()).unwrap()
    );
}

// -- helpers over a real exporter -------------------------------------------

struct Harness {
    dir: PathBuf,
    path: PathBuf,
    exporter: Exporter,
    clock: Arc<AtomicI64>,
}

const T0: i64 = 1_792_314_000_000; // 2026-10-18T09:00:00.000Z

impl Harness {
    fn new(tag: &str, signer: Arc<dyn CheckpointSigner>) -> Self {
        let dir = temp_dir(tag);
        Self::over(dir, b"", signer)
    }

    fn over(dir: PathBuf, existing: &[u8], signer: Arc<dyn CheckpointSigner>) -> Self {
        let path = dir.join("events").join("tokenfuse.ndjson");
        if !existing.is_empty() || !path.exists() {
            std::fs::write(&path, existing).unwrap();
        }
        let exporter = Exporter::open(path.to_str().unwrap()).unwrap();
        let clock = Arc::new(AtomicI64::new(T0));
        let c = Arc::clone(&clock);
        exporter
            .attach_checkpoints(CheckpointConfig {
                dir: dir.join("checkpoints"),
                signer,
                clock: Arc::new(move || c.load(Ordering::SeqCst)),
            })
            .unwrap();
        Harness {
            dir,
            path,
            exporter,
            clock,
        }
    }

    fn emit(&self, n: usize) {
        for i in 0..n {
            let out = self.exporter.emit(
                EventType::BreakerTripped,
                T0 + i as i64,
                Some("agent://acme.example/support/bot"),
                Some("run-1"),
                None,
                serde_json::json!({"i": i}),
            );
            assert_eq!(out, crate::agent_event::EmitOutcome::Written);
        }
    }

    fn advance(&self, ms: i64) {
        self.clock.fetch_add(ms, Ordering::SeqCst);
    }

    fn stream(&self) -> Vec<u8> {
        std::fs::read(&self.path).unwrap()
    }

    fn sidecar(&self) -> Vec<u8> {
        std::fs::read(self.dir.join("checkpoints/tokenfuse.ndjson.ckpt.ndjson")).unwrap_or_default()
    }

    fn records(&self) -> Vec<Value> {
        lines_of(&self.sidecar())
            .into_iter()
            .map(|(l, _)| serde_json::from_slice(l).unwrap())
            .collect()
    }

    fn verdicts(&self) -> Vec<Verdict> {
        verify(&self.stream(), &self.sidecar(), "tokenfuse.ndjson")
    }
}

fn all_valid(v: &[Verdict]) -> bool {
    v.iter().all(|x| *x == Verdict::Valid)
}

// -- when a record is written -----------------------------------------------

#[test]
fn every_64_lines_writes_one_record() {
    let h = Harness::new("every-64", TestSigner::signing());
    h.emit(63);
    assert!(
        h.records().is_empty(),
        "63 lines and no time: no record yet"
    );
    h.emit(1);
    let recs = h.records();
    assert_eq!(recs.len(), 1);
    assert_eq!(recs[0]["kind"], "checkpoint");
    assert_eq!(recs[0]["count"], 64);
    h.emit(64);
    assert_eq!(h.records().len(), 2);
    assert_eq!(h.records()[1]["count"], 128);
    let v = h.verdicts();
    assert!(all_valid(&v), "{v:?}");
}

#[test]
fn ten_seconds_with_lines_waiting_writes_a_record_and_an_idle_stream_writes_none() {
    let h = Harness::new("interval", TestSigner::signing());
    h.emit(3);
    h.advance(INTERVAL_MILLIS - 1);
    h.exporter.checkpoint_tick();
    assert!(h.records().is_empty(), "9.999 s: not due yet");
    h.advance(1);
    h.exporter.checkpoint_tick();
    let recs = h.records();
    assert_eq!(recs.len(), 1, "10 s with three lines waiting");
    assert_eq!(recs[0]["count"], 3);
    h.advance(60_000);
    h.exporter.checkpoint_tick();
    assert_eq!(h.records().len(), 1, "nothing waiting: no record");
    assert!(all_valid(&h.verdicts()));
}

#[test]
fn close_writes_a_close_record_naming_the_whole_stream() {
    let h = Harness::new("close", TestSigner::signing());
    h.emit(70);
    h.advance(5);
    assert_eq!(h.exporter.close_checkpoints().unwrap(), Some(70));
    let recs = h.records();
    assert_eq!(recs.len(), 2);
    assert_eq!(recs[0]["count"], 64);
    assert_eq!(recs[1]["kind"], "close");
    assert_eq!(recs[1]["count"], 70);
    assert!(all_valid(&h.verdicts()));
}

#[test]
fn close_on_an_empty_stream_writes_nothing() {
    let h = Harness::new("close-empty", TestSigner::signing());
    assert_eq!(h.exporter.close_checkpoints().unwrap(), None);
    assert!(h.sidecar().is_empty());
}

#[test]
fn prev_chains_from_genesis_through_every_record_and_across_a_reopen() {
    let h = Harness::new("prev-chain", TestSigner::signing());
    h.emit(130);
    h.exporter.close_checkpoints().unwrap();
    let first = h.records();
    assert_eq!(first[0]["prev"], GENESIS);
    let dir = h.dir.clone();
    drop(h);
    let h = Harness::over(dir, b"", TestSigner::signing());
    h.emit(64);
    let recs = h.records();
    assert_eq!(recs.len(), first.len() + 1);
    let side = h.sidecar();
    let last_before = lines_of(&side)[first.len() - 1].0;
    assert_eq!(recs[first.len()]["prev"], sha256_hex(last_before));
    let v = h.verdicts();
    assert!(all_valid(&v), "{v:?}");
}

#[test]
fn a_torn_record_in_the_sidecar_is_cut_before_the_next_is_appended() {
    let h = Harness::new("torn-sidecar", TestSigner::signing());
    h.emit(64);
    let dir = h.dir.clone();
    drop(h);
    let side = dir.join("checkpoints/tokenfuse.ndjson.ckpt.ndjson");
    let mut bytes = std::fs::read(&side).unwrap();
    let whole = bytes.clone();
    bytes.extend_from_slice(b"{\"alg\":\"ES256\",\"at\":\"2026-1");
    std::fs::write(&side, &bytes).unwrap();
    let h = Harness::over(dir, b"", TestSigner::signing());
    assert_eq!(
        std::fs::read(&side).unwrap(),
        whole,
        "the torn bytes are gone"
    );
    h.emit(64);
    let v = h.verdicts();
    assert_eq!(v.len(), 2);
    assert!(all_valid(&v), "{v:?}");
}

// -- resume, and a stream another hand touched --------------------------------

fn event_line(i: usize) -> Vec<u8> {
    let mut l = format!(
        "{{\"agent_id\":\"agent://acme.example/support/bot\",\"data\":{{\"i\":{i}}},\"schema\":\"taipanbox.dev/agent-event/v0.2\",\"severity\":\"medium\",\"source\":\"tokenfuse\",\"ts\":\"2026-10-18T09:00:00.000Z\",\"type\":\"breaker_tripped\"}}"
    )
    .into_bytes();
    l.push(b'\n');
    l
}

#[test]
fn a_stream_left_torn_gets_a_resume_record_and_its_fragment_is_terminated() {
    let dir = temp_dir("torn-stream");
    let mut existing = event_line(1);
    existing.extend(event_line(2));
    existing.extend_from_slice(b"{\"agent_id\":\"agent://acme.ex");
    let h = Harness::over(dir, &existing, TestSigner::signing());
    let recs = h.records();
    assert_eq!(recs.len(), 1);
    assert_eq!(recs[0]["kind"], "resume");
    assert_eq!(recs[0]["count"], 2, "the last event before the fragment");
    h.emit(1);
    let stream = h.stream();
    let lines = lines_of(&stream);
    assert_eq!(lines.len(), 4, "the fragment is a line of its own now");
    assert!(
        head_of_line(lines[3].0).is_some(),
        "the new event is not glued onto it"
    );
    h.advance(INTERVAL_MILLIS);
    h.exporter.checkpoint_tick();
    let v = h.verdicts();
    assert_eq!(v.len(), 2);
    assert!(all_valid(&v), "{v:?}");
    assert_eq!(h.records()[1]["count"], 4);
}

#[test]
fn a_stream_ending_in_a_malformed_line_gets_a_resume_naming_the_last_event() {
    let dir = temp_dir("malformed-tail");
    let mut existing = event_line(1);
    existing.extend(event_line(2));
    existing.extend_from_slice(b"not an event\n");
    let h = Harness::over(dir, &existing, TestSigner::signing());
    let recs = h.records();
    assert_eq!(recs.len(), 1);
    assert_eq!(recs[0]["kind"], "resume");
    assert_eq!(recs[0]["count"], 2);
    assert!(all_valid(&h.verdicts()));
}

#[test]
fn a_stream_the_exporter_chains_from_gets_no_resume() {
    let dir = temp_dir("chained");
    let mut existing = event_line(1);
    existing.extend(event_line(2));
    let h = Harness::over(dir, &existing, TestSigner::signing());
    assert!(
        h.records().is_empty(),
        "the next line chains on, so nothing to resume"
    );
    h.emit(64);
    let recs = h.records();
    assert_eq!(recs.len(), 1);
    assert_eq!(recs[0]["kind"], "checkpoint");
    assert_eq!(
        recs[0]["count"], 66,
        "the two found are counted, the 64 new are what was due"
    );
    assert!(all_valid(&h.verdicts()));
}

#[test]
fn lines_another_writer_appended_are_read_back_into_the_prefix() {
    let h = Harness::new("foreign", TestSigner::signing());
    h.emit(10);
    {
        let mut f = OpenOptions::new().append(true).open(&h.path).unwrap();
        f.write_all(&event_line(99)).unwrap();
        f.write_all(b"garbage another hand wrote\n").unwrap();
        f.write_all(&event_line(100)).unwrap();
    }
    h.emit(60);
    h.exporter.close_checkpoints().unwrap();
    let recs = h.records();
    assert_eq!(recs.len(), 2);
    assert_eq!(
        recs[0]["count"], 64,
        "the three foreign lines count toward the 64"
    );
    assert_eq!(recs[1]["count"], 73);
    let v = h.verdicts();
    assert!(all_valid(&v), "{v:?}");
}

#[test]
fn a_shortened_stream_is_hashed_again_from_byte_zero() {
    let h = Harness::new("shrunk", TestSigner::signing());
    h.emit(64);
    let stream = h.stream();
    let keep = lines_of(&stream)[9].1;
    std::fs::OpenOptions::new()
        .write(true)
        .open(&h.path)
        .unwrap()
        .set_len(keep as u64)
        .unwrap();
    h.emit(54);
    let recs = h.records();
    assert_eq!(recs.len(), 2);
    assert_eq!(
        recs[1]["count"], 64,
        "ten kept plus 54 new, counted from byte zero"
    );
    let v = h.verdicts();
    assert!(
        matches!(v[0], Verdict::Refused(_)),
        "the first named bytes that are gone"
    );
    assert_eq!(v[1], Verdict::Valid, "{v:?}");
}

// -- signed, unsigned, refused -------------------------------------------------

#[test]
fn an_unsigned_record_is_written_when_no_key_is_valid_and_counted_as_unsigned() {
    let h = Harness::new("unsigned", TestSigner::none(NoKey::NeverCertified));
    h.emit(64);
    let recs = h.records();
    assert_eq!(
        recs.len(),
        1,
        "no key: the record is written, never dropped"
    );
    let r = recs[0].as_object().unwrap();
    assert_eq!(r["unsigned_reason"], KEY_EXPIRED);
    for m in ["alg", "kid", "sig"] {
        assert!(!r.contains_key(m), "an unsigned record carries no {m}");
    }
    assert_eq!(h.verdicts(), vec![Verdict::Unsigned]);
    let stats = h.exporter.checkpoint_stats().unwrap();
    assert_eq!((stats.signed, stats.unsigned), (0, 1));
    assert_eq!(stats.last_signed, Some(false));
    assert_eq!(stats.last_unsigned_reason, Some(NoKey::NeverCertified));
}

#[test]
fn a_signed_record_is_counted_as_signed() {
    let h = Harness::new("signed", TestSigner::signing());
    h.emit(64);
    let stats = h.exporter.checkpoint_stats().unwrap();
    assert_eq!((stats.signed, stats.unsigned), (1, 0));
    assert_eq!(stats.last_signed, Some(true));
    assert_eq!(h.records()[0]["kid"], TEST_KID);
}

#[test]
fn a_key_that_cannot_sign_writes_no_record_and_the_event_is_kept() {
    let signer = TestSigner::signing();
    signer.set(Ok(true));
    let h = Harness::new("sign-fails", signer.clone());
    h.emit(64);
    assert!(h.records().is_empty());
    assert_eq!(lines_of(&h.stream()).len(), 64, "every event is on disk");
    let stats = h.exporter.checkpoint_stats().unwrap();
    assert_eq!(stats.errors, 1);
    signer.set(Ok(false));
    h.emit(1);
    let recs = h.records();
    assert_eq!(recs.len(), 1, "the record is retried on the next line");
    assert_eq!(recs[0]["count"], 65);
    assert!(all_valid(&h.verdicts()));
}

#[test]
fn the_key_is_chosen_for_the_records_own_at() {
    let signer = TestSigner::signing();
    let h = Harness::new("key-at", signer.clone());
    h.emit(3);
    h.advance(12_345);
    h.exporter.checkpoint_tick();
    let recs = h.records();
    assert_eq!(recs.len(), 1);
    let asked = signer.asked.lock().unwrap().clone();
    assert_eq!(asked, vec![T0 + 12_345]);
    assert_eq!(recs[0]["at"], format_at(T0 + 12_345));
}

#[test]
fn the_signature_covers_the_canonical_signing_input() {
    let h = Harness::new("sig-input", TestSigner::signing());
    h.emit(64);
    let rec = h.records().remove(0);
    let mut m = rec.as_object().unwrap().clone();
    let sig = m.remove("sig").unwrap();
    let input = crate::jcs::canonicalize(&Value::Object(m));
    let d = Sha256::digest(input.as_bytes());
    let mut want = [0u8; 64];
    want[..32].copy_from_slice(&d);
    want[32..].copy_from_slice(&d);
    assert_eq!(sig, base64url(&want));
}

// -- off, and refusals ----------------------------------------------------------

#[test]
fn checkpoints_off_leave_the_stream_byte_for_byte_as_before() {
    let dir = temp_dir("off");
    let path = dir.join("events").join("tokenfuse.ndjson");
    std::fs::write(&path, b"{\"agent_id\":\"agent://acme.ex").unwrap();
    let exporter = Exporter::open(path.to_str().unwrap()).unwrap();
    exporter.emit(
        EventType::BreakerTripped,
        T0,
        Some("agent://acme.example/support/bot"),
        None,
        None,
        Value::Null,
    );
    let stream = std::fs::read(&path).unwrap();
    assert!(
        stream.starts_with(b"{\"agent_id\":\"agent://acme.ex{"),
        "with no sidecar a torn tail is written onto exactly as before"
    );
    assert!(exporter.checkpoint_stats().is_none());
    assert_eq!(exporter.close_checkpoints().unwrap(), None);
    assert!(std::fs::read_dir(dir.join("checkpoints"))
        .unwrap()
        .next()
        .is_none());
}

#[test]
fn a_second_writer_cannot_attach_to_a_held_sidecar() {
    let h = Harness::new("held", TestSigner::signing());
    let other = Exporter::open(h.path.to_str().unwrap()).unwrap();
    let err = other
        .attach_checkpoints(CheckpointConfig {
            dir: h.dir.join("checkpoints"),
            signer: TestSigner::signing(),
            clock: system_clock(),
        })
        .unwrap_err();
    assert!(err.contains("held by another process"), "{err}");
}

#[test]
fn a_sidecar_in_the_streams_own_directory_is_refused() {
    let dir = temp_dir("same-dir");
    let path = dir.join("events").join("tokenfuse.ndjson");
    let exporter = Exporter::open(path.to_str().unwrap()).unwrap();
    let err = exporter
        .attach_checkpoints(CheckpointConfig {
            dir: dir.join("events"),
            signer: TestSigner::signing(),
            clock: system_clock(),
        })
        .unwrap_err();
    assert!(err.contains("directory of its own"), "{err}");
}

#[test]
fn a_stream_name_keyryx_would_refuse_is_refused() {
    let dir = temp_dir("bad-name");
    for name in ["events.log", ".hidden.ndjson", "spaced name.ndjson"] {
        let path = dir.join("events").join(name);
        let exporter = Exporter::open(path.to_str().unwrap()).unwrap();
        let err = exporter
            .attach_checkpoints(CheckpointConfig {
                dir: dir.join("checkpoints"),
                signer: TestSigner::signing(),
                clock: system_clock(),
            })
            .unwrap_err();
        assert!(
            err.contains("not one a checkpoint record may name"),
            "{name}: {err}"
        );
    }
    assert!(stream_name_is_valid("tokenfuse.ndjson"));
    assert!(stream_name_is_valid("tokenfuse-mcp_broker.v2.ndjson"));
    assert!(!stream_name_is_valid(&format!(
        "{}.ndjson",
        "a".repeat(252)
    )));
    assert!(stream_name_is_valid(&format!("{}.ndjson", "a".repeat(251))));
}

#[test]
fn head_of_line_follows_the_go_verifiers_rule() {
    let good =
        r#"{"agent_id":"agent://a.example/b","schema":"s","source":"x","ts":"t","type":"y"}"#;
    assert!(head_of_line(good.as_bytes()).is_some());
    assert_eq!(
        head_of_line(format!("  {good}\r").as_bytes()),
        head_of_line(good.as_bytes()),
        "trimmed before it is read"
    );
    for (bad, why) in [
        (
            r#"{"agent_id":"a","schema":"s","source":"x","ts":"t"}"#,
            "no type",
        ),
        (
            r#"{"agent_id":"","schema":"s","source":"x","ts":"t","type":"y"}"#,
            "empty agent_id",
        ),
        (
            r#"{"agent_id":"a","schema":"s","source":"x","ts":"t","type":5}"#,
            "type a number",
        ),
        (
            r#"{"agent_id":"a","schema":"s","source":"x","ts":"t","type":"y","data":3}"#,
            "data not an object",
        ),
        (
            r#"{"agent_id":"a","schema":"s","source":"x","ts":"t","type":"y","on_behalf_of":"u"}"#,
            "chain not a list",
        ),
        (
            r#"{"agent_id":"a","schema":"s","source":"x","ts":"t","type":"y","severity":1}"#,
            "severity a number",
        ),
        (
            r#"{"agent_id":"a","Schema":"s","schema":"s","source":"x","ts":"t","type":"y"}"#,
            "a key differing only in case",
        ),
        ("[1,2]", "not an object"),
        ("", "empty"),
        ("not json", "not JSON"),
    ] {
        assert!(head_of_line(bad.as_bytes()).is_none(), "{why}");
    }
    let long = format!(
        r#"{{"agent_id":"a","schema":"s","source":"x","ts":"t","type":"y","data":{{"p":"{}"}}}}"#,
        "x".repeat(LINE_CAP)
    );
    assert!(head_of_line(long.as_bytes()).is_none(), "over the line cap");
}

#[test]
fn base64url_matches_rfc_4648_vectors() {
    for (raw, enc) in [
        ("", ""),
        ("f", "Zg"),
        ("fo", "Zm8"),
        ("foo", "Zm9v"),
        ("foob", "Zm9vYg"),
        ("fooba", "Zm9vYmE"),
        ("foobar", "Zm9vYmFy"),
    ] {
        assert_eq!(base64url(raw.as_bytes()), enc);
    }
    assert_eq!(base64url(&[0xfb, 0xff]), "-_8");
    assert_eq!(base64url(&[0u8; 64]).len(), 86);
}

#[test]
fn format_at_is_the_one_form_v1_allows() {
    assert_eq!(format_at(T0), "2026-10-18T09:00:00.000Z");
    assert_eq!(format_at(T0 + 10_007), "2026-10-18T09:00:10.007Z");
}

// -- hostile inputs ---------------------------------------------------------------

/// A small deterministic generator, so a failing seed can be replayed.
struct Rng(u64);
impl Rng {
    fn next(&mut self) -> u64 {
        self.0 ^= self.0 << 13;
        self.0 ^= self.0 >> 7;
        self.0 ^= self.0 << 17;
        self.0
    }
    fn below(&mut self, n: u64) -> u64 {
        self.next() % n
    }
}

fn hostile_bytes(r: &mut Rng) -> Vec<u8> {
    let mut out = vec![];
    for _ in 0..r.below(12) {
        match r.below(9) {
            0 => out.extend(event_line(r.below(1000) as usize)),
            1 => out.extend_from_slice(b"\n"),
            2 => out.extend_from_slice(b"\r\n"),
            3 => out.extend_from_slice(b"{\"agent_id\":\"agent://x.example/y\",\"type\":\"z\"}\n"),
            4 => out.extend_from_slice("{\"schema\":\"é\",\"ts\":\"\u{a0}\"}\n".as_bytes()),
            5 => {
                let n = r.below(300) as usize;
                out.extend((0..n).map(|_| (r.next() & 0xff) as u8));
            }
            6 => out.extend_from_slice(b"{\"agent_id\":\"agent://acme.ex"),
            7 => out.extend_from_slice(&[0, 0xff, 0xfe, b'\n']),
            _ => out.extend_from_slice(b"   \t \n"),
        }
    }
    out
}

#[test]
fn hostile_streams_never_panic_and_every_record_written_verifies() {
    let mut records = 0;
    for seed in 1..=200u64 {
        let mut r = Rng(seed.wrapping_mul(0x9E37_79B9_7F4A_7C15) | 1);
        let dir = temp_dir(&format!("hostile-{seed}"));
        let h = Harness::over(dir, &hostile_bytes(&mut r), TestSigner::signing());
        for _ in 0..r.below(6) {
            h.emit(r.below(70) as usize);
            if r.below(3) == 0 {
                let mut f = OpenOptions::new().append(true).open(&h.path).unwrap();
                f.write_all(&hostile_bytes(&mut r)).unwrap();
            }
            h.advance(r.below(15_000) as i64);
            h.exporter.checkpoint_tick();
        }
        let _ = h.exporter.close_checkpoints();
        let v = h.verdicts();
        records += v.len();
        // A foreign fragment left at the very end is not covered by any record;
        // everything a record names must verify.
        assert!(all_valid(&v), "seed {seed}: {v:?}");
        let _ = std::fs::remove_dir_all(&h.dir);
    }
    assert!(
        records > 200,
        "the sweep wrote {records} records, which measured too little"
    );
}

#[test]
fn hostile_sidecars_never_panic_and_the_next_record_chains_from_the_last_complete_line() {
    for seed in 1..=200u64 {
        let mut r = Rng(seed.wrapping_mul(0xD1B5_4A32_D192_ED03) | 1);
        let dir = temp_dir(&format!("hostile-side-{seed}"));
        let side = dir.join("checkpoints/tokenfuse.ndjson.ckpt.ndjson");
        let garbage = hostile_bytes(&mut r);
        std::fs::write(&side, &garbage).unwrap();
        let complete = garbage
            .iter()
            .rposition(|b| *b == b'\n')
            .map(|i| i + 1)
            .unwrap_or(0);
        let want_prev = match lines_of(&garbage[..complete]).last() {
            Some((l, _)) => sha256_hex(l),
            None => GENESIS.to_string(),
        };
        let h = Harness::over(dir, b"", TestSigner::signing());
        h.emit(64);
        let side_now = h.sidecar();
        assert_eq!(&side_now[..complete], &garbage[..complete], "seed {seed}");
        let last: Value = serde_json::from_slice(lines_of(&side_now).last().unwrap().0).unwrap();
        assert_eq!(last["prev"], want_prev.as_str(), "seed {seed}");
        let _ = std::fs::remove_dir_all(&h.dir);
    }
}
