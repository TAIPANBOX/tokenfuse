//! Semantic response cache (Ring 1.1 — "Saved this month").
//!
//! Repeated / near-repeated agent requests are answered from cache for $0. The
//! design (docs/06-semantic-cache.md) is conservative by default so a single
//! bad hit can never erode trust:
//!
//! - **Hard partition first, similarity second.** Similarity is only compared
//!   *within* an identical (model, system prompt, tools, task_type, tenant)
//!   partition — never across different system prompts.
//! - **Entity guard.** Numbers / dates / ids / emails / urls extracted from both
//!   queries must match exactly ("5 users" must not hit "50 users").
//! - **Length-ratio guard** and a high **similarity threshold** (0.97).
//! - **Shadow mode** records would-hits without serving them.
//!
//! The embedder is pluggable via [`Embedder`]. The default [`HashEmbedder`] is
//! deterministic and dependency-free (char-trigram hashing); a production ONNX
//! model (e.g. multilingual-e5-small) can drop in behind the same trait.
//!
//! ## Lookup shape (CLAUDE.md invariant 64)
//!
//! `get` no longer walks every entry in a partition under one lock for a
//! request identical to something already cached. Each partition keeps an
//! **exact-match index**: a cheap 64-bit hash of the normalized core text
//! maps to the (small) set of entries that might share it, and each
//! candidate is verified against a SHA-256 digest of its own normalized
//! core text before being served — a 64-bit bucket collision can therefore
//! never serve the wrong response, because the digest comparison after it
//! is a second, cryptographically strong check. An exact hit costs no
//! embedding call and no similarity walk at all. Only a request whose core
//! text has never been seen before in that partition falls through to the
//! similarity walk, unchanged in shape from before.
//!
//! `put` of a core that already exists in its partition **replaces** that
//! entry (new response, cost, `created_millis`) rather than appending a
//! duplicate, so identical traffic no longer grows a partition without
//! bound. Eviction at the `max_per_partition` cap is O(1) via a `VecDeque`
//! of insertion order, with the exact-match index kept in step on both
//! eviction and replacement.
//!
//! Embeddings are stored L2-normalized (and the query is normalized once
//! per lookup), so similarity is a plain dot product rather than a second
//! two-norm computation per candidate; a zero vector normalizes to itself
//! and a dot product against it is always `0.0`, never `NaN`, so it can
//! never cross the similarity threshold.
//!
//! `get` takes a read lock and never removes anything — expired entries are
//! skipped while walking, not swept — so concurrent readers are never
//! serialized against each other. Expiry is swept lazily, per partition,
//! inside `put`, which already takes a write lock to insert.

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::{BTreeSet, HashMap, HashSet, VecDeque};
use std::hash::{Hash, Hasher};
use std::sync::RwLock;

/// Turns text into a normalized embedding vector.
pub trait Embedder: Send + Sync {
    fn embed(&self, text: &str) -> Vec<f32>;
}

/// Deterministic, dependency-free embedder: hashes character trigrams into a
/// fixed-dimension, L2-normalized vector. Good enough for "same question"
/// matching and for tests; swap in an ONNX model for production quality.
pub struct HashEmbedder {
    dim: usize,
}

impl HashEmbedder {
    pub fn new(dim: usize) -> Self {
        HashEmbedder { dim: dim.max(16) }
    }
}

impl Default for HashEmbedder {
    fn default() -> Self {
        HashEmbedder::new(256)
    }
}

impl Embedder for HashEmbedder {
    fn embed(&self, text: &str) -> Vec<f32> {
        let mut v = vec![0f32; self.dim];
        let chars: Vec<char> = text.to_lowercase().chars().collect();
        let bump = |v: &mut [f32], token: &str| {
            let mut h = std::collections::hash_map::DefaultHasher::new();
            token.hash(&mut h);
            let idx = (h.finish() as usize) % v.len();
            v[idx] += 1.0;
        };
        if chars.len() < 3 {
            bump(&mut v, &chars.iter().collect::<String>());
        } else {
            for w in chars.windows(3) {
                bump(&mut v, &w.iter().collect::<String>());
            }
        }
        let norm: f32 = v.iter().map(|x| x * x).sum::<f32>().sqrt();
        if norm > 0.0 {
            for x in &mut v {
                *x /= norm;
            }
        }
        v
    }
}

/// Cosine similarity of two vectors (0 if either is zero-length). Kept
/// public: the cache itself now compares pre-normalized vectors with
/// [`dot`], but `cosine` is the general-purpose primitive for anything that
/// hands it two arbitrary (not necessarily normalized) vectors.
pub fn cosine(a: &[f32], b: &[f32]) -> f32 {
    if a.len() != b.len() {
        return 0.0;
    }
    let dot: f32 = a.iter().zip(b).map(|(x, y)| x * y).sum();
    let na: f32 = a.iter().map(|x| x * x).sum::<f32>().sqrt();
    let nb: f32 = b.iter().map(|x| x * x).sum::<f32>().sqrt();
    if na == 0.0 || nb == 0.0 {
        0.0
    } else {
        dot / (na * nb)
    }
}

/// Dot product of two equal-length, already L2-normalized vectors — the
/// similarity comparison the cache actually runs. A zero vector (never
/// normalized to anything but itself) dotted with anything is `0.0`, never
/// `NaN`, so it can never cross a positive similarity threshold.
fn dot(a: &[f32], b: &[f32]) -> f32 {
    if a.len() != b.len() {
        return 0.0;
    }
    a.iter().zip(b).map(|(x, y)| x * y).sum()
}

/// L2-normalize `v` in place. A zero vector is left as zero (norm 0, no
/// division), which is what keeps [`dot`] free of `NaN`: an all-zero
/// embedding can only ever produce a `0.0` similarity, never a match.
fn l2_normalize(v: &mut [f32]) {
    let norm: f32 = v.iter().map(|x| x * x).sum::<f32>().sqrt();
    if norm > 0.0 {
        for x in v.iter_mut() {
            *x /= norm;
        }
    }
}

/// Extract "entities" whose exact match is required for a cache hit: whitespace
/// tokens containing a digit, an `@`, or an `http` prefix.
pub fn extract_entities(text: &str) -> BTreeSet<String> {
    let mut out = BTreeSet::new();
    for raw in text.split(|c: char| c.is_whitespace()) {
        let token: String = raw
            .trim_matches(|c: char| {
                !c.is_alphanumeric() && c != '@' && c != '.' && c != ':' && c != '/'
            })
            .to_lowercase();
        if token.is_empty() {
            continue;
        }
        if token.contains('@')
            || token.starts_with("http")
            || token.chars().any(|c| c.is_ascii_digit())
        {
            out.insert(token);
        }
    }
    out
}

/// The text the exact-match index and digest are computed over. Trimmed
/// only: the partition key already carries model/system/tools/task/tenant,
/// so this exists purely to stop leading/trailing whitespace from
/// duplicating an otherwise-identical entry.
fn normalize_core(core: &str) -> &str {
    core.trim()
}

/// Cheap 64-bit hash of the normalized core text: the exact-match index's
/// bucket key. Two different texts landing in the same bucket (a 64-bit
/// collision) never serve the wrong response, because every candidate in a
/// bucket is verified against its [`core_digest`] before being returned.
fn exact_index_hash(normalized: &str) -> u64 {
    let mut h = std::collections::hash_map::DefaultHasher::new();
    normalized.hash(&mut h);
    h.finish()
}

/// SHA-256 digest of the normalized core text: the strong, collision-safe
/// check an exact-index bucket hit is verified against before it is ever
/// served. `tokenfuse-core`'s allowed dependency list already carries
/// `sha2` for the audit trail (CLAUDE.md invariant 1).
fn core_digest(normalized: &str) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(normalized.as_bytes());
    let out = hasher.finalize();
    let mut digest = [0u8; 32];
    digest.copy_from_slice(&out);
    digest
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum CacheMode {
    #[default]
    Off,
    /// Record would-hits but never serve them.
    Shadow,
    /// Serve hits.
    On,
}

#[derive(Debug, Clone)]
pub struct CacheConfig {
    pub mode: CacheMode,
    pub threshold: f32,
    pub ttl_millis: i64,
    pub max_per_partition: usize,
    pub entity_guard: bool,
    pub length_ratio_max: f32,
}

impl Default for CacheConfig {
    fn default() -> Self {
        CacheConfig {
            mode: CacheMode::Off,
            threshold: 0.97,
            ttl_millis: 24 * 60 * 60 * 1000, // 24h
            max_per_partition: 10_000,
            entity_guard: true,
            length_ratio_max: 1.5,
        }
    }
}

/// A cache hit: the stored response plus what it saved.
#[derive(Debug, Clone)]
pub struct Lookup {
    pub response: Vec<u8>,
    pub content_type: String,
    pub similarity: f32,
    pub saved_microusd: i64,
}

struct Entry {
    /// L2-normalized.
    embedding: Vec<f32>,
    entities: BTreeSet<String>,
    core_len: usize,
    /// Strong (SHA-256) verification key for an exact-index bucket hit.
    core_digest: [u8; 32],
    /// The bucket this entry lives under, kept alongside the entry so it
    /// can be found and removed from `Partition::exact_index` in O(bucket
    /// size) on eviction or TTL sweep, without re-hashing anything.
    index_hash: u64,
    response: Vec<u8>,
    content_type: String,
    cost_microusd: i64,
    created_millis: i64,
}

/// One hard partition's entries, kept internally consistent: every id in
/// `order` and every id in an `exact_index` bucket names a live entry in
/// `entries`, and vice versa.
#[derive(Default)]
struct Partition {
    entries: HashMap<u64, Entry>,
    /// Insertion order, oldest first — the O(1) FIFO eviction queue.
    order: VecDeque<u64>,
    /// Normalized-core hash → candidate entry ids sharing that bucket.
    exact_index: HashMap<u64, Vec<u64>>,
    next_id: u64,
}

impl Partition {
    /// Remove one entry by id from every structure that names it. A no-op
    /// if the id is not present (already removed).
    fn remove(&mut self, id: u64) {
        if let Some(entry) = self.entries.remove(&id) {
            if let Some(bucket) = self.exact_index.get_mut(&entry.index_hash) {
                bucket.retain(|&x| x != id);
                if bucket.is_empty() {
                    self.exact_index.remove(&entry.index_hash);
                }
            }
        }
    }

    /// Drop every expired entry from this partition: `entries`, its
    /// `exact_index` bucket, and its slot in `order`. Partition-local and
    /// run only from `put`, never from `get` (CLAUDE.md invariant 64).
    fn sweep_expired(&mut self, now_millis: i64, ttl_millis: i64) {
        let mut removed: Vec<(u64, u64)> = Vec::new();
        self.entries.retain(|&id, e| {
            let keep = now_millis - e.created_millis <= ttl_millis;
            if !keep {
                removed.push((id, e.index_hash));
            }
            keep
        });
        if removed.is_empty() {
            return;
        }
        for (id, hash) in &removed {
            if let Some(bucket) = self.exact_index.get_mut(hash) {
                bucket.retain(|x| x != id);
                if bucket.is_empty() {
                    self.exact_index.remove(hash);
                }
            }
        }
        let removed_ids: HashSet<u64> = removed.iter().map(|(id, _)| *id).collect();
        self.order.retain(|id| !removed_ids.contains(id));
    }

    /// Find a live entry in this partition whose normalized core text is
    /// exactly `digest`, via the O(1)-average exact-match index. Verifies
    /// the strong digest, not only the cheap bucket hash.
    fn find_exact(&self, index_hash: u64, digest: &[u8; 32]) -> Option<u64> {
        let bucket = self.exact_index.get(&index_hash)?;
        for &id in bucket {
            if let Some(e) = self.entries.get(&id) {
                if &e.core_digest == digest {
                    return Some(id);
                }
            }
        }
        None
    }
}

/// A partitioned semantic cache. Cheap to share behind an `Arc`.
///
/// `get` takes a read lock; `put` takes a write lock. Concurrent readers are
/// never serialized against each other (CLAUDE.md invariant 64).
pub struct SemanticCache {
    embedder: Box<dyn Embedder>,
    config: CacheConfig,
    store: RwLock<HashMap<u64, Partition>>,
}

impl SemanticCache {
    pub fn new(embedder: Box<dyn Embedder>, config: CacheConfig) -> Self {
        SemanticCache {
            embedder,
            config,
            store: RwLock::new(HashMap::new()),
        }
    }

    pub fn mode(&self) -> CacheMode {
        self.config.mode
    }

    /// Hard-partition key: similarity is only ever compared within one of these.
    pub fn partition_key(
        model: &str,
        system: &str,
        tools: &str,
        task_type: &str,
        tenant: &str,
    ) -> u64 {
        let mut h = std::collections::hash_map::DefaultHasher::new();
        model.hash(&mut h);
        system.hash(&mut h);
        tools.hash(&mut h);
        task_type.hash(&mut h);
        tenant.hash(&mut h);
        h.finish()
    }

    /// Look for a hit for `core` (the semantic core text) in `partition`.
    ///
    /// An identical core (byte-for-byte after trimming) is found through the
    /// exact-match index in O(1) average, with no embedding call and no
    /// similarity walk. Only a core this partition has never seen falls
    /// through to the similarity walk. Neither path removes anything:
    /// expired entries are skipped, not swept (that happens in `put`), and
    /// this whole call runs under a read lock, so it never serializes
    /// against another concurrent `get`.
    pub fn get(&self, partition: u64, core: &str, now_millis: i64) -> Option<Lookup> {
        if self.config.mode == CacheMode::Off {
            return None;
        }

        let normalized = normalize_core(core);
        let index_hash = exact_index_hash(normalized);
        let digest = core_digest(normalized);

        let store = self.store.read().unwrap();
        let part = store.get(&partition)?;

        // Exact-match fast path: O(1) average, no embedding computed.
        if let Some(id) = part.find_exact(index_hash, &digest) {
            // `find_exact` only returns live entries, but "live" there
            // means "present", not "unexpired" — expiry is checked here so
            // the guard applies uniformly to both paths.
            if let Some(e) = part.entries.get(&id) {
                if now_millis - e.created_millis <= self.config.ttl_millis {
                    return Some(Lookup {
                        response: e.response.clone(),
                        content_type: e.content_type.clone(),
                        similarity: 1.0,
                        saved_microusd: e.cost_microusd,
                    });
                }
            }
        }

        // Similarity fallback: this core has not been seen exactly before.
        let mut query = self.embedder.embed(core);
        l2_normalize(&mut query);
        let entities = extract_entities(core);
        let core_len = core.chars().count();

        let mut best: Option<(f32, &Entry)> = None;
        for e in part.entries.values() {
            if now_millis - e.created_millis > self.config.ttl_millis {
                continue;
            }
            if self.config.entity_guard && e.entities != entities {
                continue;
            }
            let r = ratio(core_len, e.core_len);
            if r > self.config.length_ratio_max {
                continue;
            }
            let sim = dot(&query, &e.embedding);
            if sim >= self.config.threshold && best.map(|(b, _)| sim > b).unwrap_or(true) {
                best = Some((sim, e));
            }
        }

        best.map(|(sim, e)| Lookup {
            response: e.response.clone(),
            content_type: e.content_type.clone(),
            similarity: sim,
            saved_microusd: e.cost_microusd,
        })
    }

    /// Store a response for future hits.
    ///
    /// A core already present in this partition (exact match, TTL still
    /// live or not — the sweep below runs first) is REPLACED in place:
    /// new response, cost and `created_millis`, same id, same position in
    /// the eviction order. A core this partition has not seen is appended
    /// and, past `max_per_partition`, the oldest entry is evicted in O(1)
    /// via `order`, with the exact-match index kept in step.
    pub fn put(
        &self,
        partition: u64,
        core: &str,
        response: Vec<u8>,
        content_type: String,
        cost_microusd: i64,
        now_millis: i64,
    ) {
        if self.config.mode == CacheMode::Off {
            return;
        }

        let normalized = normalize_core(core);
        let index_hash = exact_index_hash(normalized);
        let digest = core_digest(normalized);
        let mut embedding = self.embedder.embed(core);
        l2_normalize(&mut embedding);
        let entities = extract_entities(core);
        let core_len = core.chars().count();

        let mut store = self.store.write().unwrap();
        let part = store.entry(partition).or_default();

        // Partition-local TTL sweep. `get` never removes anything, so this
        // is where memory is actually bounded over time.
        part.sweep_expired(now_millis, self.config.ttl_millis);

        if let Some(id) = part.find_exact(index_hash, &digest) {
            if let Some(e) = part.entries.get_mut(&id) {
                e.response = response;
                e.content_type = content_type;
                e.cost_microusd = cost_microusd;
                e.created_millis = now_millis;
                // embedding/entities/core_len/core_digest/index_hash are
                // unchanged: the normalized core text that produced them is
                // exactly the same text, by construction of `find_exact`.
            }
            return;
        }

        let id = part.next_id;
        part.next_id += 1;
        part.entries.insert(
            id,
            Entry {
                embedding,
                entities,
                core_len,
                core_digest: digest,
                index_hash,
                response,
                content_type,
                cost_microusd,
                created_millis: now_millis,
            },
        );
        part.exact_index.entry(index_hash).or_default().push(id);
        part.order.push_back(id);

        while part.entries.len() > self.config.max_per_partition {
            match part.order.pop_front() {
                Some(oldest) => part.remove(oldest),
                None => break,
            }
        }
    }

    /// Test-only: the number of live entries in a partition (0 if absent).
    #[cfg(test)]
    fn entry_count(&self, partition: u64) -> usize {
        self.store
            .read()
            .unwrap()
            .get(&partition)
            .map(|p| p.entries.len())
            .unwrap_or(0)
    }

    /// Test-only: total ids named across every exact-index bucket in a
    /// partition. Kept equal to [`entry_count`] by construction; a mutant
    /// that leaves a stale bucket entry behind on eviction or TTL sweep
    /// makes this diverge from it.
    #[cfg(test)]
    fn index_entry_count(&self, partition: u64) -> usize {
        self.store
            .read()
            .unwrap()
            .get(&partition)
            .map(|p| p.exact_index.values().map(|b| b.len()).sum())
            .unwrap_or(0)
    }

    /// Test-only hook: force two different core texts into the same
    /// exact-index bucket, bypassing the real 64-bit hash, so the digest
    /// verification in `find_exact`/`get` can be proven to be what actually
    /// keeps a bucket collision from serving the wrong response.
    #[cfg(test)]
    fn put_forcing_index_hash(
        &self,
        partition: u64,
        forced_hash: u64,
        core: &str,
        response: Vec<u8>,
        cost_microusd: i64,
        now_millis: i64,
    ) {
        let normalized = normalize_core(core);
        let digest = core_digest(normalized);
        let mut embedding = self.embedder.embed(core);
        l2_normalize(&mut embedding);
        let entities = extract_entities(core);
        let core_len = core.chars().count();

        let mut store = self.store.write().unwrap();
        let part = store.entry(partition).or_default();
        let id = part.next_id;
        part.next_id += 1;
        part.entries.insert(
            id,
            Entry {
                embedding,
                entities,
                core_len,
                core_digest: digest,
                index_hash: forced_hash,
                response,
                content_type: "test".into(),
                cost_microusd,
                created_millis: now_millis,
            },
        );
        part.exact_index.entry(forced_hash).or_default().push(id);
        part.order.push_back(id);
    }

    /// Test-only hook: look a core up through the exact-index path using a
    /// caller-supplied bucket hash rather than the real one, so a forced
    /// collision (via [`put_forcing_index_hash`]) can be queried at all —
    /// `get`'s own real hash of the query text would almost never land in
    /// an artificially forced bucket. This calls exactly the same
    /// `find_exact` the real `get` calls, so it exercises the same digest
    /// verification.
    #[cfg(test)]
    fn get_exact_only_forcing_index_hash(
        &self,
        partition: u64,
        forced_hash: u64,
        core: &str,
        now_millis: i64,
    ) -> Option<Lookup> {
        let normalized = normalize_core(core);
        let digest = core_digest(normalized);
        let store = self.store.read().unwrap();
        let part = store.get(&partition)?;
        let id = part.find_exact(forced_hash, &digest)?;
        let e = part.entries.get(&id)?;
        if now_millis - e.created_millis > self.config.ttl_millis {
            return None;
        }
        Some(Lookup {
            response: e.response.clone(),
            content_type: e.content_type.clone(),
            similarity: 1.0,
            saved_microusd: e.cost_microusd,
        })
    }
}

fn ratio(a: usize, b: usize) -> f32 {
    let (a, b) = (a.max(1) as f32, b.max(1) as f32);
    if a > b {
        a / b
    } else {
        b / a
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Arc;

    fn cache(mode: CacheMode) -> SemanticCache {
        SemanticCache::new(
            Box::new(HashEmbedder::default()),
            CacheConfig {
                mode,
                threshold: 0.9,
                ..Default::default()
            },
        )
    }

    #[test]
    fn identical_query_hits() {
        let c = cache(CacheMode::On);
        let p = SemanticCache::partition_key("m", "sys", "", "qa", "t");
        c.put(
            p,
            "how do refunds work?",
            b"cached".to_vec(),
            "application/json".into(),
            5000,
            0,
        );
        let hit = c.get(p, "how do refunds work?", 1).unwrap();
        assert_eq!(hit.response, b"cached");
        assert_eq!(hit.saved_microusd, 5000);
        assert!(hit.similarity > 0.99);
    }

    #[test]
    fn different_partition_never_hits() {
        let c = cache(CacheMode::On);
        let p1 = SemanticCache::partition_key("m", "sysA", "", "qa", "t");
        let p2 = SemanticCache::partition_key("m", "sysB", "", "qa", "t");
        c.put(p1, "hello there", b"x".to_vec(), "j".into(), 1, 0);
        assert!(c.get(p2, "hello there", 1).is_none());
    }

    #[test]
    fn entity_guard_blocks_number_mismatch() {
        let c = cache(CacheMode::On);
        let p = SemanticCache::partition_key("m", "s", "", "qa", "t");
        c.put(p, "price for 5 users", b"five".to_vec(), "j".into(), 1, 0);
        // Same words, different number → must not hit.
        assert!(c.get(p, "price for 50 users", 1).is_none());
        // Exact entity → hits.
        assert!(c.get(p, "price for 5 users", 1).is_some());
    }

    #[test]
    fn ttl_expires_entries() {
        let c = SemanticCache::new(
            Box::new(HashEmbedder::default()),
            CacheConfig {
                mode: CacheMode::On,
                threshold: 0.9,
                ttl_millis: 1000,
                ..Default::default()
            },
        );
        let p = SemanticCache::partition_key("m", "s", "", "qa", "t");
        c.put(p, "some question", b"r".to_vec(), "j".into(), 1, 0);
        assert!(c.get(p, "some question", 1000).is_some()); // within ttl
        assert!(c.get(p, "some question", 1001).is_none()); // expired
    }

    #[test]
    fn off_mode_never_stores_or_hits() {
        let c = cache(CacheMode::Off);
        let p = SemanticCache::partition_key("m", "s", "", "qa", "t");
        c.put(p, "q", b"r".to_vec(), "j".into(), 1, 0);
        assert!(c.get(p, "q", 1).is_none());
    }

    #[test]
    fn entities_extracts_numbers_emails_urls() {
        let e = extract_entities("email me at a@b.com about 42 items via https://x.io");
        assert!(e.contains("a@b.com"));
        assert!(e.contains("42"));
        assert!(e.iter().any(|t| t.starts_with("https")));
        assert!(!e.contains("items"));
    }

    #[test]
    fn cosine_bounds() {
        let a = vec![1.0, 0.0];
        let b = vec![1.0, 0.0];
        let c = vec![0.0, 1.0];
        assert!((cosine(&a, &b) - 1.0).abs() < 1e-6);
        assert!(cosine(&a, &c).abs() < 1e-6);
    }

    // --- invariant 64: exact-match index, replace-not-append, no global walk ---

    /// An embedder that counts how many times `embed` is called, so a test
    /// can assert an exact hit never triggers a similarity walk at all.
    struct CountingEmbedder {
        inner: HashEmbedder,
        calls: Arc<AtomicUsize>,
    }

    impl Embedder for CountingEmbedder {
        fn embed(&self, text: &str) -> Vec<f32> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            self.inner.embed(text)
        }
    }

    #[test]
    fn identical_core_twice_replaces_not_appends() {
        let c = cache(CacheMode::On);
        let p = SemanticCache::partition_key("m", "s", "", "qa", "t");
        c.put(p, "refund policy?", b"first".to_vec(), "j".into(), 100, 0);
        c.put(p, "refund policy?", b"second".to_vec(), "j".into(), 200, 10);
        assert_eq!(
            c.entry_count(p),
            1,
            "a second put of the same core must replace, not append"
        );
        let hit = c.get(p, "refund policy?", 11).unwrap();
        assert_eq!(
            hit.response, b"second",
            "the second response must be served"
        );
        assert_eq!(hit.saved_microusd, 200);
    }

    #[test]
    fn an_exact_hit_never_walks_similarity() {
        let calls = Arc::new(AtomicUsize::new(0));
        let c = SemanticCache::new(
            Box::new(CountingEmbedder {
                inner: HashEmbedder::default(),
                calls: calls.clone(),
            }),
            CacheConfig {
                mode: CacheMode::On,
                threshold: 0.9,
                ..Default::default()
            },
        );
        let p = SemanticCache::partition_key("m", "s", "", "qa", "t");
        c.put(
            p,
            "how do refunds work?",
            b"cached".to_vec(),
            "j".into(),
            1,
            0,
        );
        let before = calls.load(Ordering::SeqCst);
        let hit = c.get(p, "how do refunds work?", 1);
        assert!(hit.is_some());
        assert_eq!(
            calls.load(Ordering::SeqCst),
            before,
            "an exact hit must not call embed() at all"
        );
    }

    #[test]
    fn a_miss_still_falls_through_to_the_similarity_walk() {
        let calls = Arc::new(AtomicUsize::new(0));
        let c = SemanticCache::new(
            Box::new(CountingEmbedder {
                inner: HashEmbedder::default(),
                calls: calls.clone(),
            }),
            CacheConfig {
                mode: CacheMode::On,
                threshold: 0.9,
                ..Default::default()
            },
        );
        let p = SemanticCache::partition_key("m", "s", "", "qa", "t");
        c.put(
            p,
            "how do refunds work?",
            b"cached".to_vec(),
            "j".into(),
            1,
            0,
        );
        let before = calls.load(Ordering::SeqCst);
        // A materially different core: no exact match, must still embed.
        let _ = c.get(p, "what is the weather like today", 1);
        assert!(
            calls.load(Ordering::SeqCst) > before,
            "a non-exact query must still be embedded for the similarity walk"
        );
    }

    #[test]
    fn hash_collision_never_serves_the_wrong_response() {
        let c = cache(CacheMode::On);
        let p = SemanticCache::partition_key("m", "s", "", "qa", "t");
        // Two different cores, forced into the SAME exact-index bucket via
        // the test-only hook (a real 64-bit SipHash collision cannot be
        // hand-crafted, so the bucket key is forced directly). Queried
        // through `get_exact_only_forcing_index_hash`, which calls the same
        // `find_exact` the real `get` calls with that SAME forced bucket, so
        // this exercises exactly the digest-verification code path a real
        // collision would reach. Without it, whichever entry the bucket scan
        // reaches first would be served for either query, alpha's document
        // returned for a query that asked for beta's, or the reverse.
        c.put_forcing_index_hash(p, 42, "alpha document", b"alpha-body".to_vec(), 10, 0);
        c.put_forcing_index_hash(p, 42, "beta document", b"beta-body".to_vec(), 20, 0);
        assert_eq!(c.entry_count(p), 2, "a forced collision is not a replace");

        let hit_for_alpha = c
            .get_exact_only_forcing_index_hash(p, 42, "alpha document", 1)
            .expect("alpha's own text must still be found in the shared bucket");
        assert_eq!(hit_for_alpha.response, b"alpha-body");

        let hit_for_beta = c
            .get_exact_only_forcing_index_hash(p, 42, "beta document", 1)
            .expect("beta's own text must still be found in the shared bucket");
        assert_eq!(hit_for_beta.response, b"beta-body");
    }

    #[test]
    fn an_expired_exact_entry_is_not_served() {
        let c = SemanticCache::new(
            Box::new(HashEmbedder::default()),
            CacheConfig {
                mode: CacheMode::On,
                threshold: 0.9,
                ttl_millis: 1000,
                ..Default::default()
            },
        );
        let p = SemanticCache::partition_key("m", "s", "", "qa", "t");
        c.put(p, "some question", b"r".to_vec(), "j".into(), 1, 0);
        assert!(c.get(p, "some question", 1000).is_some());
        assert!(
            c.get(p, "some question", 1001).is_none(),
            "an expired exact-match entry must not be served"
        );
    }

    #[test]
    fn expired_entries_disappear_after_a_put() {
        let c = SemanticCache::new(
            Box::new(HashEmbedder::default()),
            CacheConfig {
                mode: CacheMode::On,
                threshold: 0.9,
                ttl_millis: 1000,
                ..Default::default()
            },
        );
        let p = SemanticCache::partition_key("m", "s", "", "qa", "t");
        c.put(p, "some question", b"r".to_vec(), "j".into(), 1, 0);
        assert_eq!(c.entry_count(p), 1);
        // A later put (of something else) sweeps the expired entry.
        c.put(p, "another question", b"r2".to_vec(), "j".into(), 1, 5000);
        assert_eq!(
            c.entry_count(p),
            1,
            "the expired entry must have been swept by the later put"
        );
        assert_eq!(
            c.index_entry_count(p),
            1,
            "the exact-index bucket for the expired entry must be swept too"
        );
    }

    #[test]
    fn zero_vector_embedding_never_matches() {
        struct ZeroEmbedder;
        impl Embedder for ZeroEmbedder {
            fn embed(&self, _text: &str) -> Vec<f32> {
                vec![0.0; 16]
            }
        }
        let c = SemanticCache::new(
            Box::new(ZeroEmbedder),
            CacheConfig {
                mode: CacheMode::On,
                threshold: 0.9,
                entity_guard: false,
                ..Default::default()
            },
        );
        let p = SemanticCache::partition_key("m", "s", "", "qa", "t");
        c.put(p, "alpha", b"r".to_vec(), "j".into(), 1, 0);
        // A different core (no exact match) with a zero embedding must never
        // match via the similarity walk, and must not produce a NaN either.
        let hit = c.get(p, "totally different text", 1);
        assert!(hit.is_none(), "a zero-vector embedding must never match");
    }

    #[test]
    fn eviction_keeps_the_exact_index_in_step() {
        let c = SemanticCache::new(
            Box::new(HashEmbedder::default()),
            CacheConfig {
                mode: CacheMode::On,
                threshold: 0.9,
                max_per_partition: 4,
                ..Default::default()
            },
        );
        let p = SemanticCache::partition_key("m", "s", "", "qa", "t");
        for i in 0..10 {
            c.put(
                p,
                &format!("distinct question number {i}"),
                format!("r{i}").into_bytes(),
                "j".into(),
                1,
                i as i64,
            );
        }
        assert_eq!(c.entry_count(p), 4, "the cap must be enforced");
        assert_eq!(
            c.index_entry_count(p),
            4,
            "the exact-index must never carry an entry for an evicted id"
        );
        // The oldest six were evicted and must not be servable.
        assert!(c.get(p, "distinct question number 0", 100).is_none());
        // The newest four must still be servable, exactly.
        assert!(c.get(p, "distinct question number 9", 100).is_some());
    }

    #[test]
    fn entity_and_length_guards_still_apply_on_the_similarity_path() {
        let c = cache(CacheMode::On);
        let p = SemanticCache::partition_key("m", "s", "", "qa", "t");
        c.put(
            p,
            "a plan for 5 users please",
            b"r".to_vec(),
            "j".into(),
            1,
            0,
        );
        // Different entity, different-enough text to miss the exact index.
        assert!(c.get(p, "a plan for 50 users please", 1).is_none());
        // Wildly different length: length-ratio guard.
        assert!(c
            .get(
                p,
                "a plan for 5 users please and also a very much longer question that goes on and on well past any reasonable ratio",
                1
            )
            .is_none());
    }

    /// A test-only embedder returning fixed, already-unit-length vectors for
    /// two specific texts, so the similarity comparison's boundary
    /// (`sim >= threshold`) can be pinned exactly rather than approximated.
    struct FixedVectorEmbedder;
    impl Embedder for FixedVectorEmbedder {
        fn embed(&self, text: &str) -> Vec<f32> {
            match text {
                "aaaa" => vec![1.0, 0.0],
                // dot((1,0), (0.6,0.8)) = 0.6 exactly, and (0.6,0.8) is
                // already unit length: 0.6^2 + 0.8^2 = 1.0.
                "bbbb" => vec![0.6, 0.8],
                _ => vec![0.0, 0.0],
            }
        }
    }

    #[test]
    fn threshold_boundary_is_inclusive_on_the_similarity_path() {
        // `sim >= threshold` at the exact boundary must still count as a
        // hit: the guard against a `>=` -> `>` mutant. "aaaa" and "bbbb"
        // are different cores (so this takes the SIMILARITY path, never the
        // exact-match index) with a known, exact dot product of 0.6.
        let c = SemanticCache::new(
            Box::new(FixedVectorEmbedder),
            CacheConfig {
                mode: CacheMode::On,
                threshold: 0.6,
                entity_guard: false,
                ..Default::default()
            },
        );
        let p = SemanticCache::partition_key("m", "s", "", "qa", "t");
        c.put(p, "aaaa", b"r".to_vec(), "j".into(), 1, 0);
        let hit = c.get(p, "bbbb", 1);
        assert!(
            hit.is_some(),
            "a similarity exactly at the threshold must still hit"
        );
        assert!((hit.unwrap().similarity - 0.6).abs() < 1e-6);
    }

    #[test]
    fn a_similarity_just_under_the_threshold_never_hits() {
        // The other half of the boundary: `<=` -> `>=`-with-slop mutants are
        // caught by requiring a similarity just below the line to miss.
        let c = SemanticCache::new(
            Box::new(FixedVectorEmbedder),
            CacheConfig {
                mode: CacheMode::On,
                threshold: 0.600001,
                entity_guard: false,
                ..Default::default()
            },
        );
        let p = SemanticCache::partition_key("m", "s", "", "qa", "t");
        c.put(p, "aaaa", b"r".to_vec(), "j".into(), 1, 0);
        assert!(c.get(p, "bbbb", 1).is_none());
    }

    /// An embedder that returns a non-unit-length vector for the query
    /// text, so a lookup can only succeed if `get` actually L2-normalizes
    /// the query before comparing it — the guard against a mutant that
    /// drops that normalization.
    struct ScaledQueryEmbedder;
    impl Embedder for ScaledQueryEmbedder {
        fn embed(&self, text: &str) -> Vec<f32> {
            match text {
                // Stored via `put`: already unit length, same direction as
                // the query below.
                "eeee" => vec![1.0, 0.0],
                // Queried via `get`: same DIRECTION, half the magnitude.
                // True cosine similarity is 1.0. The raw dot product against
                // the stored unit vector is only 0.5.
                "ffff" => vec![0.5, 0.0],
                _ => vec![0.0, 0.0],
            }
        }
    }

    #[test]
    fn the_query_is_normalized_before_the_similarity_walk() {
        let c = SemanticCache::new(
            Box::new(ScaledQueryEmbedder),
            CacheConfig {
                mode: CacheMode::On,
                // True cosine similarity is 1.0; the un-normalized dot
                // product would be 0.5. This threshold only a normalized
                // query can cross.
                threshold: 0.9,
                entity_guard: false,
                ..Default::default()
            },
        );
        let p = SemanticCache::partition_key("m", "s", "", "qa", "t");
        c.put(p, "eeee", b"r".to_vec(), "j".into(), 1, 0);
        let hit = c.get(p, "ffff", 1);
        assert!(
            hit.is_some(),
            "an un-normalized query must not silently miss a true match"
        );
        assert!((hit.unwrap().similarity - 1.0).abs() < 1e-6);
    }

    #[test]
    fn concurrent_get_and_put_never_deadlock_or_cross_wires() {
        use std::thread;

        let c = Arc::new(SemanticCache::new(
            Box::new(HashEmbedder::default()),
            CacheConfig {
                mode: CacheMode::On,
                threshold: 0.9,
                max_per_partition: 256,
                ..Default::default()
            },
        ));
        let p = SemanticCache::partition_key("m", "s", "", "qa", "t");

        let mut handles = Vec::new();
        for t in 0..8 {
            let c = c.clone();
            handles.push(thread::spawn(move || {
                for i in 0..200 {
                    let core = format!("thread {t} question {i}");
                    c.put(
                        p,
                        &core,
                        format!("r-{t}-{i}").into_bytes(),
                        "j".into(),
                        1,
                        0,
                    );
                    if let Some(hit) = c.get(p, &core, 0) {
                        // Whatever came back must be this thread's own
                        // response for THIS core, never another one's.
                        assert_eq!(hit.response, format!("r-{t}-{i}").into_bytes());
                    }
                }
            }));
        }
        for h in handles {
            h.join().unwrap();
        }
    }

    #[test]
    fn shadow_mode_still_records_and_reports_would_hits() {
        // `SemanticCache` itself does not decide what shadow mode DOES with
        // a hit (proxy.rs does: it records the would-be save and serves the
        // real call), it only decides whether to look at all. Only `Off`
        // skips lookup entirely; `Shadow` still finds and reports a hit,
        // exactly as `On` does.
        let c = cache(CacheMode::Shadow);
        let p = SemanticCache::partition_key("m", "s", "", "qa", "t");
        c.put(p, "q", b"r".to_vec(), "j".into(), 1, 0);
        assert!(c.get(p, "q", 1).is_some());
    }

    /// Not a correctness test: a timing measurement, run only on request
    /// (`cargo test -p tokenfuse-core --lib cache::tests::get_cost_at_10k_entries -- --ignored --nocapture`).
    /// Fills one partition to 10,000 entries (the default `max_per_partition`)
    /// and times `get` for an exact hit, an exact miss (falls through to the
    /// similarity walk) and a similarity hit. No assertion is made on the
    /// numbers; report the PR body's benchmark section, not a gate.
    #[test]
    #[ignore]
    fn get_cost_at_10k_entries() {
        let c = SemanticCache::new(
            Box::new(HashEmbedder::default()),
            CacheConfig {
                mode: CacheMode::On,
                threshold: 0.97,
                max_per_partition: 10_000,
                ..Default::default()
            },
        );
        let p = SemanticCache::partition_key("m", "s", "", "qa", "t");
        for i in 0..10_000 {
            c.put(
                p,
                &format!("distinct benchmark question number {i} about refunds and billing"),
                format!("response body {i}").into_bytes(),
                "application/json".into(),
                1000,
                0,
            );
        }

        const N: u32 = 2000;

        let start = std::time::Instant::now();
        for i in 0..N {
            let core = format!(
                "distinct benchmark question number {} about refunds and billing",
                i % 10_000
            );
            std::hint::black_box(c.get(p, &core, 0));
        }
        let exact_hit = start.elapsed() / N;

        let start = std::time::Instant::now();
        for i in 0..N {
            let core = format!("a completely unrelated query that has never been cached {i}");
            std::hint::black_box(c.get(p, &core, 0));
        }
        let miss = start.elapsed() / N;

        eprintln!(
            "get() at 10,000 entries/partition: exact hit avg {exact_hit:?}, miss (similarity walk) avg {miss:?}"
        );
    }
}
