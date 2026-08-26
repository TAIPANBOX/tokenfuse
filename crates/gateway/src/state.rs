//! Shared application state handed to every request handler.

use crate::clientkeys::ClientKeys;
use crate::firewall::FirewallConfig;
use crate::identitymap::{IdentityMap, StrictMode};
use crate::keystats::KeyStats;
use crate::ledger_backend::{LedgerBackend, LocalLedger};
use crate::provider::Provider;
use crate::router::Router;
use crate::sink::{EventSink, NullSink};
use crate::unitledger::UnitLedger;
use crate::wardryx::Wardryx;
use crate::wasmpolicy::WasmEval;
use std::collections::{HashMap, HashSet};
use std::sync::{Arc, Mutex};
use tokenfuse_core::agent_event::Exporter as EventExporter;
use tokenfuse_core::cache::{CacheConfig, HashEmbedder};
use tokenfuse_core::taint::{Labels, ToolUse};
use tokenfuse_core::{DlpMode, Ledger, Microusd, Policy, PriceBook, SemanticCache};

/// Per-run history of input sizes (tokens), used by the context-growth loop
/// detector. Bounded so a long-lived run cannot grow it without limit.
type History = Arc<Mutex<HashMap<String, Vec<u64>>>>;

/// Set of run ids an operator has killed (hard stop, any mode).
type Killed = Arc<Mutex<HashSet<String>>>;

/// Cloneable handle to the gateway's shared state (all fields are `Arc`).
#[derive(Clone)]
pub struct AppState {
    /// The budget ledger authority — in-process by default, or a raft-replicated
    /// backend under the `cluster` feature (see [`crate::ledger_backend`]).
    pub ledger: Arc<dyn LedgerBackend>,
    pub prices: Arc<PriceBook>,
    pub policy: Arc<Policy>,
    pub provider: Arc<dyn Provider>,
    /// Identifier of the active policy, echoed in the 402 contract.
    pub policy_id: Arc<str>,
    /// Where settled calls are recorded (Parquet, or a no-op by default).
    pub sink: Arc<dyn EventSink>,
    /// Semantic response cache (Off by default).
    pub cache: Arc<SemanticCache>,
    /// Agent-firewall config (Off by default).
    pub firewall: Arc<FirewallConfig>,
    /// Secret-scanning (DLP) mode (Off by default).
    pub dlp: DlpMode,
    /// Refuse a call that carries no `x-fuse-run-id` instead of passing it
    /// through unmetered (false by default).
    ///
    /// The pass-through is what makes this gateway drop-in safe, and it stays
    /// the default for that reason. What it also means is that the meter is
    /// switched on by the caller: omit the header and a real call reaches the
    /// provider with nothing recorded in the ledger, the trace or the event
    /// stream. That is the right trade for an evaluation and the wrong one for
    /// a deployment whose whole claim is that every call is accounted for.
    /// Setting this turns "unmetered" into a 400 rather than a silence.
    pub require_run_id: bool,
    /// PII-masking mode: a separate, opt-in extension of the DLP scanner
    /// (email/card/phone, regex-only, see `tokenfuse_core::dlp`'s module
    /// doc). Off by default, and switched independently of `dlp` so an
    /// existing secret-scanning deployment sees no behavior change until an
    /// operator turns this on too.
    pub dlp_pii: DlpMode,
    /// Model router: picks the cheapest model that still meets a task's
    /// required quality tier (Off by default). See `crate::router`.
    pub router: Arc<Router>,
    /// Optional custom WASM policy.
    pub wasm: Option<Arc<dyn WasmEval>>,
    /// Wardryx enforcement hook (a PEP): enforces decisions made by the
    /// Wardryx policy service (a PDP). Off by default. See `crate::wardryx`.
    pub wardryx: Arc<Wardryx>,
    /// The delegation issuer's keys, or `None` when no issuer is configured.
    ///
    /// `None` is the default and it is not a degraded mode: it means every
    /// chain reaching the PDP is a claim, which is what this gateway sent for
    /// its whole life before 2026-08-26. What changed is that it now SAYS so.
    pub chain_proof: crate::chainproof::ChainProof,
    /// The revocation list this gateway polls, or `None` when it polls none.
    /// See `crate::revocations`.
    pub revocations: crate::revocations::Feed,
    history: History,
    killed: Killed,
    /// Run taint, shared so the MCP broker judges against the same state.
    pub taint: Arc<TaintStore>,
    /// Per-run budgets pushed from the Cloud control plane (override the
    /// client-supplied budget). Empty unless cloud mode is on.
    cloud_budgets: Arc<Mutex<HashMap<String, Microusd>>>,
    /// Agent-event NDJSON exporter (agent-passport SPEC.md §6). Disabled
    /// (zero per-request cost) unless `TOKENFUSE_EVENTS_PATH` is set at
    /// startup — see `crate::events`.
    pub events: Arc<EventExporter>,
    /// What to do about an `agent_id` the envelope would reject. `Off` by
    /// default, which is the historical behaviour; see `crate::agentids`.
    pub agent_id_mode: crate::agentids::AgentIdMode,
    /// Who may send calls through this gateway, and the stable `key_id` their
    /// spend is attributed to. Empty (authentication off, `key_id` empty)
    /// unless `TOKENFUSE_CLIENT_KEYS` is set at startup — see
    /// `crate::clientkeys`.
    pub client_keys: Arc<ClientKeys>,
    /// The declarative key<->agent<->unit identity map (docs/20). Disabled
    /// (every call resolves to no unit, no checks) unless
    /// `TOKENFUSE_IDENTITY_MAP` is set at startup - see `crate::identitymap`.
    pub identity: Arc<IdentityMap>,
    /// How a key<->agent mismatch is handled (`TOKENFUSE_IDENTITY_STRICT`):
    /// off = resolution only, warn = response header, enforce = 403. Governs
    /// ONLY the binding check; unit budgets follow `policy.mode` like every
    /// other budget.
    pub identity_strict: StrictMode,
    /// Per-unit monthly budget counters (docs/20). Uncapped units are not
    /// accounted; disabled entirely when the identity map is off.
    pub units: Arc<UnitLedger>,
    /// Since-startup, in-process counters for client-key activity
    /// (docs/22-key-lifecycle.md): per-key calls/mismatches and an
    /// aggregate unauthorized-attempt count. Always present - it is a plain
    /// in-memory tally with no persistence and no env toggle, harmless
    /// whether or not client keys/identity are configured. See
    /// `crate::keystats`/`crate::keysreport`.
    pub keystats: Arc<KeyStats>,
}

/// The one label no review can take off a run.
///
/// docs/07 B.9 locks anti-exfiltration on in enforce mode. Clearing `secrets`
/// would make that rule unreachable for the run, which is disabling it by
/// another door, and a door is what somebody eventually finds.
pub const UNCLEARABLE: &str = "secrets";

/// The run-taint store, held apart from [`AppState`] so more than one door can
/// judge against one state.
///
/// It exists because the MCP broker is a second enforcement point (docs/07 B.7
/// level 3) with its own state and no `AppState`, and two doors keeping two
/// taint maps would be two answers about one run: an operator reading a refusal
/// at one and a permission at the other has no way to tell which was right.
#[derive(Debug, Default)]
pub struct TaintStore {
    labels: Mutex<HashMap<String, Labels>>,
    /// Labels a human has let go of, per run, and not yet re-acquired
    /// (docs/07 B.4 gate 1). See [`TaintStore::clear`].
    cleared: Mutex<HashMap<String, Labels>>,
    /// Child run -> the parent it declared, for docs/07 B.3 P3. Separate from
    /// the ledger's budget hierarchy: that one is about money and is opened
    /// once per run, this is consulted on every request and must survive a
    /// caller declaring a parent it never opened.
    parents: Mutex<HashMap<String, String>>,
    /// Per run: the tool blocks this gateway has carried, and which of them a
    /// human has signed for. See [`BlockLedger`] and [`TaintStore::split_history`].
    blocks: Mutex<HashMap<String, BlockLedger>>,
}

/// How many tool blocks are tracked per run.
///
/// The set has to survive across requests, because a clearance and the turn it
/// releases are different HTTP calls, and it must not grow without limit: a
/// conversation can carry hundreds of blocks and a run can live for hours.
///
/// The arithmetic, so the number is a decision rather than a round figure. An
/// id is about 30 bytes (`toolu_01A09q9rDvhhBmiSMDCLwuTs`), held twice at the
/// worst (once in arrival order, once in the reviewed set), so a run sitting at
/// this cap with everything reviewed costs on the order of 28 KB. A run with
/// three tool calls costs three ids. 256 covers a long agent conversation
/// without covering a full 200k-token context window, which at roughly 500
/// tokens per call-and-result pair would be nearer 400.
///
/// **Overflow is fail-closed and it is not silent.** The oldest ids are
/// dropped, so the blocks they named read as unreviewed again and their labels
/// return on the next turn. That is the noisy direction rather than the unsafe
/// one, and [`crate::declassify`] reports how many blocks a clearance actually
/// covered so a half-covered conversation says so instead of looking like a
/// broken feature.
pub const MAX_TRACKED_BLOCKS: usize = 256;

/// One run's tool blocks: everything seen, and the subset a human signed for.
///
/// `order` doubles as the membership test. A separate `HashSet` would make
/// `note` O(1) instead of O(cap), and it would also hold a third copy of every
/// id; `note` runs once per request over the blocks that request carried, and
/// a few thousand short string comparisons is not what costs anything on this
/// path.
#[derive(Debug, Default)]
struct BlockLedger {
    /// Every block id this gateway has seen on the run, oldest first.
    order: std::collections::VecDeque<String>,
    /// The subset a human signed for. Always a subset of `order`: an id that
    /// falls out of the window takes its review with it.
    reviewed: HashSet<String>,
}

impl BlockLedger {
    fn note(&mut self, id: &str) {
        if self.order.iter().any(|k| k == id) {
            return;
        }
        self.order.push_back(id.to_string());
        while self.order.len() > MAX_TRACKED_BLOCKS {
            if let Some(old) = self.order.pop_front() {
                self.reviewed.remove(&old);
            }
        }
    }
}

/// A request's tool history, split by whether a human has signed for the block
/// that carried each name.
///
/// Names rather than blocks on both sides, because a label belongs to a tool
/// and [`tokenfuse_core::taint::labels_for_tools`] is what turns one into the
/// other. A name carried by BOTH a reviewed and an unreviewed block lands in
/// `unreviewed` and is absent from `reviewed_only`: a fresh page is a fresh
/// page, whichever earlier page was signed for.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct HistorySplit {
    /// Tools whose blocks nobody has signed for. These still supply labels.
    pub unreviewed: Vec<String>,
    /// Tools every one of whose blocks a human signed for. These supply
    /// nothing: re-supplying them is what spent the clearance.
    pub reviewed_only: Vec<String>,
}

impl TaintStore {
    /// Record which run a child declared as its parent.
    ///
    /// Last write wins, deliberately: the value comes off a request header, so
    /// a caller that changes its mind mid-run has told us something different,
    /// and refusing the second value would mean holding a claim against a
    /// caller that can already say anything. It cannot LOSE taint either way,
    /// because [`inherited`](Self::inherited) only ever adds and a run's own
    /// set is monotonic.
    pub fn note_parent(&self, run_id: &str, parent: &str) {
        if run_id.is_empty() || parent.is_empty() || run_id == parent {
            return;
        }
        self.parents
            .lock()
            .unwrap()
            .insert(run_id.to_string(), parent.to_string());
    }

    /// Every label this run's ancestors carry (docs/07 B.3 P3).
    ///
    /// Walked on each request rather than seeded once when the child opens, so
    /// a parent that becomes untrusted AFTER its child started is picked up on
    /// the child's next call. Seeding once would have made "spawn the child
    /// first" the same bypass in a different order.
    ///
    /// The chain comes off a request header, so its shape is the caller's to
    /// choose and a cycle is one line of curl. The visited set and the depth
    /// cap are not defensive programming: without them this spins inside a
    /// lock held on the request path, which takes down the gateway rather than
    /// the run.
    pub fn inherited(&self, run_id: &str) -> Labels {
        const MAX_DEPTH: usize = 32;
        let parents = self.parents.lock().unwrap();
        let labels = self.labels.lock().unwrap();
        let mut out = Labels::new();
        let mut seen: std::collections::HashSet<String> =
            std::collections::HashSet::from([run_id.to_string()]);
        let mut cursor = parents.get(run_id).cloned();
        let mut depth = 0;
        while let Some(id) = cursor {
            if depth >= MAX_DEPTH || !seen.insert(id.clone()) {
                break;
            }
            depth += 1;
            if let Some(l) = labels.get(&id) {
                out.extend(l.iter().cloned());
            }
            cursor = parents.get(&id).cloned();
        }
        out
    }

    /// Record the tool blocks this request carried, so a clearance arriving
    /// afterwards can say which ones were on the screen somebody read.
    ///
    /// Append-only across requests, within [`MAX_TRACKED_BLOCKS`]. A client
    /// that trims its context therefore does not lose the clearance it was
    /// given for the blocks it dropped, which it would if this were replaced
    /// per request.
    pub fn note_blocks(&self, run_id: &str, blocks: &[ToolUse]) {
        if run_id.is_empty() || blocks.is_empty() {
            return;
        }
        let mut map = self.blocks.lock().unwrap();
        let entry = map.entry(run_id.to_string()).or_default();
        for b in blocks {
            if let Some(id) = &b.id {
                entry.note(id);
            }
        }
    }

    /// Split a request's tool history by whether a human signed for the block.
    ///
    /// This is docs/07 B.4 gate 1 doing the thing it claimed to do. Taint is
    /// re-derived from the whole `messages[]` array on every request, and an
    /// agent loop resends the whole conversation, so before this a clearance
    /// was spent by the next turn of the SAME conversation and the valve
    /// released nothing.
    ///
    /// **A block with no id is unreviewed.** Falling back the other way would
    /// mean a caller could put a block past a clearance by omitting one field,
    /// which is a bypass; falling back this way costs an operator whose
    /// producer sends no ids a valve that still spends on every turn, which is
    /// exactly where they were before.
    pub fn split_history(&self, run_id: &str, blocks: &[ToolUse]) -> HistorySplit {
        let mut split = HistorySplit::default();
        if blocks.is_empty() {
            return split;
        }
        let map = self.blocks.lock().unwrap();
        let reviewed = map.get(run_id).map(|l| &l.reviewed);
        for b in blocks {
            let signed = match (&b.id, reviewed) {
                (Some(id), Some(set)) => set.contains(id),
                _ => false,
            };
            if signed {
                split.reviewed_only.push(b.name.clone());
            } else {
                split.unreviewed.push(b.name.clone());
            }
        }
        split
            .reviewed_only
            .retain(|n| !split.unreviewed.contains(n));
        split.reviewed_only.dedup();
        split
    }

    /// Sign for tool blocks on a run, on behalf of the human who read them.
    ///
    /// An empty `ids` is the INFERENCE: everything this gateway has seen on the
    /// run. That is the friendly form and the accurate one. What an operator is
    /// looking at when they clear a run is the refusal, which carries the rule,
    /// the labels and the tool but not the conversation, and this gateway does
    /// not store conversations for a console to fetch. Requiring ids would push
    /// the decision about what a human read onto the agent framework, which is
    /// the party this endpoint exists to overrule.
    ///
    /// A non-empty `ids` is honoured, and any id this run never carried refuses
    /// the WHOLE list: it is either a mistake or an attempt to sign for a block
    /// that has not arrived yet, and a forward-dated review is the permanent
    /// exemption this valve must not hand out. Returns `Err` with those ids.
    pub fn mark_reviewed(&self, run_id: &str, ids: &[String]) -> Result<usize, Vec<String>> {
        let mut map = self.blocks.lock().unwrap();
        let Some(entry) = map.get_mut(run_id) else {
            // Nothing seen: no ids to sign for, and any named id is unknown.
            return if ids.is_empty() {
                Ok(0)
            } else {
                Err(ids.to_vec())
            };
        };
        if ids.is_empty() {
            entry.reviewed = entry.order.iter().cloned().collect();
            return Ok(entry.reviewed.len());
        }
        // Checked in full before anything is written: a partly-applied review
        // is a state nobody asked for and nobody can read back.
        let unknown: Vec<String> = ids
            .iter()
            .filter(|id| !entry.order.iter().any(|k| k == *id))
            .cloned()
            .collect();
        if !unknown.is_empty() {
            return Err(unknown);
        }
        for id in ids {
            entry.reviewed.insert(id.clone());
        }
        Ok(ids.len())
    }

    /// Let a human's review take a label off a run (docs/07 B.4 gate 1).
    ///
    /// Returns what was actually let go. `secrets` is never among it: docs/07
    /// B.9 locks anti-exfiltration on in enforce mode, and clearing that label
    /// would make the rule unreachable for a run, which is disabling it by
    /// another door.
    ///
    /// **A clearance is spent by the next arrival of that label from a block
    /// nobody signed for.** The human reviewed what was THERE, not what comes
    /// next, and a clearance that survived the next arrival would mean one
    /// review buys an agent a permanent exemption, which is worse than having
    /// no valve at all. See [`accumulate`](Self::accumulate), which is where it
    /// is spent, and [`split_history`](Self::split_history), which decides
    /// which arrivals count.
    ///
    /// "Arrival" used to mean the label appearing anywhere in the request, and
    /// that made the valve useless: an agent loop resends the whole
    /// conversation on every turn, so the very block a human had just reviewed
    /// re-supplied its label and spent the clearance before the run's next
    /// action was judged. A review is now about blocks, so the same block
    /// arriving again is not an arrival.
    pub fn clear(&self, run_id: &str, labels: &[String]) -> (Vec<String>, Vec<String>) {
        let mut refused = Vec::new();
        let mut cleared = Vec::new();
        let mut own = self.labels.lock().unwrap();
        let mut gone = self.cleared.lock().unwrap();
        let entry = gone.entry(run_id.to_string()).or_default();
        for l in labels {
            if l == UNCLEARABLE {
                refused.push(l.clone());
                continue;
            }
            entry.insert(l.clone());
            if let Some(set) = own.get_mut(run_id) {
                set.remove(l);
            }
            cleared.push(l.clone());
        }
        cleared.sort();
        refused.sort();
        (cleared, refused)
    }

    /// Labels this run is judged against that a clearance is NOT hiding,
    /// because they are still arriving from an ancestor.
    ///
    /// Reported back to whoever cleared, so a half-done job says so instead of
    /// looking like a broken feature: clear a child while its parent is dirty
    /// and the label returns on the child's very next call, correctly, because
    /// the parent is still dirty and the child is still downstream of it.
    pub fn still_inherited(&self, run_id: &str, labels: &[String]) -> Vec<String> {
        let inherited = self.inherited(run_id);
        let mut out: Vec<String> = labels
            .iter()
            .filter(|l| inherited.contains(*l))
            .cloned()
            .collect();
        out.sort();
        out
    }

    /// Merge `new_labels` into a run's set and report what changed.
    ///
    /// Returns the delta as well as the total because a caller has to be able
    /// to tell a run that just became untrusted from one that has been
    /// untrusted for thirty turns. Before 2026-08-26 this returned only the
    /// total, which is why the acquisition could not be recorded: by the time
    /// the set was in hand there was no way left to know which of it was new.
    pub fn accumulate(&self, run_id: &str, new_labels: Labels) -> TaintDelta {
        // Spending a clearance, and it happens HERE rather than in `clear`
        // because "the next arrival" is an arrival, and this is the only place
        // one happens. A label supplied again by a tool, a header or an
        // ancestor takes its clearance with it.
        if !new_labels.is_empty() {
            let mut gone = self.cleared.lock().unwrap();
            if let Some(set) = gone.get_mut(run_id) {
                for l in &new_labels {
                    set.remove(l);
                }
            }
        }
        let mut map = self.labels.lock().unwrap();
        let entry = map.entry(run_id.to_string()).or_default();
        let added: Labels = new_labels.difference(entry).cloned().collect();
        entry.extend(new_labels);
        TaintDelta {
            added,
            carrying: entry.clone(),
        }
    }

    /// Everything a run is judged against: its own labels plus its ancestors',
    /// minus anything a human has let go of and that has not arrived again.
    pub fn effective(&self, run_id: &str) -> Labels {
        let mut out = self.accumulate(run_id, Labels::new()).carrying;
        out.extend(self.inherited(run_id));
        if let Some(gone) = self.cleared.lock().unwrap().get(run_id) {
            out.retain(|l| !gone.contains(l));
        }
        out
    }

    /// What a run is judged against right now, for a caller that is not also
    /// accumulating. Same answer as [`effective`](Self::effective).
    pub fn judged_against(&self, run_id: &str) -> Labels {
        self.effective(run_id)
    }
}

/// What one [`TaintStore::accumulate`] call did: the labels this run did
/// not already carry, and everything it carries now.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TaintDelta {
    /// New to this run. Empty on every call after the first that supplied a
    /// given label, because taint is monotonic.
    pub added: Labels,
    /// The full set after the merge.
    pub carrying: Labels,
}

impl AppState {
    pub fn new(
        ledger: Arc<Ledger>,
        prices: Arc<PriceBook>,
        policy: Arc<Policy>,
        provider: Arc<dyn Provider>,
        policy_id: impl Into<Arc<str>>,
    ) -> Self {
        AppState {
            // No delegation issuer until `main` configures one, so every chain
            // is a claim and every existing deployment is unchanged.
            chain_proof: None,
            // No poller until `serve` configures one, so nothing is refused.
            revocations: None,
            // Wrap the in-process ledger as the default backend. `with_ledger`
            // swaps in a raft-replicated backend for HA (cluster feature).
            ledger: Arc::new(LocalLedger(ledger)),
            prices,
            policy,
            provider,
            policy_id: policy_id.into(),
            sink: Arc::new(NullSink),
            cache: Arc::new(SemanticCache::new(
                Box::new(HashEmbedder::default()),
                CacheConfig::default(), // Off
            )),
            firewall: Arc::new(FirewallConfig::disabled()),
            // On, since 2026-08-06. See `crate::defaults` for the finding that
            // moved both of these: a guarantee that is off until somebody sets
            // a variable protects the deployments that already knew, which are
            // the ones that needed it least.
            dlp: DlpMode::Block,
            require_run_id: true,
            dlp_pii: DlpMode::Off,
            router: Arc::new(Router::disabled()),
            wasm: None,
            wardryx: Arc::new(Wardryx::disabled()),
            history: Arc::new(Mutex::new(HashMap::new())),
            killed: Arc::new(Mutex::new(HashSet::new())),
            taint: Arc::new(TaintStore::default()),
            cloud_budgets: Arc::new(Mutex::new(HashMap::new())),
            events: Arc::new(EventExporter::disabled()),
            agent_id_mode: crate::agentids::AgentIdMode::default(),
            client_keys: Arc::new(ClientKeys::default()),
            identity: Arc::new(IdentityMap::default()),
            identity_strict: StrictMode::Off,
            units: Arc::new(UnitLedger::default()),
            keystats: Arc::new(KeyStats::default()),
        }
    }

    /// Require a client credential on metered calls, resolving it to a stable
    /// `key_id`. Chainable. Not set means authentication stays off, which is
    /// what every existing deployment gets on upgrade.
    pub fn with_client_keys(mut self, keys: Arc<ClientKeys>) -> Self {
        self.client_keys = keys;
        self
    }

    /// Wire the identity map, its strict mode, and the per-unit monthly
    /// ledger (docs/20). Chainable. Not set means identity stays off, which
    /// is what every existing deployment gets on upgrade.
    pub fn with_identity(
        mut self,
        map: Arc<IdentityMap>,
        strict: StrictMode,
        units: Arc<UnitLedger>,
    ) -> Self {
        self.identity = map;
        self.identity_strict = strict;
        self.units = units;
        self
    }

    /// Replace the Cloud-managed budget overrides (run id → µUSD). Called by the
    /// budget poller when cloud mode is on.
    pub fn set_cloud_budgets(&self, budgets: HashMap<String, Microusd>) {
        *self.cloud_budgets.lock().unwrap() = budgets;
    }

    /// The Cloud-managed budget for a run, if one has been set.
    pub fn cloud_budget(&self, run_id: &str) -> Option<Microusd> {
        self.cloud_budgets.lock().unwrap().get(run_id).copied()
    }

    /// Replace the ledger backend (e.g. a raft-replicated one). Chainable.
    pub fn with_ledger(mut self, ledger: Arc<dyn LedgerBackend>) -> Self {
        self.ledger = ledger;
        self
    }

    /// Set the DLP (secret-scanning) mode. Chainable.
    pub fn with_dlp(mut self, dlp: DlpMode) -> Self {
        self.dlp = dlp;
        self
    }

    /// Refuse calls that would not be metered. Chainable.
    ///
    /// On by default since 2026-08-06. `with_require_run_id(false)` restores
    /// the historical drop-in pass-through, where a missing `x-fuse-run-id`
    /// means the call reaches the provider and leaves no trace in any ledger,
    /// trace or event stream. That is a real thing to want in front of an
    /// existing client, and it is now a thing an operator says rather than a
    /// thing that happens.
    pub fn with_require_run_id(mut self, require: bool) -> Self {
        self.require_run_id = require;
        self
    }

    /// Set the PII-masking mode. Chainable. Independent of `with_dlp`: not
    /// set means PII scanning stays off, which is what every existing
    /// deployment gets on upgrade.
    pub fn with_dlp_pii(mut self, dlp_pii: DlpMode) -> Self {
        self.dlp_pii = dlp_pii;
        self
    }

    /// Attach a custom WASM policy. Chainable.
    pub fn with_wasm(mut self, wasm: Arc<dyn WasmEval>) -> Self {
        self.wasm = Some(wasm);
        self
    }

    /// Attach an agent-firewall config. Chainable.
    pub fn with_firewall(mut self, firewall: Arc<FirewallConfig>) -> Self {
        self.firewall = firewall;
        self
    }

    /// Attach a model router. Chainable.
    pub fn with_router(mut self, router: Arc<Router>) -> Self {
        self.router = router;
        self
    }

    /// Attach the Wardryx enforcement hook. Chainable.
    pub fn with_wardryx(mut self, wardryx: Arc<Wardryx>) -> Self {
        self.wardryx = wardryx;
        self
    }

    /// The delegation issuer's keys, and the revocation list they are checked
    /// against. Taken together in one call on purpose: a door with an issuer
    /// and no feed still verifies, but a feed with no issuer verifies nothing
    /// and is the configuration `revocations::wanted` refuses at startup.
    pub fn with_chain_proof(
        mut self,
        chain_proof: crate::chainproof::ChainProof,
        revocations: crate::revocations::Feed,
    ) -> Self {
        self.chain_proof = chain_proof;
        self.revocations = revocations;
        self
    }

    /// Merge `new_labels` into a run's taint set and report what changed.
    ///
    /// Returns the delta as well as the total because the caller has to be
    /// able to tell a run that just became untrusted from one that has been
    /// untrusted for thirty turns. Before 2026-08-26 this returned only the
    /// total, which is why the acquisition could not be recorded: by the time
    /// the set was in hand there was no way left to know which of it was new.
    pub fn accumulate_taint(&self, run_id: &str, new_labels: Labels) -> TaintDelta {
        self.taint.accumulate(run_id, new_labels)
    }

    /// See [`TaintStore::note_parent`].
    pub fn note_taint_parent(&self, run_id: &str, parent: &str) {
        self.taint.note_parent(run_id, parent);
    }

    /// See [`TaintStore::inherited`].
    pub fn inherited_taint(&self, run_id: &str) -> Labels {
        self.taint.inherited(run_id)
    }

    /// Attach an event sink (e.g. the Parquet trace). Chainable.
    pub fn with_sink(mut self, sink: Arc<dyn EventSink>) -> Self {
        self.sink = sink;
        self
    }

    /// Attach the agent-event NDJSON exporter. Chainable.
    pub fn with_events(mut self, events: Arc<EventExporter>) -> Self {
        self.events = events;
        self
    }

    /// Chainable. See `crate::agentids` for why the default is permissive.
    pub fn with_agent_id_mode(mut self, mode: crate::agentids::AgentIdMode) -> Self {
        self.agent_id_mode = mode;
        self
    }

    /// Attach a semantic cache. Chainable.
    pub fn with_cache(mut self, cache: Arc<SemanticCache>) -> Self {
        self.cache = cache;
        self
    }

    /// Mark a run as killed — subsequent calls are hard-blocked in any mode.
    pub fn kill(&self, run_id: &str) {
        self.killed.lock().unwrap().insert(run_id.to_string());
    }

    pub fn is_killed(&self, run_id: &str) -> bool {
        self.killed.lock().unwrap().contains(run_id)
    }

    /// Record this step's input size for a run and return the recent history
    /// (oldest→newest), capped to the most recent `MAX` steps.
    pub fn record_input(&self, run_id: &str, input_tokens: u64) -> Vec<u64> {
        const MAX: usize = 128;
        let mut map = self.history.lock().unwrap();
        let entry = map.entry(run_id.to_string()).or_default();
        entry.push(input_tokens);
        if entry.len() > MAX {
            let excess = entry.len() - MAX;
            entry.drain(0..excess);
        }
        entry.clone()
    }
}

#[cfg(test)]
mod block_ledger_tests {
    use super::*;

    fn use_of(id: Option<&str>, name: &str) -> ToolUse {
        ToolUse {
            id: id.map(str::to_string),
            name: name.to_string(),
        }
    }

    #[test]
    fn the_same_block_arriving_again_is_not_an_arrival() {
        // The defect this exists to close, at the level below the HTTP path: an
        // agent loop resends the whole conversation, so the block a human
        // reviewed came back on every turn and re-supplied its label.
        let st = TaintStore::default();
        let history = vec![use_of(Some("t1"), "web_search")];
        st.note_blocks("r", &history);
        assert_eq!(st.mark_reviewed("r", &[]), Ok(1));
        let split = st.split_history("r", &history);
        assert!(split.unreviewed.is_empty(), "{split:?}");
        assert_eq!(split.reviewed_only, vec!["web_search"]);
    }

    #[test]
    fn one_name_on_two_blocks_is_unreviewed_while_either_is() {
        // A tool is not a block. Signing for one page does not sign for the
        // next, and the label has to come back for the unsigned one, so the
        // name lands in `unreviewed` and is absent from `reviewed_only`.
        let st = TaintStore::default();
        st.note_blocks("r", &[use_of(Some("t1"), "web_search")]);
        assert_eq!(st.mark_reviewed("r", &[]), Ok(1));
        let grown = vec![
            use_of(Some("t1"), "web_search"),
            use_of(Some("t2"), "web_search"),
        ];
        st.note_blocks("r", &grown);
        let split = st.split_history("r", &grown);
        assert_eq!(split.unreviewed, vec!["web_search"]);
        assert!(
            split.reviewed_only.is_empty(),
            "a name carried by an unsigned block is not a signed name: {split:?}"
        );
    }

    #[test]
    fn a_block_with_no_id_is_unreviewed_however_the_run_was_cleared() {
        // The unsafe fallback would be a one-field bypass: omit the id and the
        // block goes past any clearance.
        let st = TaintStore::default();
        let anon = vec![use_of(None, "web_search")];
        st.note_blocks("r", &anon);
        assert_eq!(
            st.mark_reviewed("r", &[]),
            Ok(0),
            "there was nothing identifiable to sign for"
        );
        assert_eq!(st.split_history("r", &anon).unreviewed, vec!["web_search"]);
    }

    #[test]
    fn signing_for_a_block_that_never_arrived_refuses_the_whole_list() {
        // A forward-dated review is a permanent exemption bought before the
        // thing it exempts exists. Refused whole rather than partly applied,
        // because a partly-applied review is a state nobody asked for and
        // nobody can read back.
        let st = TaintStore::default();
        st.note_blocks("r", &[use_of(Some("t1"), "web_search")]);
        assert_eq!(
            st.mark_reviewed("r", &["t1".into(), "t9".into()]),
            Err(vec!["t9".to_string()])
        );
        assert_eq!(
            st.split_history("r", &[use_of(Some("t1"), "web_search")])
                .unreviewed,
            vec!["web_search"],
            "and nothing was written on the way to refusing"
        );
    }

    #[test]
    fn the_tracked_set_is_bounded_and_overflowing_it_is_fail_closed() {
        // An unbounded set is a leak: a conversation can carry hundreds of
        // blocks and a run can live for hours. Overflow drops the OLDEST, so
        // the blocks it drops read as unreviewed again and their labels return,
        // which is the noisy direction rather than the unsafe one.
        let st = TaintStore::default();
        let all: Vec<ToolUse> = (0..MAX_TRACKED_BLOCKS + 1)
            .map(|i| use_of(Some(&format!("t{i}")), "web_search"))
            .collect();
        st.note_blocks("r", &all);
        assert_eq!(st.mark_reviewed("r", &[]), Ok(MAX_TRACKED_BLOCKS));

        let oldest = vec![use_of(Some("t0"), "web_search")];
        assert_eq!(
            st.split_history("r", &oldest).unreviewed,
            vec!["web_search"],
            "the id that fell out of the window took its review with it"
        );
        let newest = vec![use_of(
            Some(&format!("t{MAX_TRACKED_BLOCKS}")),
            "web_search",
        )];
        assert!(st.split_history("r", &newest).unreviewed.is_empty());
    }

    #[test]
    fn a_review_that_scrolls_out_of_the_window_stops_counting() {
        // The other half of the cap, and the half a mutant caught: without it
        // the reviewed set outlives the block list it is about and grows
        // without limit, which is the leak the cap exists to stop, and a
        // reviewed id that no longer names anything is a review nobody can
        // read back.
        //
        // Written after `the_tracked_set_is_bounded_and_overflowing_it_is_fail_closed`
        // failed to catch `reviewed.remove(&old)` being deleted: that test
        // signs for the blocks AFTER the overflow, so the evicted id was never
        // in the reviewed set at all and the cull was never exercised.
        let st = TaintStore::default();
        st.note_blocks("r", &[use_of(Some("t0"), "web_search")]);
        assert_eq!(st.mark_reviewed("r", &[]), Ok(1));

        let later: Vec<ToolUse> = (1..=MAX_TRACKED_BLOCKS)
            .map(|i| use_of(Some(&format!("t{i}")), "read_upload"))
            .collect();
        st.note_blocks("r", &later);

        assert_eq!(
            st.split_history("r", &[use_of(Some("t0"), "web_search")])
                .unreviewed,
            vec!["web_search"],
            "an id that fell out of the window takes its review with it"
        );
    }

    #[test]
    fn a_client_that_trims_its_context_keeps_the_clearance_it_was_given() {
        // The set is append-only across requests rather than replaced per
        // request. Replacing it would mean a client dropping old turns from its
        // context silently un-reviewed them, and the label would come back for
        // a block nobody re-sent.
        let st = TaintStore::default();
        let full = vec![
            use_of(Some("t1"), "web_search"),
            use_of(Some("t2"), "read_upload"),
        ];
        st.note_blocks("r", &full);
        assert_eq!(st.mark_reviewed("r", &[]), Ok(2));
        // Next turn the client sends only the tail.
        let trimmed = vec![use_of(Some("t2"), "read_upload")];
        st.note_blocks("r", &trimmed);
        // The turn after, the head is back.
        assert!(st.split_history("r", &full).unreviewed.is_empty());
    }
}
