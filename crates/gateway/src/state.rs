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
use tokenfuse_core::taint::Labels;
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
    /// Child run -> the parent it declared, for docs/07 B.3 P3. Separate from
    /// the ledger's budget hierarchy: that one is about money and is opened
    /// once per run, this is consulted on every request and must survive a
    /// caller declaring a parent it never opened.
    parents: Mutex<HashMap<String, String>>,
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

    /// Merge `new_labels` into a run's set and report what changed.
    ///
    /// Returns the delta as well as the total because a caller has to be able
    /// to tell a run that just became untrusted from one that has been
    /// untrusted for thirty turns. Before 2026-08-26 this returned only the
    /// total, which is why the acquisition could not be recorded: by the time
    /// the set was in hand there was no way left to know which of it was new.
    pub fn accumulate(&self, run_id: &str, new_labels: Labels) -> TaintDelta {
        let mut map = self.labels.lock().unwrap();
        let entry = map.entry(run_id.to_string()).or_default();
        let added: Labels = new_labels.difference(entry).cloned().collect();
        entry.extend(new_labels);
        TaintDelta {
            added,
            carrying: entry.clone(),
        }
    }

    /// Everything a run is judged against: its own labels plus its ancestors'.
    pub fn effective(&self, run_id: &str) -> Labels {
        let mut out = self.accumulate(run_id, Labels::new()).carrying;
        out.extend(self.inherited(run_id));
        out
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
