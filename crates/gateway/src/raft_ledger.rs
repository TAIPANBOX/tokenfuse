//! Raft-replicated ledger backend (feature `cluster`).
//!
//! The gateway co-locates a raft node (`tokenfuse_cluster::server::HttpNode`) and
//! runs its HTTP server so peer gateways can replicate to it. Reserve/open/settle
//! become raft writes, transparently forwarded to the leader; the budget check is
//! therefore linearized across every gateway sharing the cluster — no two agents
//! double-spend the same ceiling, and budgets survive a gateway crash.
//!
//! The replicated state machine models **hierarchical** budgets (a run rolls up
//! into its `parent`) and per-run **step** counts, matching the in-process
//! ledger. If consensus is unreachable, reserve **fails open** (consistent with
//! TokenFuse's default) so a cluster outage degrades to "no enforcement", never
//! "all agents blocked".

use std::collections::HashSet;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use tokenfuse_cluster::net_http::Peers;
use tokenfuse_cluster::server::{self, HttpNode};
use tokenfuse_cluster::types::Request;
use tokenfuse_core::{
    BudgetError, ChainLink, Microusd, OpenError, Opened, ParentDisposition, Reservation,
    RunSnapshot,
};

use crate::ledger_backend::LedgerBackend;

pub struct RaftLedger {
    node: Arc<HttpNode>,
    /// Process-local reservation ids and the outstanding set: exactly-once at THIS gateway.
    /// Not replicated: a second gateway cannot see them (documented in invariant 49).
    next_id: AtomicU64,
    outstanding: Mutex<HashSet<u64>>,
}

impl RaftLedger {
    /// Build the co-located raft node, start its HTTP server on `addr`, and
    /// optionally initialize the cluster (do this on exactly one node).
    #[allow(clippy::too_many_arguments)]
    pub async fn start(
        id: u64,
        addr: SocketAddr,
        peers: Peers,
        bootstrap: bool,
        data_dir: Option<String>,
        token: Option<String>,
    ) -> Result<Arc<Self>, Box<dyn std::error::Error>> {
        let node = match data_dir {
            Some(dir) if !dir.is_empty() => {
                tracing::info!(%dir, "raft storage: durable (redb)");
                HttpNode::build_durable(id, peers, dir, token).await?
            }
            _ => {
                tracing::info!(
                    "raft storage: in-memory (set TOKENFUSE_CLUSTER_DATA_DIR for durable)"
                );
                HttpNode::build(id, peers, token).await?
            }
        };

        // Serve peer RPCs + the admin/app API in the background. Transport:
        //   * plain HTTP                                    — no TLS env set
        //   * HTTPS (TLS_CERT + TLS_KEY)                    — server auth only
        //   * mutual TLS (+ MTLS_CA)                        — server *and* client
        //     certs required, giving cryptographic peer auth on top of the token.
        let serve_node = node.clone();
        let tls = match (
            std::env::var("TOKENFUSE_CLUSTER_TLS_CERT"),
            std::env::var("TOKENFUSE_CLUSTER_TLS_KEY"),
        ) {
            (Ok(c), Ok(k)) if !c.is_empty() && !k.is_empty() => {
                Some((std::fs::read(c)?, std::fs::read(k)?))
            }
            _ => None,
        };
        let client_ca = match std::env::var("TOKENFUSE_CLUSTER_MTLS_CA") {
            Ok(p) if !p.is_empty() => Some(std::fs::read(p)?),
            _ => None,
        };
        tokio::spawn(async move {
            let res = match (tls, client_ca) {
                (Some((cert, key)), Some(ca)) => {
                    tracing::info!("cluster server: mutual TLS (client certs required)");
                    server::serve_mtls(serve_node, addr, cert, key, ca).await
                }
                (Some((cert, key)), None) => {
                    tracing::info!("cluster server: HTTPS (TLS)");
                    server::serve_tls(serve_node, addr, cert, key).await
                }
                (None, _) => server::serve(serve_node, addr).await,
            };
            if let Err(e) = res {
                tracing::error!("cluster server exited: {e}");
            }
        });

        if bootstrap {
            let init_node = node.clone();
            tokio::spawn(async move {
                tokio::time::sleep(std::time::Duration::from_millis(300)).await;
                match init_node.init().await {
                    Ok(()) => tracing::info!("raft cluster initialized"),
                    Err(e) => tracing::info!("raft init skipped: {e}"),
                }
            });
        }

        Ok(Arc::new(Self {
            node,
            next_id: AtomicU64::new(0),
            outstanding: Mutex::new(HashSet::new()),
        }))
    }

    /// A granted reservation, whether from an accepted checked reserve, a
    /// fail-open one, or an unchecked one: the same process-local id and
    /// outstanding-set bookkeeping either way, so the three call sites
    /// cannot drift apart. `generation: 0` and a single-link chain naming
    /// only `run_id`, because the raft response does not carry the walked
    /// chain (the state machine settles by walking its own live tree,
    /// unlike the in-process ledger).
    fn grant(&self, run_id: &str, estimate: Microusd, step: u32) -> Reservation {
        let id = self.next_id.fetch_add(1, Ordering::Relaxed) + 1;
        self.outstanding.lock().unwrap().insert(id);
        Reservation {
            id,
            run_id: run_id.to_string(),
            amount: estimate,
            step,
            generation: 0,
            chain: vec![ChainLink {
                run_id: run_id.to_string(),
                generation: 0,
            }],
        }
    }
}

fn snap_of(s: tokenfuse_cluster::types::RunState) -> RunSnapshot {
    RunSnapshot {
        budget: Microusd(s.budget_micros as i64),
        reserved: Microusd(s.reserved_micros as i64),
        spent: Microusd(s.spent_micros as i64),
        steps: s.steps,
    }
}

#[async_trait]
impl LedgerBackend for RaftLedger {
    /// D2 from the LOCAL read only: `sm.read_run` is the eventually
    /// consistent copy `snapshot` reads too, so a refusal here can only be
    /// stale-ABSENT (a lagging follower whose copy has not caught up yet,
    /// which lets the submit through and keeps the state machine's old
    /// parent silently, as at `6fdef03`), never stale-WRONG: the state
    /// machine's `parent` is immutable after the first `Open`. Wider than
    /// the in-process rule on purpose: `AdoptedTooLate` fires whenever the
    /// local copy shows the run exists without a parent, admissions or not,
    /// because the state machine's `Open` never sets a parent on an
    /// existing run at all, so it cannot adopt one the way the in-process
    /// ledger does.
    async fn open_run(
        &self,
        run_id: &str,
        budget: Microusd,
        parent: Option<&str>,
    ) -> Result<Opened, OpenError> {
        if parent == Some(run_id) {
            return Err(OpenError::SelfParent {
                run_id: run_id.to_string(),
            });
        }
        let local = self.node.sm.read_run(run_id).await;
        let declared = parent.map(|p| p.to_string());
        if let Some(l) = &local {
            match (l.parent.as_deref(), declared.as_deref()) {
                (Some(h), Some(d)) if h != d => {
                    return Err(OpenError::ParentChanged {
                        run_id: run_id.to_string(),
                        held: h.to_string(),
                        declared: d.to_string(),
                    });
                }
                (None, Some(d)) => {
                    return Err(OpenError::AdoptedTooLate {
                        run_id: run_id.to_string(),
                        declared: d.to_string(),
                    });
                }
                _ => {}
            }
        }
        let req = Request::Open {
            run: run_id.to_string(),
            budget_micros: budget.0.max(0) as u64,
            parent: declared.clone(),
        };
        if let Err(e) = self.node.submit(req).await {
            tracing::warn!(run = run_id, "cluster open_run failed: {e}");
        }
        let was_absent = local.is_none();
        Ok(Opened {
            generation: 0,
            parent: local.and_then(|l| l.parent).or(declared),
            parent_disposition: if was_absent && parent.is_some() {
                ParentDisposition::Set
            } else {
                ParentDisposition::Kept
            },
            reopened: false,
        })
    }

    async fn reserve(&self, run_id: &str, estimate: Microusd) -> Result<Reservation, BudgetError> {
        let req = Request::Reserve {
            run: run_id.to_string(),
            micros: estimate.0.max(0) as u64,
        };
        match self.node.submit(req).await {
            Ok(resp) if resp.accepted => Ok(self.grant(run_id, estimate, resp.step)),
            Ok(resp) => Err(BudgetError::Exceeded {
                // The blocked run may be an ancestor — surface it so the gateway
                // can say "parent run X exceeded" vs "per-run budget exceeded".
                run_id: resp.blocked_run.unwrap_or_else(|| run_id.to_string()),
                budget: Microusd(resp.budget_micros as i64),
                spent: Microusd(resp.spent_micros as i64),
                // `would` is display-only here: the accept/reject decision was
                // already made by the raft state machine's own saturating u64
                // arithmetic (crates/cluster/src/types.rs). But this figure is
                // built independently, with a plain `+` on two `u64`s and then
                // an `as i64` cast that does not saturate: on overflow it wraps
                // and can print a negative "would" in a release build (an `as
                // i64` cast reinterprets bits rather than clamping, unlike a
                // float-to-int `as` cast). Saturate the u64 sum, clamp it into
                // i64's range before casting, then saturating_add the estimate.
                would: Microusd(
                    resp.reserved_micros
                        .saturating_add(resp.spent_micros)
                        .min(i64::MAX as u64) as i64,
                )
                .saturating_add(Microusd(estimate.0.max(0))),
            }),
            // Fail open: if consensus is unreachable, don't block the agent.
            Err(e) => {
                tracing::warn!(run = run_id, "cluster reserve failed open: {e}");
                Ok(self.grant(run_id, estimate, 0))
            }
        }
    }

    async fn reserve_unchecked(&self, run_id: &str, estimate: Microusd) -> Reservation {
        // Shadow/warn: record the attempt but always hand back a reservation.
        let step = match self
            .node
            .submit(Request::Reserve {
                run: run_id.to_string(),
                micros: estimate.0.max(0) as u64,
            })
            .await
        {
            Ok(resp) => resp.step,
            Err(_) => 0,
        };
        self.grant(run_id, estimate, step)
    }

    /// The checked reserve's question, answered from the local read: this run
    /// and every ancestor, the same walk `Ledger::would_exceed` makes, over
    /// `sm.read_run`, which is the eventually consistent copy `snapshot` reads
    /// too. So on a lagging follower this can under-report (stale `spent`, or
    /// no run yet) and, if a budget raise has not replicated, over-report.
    /// Advisory, like every shadow signal; the checked `reserve` above is
    /// where the cluster decides. Note also that `reserve_unchecked` above is
    /// a checked reserve whose refusal is ignored (the state machine refuses
    /// an over-budget `Reserve`, so the spend lands only at `Settle`); that is
    /// older than this method and is written down in invariant 42.
    async fn would_exceed(&self, run_id: &str, estimate: Microusd) -> Option<BudgetError> {
        let est = estimate.0.max(0) as u64;
        let mut next = Some(run_id.to_string());
        let mut hops = 0u32;
        while let Some(id) = next {
            // A cycle in the parent links would spin here; the in-process
            // ledger's `chain` has the same shape and the same cap is cheap.
            hops += 1;
            if hops > 64 {
                return None;
            }
            let s = self.node.sm.read_run(&id).await?;
            let would = s
                .spent_micros
                .saturating_add(s.reserved_micros)
                .saturating_add(est);
            if would > s.budget_micros {
                return Some(BudgetError::Exceeded {
                    run_id: id,
                    budget: Microusd(s.budget_micros.min(i64::MAX as u64) as i64),
                    spent: Microusd(s.spent_micros.min(i64::MAX as u64) as i64),
                    would: Microusd(would.min(i64::MAX as u64) as i64),
                });
            }
            next = s.parent;
        }
        None
    }

    async fn snapshot(&self, run_id: &str) -> Option<RunSnapshot> {
        self.node.sm.read_run(run_id).await.map(snap_of)
    }

    async fn list_runs(&self) -> Vec<(String, RunSnapshot)> {
        self.node
            .sm
            .list_runs()
            .await
            .into_iter()
            .map(|(run, s)| (run, snap_of(s)))
            .collect()
    }

    fn settle(&self, reservation: &Reservation, actual: Microusd) {
        if !self.outstanding.lock().unwrap().remove(&reservation.id) {
            tracing::debug!(
                id = reservation.id,
                run = %reservation.run_id,
                "settle ignored: not outstanding"
            );
            return;
        }
        let node = self.node.clone();
        let req = Request::Settle {
            run: reservation.run_id.clone(),
            reserved_micros: reservation.amount.0.max(0) as u64,
            actual_micros: actual.0.max(0) as u64,
        };
        // Fire-and-forget: settle needs no result and may run from Drop.
        tokio::spawn(async move {
            if let Err(e) = node.submit(req).await {
                tracing::warn!("cluster settle failed: {e}");
            }
        });
    }
}
