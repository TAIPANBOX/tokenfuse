//! End-to-end test of the raft-replicated ledger backend behind the gateway's
//! `LedgerBackend` trait (feature `cluster`). Proves the co-located raft node
//! enforces budgets — the same contract the in-process ledger provides, but
//! replicated. Compiles to nothing without the feature.
#![cfg(feature = "cluster")]

use std::collections::BTreeMap;
use std::sync::Arc;
use std::time::Duration;

use axum::body::Body;
use axum::http::Request;
use tokenfuse_core::{BudgetError, Ledger, Microusd, ModelPrice, Policy, PriceBook};
use tokenfuse_gateway::ledger_backend::LedgerBackend;
use tokenfuse_gateway::provider::StubProvider;
use tokenfuse_gateway::raft_ledger::RaftLedger;
use tokenfuse_gateway::state::AppState;
use tower::ServiceExt;

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn raft_backend_enforces_and_settles() {
    // Single-node cluster on a fixed local port (no other test uses it).
    let addr = "127.0.0.1:5599";
    let mut peers = BTreeMap::new();
    peers.insert(1u64, format!("http://{addr}"));
    let rl: Arc<dyn LedgerBackend> =
        RaftLedger::start(1, addr.parse().unwrap(), Arc::new(peers), true, None, None)
            .await
            .unwrap();

    // Wait until the cluster is ready: open_run only sticks once a leader exists,
    // so poll snapshot until the budget is replicated.
    let run = "r";
    let mut ready = false;
    for _ in 0..100 {
        rl.open_run(run, Microusd::from_usd(1.0), None).await;
        if let Some(s) = rl.snapshot(run).await {
            if s.budget == Microusd::from_usd(1.0) {
                ready = true;
                break;
            }
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    assert!(ready, "single-node cluster never became ready");

    // First reserve fits; the second pushes over $1.00 and must be denied.
    let a = rl.reserve(run, Microusd::from_usd(0.6)).await;
    assert!(a.is_ok(), "first reserve should fit");

    let b = rl.reserve(run, Microusd::from_usd(0.6)).await;
    match b {
        Err(BudgetError::Exceeded { .. }) => {}
        other => panic!("second reserve must be denied by consensus, got {other:?}"),
    }

    // Settle the first reservation; spend must show up in the replicated snapshot.
    rl.settle(&a.unwrap(), Microusd::from_usd(0.4));
    let mut settled = false;
    for _ in 0..100 {
        if let Some(s) = rl.snapshot(run).await {
            if s.spent == Microusd::from_usd(0.4) && s.reserved == Microusd::ZERO {
                settled = true;
                break;
            }
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    assert!(settled, "settle must replicate to the state machine");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn raft_backend_enforces_parent_budget() {
    let addr = "127.0.0.1:5601";
    let mut peers = BTreeMap::new();
    peers.insert(1u64, format!("http://{addr}"));
    let rl: Arc<dyn LedgerBackend> =
        RaftLedger::start(1, addr.parse().unwrap(), Arc::new(peers), true, None, None)
            .await
            .unwrap();

    // Wait for readiness by opening the parent until it replicates.
    let mut ready = false;
    for _ in 0..100 {
        rl.open_run("parent", Microusd::from_usd(1.0), None).await;
        if rl
            .snapshot("parent")
            .await
            .is_some_and(|s| s.budget == Microusd::from_usd(1.0))
        {
            ready = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    assert!(ready);
    // Child has a huge own budget but rolls up into the $1.00 parent.
    rl.open_run("child", Microusd::from_usd(100.0), Some("parent"))
        .await;

    let a = rl.reserve("child", Microusd::from_usd(0.6)).await;
    assert!(a.is_ok(), "first child reserve fits child and parent");

    // Second child reserve fits the child but busts the parent → denied, and the
    // error must name the *parent* as the blocked run.
    match rl.reserve("child", Microusd::from_usd(0.6)).await {
        Err(BudgetError::Exceeded { run_id, .. }) => {
            assert_eq!(run_id, "parent", "the parent must be the blocking run");
        }
        other => panic!("expected parent-budget denial, got {other:?}"),
    }
}

/// Reproduces the live incident: a burst of concurrent *first* requests for
/// distinct runs, fired straight at a **follower** node, not the leader.
/// `open_run`/`reserve` on a follower go through `HttpNode::submit`, which
/// forwards the write over HTTP to the leader and returns once the leader's
/// write is committed — but that tells us nothing about whether *this*
/// follower's own raft log has replicated and applied the entry yet.
/// `snapshot()` only ever reads this node's local copy (`sm.read_run`), so a
/// burst of fresh runs hitting the follower can race its own replication
/// catch-up even though every `open_run` already succeeded from the caller's
/// point of view. `crates/cluster/tests/http_cluster.rs
/// ::http_cluster_replicates_and_enforces` shows the same follower-lag window
/// (it polls up to 100×20ms for a follower to catch up) — this test drives
/// the real gateway handler through that exact window instead of polling
/// around it, and asserts every request in the burst completes with a real
/// HTTP response, none panic. Before the fix in `crates/gateway/src/proxy.rs`
/// (`.expect("run just opened")`), this reliably reproduces the live
/// incident: multiple `tokio-rt-worker` panics with `"run just opened"` per
/// run, the client-observed symptom being the request silently dropped
/// (matching production's "1 of 26 requests lost").
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn follower_burst_of_fresh_runs_does_not_panic_on_snapshot_lag() {
    let addrs = ["127.0.0.1:5610", "127.0.0.1:5611", "127.0.0.1:5612"];
    let mut peers_map = BTreeMap::new();
    for (i, a) in addrs.iter().enumerate() {
        peers_map.insert(i as u64 + 1, format!("http://{a}"));
    }
    let peers = Arc::new(peers_map);

    // Node 1 bootstraps the 3-member cluster and becomes the initial leader;
    // nodes 2 and 3 join the same membership without independently calling
    // `init()`.
    let node1: Arc<dyn LedgerBackend> = RaftLedger::start(
        1,
        addrs[0].parse().unwrap(),
        peers.clone(),
        true,
        None,
        None,
    )
    .await
    .unwrap();
    let node2: Arc<dyn LedgerBackend> = RaftLedger::start(
        2,
        addrs[1].parse().unwrap(),
        peers.clone(),
        false,
        None,
        None,
    )
    .await
    .unwrap();
    let _node3: Arc<dyn LedgerBackend> = RaftLedger::start(
        3,
        addrs[2].parse().unwrap(),
        peers.clone(),
        false,
        None,
        None,
    )
    .await
    .unwrap();

    // Wait only for the leader (node 1) to be up and committing — the same
    // readiness signal the single-node tests above use. Deliberately do NOT
    // wait for anything to reach node 2; that catch-up window is the bug.
    let mut ready = false;
    for _ in 0..150 {
        node1
            .open_run("warmup", Microusd::from_usd(1.0), None)
            .await;
        if node1
            .snapshot("warmup")
            .await
            .is_some_and(|s| s.budget == Microusd::from_usd(1.0))
        {
            ready = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    assert!(ready, "3-node cluster never elected a leader");

    // The gateway a client actually talks to when routed to the follower.
    let prices = PriceBook::new().with(
        "test-model",
        ModelPrice::per_mtok_usd(3.0, 15.0, 0.30, 3.75),
    );
    let st = AppState::new(
        Arc::new(Ledger::new()),
        Arc::new(prices),
        Arc::new(Policy {
            mode: tokenfuse_core::Mode::Enforce,
            ..Default::default()
        }),
        Arc::new(StubProvider::default()),
        "cluster-follower-burst-test",
    )
    .with_ledger(node2);
    let app = tokenfuse_gateway::app(st);

    // 25 distinct fresh runs, each hit with its first request concurrently,
    // straight at the follower — the live incident's exact shape (a
    // 25-request burst on a follower node, 1 lost to the panic).
    let mut tasks = tokio::task::JoinSet::new();
    for i in 0..25 {
        let app = app.clone();
        tasks.spawn(async move {
            let req = Request::post("/v1/messages")
                .header("x-fuse-run-id", format!("follower-burst-{i}"))
                .header("x-fuse-budget-usd", "5.0")
                .body(Body::from(
                    r#"{"model":"test-model","max_tokens":100}"#.to_string(),
                ))
                .unwrap();
            app.oneshot(req).await.map(|resp| resp.status())
        });
    }

    let mut completed = 0;
    while let Some(res) = tasks.join_next().await {
        match res {
            Ok(Ok(status)) => {
                completed += 1;
                assert!(
                    status.is_success() || status.as_u16() == 402,
                    "unexpected status under follower snapshot-lag burst: {status}"
                );
            }
            Ok(Err(e)) => panic!("request future returned an error: {e}"),
            Err(join_err) => panic!(
                "a request task panicked instead of returning a response on the \
                 follower node — this is the ledger-snapshot-panic bug (dropped \
                 request): {join_err}"
            ),
        }
    }
    assert_eq!(
        completed, 25,
        "every burst request against the follower must complete, none dropped to a panic"
    );
}
