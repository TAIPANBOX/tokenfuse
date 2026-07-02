//! `tokenfuse-cluster` demo: start a 3-node raft cluster in one process,
//! replicate a budget across it, and show that the affordability check is
//! enforced by consensus (not by any single node).
//!
//!   cargo run -p tokenfuse-cluster
//!
//! Output walks through: leader election → open a $1.00 budget → reserve until
//! it's exhausted (the over-budget reserve is *denied by the state machine*) →
//! read the replicated spend back from a **follower**.

use std::time::Duration;

use tokenfuse_cluster::types::Request;
use tokenfuse_cluster::Cluster;

const USD: u64 = 1_000_000; // 1 USD in microdollars

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("error")),
        )
        .init();

    println!("── TokenFuse HA cluster demo ──\n");
    println!("starting 3 nodes {{1, 2, 3}} …");
    let cluster = Cluster::start(&[1, 2, 3]).await?;

    let leader = cluster
        .wait_for_leader(Duration::from_secs(5))
        .await
        .ok_or("no leader elected")?;
    println!("leader elected: node {leader}\n");

    // Open a $1.00 budget for run "agent-42".
    let run = "agent-42";
    cluster
        .write(Request::Open {
            run: run.to_string(),
            budget_micros: USD,
        })
        .await?;
    println!("opened budget for {run}: $1.00\n");

    // Reserve $0.40 twice (fits), then $0.40 again (must be denied: $1.20 > $1.00).
    for (i, cents) in [40, 40, 40].into_iter().enumerate() {
        let micros = cents * 10_000; // cents → µUSD
        let resp = cluster
            .write(Request::Reserve {
                run: run.to_string(),
                micros,
            })
            .await?;
        let verdict = if resp.accepted {
            "ACCEPTED"
        } else {
            "DENIED  "
        };
        println!(
            "reserve #{}  ${:.2}  → {verdict}  (reserved ${:.2} / budget ${:.2}){}",
            i + 1,
            micros as f64 / USD as f64,
            resp.reserved_micros as f64 / USD as f64,
            resp.budget_micros as f64 / USD as f64,
            if resp.accepted {
                String::new()
            } else {
                format!("  — {}", resp.reason)
            }
        );
    }

    // Settle the first reservation with a smaller actual spend.
    cluster
        .write(Request::Settle {
            run: run.to_string(),
            reserved_micros: 40 * 10_000,
            actual_micros: 25 * 10_000,
        })
        .await?;
    println!("\nsettled reservation #1: actual $0.25 (was reserved $0.40)");

    // Give followers a beat to apply, then read from a NON-leader node.
    tokio::time::sleep(Duration::from_millis(200)).await;
    let follower_id = cluster
        .nodes
        .iter()
        .map(|n| n.id)
        .find(|&id| id != leader)
        .unwrap();
    let follower = cluster.node(follower_id).unwrap();
    let state = follower.read_run(run).await.unwrap();
    println!(
        "\nread replicated state from follower node {follower_id}:\n  spent    ${:.2}\n  reserved ${:.2}\n  budget   ${:.2}",
        state.spent_micros as f64 / USD as f64,
        state.reserved_micros as f64 / USD as f64,
        state.budget_micros as f64 / USD as f64,
    );

    println!("\n✔ budget replicated + enforced by consensus across 3 nodes.");
    cluster.shutdown().await;
    Ok(())
}
