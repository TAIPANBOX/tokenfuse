//! `tokenfuse sql "<query>"` — run SQL over the Parquet trace with DataFusion.
//!
//! The trace directory is registered as a table named `calls`, so you can ask
//! things like:
//!   tokenfuse sql "select run_id, sum(cost_microusd)/1e6 as usd \
//!                  from calls group by run_id order by usd desc"

use datafusion::arrow::record_batch::RecordBatch;
use datafusion::arrow::util::pretty::pretty_format_batches;
use datafusion::prelude::{ParquetReadOptions, SessionContext};

/// Run `query` against the Parquet trace in `dir`, returning result batches.
pub async fn query(sql: &str, dir: &str) -> Result<Vec<RecordBatch>, Box<dyn std::error::Error>> {
    let ctx = SessionContext::new();
    ctx.register_parquet("calls", dir, ParquetReadOptions::default())
        .await?;
    let df = ctx.sql(sql).await?;
    Ok(df.collect().await?)
}

/// Run `query` and print the result as a table (used by the CLI).
pub async fn run(sql: &str, dir: &str) -> Result<(), Box<dyn std::error::Error>> {
    let batches = query(sql, dir).await?;
    println!("{}", pretty_format_batches(&batches)?);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sink::{CallRecord, EventSink, ParquetSink};

    #[tokio::test]
    async fn writes_then_queries_aggregate_cost() {
        let dir = std::env::temp_dir().join(format!("tf-sql-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let dir_str = dir.to_str().unwrap().to_string();

        // Write a few records via the sink, then query them back.
        {
            let sink = ParquetSink::new(&dir, 1).unwrap();
            for (i, cost) in [1_000_000i64, 2_000_000, 3_000_000].into_iter().enumerate() {
                sink.record(CallRecord {
                    ts_millis: i as i64,
                    run_id: "r1".into(),
                    model: "m".into(),
                    decision: "allow".into(),
                    input_tokens: 10,
                    output_tokens: 5,
                    cost_microusd: cost,
                    step: (i + 1) as u32,
                });
            }
        }

        let batches = query(
            "select sum(cost_microusd) as total, count(*) as n from calls",
            &dir_str,
        )
        .await
        .unwrap();

        let total = batches[0]
            .column(0)
            .as_any()
            .downcast_ref::<datafusion::arrow::array::Int64Array>()
            .unwrap()
            .value(0);
        let n = batches[0]
            .column(1)
            .as_any()
            .downcast_ref::<datafusion::arrow::array::Int64Array>()
            .unwrap()
            .value(0);
        assert_eq!(total, 6_000_000);
        assert_eq!(n, 3);

        std::fs::remove_dir_all(&dir).ok();
    }
}
