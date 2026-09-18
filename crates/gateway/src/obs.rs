//! Observability endpoints: list active runs and kill a runaway.
//!
//! These back the `tokenfuse top` TUI and the kill endpoint. Everything is
//! metadata (ids, budgets, spend, steps) — no prompt contents.

use crate::state::AppState;
use axum::extract::{Path, State};
use axum::Json;
use serde::Serialize;
use tokenfuse_core::Microusd;

/// A run as shown in the dashboard / TUI. Money is rendered in USD at the edge.
#[derive(Serialize)]
pub struct RunView {
    pub run_id: String,
    pub budget_usd: f64,
    pub spent_usd: f64,
    pub reserved_usd: f64,
    pub remaining_usd: f64,
    pub steps: u32,
    pub pct_used: f64,
    pub killed: bool,
    /// Reservations on this run kept outstanding on purpose (invariant 50):
    /// the provider held the request when the caller left, so the outcome
    /// is unknown rather than settled or released. Additive under
    /// `compat/1.0.json` (spec-guard-pr2.md section 4.1); `reserved_usd`
    /// already counted this amount, unchanged. Entries past
    /// `crate::settle::MAX_RETAINED` are not listed here (`listed=false` on
    /// the retain warn line) but still hold their reservation.
    pub retained: u32,
    /// The sum of `retained`'s reservations, in USD.
    pub retained_usd: f64,
}

/// `GET /v1/runs` — all known runs, most-spent first.
pub async fn list_runs(State(st): State<AppState>) -> Json<Vec<RunView>> {
    let mut views: Vec<RunView> = st
        .ledger
        .list_runs()
        .await
        .into_iter()
        .map(|(run_id, s)| {
            let budget = s.budget.as_usd();
            let spent = s.spent.as_usd();
            let held = st.retained.for_run(&run_id);
            let retained_usd = held
                .iter()
                .fold(Microusd::ZERO, |a, r| a.saturating_add(r.run.amount))
                .as_usd();
            RunView {
                killed: st.is_killed(&run_id),
                budget_usd: budget,
                spent_usd: spent,
                reserved_usd: s.reserved.as_usd(),
                remaining_usd: s.remaining().as_usd(),
                steps: s.steps,
                pct_used: if budget > 0.0 {
                    (s.in_flight().as_usd() / budget) * 100.0
                } else {
                    0.0
                },
                retained: held.len() as u32,
                retained_usd,
                run_id,
            }
        })
        .collect();
    views.sort_by(|a, b| {
        b.spent_usd
            .partial_cmp(&a.spent_usd)
            .unwrap_or(std::cmp::Ordering::Equal)
    });
    Json(views)
}

/// `POST /v1/runs/{id}/kill` — hard-stop a run; subsequent calls get 402.
pub async fn kill_run(
    State(st): State<AppState>,
    Path(id): Path<String>,
) -> Json<serde_json::Value> {
    st.kill(&id);
    Json(serde_json::json!({ "killed": id }))
}
