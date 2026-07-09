//! ROI savings projection (P2 — "what enforcement actually saved").
//!
//! Where [`crate::backtest`] replays a *candidate* policy over history to show
//! what it *would* have saved, this module reports what enforcement *already*
//! saved: it sums the avoided spend recorded at every budget-protection BLOCK
//! site in the trace. The gateway writes a block row per prevented call with
//! `cost_microusd` = the avoided estimate, so this is a pure aggregation.
//!
//! Pure logic: it operates on a flat list of [`Call`]s loaded from the Parquet
//! trace by the gateway. This mirrors [`backtest::Call`](crate::backtest::Call),
//! but carries the block `decision` (the reason a call was stopped) instead of
//! `step`, since savings keys off *why* a call was blocked rather than replaying
//! per-step budgets.

use std::collections::{BTreeMap, BTreeSet};

use serde::Serialize;

/// One recorded call from the trace, the input unit of a savings projection.
#[derive(Debug, Clone)]
pub struct Call {
    pub run_id: String,
    /// The wire decision string recorded for this call (e.g. `allow`,
    /// `cache_hit`, `budget_exceeded`, `dlp_blocked`).
    pub decision: String,
    pub cost_microusd: i64,
    /// Dollars a semantic-cache hit avoided (microdollars). Non-zero only on
    /// `cache_hit` rows; `0` everywhere else (see `gateway::sink::CallRecord`).
    pub saved_microusd: i64,
}

/// Block decisions that represent FinOps *dollar* savings — runaway spend that
/// budget protection stopped.
///
/// Security blocks (`dlp_blocked`, `taint_blocked`) are deliberately EXCLUDED:
/// they prevent data-exfiltration / prompt-injection harm, not dollar burn, and
/// their recorded `cost_microusd` is 0. Folding security value into a "$ saved"
/// number would conflate two different kinds of ROI and overstate the FinOps
/// figure, so this projection counts budget-protection reasons only.
pub const BUDGET_PROTECTION_REASONS: [&str; 5] = [
    "budget_exceeded",
    "loop_detected",
    "policy_violation",
    "wasm_policy",
    "killed",
];

/// Whether a decision string is a budget-protection block (vs. an allow, a cache
/// hit, or a security block).
pub fn is_budget_protection(decision: &str) -> bool {
    BUDGET_PROTECTION_REASONS.contains(&decision)
}

/// What budget protection saved over the trace.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
pub struct SavingsReport {
    /// Sum of avoided spend across all budget-protection block rows.
    pub blocked_spend_microusd: i64,
    /// Number of DISTINCT runs that were blocked at least once by a
    /// budget-protection reason (i.e. runs whose runaway was stopped).
    pub budget_breaks_prevented: usize,
    /// Total count of budget-protection block rows.
    pub blocked_calls: usize,
    /// Blocked spend broken down by decision reason (budget-protection only).
    pub by_reason_microusd: BTreeMap<String, i64>,
    /// Dollars the semantic cache avoided (microdollars), summed from
    /// `saved_microusd` on `cache_hit` rows only. This is a *different* kind
    /// of ROI from `blocked_spend_microusd` (spend that was served for free
    /// vs. runaway spend that was stopped), so it is reported as its own line.
    pub cache_saved_microusd: i64,
    /// Dollars the model router avoided (microdollars) by routing a call to a
    /// cheaper model than the one requested, summed from `saved_microusd` on
    /// `allow` rows. A cache hit records its own `cache_hit` row and returns
    /// before an `allow` row is ever written for that call, so this and
    /// `cache_saved_microusd` never double-count the same call. Reported as
    /// its own line for the same reason cache savings are: it is a different
    /// kind of ROI from both blocked spend and cache savings.
    pub router_saved_microusd: i64,
}

/// Aggregate the budget-protection block rows in `calls` into a [`SavingsReport`].
///
/// Rows whose decision is not a budget-protection reason (allows, cache hits,
/// and the security blocks `dlp_blocked`/`taint_blocked`) are ignored for
/// `blocked_spend_microusd`, but `allow` and `cache_hit` rows are still read
/// for their own `saved_microusd` dimension (see the match below).
pub fn compute_savings(calls: &[Call]) -> SavingsReport {
    let mut blocked_spend_microusd = 0i64;
    let mut blocked_calls = 0usize;
    let mut breaks: BTreeSet<&str> = BTreeSet::new();
    let mut by_reason_microusd: BTreeMap<String, i64> = BTreeMap::new();
    let mut cache_saved_microusd = 0i64;
    let mut router_saved_microusd = 0i64;

    for c in calls {
        // `saved_microusd` is nonzero on exactly two decisions, and they are
        // mutually exclusive per call: a semantic-cache hit records its own
        // `cache_hit` row and returns early, so an `allow` row with nonzero
        // `saved_microusd` can only be the model router's avoided spend (see
        // `gateway::proxy`). Attribute each to its own dimension rather than
        // folding both into one "cache" figure.
        match c.decision.as_str() {
            "cache_hit" => cache_saved_microusd += c.saved_microusd,
            "allow" => router_saved_microusd += c.saved_microusd,
            _ => {}
        }
        if is_budget_protection(&c.decision) {
            blocked_spend_microusd += c.cost_microusd;
            blocked_calls += 1;
            breaks.insert(c.run_id.as_str());
            *by_reason_microusd.entry(c.decision.clone()).or_insert(0) += c.cost_microusd;
        }
    }

    SavingsReport {
        blocked_spend_microusd,
        budget_breaks_prevented: breaks.len(),
        blocked_calls,
        by_reason_microusd,
        cache_saved_microusd,
        router_saved_microusd,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn call(run: &str, decision: &str, cost: i64) -> Call {
        Call {
            run_id: run.into(),
            decision: decision.into(),
            cost_microusd: cost,
            saved_microusd: 0,
        }
    }

    /// A cache-hit row: cost 0, but `saved` records the avoided spend.
    fn cache_hit(run: &str, saved: i64) -> Call {
        Call {
            run_id: run.into(),
            decision: "cache_hit".into(),
            cost_microusd: 0,
            saved_microusd: saved,
        }
    }

    /// A router-routed `allow` row: `cost` is what the call actually spent
    /// after routing, `saved` is the model router's avoided spend for it.
    fn router_hit(run: &str, cost: i64, saved: i64) -> Call {
        Call {
            run_id: run.into(),
            decision: "allow".into(),
            cost_microusd: cost,
            saved_microusd: saved,
        }
    }

    #[test]
    fn sums_only_budget_family_spend() {
        // Allows are ignored; only the two budget-protection blocks count.
        let calls = vec![
            call("r", "allow", 500_000),
            call("r", "budget_exceeded", 1_000_000),
            call("r", "loop_detected", 2_000_000),
            call("r", "allow", 300_000),
        ];
        let report = compute_savings(&calls);
        assert_eq!(report.blocked_spend_microusd, 3_000_000);
        assert_eq!(report.blocked_calls, 2);
    }

    #[test]
    fn budget_breaks_count_distinct_runs() {
        // Two runs each hit a budget-protection block → 2 breaks.
        let calls = vec![
            call("a", "budget_exceeded", 1_000_000),
            call("b", "killed", 1_000_000),
        ];
        let report = compute_savings(&calls);
        assert_eq!(report.budget_breaks_prevented, 2);
        assert_eq!(report.blocked_calls, 2);
    }

    #[test]
    fn same_run_blocked_twice_is_one_break() {
        // A single run blocked twice: two blocked calls but one budget break.
        let calls = vec![
            call("r", "budget_exceeded", 1_000_000),
            call("r", "budget_exceeded", 1_000_000),
        ];
        let report = compute_savings(&calls);
        assert_eq!(report.budget_breaks_prevented, 1);
        assert_eq!(report.blocked_calls, 2);
        assert_eq!(report.blocked_spend_microusd, 2_000_000);
    }

    #[test]
    fn dlp_blocked_is_excluded() {
        // Security blocks are not FinOps savings — excluded from every count.
        let calls = vec![
            call("r", "dlp_blocked", 4_000_000),
            call("r", "budget_exceeded", 1_000_000),
        ];
        let report = compute_savings(&calls);
        assert_eq!(report.blocked_spend_microusd, 1_000_000);
        assert_eq!(report.blocked_calls, 1);
        assert_eq!(report.budget_breaks_prevented, 1);
    }

    #[test]
    fn taint_blocked_is_excluded() {
        let calls = vec![
            call("r", "taint_blocked", 9_000_000),
            call("r", "allow", 100_000),
        ];
        let report = compute_savings(&calls);
        assert_eq!(report, SavingsReport::default());
    }

    #[test]
    fn cache_hits_and_allows_are_excluded_from_blocked_spend() {
        // Cache hits and allows never count as budget-protection blocks. This
        // `allow` row has no router savings (saved_microusd 0 via `call`), so
        // it must not contribute to router_saved_microusd either.
        let calls = vec![cache_hit("r", 250_000), call("r", "allow", 500_000)];
        let report = compute_savings(&calls);
        assert_eq!(report.blocked_spend_microusd, 0);
        assert_eq!(report.blocked_calls, 0);
        assert_eq!(report.budget_breaks_prevented, 0);
        // The cache hit's avoided spend is captured on its own line.
        assert_eq!(report.cache_saved_microusd, 250_000);
        assert_eq!(report.router_saved_microusd, 0);
    }

    #[test]
    fn router_savings_are_a_dimension_separate_from_cache() {
        // A router-routed `allow` row must land under router_saved_microusd,
        // never under cache_saved_microusd: folding the two together was the
        // bug (router savings mislabeled as cache savings). A cache hit and a
        // budget-protection block are mixed in too, to confirm all three
        // dimensions stay independent in the same report.
        let calls = vec![
            router_hit("a", 400_000, 100_000),
            cache_hit("b", 250_000),
            call("c", "budget_exceeded", 1_000_000),
        ];
        let report = compute_savings(&calls);
        assert_eq!(report.router_saved_microusd, 100_000);
        assert_eq!(report.cache_saved_microusd, 250_000);
        assert_eq!(report.blocked_spend_microusd, 1_000_000);
    }

    #[test]
    fn cache_saved_sums_across_hits_and_ignores_other_rows() {
        // Two cache hits contribute their savings; the allow and the block do
        // not (their `saved_microusd` is 0), while the block still counts as a
        // budget break. The three ROI figures are independent.
        let calls = vec![
            cache_hit("a", 100_000),
            call("a", "allow", 500_000),
            cache_hit("b", 400_000),
            call("b", "budget_exceeded", 2_000_000),
        ];
        let report = compute_savings(&calls);
        assert_eq!(report.cache_saved_microusd, 500_000);
        assert_eq!(report.router_saved_microusd, 0);
        assert_eq!(report.blocked_spend_microusd, 2_000_000);
        assert_eq!(report.blocked_calls, 1);
    }

    #[test]
    fn all_allow_trace_is_zeros() {
        let calls = vec![call("a", "allow", 1_000_000), call("b", "allow", 2_000_000)];
        assert_eq!(compute_savings(&calls), SavingsReport::default());
    }

    #[test]
    fn empty_trace_is_zeros() {
        assert_eq!(compute_savings(&[]), SavingsReport::default());
    }

    #[test]
    fn every_budget_reason_is_recognized() {
        // One block of each budget-protection reason, one run each.
        let calls: Vec<Call> = BUDGET_PROTECTION_REASONS
            .iter()
            .enumerate()
            .map(|(i, reason)| call(&format!("run-{i}"), reason, 1_000_000))
            .collect();
        let report = compute_savings(&calls);
        assert_eq!(report.blocked_calls, BUDGET_PROTECTION_REASONS.len());
        assert_eq!(
            report.budget_breaks_prevented,
            BUDGET_PROTECTION_REASONS.len()
        );
        assert_eq!(
            report.blocked_spend_microusd,
            BUDGET_PROTECTION_REASONS.len() as i64 * 1_000_000
        );
    }

    #[test]
    fn per_reason_breakdown_is_partitioned() {
        let calls = vec![
            call("a", "budget_exceeded", 1_000_000),
            call("b", "budget_exceeded", 500_000),
            call("c", "loop_detected", 2_000_000),
            call("d", "dlp_blocked", 9_000_000), // excluded
        ];
        let report = compute_savings(&calls);
        assert_eq!(
            report.by_reason_microusd.get("budget_exceeded").copied(),
            Some(1_500_000)
        );
        assert_eq!(
            report.by_reason_microusd.get("loop_detected").copied(),
            Some(2_000_000)
        );
        assert!(!report.by_reason_microusd.contains_key("dlp_blocked"));
        // The breakdown sums back to the headline figure.
        let sum: i64 = report.by_reason_microusd.values().sum();
        assert_eq!(sum, report.blocked_spend_microusd);
    }
}
