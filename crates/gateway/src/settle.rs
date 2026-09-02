//! A guard that guarantees a streaming reservation is always settled — even if
//! the client disconnects mid-stream and the response future is dropped before
//! the normal end-of-stream settle runs.
//!
//! On normal completion the caller invokes [`SettleGuard::complete`], which
//! settles with the usage parsed from the stream. If the guard is dropped first
//! (client cancel, or an upstream error propagated via `?`), its `Drop` settles
//! with whatever usage was parsed so far, falling back to the reserved estimate
//! so the budget is never left over-reserved (a leaked reservation would wrongly
//! block later calls in the same run).
//!
//! The fallback is only honest when a completion actually happened, which is
//! what [`SettleGuard::provider_refused`] decides. Either way the reservation is
//! released, so neither answer can leak one.

use crate::keystats::KeyStats;
use crate::ledger_backend::LedgerBackend;
use crate::provider::{ParsedUsage, UsageSlot};
use crate::sink::{now_millis, CallRecord, EventSink};
use crate::unitledger::{UnitLedger, UnitReservation};
use std::sync::Arc;
use tokenfuse_core::{Microusd, PriceBook, Reservation, Usage};

/// The basis a settlement's charged amount rests on. Not a Parquet column
/// (see the PR body for why adding one was not a small change) - this exists
/// so the three cases below are a named, testable value rather than
/// reconstructed after the fact from which `Microusd` happened to come out,
/// which two different bases can produce by coincidence.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum CostBasis {
    /// Real usage, parsed from a body the cap never touched.
    Parsed,
    /// Not truncated, but the body carried nothing to price - settled on the
    /// estimate because there was nothing else to settle on.
    EstimateNoUsage,
    /// [`UsageParser::CAP`](crate::provider::UsageParser::CAP) dropped bytes
    /// before the usage block arrived - settled on the estimate because
    /// whatever partial usage survived the cut cannot be trusted (a
    /// cumulative field, like Anthropic's `output_tokens`, can look real and
    /// still be short). The `Usage` returned alongside this is always
    /// [`Usage::default`], never the partial numbers that were parsed - see
    /// `settle_amount`'s doc for why.
    EstimateTruncated,
}

/// Decides what a settlement charges and why, from the parsed usage (if any)
/// and the pre-flight estimate to fall back to. Pure and unit-tested on its
/// own below; both settle paths in this crate (`SettleGuard::settle_now` here
/// and `crate::proxy::buffered_managed`) call this one function so the
/// three-way decision is made in exactly one place.
///
/// Returns the amount to charge, the usage to record on the `CallRecord`
/// (defaulted when nothing was parsed, same as before this function existed),
/// and the basis the amount rests on.
///
/// **Truncated always records `Usage::default()`, never the partial usage
/// that was parsed.** `focusexport::to_row` infers a row's FOCUS
/// `x_cost_basis` from its shape alone - zero tokens beside a nonzero cost
/// reads as `"estimated"`, everything else as `"settled"` (see that module's
/// doc). A truncated body that kept its partial, untrusted token counts would
/// carry real-looking nonzero tokens beside the estimated cost, which is
/// exactly the `"settled"` shape: the FOCUS export, and CostCrew reading it,
/// would call an estimated call settled. Reporting the same all-zero shape a
/// body with no usage at all gets is what keeps that export honest, at the
/// cost of also losing whatever partial counts a truncated body happened to
/// carry - a real loss, but the alternative is a wrong label on a downstream
/// billing export, which is worse.
pub(crate) fn settle_amount(
    prices: &PriceBook,
    model: &str,
    parsed: Option<ParsedUsage>,
    unmeasured: Microusd,
) -> (Microusd, Usage, CostBasis) {
    let truncated = parsed.as_ref().is_some_and(|p| p.truncated);
    let usage = parsed.map(|p| p.usage).unwrap_or_default();
    if truncated {
        // Never priced, no matter what partial numbers survived the cut, and
        // never RECORDED either - see this function's doc and
        // `CostBasis::EstimateTruncated`'s.
        return (unmeasured, Usage::default(), CostBasis::EstimateTruncated);
    }
    match prices.cost(model, &usage) {
        Some(cost) if usage != Usage::default() => (cost, usage, CostBasis::Parsed),
        // Either the model has no price at all, or nothing was parsed
        // (`usage` defaulted, whether because the body carried no usage or
        // the guard was dropped before any was ever written to the slot).
        _ => (unmeasured, usage, CostBasis::EstimateNoUsage),
    }
}

pub struct SettleGuard {
    ledger: Arc<dyn LedgerBackend>,
    prices: Arc<PriceBook>,
    sink: Arc<dyn EventSink>,
    model: String,
    usage: UsageSlot,
    fallback: Microusd,
    /// Whether the upstream answered with a non-2xx, which decides whether
    /// `fallback` may be charged at all.
    ///
    /// On a success the fallback is the conservative estimate it was written
    /// to be: a completion did happen and we could not measure it, so charging
    /// what was reserved beats letting an unmeasurable model spend a run's
    /// budget for free. On a refusal there is no completion to measure, so the
    /// estimate is not a fallback measurement of anything: it is a number this
    /// gateway invented and then wrote into the run's budget, the unit's
    /// monthly cap, the trace, the FOCUS export and the Cloud aggregates as
    /// money somebody was billed. A provider that 429s a run repeatedly would
    /// otherwise exhaust that run's budget on calls that cost nothing.
    ///
    /// This is a required constructor argument rather than a value folded into
    /// `fallback` by the caller on purpose. `stream_managed` inherited the
    /// buffered path's unconditional estimate and kept it through the fix for
    /// that path (PR #167), because nothing made it answer the question. Now
    /// nothing can construct this guard without answering it.
    ///
    /// Reported usage is settled as itself either way, including on a refusal:
    /// a provider that generated part of a response and then failed over it
    /// bills for what it generated, and that is real money rather than an
    /// estimate. Only the "no usage to price" fallback is affected.
    provider_refused: bool,
    reservation: Option<Reservation>,
    /// Request-scoped attribution carried into the settled `CallRecord`.
    agent_id: String,
    /// Request-scoped `X-Fuse-Parent-Run-Id`, carried into the settled
    /// `CallRecord` (agent-passport SPEC.md §3.2). `""` when unset.
    parent_run_id: String,
    /// Request-scoped raw `X-Fuse-On-Behalf-Of` value, carried into the
    /// settled `CallRecord` (agent-passport SPEC.md §5). `""` when unset.
    on_behalf_of: String,
    /// Request-scoped `X-Fuse-Outcome` value, carried into the settled
    /// `CallRecord` (P4, unit economics). `""` when unset.
    outcome: String,
    /// The server-resolved client credential identity, carried into the
    /// settled `CallRecord`. `""` when client keys are not configured. Unlike
    /// every other field here it does not come from a request header the
    /// caller wrote — see `CallRecord::key_id`.
    key_id: String,
    /// The server-resolved business unit (docs/20), carried into the settled
    /// `CallRecord`. `""` when the identity map is off or nothing matched.
    unit: String,
    /// The per-unit monthly ledger and this call's unit reservation, settled
    /// alongside the run reservation with the same actual cost. `None` when
    /// the unit has no cap in effect (nothing was reserved).
    units: Arc<UnitLedger>,
    unit_reservation: Option<UnitReservation>,
    /// Where a truncated settlement's counter goes
    /// (`crate::keystats::KeyStats::record_truncated_settlement`). Added
    /// alongside the truncation fix rather than threaded through every other
    /// field above: nothing before this needed a place to report an
    /// in-process signal that isn't part of the settled `CallRecord`.
    keystats: Arc<KeyStats>,
}

impl SettleGuard {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        ledger: Arc<dyn LedgerBackend>,
        prices: Arc<PriceBook>,
        sink: Arc<dyn EventSink>,
        model: String,
        usage: UsageSlot,
        fallback: Microusd,
        provider_refused: bool,
        reservation: Reservation,
        agent_id: String,
        parent_run_id: String,
        on_behalf_of: String,
        outcome: String,
        key_id: String,
        unit: String,
        units: Arc<UnitLedger>,
        unit_reservation: Option<UnitReservation>,
        keystats: Arc<KeyStats>,
    ) -> Self {
        SettleGuard {
            ledger,
            prices,
            sink,
            model,
            usage,
            fallback,
            provider_refused,
            reservation: Some(reservation),
            agent_id,
            parent_run_id,
            on_behalf_of,
            outcome,
            key_id,
            unit,
            units,
            unit_reservation,
            keystats,
        }
    }

    fn settle_now(&mut self) {
        let Some(reservation) = self.reservation.take() else {
            return;
        };
        let parsed = self.usage.lock().unwrap().take();
        // What to settle when the stream reported no usage we can price. See
        // `provider_refused`'s doc for why a refusal may not be charged the
        // estimate; this mirrors `buffered_managed`'s `unmeasured` binding.
        let unmeasured = if self.provider_refused {
            Microusd::ZERO
        } else {
            self.fallback
        };
        let (actual, usage, basis) = settle_amount(&self.prices, &self.model, parsed, unmeasured);
        if basis == CostBasis::EstimateTruncated {
            // `settled_microusd` is named, not assumed nonzero: a refused
            // call whose error body also overran the cap settles zero here,
            // same as any other refusal, and the log line must not read as
            // though an estimate was charged when nothing was.
            tracing::warn!(
                model = %self.model,
                buffered_bytes = crate::provider::UsageParser::CAP,
                settled_microusd = actual.0,
                "usage-parser cap hit before the response's usage block arrived; \
                 the parsed usage cannot be trusted, so this settled on the \
                 fallback amount above instead"
            );
            self.keystats.record_truncated_settlement();
        }
        self.ledger.settle(&reservation, actual);
        if let Some(ur) = self.unit_reservation.take() {
            self.units.settle(&ur, actual, now_millis());
        }

        self.sink.record(CallRecord {
            ts_millis: now_millis(),
            run_id: reservation.run_id.clone(),
            model: self.model.clone(),
            decision: "allow".into(),
            input_tokens: usage.input_tokens,
            output_tokens: usage.output_tokens,
            cost_microusd: actual.0,
            step: reservation.step,
            agent_id: self.agent_id.clone(),
            // Streaming allows never serve from cache — no savings to record.
            saved_microusd: 0,
            parent_run_id: self.parent_run_id.clone(),
            on_behalf_of: self.on_behalf_of.clone(),
            outcome: self.outcome.clone(),
            key_id: self.key_id.clone(),
            unit: self.unit.clone(),
            // The model-emitted tool-call count parsed out of the streamed
            // response, same source as `input_tokens`/`output_tokens` above
            // (I1, docs/21-tool-runs.md). `None` on the drop-without-complete
            // path (cancel/error before any usage was parsed).
            tool_calls: usage.tool_calls,
        });
    }

    /// Settle now with the parsed usage (normal end-of-stream). Consumes the
    /// guard so its `Drop` becomes a no-op.
    pub fn complete(mut self) {
        self.settle_now();
    }
}

impl Drop for SettleGuard {
    fn drop(&mut self) {
        // Only fires if `complete()` was not called (cancel / error path).
        self.settle_now();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::keystats::KeyStats;
    use crate::provider::{ParsedUsage, UsageSlot};
    use std::sync::Mutex;
    use tokenfuse_core::{Ledger, ModelPrice, PriceBook, Usage};

    fn setup() -> (Arc<Ledger>, Arc<PriceBook>, UsageSlot, Reservation) {
        let ledger = Arc::new(Ledger::new());
        ledger.open_run("r", Microusd::from_usd(5.0), None);
        let reservation = ledger.reserve("r", Microusd::from_usd(1.0)).unwrap();
        let prices =
            Arc::new(PriceBook::new().with("m", ModelPrice::per_mtok_usd(3.0, 15.0, 0.0, 0.0)));
        let usage: UsageSlot = Arc::new(Mutex::new(None));
        (ledger, prices, usage, reservation)
    }

    #[test]
    fn complete_settles_with_parsed_usage() {
        let (ledger, prices, usage, reservation) = setup();
        *usage.lock().unwrap() = Some(ParsedUsage {
            usage: Usage {
                input_tokens: 1_000_000,
                output_tokens: 0,
                ..Default::default()
            },
            truncated: false,
        });
        let guard = SettleGuard::new(
            Arc::new(crate::ledger_backend::LocalLedger(ledger.clone())),
            prices,
            Arc::new(crate::sink::NullSink),
            "m".into(),
            usage,
            Microusd::from_usd(1.0),
            false, // a 200 stream: the estimate is a legitimate fallback
            reservation,
            String::new(),
            String::new(),
            String::new(),
            String::new(),
            String::new(),
            String::new(),
            Arc::new(UnitLedger::default()),
            None,
            Arc::new(KeyStats::default()),
        );
        guard.complete();

        let snap = ledger.snapshot("r").unwrap();
        assert_eq!(snap.reserved, Microusd::ZERO); // released
        assert_eq!(snap.spent, Microusd::from_usd(3.0)); // 1M input @ $3/Mtok
    }

    #[test]
    fn drop_without_complete_settles_with_fallback() {
        let (ledger, prices, usage, reservation) = setup();
        // No usage parsed (cancel before any usage event).
        let fallback = Microusd::from_usd(1.0);
        {
            let _guard = SettleGuard::new(
                Arc::new(crate::ledger_backend::LocalLedger(ledger.clone())),
                prices,
                Arc::new(crate::sink::NullSink),
                "m".into(),
                usage,
                fallback,
                false, // a 200 stream: the estimate is a legitimate fallback
                reservation,
                String::new(),
                String::new(),
                String::new(),
                String::new(),
                String::new(),
                String::new(),
                Arc::new(UnitLedger::default()),
                None,
                Arc::new(KeyStats::default()),
            );
            // dropped here without complete()
        }
        let snap = ledger.snapshot("r").unwrap();
        assert_eq!(snap.reserved, Microusd::ZERO); // reservation released, not leaked
        assert_eq!(snap.spent, fallback); // conservative fallback charge
    }

    /// The same cancel path, on a stream the provider had already refused.
    ///
    /// This is the case no HTTP test can reach: the two in `proxy.rs` drain the
    /// body, so they exercise `complete()`. A client that gives up on a 429
    /// before draining it goes through `Drop` instead, and the estimate is
    /// exactly as invented there. The reservation must still be released, which
    /// is the guard's whole reason for existing.
    #[test]
    fn a_refused_stream_dropped_without_complete_settles_zero_not_the_estimate() {
        let (ledger, prices, usage, reservation) = setup();
        {
            let _guard = SettleGuard::new(
                Arc::new(crate::ledger_backend::LocalLedger(ledger.clone())),
                prices,
                Arc::new(crate::sink::NullSink),
                "m".into(),
                usage,
                Microusd::from_usd(1.0),
                true, // the provider refused: nothing was generated
                reservation,
                String::new(),
                String::new(),
                String::new(),
                String::new(),
                String::new(),
                String::new(),
                Arc::new(UnitLedger::default()),
                None,
                Arc::new(KeyStats::default()),
            );
            // dropped here without complete()
        }
        let snap = ledger.snapshot("r").unwrap();
        assert_eq!(
            snap.reserved,
            Microusd::ZERO,
            "the reservation is still released, refusal or not: leaking one would \
             wrongly block later calls in the same run"
        );
        assert_eq!(
            snap.spent,
            Microusd::ZERO,
            "but nothing is charged for a call the provider never answered"
        );
    }

    /// A refusal that DOES report usage is still settled as that usage, on the
    /// guard as well as through HTTP. Pins the fix as "do not charge an
    /// estimate for nothing", not "a non-2xx is free".
    #[test]
    fn a_refused_stream_that_reported_usage_still_settles_it() {
        let (ledger, prices, usage, reservation) = setup();
        *usage.lock().unwrap() = Some(ParsedUsage {
            usage: Usage {
                input_tokens: 1_000_000,
                output_tokens: 0,
                ..Default::default()
            },
            truncated: false,
        });
        let guard = SettleGuard::new(
            Arc::new(crate::ledger_backend::LocalLedger(ledger.clone())),
            prices,
            Arc::new(crate::sink::NullSink),
            "m".into(),
            usage,
            Microusd::from_usd(1.0),
            true, // refused, but it billed for what it generated
            reservation,
            String::new(),
            String::new(),
            String::new(),
            String::new(),
            String::new(),
            String::new(),
            Arc::new(UnitLedger::default()),
            None,
            Arc::new(KeyStats::default()),
        );
        guard.complete();

        let snap = ledger.snapshot("r").unwrap();
        assert_eq!(snap.reserved, Microusd::ZERO);
        assert_eq!(
            snap.spent,
            Microusd::from_usd(3.0),
            "1M input @ $3/Mtok: real money the provider reported, not zeroed"
        );
    }

    #[test]
    fn a_unit_reservation_settles_alongside_the_run_reservation() {
        let (ledger, prices, usage, reservation) = setup();
        *usage.lock().unwrap() = Some(ParsedUsage {
            usage: Usage {
                input_tokens: 1_000_000,
                output_tokens: 0,
                ..Default::default()
            },
            truncated: false,
        });
        let units = Arc::new(UnitLedger::new(std::collections::HashMap::from([(
            "treasury".to_string(),
            Microusd::from_usd(10.0),
        )])));
        let now = now_millis();
        let ur = units
            .try_reserve("treasury", Microusd::from_usd(1.0), now)
            .unwrap()
            .expect("capped unit reserves");
        let guard = SettleGuard::new(
            Arc::new(crate::ledger_backend::LocalLedger(ledger.clone())),
            prices,
            Arc::new(crate::sink::NullSink),
            "m".into(),
            usage,
            Microusd::from_usd(1.0),
            false, // a 200 stream: the estimate is a legitimate fallback
            reservation,
            String::new(),
            String::new(),
            String::new(),
            String::new(),
            String::new(),
            "treasury".into(),
            units.clone(),
            Some(ur),
            Arc::new(KeyStats::default()),
        );
        guard.complete();
        // The unit ledger absorbed the same actual cost as the run ledger.
        assert_eq!(units.spent("treasury", now), Microusd::from_usd(3.0));
    }

    /// A minimal `EventSink` test double that just captures the last
    /// settled `CallRecord`, so a test can inspect a field `NullSink`
    /// (used everywhere above) throws away.
    #[derive(Default)]
    struct CapturingSink {
        last: Mutex<Option<CallRecord>>,
    }

    impl crate::sink::EventSink for CapturingSink {
        fn record(&self, rec: CallRecord) {
            *self.last.lock().unwrap() = Some(rec);
        }
        fn flush(&self) {}
    }

    /// I1 (docs/21-tool-runs.md): the streaming settle path carries
    /// `Usage::tool_calls` through into the settled `CallRecord`, exactly
    /// like `input_tokens`/`output_tokens` - proven here for the streaming
    /// path specifically, since `buffered_managed`'s non-streaming path is
    /// covered separately in `proxy.rs`.
    #[test]
    fn complete_settles_with_parsed_tool_calls() {
        let (ledger, prices, usage, reservation) = setup();
        *usage.lock().unwrap() = Some(ParsedUsage {
            usage: Usage {
                input_tokens: 1_000_000,
                output_tokens: 0,
                tool_calls: Some(2),
                ..Default::default()
            },
            truncated: false,
        });
        let sink = Arc::new(CapturingSink::default());
        let guard = SettleGuard::new(
            Arc::new(crate::ledger_backend::LocalLedger(ledger)),
            prices,
            sink.clone(),
            "m".into(),
            usage,
            Microusd::from_usd(1.0),
            false, // a 200 stream: the estimate is a legitimate fallback
            reservation,
            String::new(),
            String::new(),
            String::new(),
            String::new(),
            String::new(),
            String::new(),
            Arc::new(UnitLedger::default()),
            None,
            Arc::new(KeyStats::default()),
        );
        guard.complete();

        let rec = sink
            .last
            .lock()
            .unwrap()
            .clone()
            .expect("a record was settled");
        assert_eq!(rec.tool_calls, Some(2));
    }

    /// The drop-without-complete (cancel/error) path never parsed any usage,
    /// so `tool_calls` must be `None`, not a fabricated `Some(0)`.
    #[test]
    fn drop_without_complete_leaves_tool_calls_none() {
        let (ledger, prices, usage, reservation) = setup();
        let sink = Arc::new(CapturingSink::default());
        {
            let _guard = SettleGuard::new(
                Arc::new(crate::ledger_backend::LocalLedger(ledger)),
                prices,
                sink.clone(),
                "m".into(),
                usage,
                Microusd::from_usd(1.0),
                false, // a 200 stream: the estimate is a legitimate fallback
                reservation,
                String::new(),
                String::new(),
                String::new(),
                String::new(),
                String::new(),
                String::new(),
                Arc::new(UnitLedger::default()),
                None,
                Arc::new(KeyStats::default()),
            );
            // dropped here without complete()
        }
        let rec = sink
            .last
            .lock()
            .unwrap()
            .clone()
            .expect("a record was settled");
        assert_eq!(rec.tool_calls, None);
    }

    // -- settle_amount: the three-way basis, isolated from the guard -------
    //
    // These four cover `CostBasis` directly, by name. The `SettleGuard`-level
    // tests below cover the same three settle-time cases end-to-end (the
    // ledger charge and the truncation counter), since `basis` itself is
    // in-process only and not part of the settled `CallRecord` (see the PR
    // body for why no Parquet column was added).

    #[test]
    fn settle_amount_prices_real_usage_as_parsed() {
        let prices = PriceBook::new().with("m", ModelPrice::per_mtok_usd(3.0, 15.0, 0.0, 0.0));
        let parsed = Some(ParsedUsage {
            usage: Usage {
                input_tokens: 1_000_000,
                ..Default::default()
            },
            truncated: false,
        });
        let (actual, usage, basis) = settle_amount(&prices, "m", parsed, Microusd::from_usd(1.0));
        assert_eq!(actual, Microusd::from_usd(3.0));
        assert_eq!(usage.input_tokens, 1_000_000);
        assert_eq!(basis, CostBasis::Parsed);
    }

    #[test]
    fn settle_amount_falls_back_to_the_estimate_when_the_body_carried_no_usage() {
        let prices = PriceBook::new().with("m", ModelPrice::per_mtok_usd(3.0, 15.0, 0.0, 0.0));
        let parsed = Some(ParsedUsage {
            usage: Usage::default(),
            truncated: false,
        });
        let (actual, usage, basis) = settle_amount(&prices, "m", parsed, Microusd::from_usd(1.0));
        assert_eq!(
            actual,
            Microusd::from_usd(1.0),
            "nothing to price, but the cap was never hit"
        );
        assert_eq!(usage, Usage::default());
        assert_eq!(basis, CostBasis::EstimateNoUsage);
    }

    /// The case this whole fix is about: partial usage DID survive the cut,
    /// and trusting it is exactly the defect. 500k input tokens would price
    /// at $1.50 - that must not be what comes out.
    #[test]
    fn settle_amount_falls_back_to_the_estimate_when_truncated_even_with_partial_usage() {
        let prices = PriceBook::new().with("m", ModelPrice::per_mtok_usd(3.0, 15.0, 0.0, 0.0));
        let parsed = Some(ParsedUsage {
            usage: Usage {
                input_tokens: 500_000,
                ..Default::default()
            },
            truncated: true,
        });
        let estimate = Microusd::from_usd(1.0);
        let (actual, usage, basis) = settle_amount(&prices, "m", parsed, estimate);
        assert_eq!(
            actual, estimate,
            "a truncated body's partial usage must never be priced, even though it parsed"
        );
        assert_eq!(
            usage,
            Usage::default(),
            "not recorded either, even though it parsed: focusexport::to_row reads \
             zero tokens beside a nonzero cost as \"estimated\" and anything else as \
             \"settled\", so a real-looking partial token count here would mislabel \
             this row as settled in the FOCUS export"
        );
        assert_eq!(basis, CostBasis::EstimateTruncated);
    }

    #[test]
    fn settle_amount_on_no_slot_write_at_all_is_estimate_no_usage() {
        // The cancel/drop path: nothing was ever written to the slot.
        let prices = PriceBook::new().with("m", ModelPrice::per_mtok_usd(3.0, 15.0, 0.0, 0.0));
        let (actual, usage, basis) = settle_amount(&prices, "m", None, Microusd::from_usd(1.0));
        assert_eq!(actual, Microusd::from_usd(1.0));
        assert_eq!(usage, Usage::default());
        assert_eq!(basis, CostBasis::EstimateNoUsage);
    }

    // -- SettleGuard end-to-end: the truncation fallback and its counter ---

    /// RED-FIRST at the guard level (see `provider.rs` for the parser-level
    /// red-first): before this fix, `SettleGuard` had no way to be told a
    /// result was truncated at all, so a partial 500k-input-token parse would
    /// have settled at $1.50 - real money computed from data the cap had
    /// already cut off.
    #[test]
    fn a_truncated_result_settles_on_the_estimate_and_counts_it() {
        let (ledger, prices, usage, reservation) = setup();
        *usage.lock().unwrap() = Some(ParsedUsage {
            usage: Usage {
                input_tokens: 500_000,
                ..Default::default()
            },
            truncated: true,
        });
        let keystats = Arc::new(KeyStats::default());
        let sink = Arc::new(CapturingSink::default());
        let guard = SettleGuard::new(
            Arc::new(crate::ledger_backend::LocalLedger(ledger.clone())),
            prices,
            sink.clone(),
            "m".into(),
            usage,
            Microusd::from_usd(1.0),
            false, // a 200 stream: the estimate is a legitimate fallback
            reservation,
            String::new(),
            String::new(),
            String::new(),
            String::new(),
            String::new(),
            String::new(),
            Arc::new(UnitLedger::default()),
            None,
            keystats.clone(),
        );
        guard.complete();

        let snap = ledger.snapshot("r").unwrap();
        assert_eq!(
            snap.spent,
            Microusd::from_usd(1.0),
            "the estimate, not the $1.50 the untrusted partial usage would have priced"
        );
        assert_eq!(keystats.snapshot().truncated_settlements.settlements, 1);

        // The CallRecord side of the same fix: focusexport::to_row reads
        // "zero tokens + nonzero cost" as x_cost_basis "estimated" and
        // anything else as "settled" (see its module doc). The 500k partial
        // input tokens parsed above must NOT reach the record, or a
        // downstream FOCUS reader (CostCrew) would call this settled money
        // rather than the estimate it actually is.
        let rec = sink
            .last
            .lock()
            .unwrap()
            .clone()
            .expect("a record was settled");
        assert_eq!(
            (rec.input_tokens, rec.output_tokens),
            (0, 0),
            "the parsed partial usage must not reach the trace, or the FOCUS \
             export would read this row's shape as settled instead of estimated"
        );
    }

    #[test]
    fn a_parsed_result_under_the_cap_does_not_touch_the_truncation_counter() {
        let (ledger, prices, usage, reservation) = setup();
        *usage.lock().unwrap() = Some(ParsedUsage {
            usage: Usage {
                input_tokens: 1_000_000,
                ..Default::default()
            },
            truncated: false,
        });
        let keystats = Arc::new(KeyStats::default());
        let guard = SettleGuard::new(
            Arc::new(crate::ledger_backend::LocalLedger(ledger.clone())),
            prices,
            Arc::new(crate::sink::NullSink),
            "m".into(),
            usage,
            Microusd::from_usd(1.0),
            false,
            reservation,
            String::new(),
            String::new(),
            String::new(),
            String::new(),
            String::new(),
            String::new(),
            Arc::new(UnitLedger::default()),
            None,
            keystats.clone(),
        );
        guard.complete();

        let snap = ledger.snapshot("r").unwrap();
        assert_eq!(
            snap.spent,
            Microusd::from_usd(3.0),
            "priced from the real usage, not the estimate"
        );
        assert_eq!(keystats.snapshot().truncated_settlements.settlements, 0);
    }

    #[test]
    fn a_body_under_the_cap_with_no_usage_settles_the_estimate_without_counting_as_truncated() {
        let (ledger, prices, usage, reservation) = setup();
        *usage.lock().unwrap() = Some(ParsedUsage {
            usage: Usage::default(),
            truncated: false,
        });
        let keystats = Arc::new(KeyStats::default());
        let guard = SettleGuard::new(
            Arc::new(crate::ledger_backend::LocalLedger(ledger.clone())),
            prices,
            Arc::new(crate::sink::NullSink),
            "m".into(),
            usage,
            Microusd::from_usd(1.0),
            false,
            reservation,
            String::new(),
            String::new(),
            String::new(),
            String::new(),
            String::new(),
            String::new(),
            Arc::new(UnitLedger::default()),
            None,
            keystats.clone(),
        );
        guard.complete();

        let snap = ledger.snapshot("r").unwrap();
        assert_eq!(
            snap.spent,
            Microusd::from_usd(1.0),
            "the estimate: the body genuinely carried nothing to price"
        );
        assert_eq!(
            keystats.snapshot().truncated_settlements.settlements,
            0,
            "not the cap's doing, so it must not count as a truncated settlement"
        );
    }
}
