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

use crate::ledger_backend::LedgerBackend;
use crate::provider::UsageSlot;
use crate::sink::{now_millis, CallRecord, EventSink};
use crate::unitledger::{UnitLedger, UnitReservation};
use std::sync::Arc;
use tokenfuse_core::{Microusd, PriceBook, Reservation};

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
        let actual = parsed
            .as_ref()
            .and_then(|u| self.prices.cost(&self.model, u))
            .unwrap_or(unmeasured);
        self.ledger.settle(&reservation, actual);
        if let Some(ur) = self.unit_reservation.take() {
            self.units.settle(&ur, actual, now_millis());
        }

        let usage = parsed.unwrap_or_default();
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
    use crate::provider::UsageSlot;
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
        *usage.lock().unwrap() = Some(Usage {
            input_tokens: 1_000_000,
            output_tokens: 0,
            ..Default::default()
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
        *usage.lock().unwrap() = Some(Usage {
            input_tokens: 1_000_000,
            output_tokens: 0,
            ..Default::default()
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
        *usage.lock().unwrap() = Some(Usage {
            input_tokens: 1_000_000,
            output_tokens: 0,
            ..Default::default()
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
        *usage.lock().unwrap() = Some(Usage {
            input_tokens: 1_000_000,
            output_tokens: 0,
            tool_calls: Some(2),
            ..Default::default()
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
}
