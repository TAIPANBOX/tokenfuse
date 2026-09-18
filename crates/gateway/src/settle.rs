//! The owner of a managed call's reservations, from the first one taken to the terminal
//! transition, and the one place that decides what each outcome is charged.
//!
//! A managed call takes up to two reservations before it is forwarded: one on the run's budget
//! chain (`Reservation`) and one on the unit's monthly cap (`UnitReservation`). This guard is
//! created in `proxy::handle` the moment the unit half exists (or would have: it is created
//! even when the unit has no cap), holds both halves across every await that follows (the run
//! reserve, `Provider::send`, the buffered body read, the stream), and on `Drop` decides from
//! [`CallOutcome`] rather than from whether anybody remembered to call settle. Until
//! 2026-09-18 it existed only on the streaming path and only after the provider had answered,
//! so a client that gave up while the provider still held the request leaked both halves
//! (F03/3.4 of the 2026-09-18 money-path review) and a 2xx whose body broke was settled at
//! zero on both (F04/3.5). Invariant 50.
//!
//! The states are what happened on the wire. How much is charged for an answered call is
//! [`settle_amount`]'s basis, unchanged: parsed usage as parsed, else the estimate on a 2xx and
//! zero on a refusal (invariants 43 and 47). A call the provider held when the caller left is
//! neither settled nor released: it is RETAINED, listed in [`Retained`], and stays outstanding
//! until somebody reconciles it (D7, `@decided 2026-09-18`).

use crate::keystats::KeyStats;
use crate::ledger_backend::LedgerBackend;
use crate::provider::{ParsedUsage, UsageSlot};
use crate::sink::{now_millis, CallRecord, EventSink};
use crate::unitledger::{UnitLedger, UnitReservation};
use axum::http::StatusCode;
use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use tokenfuse_core::{Microusd, PriceBook, Reservation, Usage};

/// The basis a settlement's charged amount rests on. Not a Parquet column
/// (see the PR body for why adding one was not a small change) - this exists
/// so the three cases below are a named, testable value rather than
/// reconstructed after the fact from which `Microusd` happened to come out,
/// which two different bases can produce by coincidence.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CostBasis {
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
/// and the pre-flight estimate to fall back to. "Parsed" means at least one
/// priced token count came out of the body (`Usage::carries_priced_tokens`);
/// a body that parsed as JSON and carried no usage block is
/// `EstimateNoUsage`. That question used to be asked as
/// `usage != Usage::default()`, which `tool_calls: Some(0)` satisfies with
/// every count zero, so a 2xx stream with no usage block settled as `Parsed`
/// at zero: tokenfuse#283, measured 2026-09-13 on Ollama and Bedrock's OpenAI
/// door on the released v0.5.0 image (OpenAI itself omits the chunk by its own
/// reference when the caller sets `include_usage: false`; not measured here).
/// Vertex Gemini and OpenRouter, one model each, send usage regardless and
/// were never affected. Cache reads alone count as a measured response. Pure and unit-tested on its
/// own below; `SettleGuard::charge` is the one caller, so the three-way
/// decision is made in exactly one place (invariant 50, 2026-09-18: until
/// then `SettleGuard::settle_now` and `proxy::buffered_managed` were two
/// separate callers of the same function).
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
pub fn settle_amount(
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
        Some(cost) if usage.carries_priced_tokens() => (cost, usage, CostBasis::Parsed),
        // Either the model has no price at all, or no token count was parsed
        // (the body carried no usage block, or the guard was dropped before
        // any was ever written to the slot). `usage` is recorded as it came,
        // so an observation that rides alongside the counts (`tool_calls`)
        // survives on the record even when the amount is the estimate.
        _ => (unmeasured, usage, CostBasis::EstimateNoUsage),
    }
}

/// Where a managed call stands between its first reservation and its terminal transition.
/// Set only by `proxy::handle` at the sites section 1.3 names; read only by `disposition`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CallOutcome {
    /// Reserved (the unit half, the run half, or both) and `Provider::send` not yet called.
    /// A guard that ends here releases both at zero.
    NotDispatched,
    /// `Provider::send` has been called and has not returned. The request may be on the wire
    /// or executing at the provider; nothing this process holds says which. A guard that ends
    /// here RETAINS both halves (D7).
    Unknown,
    /// `Provider::send` returned `Err`. Read as "the request did not reach the provider";
    /// invariant 50 records the honest limit of that reading. Releases both at zero.
    NotSent,
    /// A non-2xx status line arrived. Charges what the provider reported, else zero
    /// (invariant 47).
    Refused,
    /// A 2xx status line arrived. Charges what the body reported, else the estimate
    /// (invariant 43), whether the body completed, broke, or was abandoned by the caller.
    Started,
}

/// What a terminal transition does with the two reservations: a pure function of the state,
/// so the table can be read in one place and a planted fault is one token.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Disposition {
    /// Settle both at zero: nothing was generated.
    Release,
    /// Settle neither; hand both to [`Retained`] and warn (D7).
    Retain,
    /// Price the usage slot through `settle_amount`; `unmeasured` is the estimate on a 2xx and
    /// zero on a refusal.
    Charge { unmeasured_is_estimate: bool },
}

fn disposition(state: CallOutcome) -> Disposition {
    match state {
        CallOutcome::NotDispatched => Disposition::Release,
        CallOutcome::NotSent => Disposition::Release,
        CallOutcome::Unknown => Disposition::Retain,
        CallOutcome::Refused => Disposition::Charge {
            unmeasured_is_estimate: false,
        },
        CallOutcome::Started => Disposition::Charge {
            unmeasured_is_estimate: true,
        },
    }
}

/// What [`SettleGuard::settle_now`] did. `None` from the method means it had already happened.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Terminal {
    Released,
    Retained {
        amount: Microusd,
        listed: bool,
    },
    Settled {
        actual: Microusd,
        usage: Usage,
        basis: CostBasis,
    },
}

/// The request-scoped fields the `allow` row carries, cloned once into the guard so the row is
/// written from one place whichever path the call took.
#[derive(Debug, Clone, Default)]
pub struct CallAttribution {
    pub model: String,
    pub agent_id: String,
    pub parent_run_id: String,
    pub on_behalf_of: String,
    pub outcome: String,
    pub key_id: String,
    pub unit: String,
    /// `Some((original, chosen))` when the FinOps router rewrote the model: the row's
    /// `saved_microusd` is what the original would have cost minus what the chosen one did,
    /// for the settled usage. `None` when nothing was routed, and `None` on the streaming
    /// path by `handle`'s choice: a routed stream keeps the zero its row carried before the
    /// row moved in here, and counting its avoided spend is a separate decision.
    pub router_route: Option<(String, String)>,
}

/// A reservation kept outstanding on purpose (D7): the request was handed to the provider and
/// the call ended before any status line came back. Neither settled nor released; listed so an
/// operator can see it and a reconciliation (D8, not built) can settle or release it with the
/// handle it needs. Process-local, like the ledger it describes.
#[derive(Debug, Clone)]
pub struct RetainedReservation {
    pub run: Reservation,
    pub unit: Option<UnitReservation>,
    pub model: String,
    pub retained_at_millis: i64,
}

/// How many retained reservations are listed. Past this the ledger still holds the
/// reservation outstanding (nothing money-wise changes) and only the handle is not kept; the
/// retain warn line says `listed=false` and [`Retained::unlisted`] counts it. Bounded because
/// a caller who can cancel calls can grow this set.
pub const MAX_RETAINED: usize = 8192;

#[derive(Debug, Default)]
struct RetainedInner {
    by_run: HashMap<String, Vec<RetainedReservation>>,
    total: usize,
}

/// The process-local registry of retained reservations, one per `AppState`.
#[derive(Debug, Default)]
pub struct Retained {
    inner: Mutex<RetainedInner>,
    unlisted: AtomicU64,
}

impl Retained {
    /// `false` when the cap refused the entry (counted).
    pub fn push(&self, entry: RetainedReservation) -> bool {
        let mut inner = self.inner.lock().unwrap();
        if inner.total >= MAX_RETAINED {
            self.unlisted.fetch_add(1, Ordering::Relaxed);
            return false;
        }
        inner.total += 1;
        inner
            .by_run
            .entry(entry.run.run_id.clone())
            .or_default()
            .push(entry);
        true
    }
    pub fn for_run(&self, run_id: &str) -> Vec<RetainedReservation> {
        self.inner
            .lock()
            .unwrap()
            .by_run
            .get(run_id)
            .cloned()
            .unwrap_or_default()
    }
    pub fn all(&self) -> Vec<RetainedReservation> {
        self.inner
            .lock()
            .unwrap()
            .by_run
            .values()
            .flatten()
            .cloned()
            .collect()
    }
    pub fn len(&self) -> usize {
        self.inner.lock().unwrap().total
    }
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
    pub fn unlisted(&self) -> u64 {
        self.unlisted.load(Ordering::Relaxed)
    }
}

pub struct SettleGuard {
    ledger: Arc<dyn LedgerBackend>,
    units: Arc<UnitLedger>,
    prices: Arc<PriceBook>,
    sink: Arc<dyn EventSink>,
    keystats: Arc<KeyStats>,
    retained: Arc<Retained>,
    run_id: String,
    /// The pre-flight estimate both reservations were taken at; equal to `run.amount` once the
    /// run half is held (asserted in debug builds).
    estimate: Microusd,
    attribution: CallAttribution,
    state: CallOutcome,
    /// The leaf's step from the run reservation; 0 until `hold_run`.
    step: u32,
    run: Option<Reservation>,
    unit_reservation: Option<UnitReservation>,
    /// The provider's usage slot, attached by `answered`. `None` until then.
    usage: Option<UsageSlot>,
}

impl SettleGuard {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        ledger: Arc<dyn LedgerBackend>,
        units: Arc<UnitLedger>,
        prices: Arc<PriceBook>,
        sink: Arc<dyn EventSink>,
        keystats: Arc<KeyStats>,
        retained: Arc<Retained>,
        run_id: String,
        estimate: Microusd,
        attribution: CallAttribution,
        unit_reservation: Option<UnitReservation>,
    ) -> Self {
        SettleGuard {
            ledger,
            units,
            prices,
            sink,
            keystats,
            retained,
            run_id,
            estimate,
            attribution,
            state: CallOutcome::NotDispatched,
            step: 0,
            run: None,
            unit_reservation,
            usage: None,
        }
    }

    /// The run half, from `reserve` or `reserve_unchecked`. Once per guard, before dispatch.
    pub fn hold_run(&mut self, reservation: Reservation) {
        debug_assert!(self.run.is_none() && self.state == CallOutcome::NotDispatched);
        debug_assert_eq!(reservation.amount, self.estimate);
        self.step = reservation.step;
        self.run = Some(reservation);
    }

    /// Called on the line before `Provider::send(..).await`, never after: from here the
    /// outcome is unknown until `not_sent` or `answered` says otherwise.
    pub fn dispatching(&mut self) {
        debug_assert!(self.state == CallOutcome::NotDispatched && self.run.is_some());
        self.state = CallOutcome::Unknown;
    }

    /// `Provider::send` returned `Err`.
    pub fn not_sent(&mut self) {
        debug_assert_eq!(self.state, CallOutcome::Unknown);
        self.state = CallOutcome::NotSent;
    }

    /// A status line arrived, with the slot the provider will fill at the end of the body.
    /// A status `StatusCode` cannot parse (outside 100..=999) is not a success here, so the
    /// ledger treats it as a refusal and charges nothing unpriced, while `stream_managed` and
    /// `buffered_managed` answer the client with `200` for the same value
    /// (`from_u16(..).unwrap_or(StatusCode::OK)`). The two
    /// readings cannot meet through `HttpProvider`: its statuses come from reqwest and are
    /// always valid, so only a test double can produce one.
    pub fn answered(&mut self, status: u16, usage: UsageSlot) {
        debug_assert_eq!(self.state, CallOutcome::Unknown);
        let ok = StatusCode::from_u16(status)
            .map(|s| s.is_success())
            .unwrap_or(false);
        self.state = if ok {
            CallOutcome::Started
        } else {
            CallOutcome::Refused
        };
        self.usage = Some(usage);
    }

    pub fn run_id(&self) -> &str {
        &self.run_id
    }
    pub fn step(&self) -> u32 {
        self.step
    }
    pub fn state(&self) -> CallOutcome {
        self.state
    }

    /// The terminal transition, exactly once: the second call answers `None` and touches
    /// nothing. Both halves are taken here, which is what makes `Drop` after `complete` a
    /// no-op and a double settle impossible from this type (the ledger's own exactly-once,
    /// invariant 49, is the second line of defence for the run half; the unit ledger has none,
    /// which is why E17 reads the unit).
    pub fn settle_now(&mut self) -> Option<Terminal> {
        let run = self.run.take();
        let unit = self.unit_reservation.take();
        if run.is_none() && unit.is_none() {
            return None;
        }
        let now = now_millis();
        Some(match disposition(self.state) {
            Disposition::Release => self.release(run.as_ref(), unit.as_ref(), now),
            Disposition::Retain => self.retain(run, unit, now),
            Disposition::Charge {
                unmeasured_is_estimate,
            } => self.charge(run.as_ref(), unit.as_ref(), unmeasured_is_estimate, now),
        })
    }

    /// Normal end of stream. Consumes the guard so its `Drop` is a no-op.
    pub fn complete(mut self) {
        self.settle_now();
    }

    fn release(
        &self,
        run: Option<&Reservation>,
        unit: Option<&UnitReservation>,
        now: i64,
    ) -> Terminal {
        if let Some(r) = run {
            self.ledger.settle(r, Microusd::ZERO);
        }
        if let Some(u) = unit {
            self.units.settle(u, Microusd::ZERO, now);
        }
        Terminal::Released
    }

    fn retain(
        &self,
        run: Option<Reservation>,
        unit: Option<UnitReservation>,
        now: i64,
    ) -> Terminal {
        let Some(run) = run else {
            // Unreachable by construction (`dispatching` asserts a held run half); written as
            // a value rather than a panic. Nothing was dispatched against the unit alone.
            tracing::error!(run = %self.run_id, "settle guard reached the unknown state with no run reservation; releasing the unit half");
            return self.release(None, unit.as_ref(), now);
        };
        let (id, step, amount) = (run.id, run.step, run.amount);
        let unit_name = unit.as_ref().map(|u| u.unit.clone()).unwrap_or_default();
        let listed = self.retained.push(RetainedReservation {
            run,
            unit,
            model: self.attribution.model.clone(),
            retained_at_millis: now,
        });
        tracing::warn!(
            run = %self.run_id,
            reservation = id,
            step,
            amount_microusd = amount.0,
            unit = %unit_name,
            model = %self.attribution.model,
            listed,
            "retained: the request was handed to the provider and the call ended before any answer came back, so its outcome is unknown; the reservation stays outstanding on the run and on the unit until it is reconciled (invariant 50), never settled at zero"
        );
        Terminal::Retained { amount, listed }
    }

    fn charge(
        &self,
        run: Option<&Reservation>,
        unit: Option<&UnitReservation>,
        unmeasured_is_estimate: bool,
        now: i64,
    ) -> Terminal {
        let parsed = self
            .usage
            .as_ref()
            .and_then(|slot| slot.lock().unwrap().take());
        let unmeasured = if unmeasured_is_estimate {
            self.estimate
        } else {
            Microusd::ZERO
        };
        let (actual, usage, basis) =
            settle_amount(&self.prices, &self.attribution.model, parsed, unmeasured);
        if basis == CostBasis::EstimateTruncated {
            // Verbatim the existing warn (settle.rs:228-235 at e25835c) and counter.
            tracing::warn!(
                model = %self.attribution.model,
                buffered_bytes = crate::provider::UsageParser::CAP,
                settled_microusd = actual.0,
                "usage-parser cap hit before the response's usage block arrived; \
                 the parsed usage cannot be trusted, so this settled on the \
                 fallback amount above instead"
            );
            self.keystats.record_truncated_settlement();
        }
        if let Some(r) = run {
            self.ledger.settle(r, actual);
        }
        if let Some(u) = unit {
            self.units.settle(u, actual, now);
        }
        if let Some(r) = run {
            self.record_row(r, actual, &usage);
        }
        Terminal::Settled {
            actual,
            usage,
            basis,
        }
    }

    /// The `allow` row, ONE site for both paths (S5). `saved_microusd` is the router's
    /// avoided spend, verbatim the arithmetic that sat in `buffered_managed` at e25835c
    /// (`proxy.rs:2202-2213`), zero on the streaming path where `handle` passes `router_route`
    /// as `None` whatever the router did (the zero that path hard-coded before).
    fn record_row(&self, run: &Reservation, actual: Microusd, usage: &Usage) {
        let a = &self.attribution;
        let saved = match &a.router_route {
            Some((original, chosen)) => match (
                self.prices.cost(original, usage),
                self.prices.cost(chosen, usage),
            ) {
                (Some(would_have_cost), Some(did_cost)) => would_have_cost.saturating_sub(did_cost),
                _ => Microusd::ZERO,
            },
            None => Microusd::ZERO,
        };
        self.sink.record(CallRecord {
            ts_millis: now_millis(),
            run_id: run.run_id.clone(),
            model: a.model.clone(),
            decision: "allow".into(),
            input_tokens: usage.input_tokens,
            output_tokens: usage.output_tokens,
            cost_microusd: actual.0,
            step: run.step,
            agent_id: a.agent_id.clone(),
            saved_microusd: saved.0,
            parent_run_id: a.parent_run_id.clone(),
            on_behalf_of: a.on_behalf_of.clone(),
            outcome: a.outcome.clone(),
            key_id: a.key_id.clone(),
            unit: a.unit.clone(),
            tool_calls: usage.tool_calls,
        });
    }
}

impl Drop for SettleGuard {
    fn drop(&mut self) {
        // Every path that did not settle explicitly ends here: a cancelled future, an error
        // propagated by `?`, an early return. The state decides; nothing else does.
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

    /// Builds a guard with both halves held and dispatched. `slot` starts empty; call
    /// `*slot.lock().unwrap() = Some(..)` before `answered`/`settle_now` to simulate a
    /// provider that published usage.
    struct Rig {
        ledger: Arc<Ledger>,
        units: Arc<UnitLedger>,
        retained: Arc<Retained>,
        sink: Arc<CapturingSink>,
        slot: UsageSlot,
    }

    fn setup() -> (Arc<Ledger>, Arc<PriceBook>, UsageSlot, Reservation) {
        let ledger = Arc::new(Ledger::new());
        ledger
            .open_run("r", Microusd::from_usd(5.0), None)
            .expect("opens");
        let reservation = ledger.reserve("r", Microusd::from_usd(1.0)).unwrap();
        let prices =
            Arc::new(PriceBook::new().with("m", ModelPrice::per_mtok_usd(3.0, 15.0, 0.0, 0.0)));
        let usage: UsageSlot = Arc::new(Mutex::new(None));
        (ledger, prices, usage, reservation)
    }

    /// A minimal `EventSink` test double that captures every settled `CallRecord`
    /// (`all`), plus `last` for the tests that only care about the most recent one.
    #[derive(Default)]
    struct CapturingSink {
        last: Mutex<Option<CallRecord>>,
        all: Mutex<Vec<CallRecord>>,
    }

    impl crate::sink::EventSink for CapturingSink {
        fn record(&self, rec: CallRecord) {
            self.all.lock().unwrap().push(rec.clone());
            *self.last.lock().unwrap() = Some(rec);
        }
        fn flush(&self) {}
    }

    #[allow(clippy::too_many_arguments)]
    fn guard(
        ledger: &Arc<Ledger>,
        prices: Arc<PriceBook>,
        sink: Arc<dyn EventSink>,
        model: &str,
        estimate: Microusd,
        unit: &str,
        units: Arc<UnitLedger>,
        unit_reservation: Option<UnitReservation>,
        retained: Arc<Retained>,
        keystats: Arc<KeyStats>,
    ) -> SettleGuard {
        SettleGuard::new(
            Arc::new(crate::ledger_backend::LocalLedger(ledger.clone())),
            units,
            prices,
            sink,
            keystats,
            retained,
            "r".into(),
            estimate,
            CallAttribution {
                model: model.into(),
                unit: unit.into(),
                ..Default::default()
            },
            unit_reservation,
        )
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
        let mut g = guard(
            &ledger,
            prices,
            Arc::new(crate::sink::NullSink),
            "m",
            Microusd::from_usd(1.0),
            "",
            Arc::new(UnitLedger::default()),
            None,
            Arc::new(Retained::default()),
            Arc::new(KeyStats::default()),
        );
        g.hold_run(reservation);
        g.dispatching();
        g.answered(200, usage);
        g.complete();

        let snap = ledger.snapshot("r").unwrap();
        assert_eq!(snap.reserved, Microusd::ZERO); // released
        assert_eq!(snap.spent, Microusd::from_usd(3.0)); // 1M input @ $3/Mtok
    }

    #[test]
    fn drop_without_complete_settles_with_fallback() {
        let (ledger, prices, usage, reservation) = setup();
        let fallback = Microusd::from_usd(1.0);
        {
            let mut g = guard(
                &ledger,
                prices,
                Arc::new(crate::sink::NullSink),
                "m",
                fallback,
                "",
                Arc::new(UnitLedger::default()),
                None,
                Arc::new(Retained::default()),
                Arc::new(KeyStats::default()),
            );
            g.hold_run(reservation);
            g.dispatching();
            g.answered(200, usage);
            // dropped here without complete()
        }
        let snap = ledger.snapshot("r").unwrap();
        assert_eq!(snap.reserved, Microusd::ZERO); // reservation released, not leaked
        assert_eq!(snap.spent, fallback); // conservative fallback charge
    }

    /// The same cancel path, on a stream the provider had already refused.
    #[test]
    fn a_refused_stream_dropped_without_complete_settles_zero_not_the_estimate() {
        let (ledger, prices, usage, reservation) = setup();
        {
            let mut g = guard(
                &ledger,
                prices,
                Arc::new(crate::sink::NullSink),
                "m",
                Microusd::from_usd(1.0),
                "",
                Arc::new(UnitLedger::default()),
                None,
                Arc::new(Retained::default()),
                Arc::new(KeyStats::default()),
            );
            g.hold_run(reservation);
            g.dispatching();
            g.answered(429, usage); // the provider refused: nothing was generated
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

    /// A refusal that DOES report usage is still settled as that usage.
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
        let mut g = guard(
            &ledger,
            prices,
            Arc::new(crate::sink::NullSink),
            "m",
            Microusd::from_usd(1.0),
            "",
            Arc::new(UnitLedger::default()),
            None,
            Arc::new(Retained::default()),
            Arc::new(KeyStats::default()),
        );
        g.hold_run(reservation);
        g.dispatching();
        g.answered(429, usage); // refused, but it billed for what it generated
        g.complete();

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
        let mut g = guard(
            &ledger,
            prices,
            Arc::new(crate::sink::NullSink),
            "m",
            Microusd::from_usd(1.0),
            "treasury",
            units.clone(),
            Some(ur),
            Arc::new(Retained::default()),
            Arc::new(KeyStats::default()),
        );
        g.hold_run(reservation);
        g.dispatching();
        g.answered(200, usage);
        g.complete();
        // The unit ledger absorbed the same actual cost as the run ledger.
        assert_eq!(units.spent("treasury", now), Microusd::from_usd(3.0));
    }

    /// I1 (docs/21-tool-runs.md): the guard carries `Usage::tool_calls`
    /// through into the settled `CallRecord`, exactly like
    /// `input_tokens`/`output_tokens`.
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
        let mut g = guard(
            &ledger,
            prices,
            sink.clone(),
            "m",
            Microusd::from_usd(1.0),
            "",
            Arc::new(UnitLedger::default()),
            None,
            Arc::new(Retained::default()),
            Arc::new(KeyStats::default()),
        );
        g.hold_run(reservation);
        g.dispatching();
        g.answered(200, usage);
        g.complete();

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
            let mut g = guard(
                &ledger,
                prices,
                sink.clone(),
                "m",
                Microusd::from_usd(1.0),
                "",
                Arc::new(UnitLedger::default()),
                None,
                Arc::new(Retained::default()),
                Arc::new(KeyStats::default()),
            );
            g.hold_run(reservation);
            g.dispatching();
            g.answered(200, usage);
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

    /// tokenfuse#283, RED-FIRST. A 2xx stream whose caller set
    /// `stream_options.include_usage: false` carries JSON chunks and no usage
    /// block. The parser still sees JSON, so `ToolCallCounter::finish()`
    /// answers `Some(0)` and the parsed `Usage` is zero tokens beside
    /// `tool_calls: Some(0)`. Before this fix `settle_amount` read "did we
    /// parse usage" as `usage != Usage::default()`, which that side field
    /// satisfies, and the call settled as `Parsed` at zero.
    #[test]
    fn settle_amount_treats_zero_tokens_beside_a_tool_call_count_as_no_usage() {
        let prices = PriceBook::new().with("m", ModelPrice::per_mtok_usd(3.0, 15.0, 0.0, 0.0));
        let parsed = Some(ParsedUsage {
            usage: Usage {
                tool_calls: Some(0),
                ..Default::default()
            },
            truncated: false,
        });
        let estimate = Microusd::from_usd(1.0);
        let (actual, usage, basis) = settle_amount(&prices, "m", parsed, estimate);
        assert_eq!(
            actual, estimate,
            "no priced token was parsed, so the estimate is what this settles on, not zero"
        );
        assert_eq!(basis, CostBasis::EstimateNoUsage);
        assert_eq!(
            usage.tool_calls,
            Some(0),
            "the observation itself stays on the record: I1 counts tool calls, it does not price them"
        );
    }

    /// The same shape on the fallback price book: a model the book does not
    /// know is priced at the fallback rate, and zero tokens at any rate is
    /// zero, so the guard has to be about tokens, not about cost.
    #[test]
    fn settle_amount_on_an_unknown_model_with_no_tokens_is_still_the_estimate() {
        let prices = crate::pricebook::default_price_book();
        let parsed = Some(ParsedUsage {
            usage: Usage {
                tool_calls: Some(0),
                ..Default::default()
            },
            truncated: false,
        });
        let estimate = Microusd::from_usd(0.004);
        let (actual, _, basis) =
            settle_amount(&prices, "amazon.nova-2-lite-v1:0", parsed, estimate);
        assert_eq!(actual, estimate);
        assert_eq!(basis, CostBasis::EstimateNoUsage);
    }

    /// A response whose only nonzero count is cache reads is still a measured
    /// response: it is priced as parsed, not thrown back on the estimate.
    #[test]
    fn settle_amount_prices_a_cache_read_only_response_as_parsed() {
        let prices = PriceBook::new().with("m", ModelPrice::per_mtok_usd(3.0, 15.0, 0.3, 3.75));
        let parsed = Some(ParsedUsage {
            usage: Usage {
                cache_read_tokens: 1_000_000,
                tool_calls: Some(0),
                ..Default::default()
            },
            truncated: false,
        });
        let (actual, _, basis) = settle_amount(&prices, "m", parsed, Microusd::from_usd(1.0));
        assert_eq!(basis, CostBasis::Parsed);
        assert_eq!(actual, Microusd::from_usd(0.3));
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
        let mut g = guard(
            &ledger,
            prices,
            sink.clone(),
            "m",
            Microusd::from_usd(1.0),
            "",
            Arc::new(UnitLedger::default()),
            None,
            Arc::new(Retained::default()),
            keystats.clone(),
        );
        g.hold_run(reservation);
        g.dispatching();
        g.answered(200, usage);
        g.complete();

        let snap = ledger.snapshot("r").unwrap();
        assert_eq!(
            snap.spent,
            Microusd::from_usd(1.0),
            "the estimate, not the $1.50 the untrusted partial usage would have priced"
        );
        assert_eq!(keystats.snapshot().truncated_settlements.settlements, 1);

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
        let mut g = guard(
            &ledger,
            prices,
            Arc::new(crate::sink::NullSink),
            "m",
            Microusd::from_usd(1.0),
            "",
            Arc::new(UnitLedger::default()),
            None,
            Arc::new(Retained::default()),
            keystats.clone(),
        );
        g.hold_run(reservation);
        g.dispatching();
        g.answered(200, usage);
        g.complete();

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
        let mut g = guard(
            &ledger,
            prices,
            Arc::new(crate::sink::NullSink),
            "m",
            Microusd::from_usd(1.0),
            "",
            Arc::new(UnitLedger::default()),
            None,
            Arc::new(Retained::default()),
            keystats.clone(),
        );
        g.hold_run(reservation);
        g.dispatching();
        g.answered(200, usage);
        g.complete();

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

    // -- invariant 50: one owner, five states, an unknown outcome is retained

    fn rig() -> Rig {
        let ledger = Arc::new(Ledger::new());
        ledger
            .open_run("r", Microusd::from_usd(5.0), None)
            .expect("opens");
        let units = Arc::new(UnitLedger::new(std::collections::HashMap::from([(
            "treasury".to_string(),
            Microusd::from_usd(10.0),
        )])));
        Rig {
            ledger,
            units,
            retained: Arc::new(Retained::default()),
            sink: Arc::new(CapturingSink::default()),
            slot: Arc::new(Mutex::new(None)),
        }
    }

    fn rig_guard(rig: &Rig) -> SettleGuard {
        let prices =
            Arc::new(PriceBook::new().with("m", ModelPrice::per_mtok_usd(3.0, 15.0, 0.0, 0.0)));
        let now = now_millis();
        let ur = rig
            .units
            .try_reserve("treasury", Microusd::from_usd(1.0), now)
            .unwrap()
            .expect("capped unit reserves");
        let reservation = rig.ledger.reserve("r", Microusd::from_usd(1.0)).unwrap();
        let mut g = SettleGuard::new(
            Arc::new(crate::ledger_backend::LocalLedger(rig.ledger.clone())),
            rig.units.clone(),
            prices,
            rig.sink.clone(),
            Arc::new(KeyStats::default()),
            rig.retained.clone(),
            "r".into(),
            Microusd::from_usd(1.0),
            CallAttribution {
                model: "m".into(),
                unit: "treasury".into(),
                ..Default::default()
            },
            Some(ur),
        );
        g.hold_run(reservation);
        g
    }

    /// E13. A guard dropped while the provider holds the request (never
    /// answered) neither settles nor releases: both ledgers stay reserved at
    /// the estimate, the registry gets exactly one entry, and one `warn`
    /// names the run, the reservation, the amount and the unit (D7).
    ///
    /// Compile-red at e25835c: `Retained`, `RetainedReservation` and
    /// `AppState.retained` do not exist there.
    #[test]
    fn a_guard_dropped_while_the_provider_holds_the_request_retains_and_warns() {
        let _serial = crate::testlog::log_lock();
        let buf = crate::testlog::captured_log();
        let start = buf.lock().unwrap().len();

        let r = rig();
        {
            let mut g = rig_guard(&r);
            g.dispatching();
            // dropped here, still `Unknown`
        }

        let snap = r.ledger.snapshot("r").unwrap();
        assert_eq!(snap.reserved, Microusd::from_usd(1.0));
        assert_eq!(snap.spent, Microusd::ZERO);
        assert_eq!(
            r.units.reserved("treasury", now_millis()),
            Microusd::from_usd(1.0)
        );
        assert_eq!(r.units.spent("treasury", now_millis()), Microusd::ZERO);
        assert_eq!(r.retained.len(), 1);
        let entry = &r.retained.for_run("r")[0];
        assert_eq!(entry.run.amount, Microusd::from_usd(1.0));
        assert_eq!(entry.unit.as_ref().unwrap().unit, "treasury");
        assert!(r.sink.all.lock().unwrap().is_empty(), "no row: D6");

        let text = String::from_utf8_lossy(&buf.lock().unwrap()[start..]).into_owned();
        assert!(text.contains("WARN"), "{text}");
        assert!(
            text.contains("retained: the request was handed to the provider"),
            "{text}"
        );
        assert!(text.contains("run=r reservation="), "{text}");
        assert!(text.contains("amount_microusd=1000000"), "{text}");
        assert!(text.contains("unit=treasury"), "{text}");
        assert!(text.contains("listed=true"), "{text}");
    }

    /// E14. A guard dropped before dispatch releases both halves at zero and
    /// writes no row. Compile-red at e25835c: the new `SettleGuard::new`
    /// signature does not exist there.
    #[test]
    fn a_guard_dropped_before_dispatch_releases_both_ledgers_and_writes_no_row() {
        let _serial = crate::testlog::log_lock();
        let buf = crate::testlog::captured_log();
        let start = buf.lock().unwrap().len();

        let r = rig();
        {
            let _g = rig_guard(&r);
            // dropped here without `dispatching()`: still NotDispatched
        }

        let snap = r.ledger.snapshot("r").unwrap();
        assert_eq!(snap.reserved, Microusd::ZERO);
        assert_eq!(snap.spent, Microusd::ZERO);
        assert_eq!(r.units.reserved("treasury", now_millis()), Microusd::ZERO);
        assert_eq!(r.units.spent("treasury", now_millis()), Microusd::ZERO);
        assert!(r.retained.is_empty());
        assert!(r.sink.all.lock().unwrap().is_empty());
        let text = String::from_utf8_lossy(&buf.lock().unwrap()[start..]).into_owned();
        assert!(!text.contains("retained:"), "{text}");
    }

    /// E15. A guard holding only the unit half (no run reservation ever
    /// taken) releases the unit half on drop and leaves the run ledger
    /// untouched.
    #[test]
    fn a_guard_holding_only_the_unit_half_releases_it_on_drop() {
        let r = rig();
        let prices =
            Arc::new(PriceBook::new().with("m", ModelPrice::per_mtok_usd(3.0, 15.0, 0.0, 0.0)));
        let now = now_millis();
        let ur = r
            .units
            .try_reserve("treasury", Microusd::from_usd(1.0), now)
            .unwrap()
            .expect("capped unit reserves");
        {
            let _g = SettleGuard::new(
                Arc::new(crate::ledger_backend::LocalLedger(r.ledger.clone())),
                r.units.clone(),
                prices,
                r.sink.clone(),
                Arc::new(KeyStats::default()),
                r.retained.clone(),
                "r".into(),
                Microusd::from_usd(1.0),
                CallAttribution {
                    model: "m".into(),
                    unit: "treasury".into(),
                    ..Default::default()
                },
                Some(ur),
            );
            // no hold_run: the run half was never taken. Dropped here.
        }
        assert_eq!(r.units.reserved("treasury", now_millis()), Microusd::ZERO);
        assert_eq!(r.units.spent("treasury", now_millis()), Microusd::ZERO);
        let snap = r.ledger.snapshot("r").unwrap();
        assert_eq!(snap.reserved, Microusd::ZERO);
        assert_eq!(snap.steps, 0);
        assert!(r.retained.is_empty());
        assert!(r.sink.all.lock().unwrap().is_empty());
    }

    /// E16. `not_sent` releases both halves at zero and writes no row, and
    /// `settle_now` answers `Some(Terminal::Released)` at the point of the
    /// explicit call, not only on drop.
    #[test]
    fn a_guard_told_the_send_failed_releases_both_and_writes_no_row() {
        let r = rig();
        let mut g = rig_guard(&r);
        g.dispatching();
        g.not_sent();
        assert_eq!(g.settle_now(), Some(Terminal::Released));
        drop(g);

        let snap = r.ledger.snapshot("r").unwrap();
        assert_eq!(snap.reserved, Microusd::ZERO);
        assert_eq!(snap.spent, Microusd::ZERO);
        assert_eq!(r.units.reserved("treasury", now_millis()), Microusd::ZERO);
        assert_eq!(r.units.spent("treasury", now_millis()), Microusd::ZERO);
        assert!(r.retained.is_empty());
        assert!(r.sink.all.lock().unwrap().is_empty());
    }

    /// E17. A second `settle_now` after the first, and a `Drop` after that,
    /// change nothing: the guard settles exactly once. The RUN ledger is
    /// shielded a second time by invariant 49's own exactly-once; the UNIT
    /// ledger has no such guard of its own, which is why this reads the unit
    /// (not 6_000_000) as the assertion that can actually go red.
    #[test]
    fn a_second_settle_of_one_guard_changes_nothing() {
        let r = rig();
        let mut g = rig_guard(&r);
        *r.slot.lock().unwrap() = Some(ParsedUsage {
            usage: Usage {
                input_tokens: 1_000_000,
                ..Default::default()
            },
            truncated: false,
        });
        g.dispatching();
        g.answered(200, r.slot.clone());

        let first = g.settle_now();
        let second = g.settle_now();
        drop(g);

        assert_eq!(
            first,
            Some(Terminal::Settled {
                actual: Microusd(3_000_000),
                usage: Usage {
                    input_tokens: 1_000_000,
                    ..Default::default()
                },
                basis: CostBasis::Parsed,
            })
        );
        assert_eq!(second, None);
        let snap = r.ledger.snapshot("r").unwrap();
        assert_eq!(snap.spent, Microusd(3_000_000));
        assert_eq!(snap.reserved, Microusd::ZERO);
        assert_eq!(
            r.units.spent("treasury", now_millis()),
            Microusd(3_000_000),
            "not 6_000_000: a second settle must not charge the unit twice"
        );
        assert_eq!(r.sink.all.lock().unwrap().len(), 1);
    }

    /// E18. The run and the unit ledgers agree in every terminal state:
    /// `reserved == 0` on one side exactly when it is on the other, and the
    /// two `spent` figures always match. Only `Unknown` leaves both
    /// outstanding.
    #[test]
    fn the_run_and_unit_ledgers_agree_in_every_terminal_state() {
        // The `Unknown` row writes a `retained:` warn into the process-wide
        // captured log; serialised so E13/E14's reads of that buffer never
        // count this test's line.
        let _serial = crate::testlog::log_lock();
        struct Row {
            name: &'static str,
            status: Option<u16>,
            slot: Option<ParsedUsage>,
            not_sent: bool,
        }
        let rows = [
            Row {
                name: "NotDispatched",
                status: None,
                slot: None,
                not_sent: false,
            },
            Row {
                name: "NotSent",
                status: None,
                slot: None,
                not_sent: true,
            },
            Row {
                name: "Refused, no usage",
                status: Some(429),
                slot: None,
                not_sent: false,
            },
            Row {
                name: "Refused, priced usage",
                status: Some(429),
                slot: Some(ParsedUsage {
                    usage: Usage {
                        input_tokens: 1_000_000,
                        ..Default::default()
                    },
                    truncated: false,
                }),
                not_sent: false,
            },
            Row {
                name: "Started, no usage",
                status: Some(200),
                slot: None,
                not_sent: false,
            },
            Row {
                name: "Started, priced usage",
                status: Some(200),
                slot: Some(ParsedUsage {
                    usage: Usage {
                        input_tokens: 1_000_000,
                        ..Default::default()
                    },
                    truncated: false,
                }),
                not_sent: false,
            },
            Row {
                name: "Started, truncated",
                status: Some(200),
                slot: Some(ParsedUsage {
                    usage: Usage {
                        input_tokens: 500_000,
                        ..Default::default()
                    },
                    truncated: true,
                }),
                not_sent: false,
            },
            Row {
                name: "Unknown",
                status: None,
                slot: None,
                not_sent: false,
            },
        ];
        let expected_spent = [
            Microusd::ZERO,
            Microusd::ZERO,
            Microusd::ZERO,
            Microusd(3_000_000),
            Microusd::from_usd(1.0),
            Microusd(3_000_000),
            Microusd::from_usd(1.0),
            Microusd::ZERO,
        ];
        for (row, &expect) in rows.iter().zip(expected_spent.iter()) {
            let r = rig();
            let mut g = rig_guard(&r);
            match row.status {
                None if !row.not_sent => {
                    // NotDispatched or Unknown: leave the state as constructed.
                    if row.name == "Unknown" {
                        g.dispatching();
                    }
                }
                None => {
                    g.dispatching();
                    g.not_sent();
                }
                Some(status) => {
                    let slot: UsageSlot = Arc::new(Mutex::new(row.slot));
                    g.dispatching();
                    g.answered(status, slot);
                }
            }
            g.settle_now();
            let run_snap = r.ledger.snapshot("r").unwrap();
            let unit_reserved_zero = r.units.reserved("treasury", now_millis()) == Microusd::ZERO;
            assert_eq!(
                run_snap.reserved == Microusd::ZERO,
                unit_reserved_zero,
                "{}: run.reserved={:?} unit.reserved_zero={}",
                row.name,
                run_snap.reserved,
                unit_reserved_zero
            );
            assert_eq!(
                run_snap.spent,
                r.units.spent("treasury", now_millis()),
                "{}",
                row.name
            );
            assert_eq!(run_snap.spent, expect, "{}", row.name);
            if row.name == "Unknown" {
                assert_eq!(run_snap.reserved, Microusd::from_usd(1.0), "{}", row.name);
                assert_eq!(r.retained.len(), 1, "{}", row.name);
            } else {
                assert_eq!(run_snap.reserved, Microusd::ZERO, "{}", row.name);
            }
        }
    }

    /// E19. `disposition` names exactly the rule the spec's table gives: the
    /// pure function is one match, so a planted fault there is one token.
    #[test]
    fn every_state_has_the_disposition_the_rule_names() {
        assert_eq!(
            disposition(CallOutcome::NotDispatched),
            Disposition::Release
        );
        assert_eq!(disposition(CallOutcome::NotSent), Disposition::Release);
        assert_eq!(disposition(CallOutcome::Unknown), Disposition::Retain);
        assert_eq!(
            disposition(CallOutcome::Refused),
            Disposition::Charge {
                unmeasured_is_estimate: false
            }
        );
        assert_eq!(
            disposition(CallOutcome::Started),
            Disposition::Charge {
                unmeasured_is_estimate: true
            }
        );
    }
}
