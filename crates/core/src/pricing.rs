//! Token usage and per-model pricing.
//!
//! Prices are expressed as microdollars per 1,000,000 tokens ("per Mtok"),
//! matching how providers publish their rates. Cache read/write are priced
//! separately on purpose: with agent loops that reuse a cached prefix, folding
//! them into the input rate would skew the accounting by a large multiple.

use crate::money::Microusd;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Token counts for a single LLM call, as reported by the provider.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Usage {
    pub input_tokens: u64,
    pub output_tokens: u64,
    pub cache_read_tokens: u64,
    /// Every cache-creation token, on either TTL: the total the provider
    /// reports as `cache_creation_input_tokens`, and the figure the trace
    /// keeps.
    pub cache_write_tokens: u64,
    /// The subset of `cache_write_tokens` written with the 1-hour TTL
    /// (`usage.cache_creation.ephemeral_1h_input_tokens`), which Anthropic
    /// bills at 2x input against 1.25x for the 5-minute default. Zero when
    /// the provider reports no breakdown. `#[serde(default)]` because a
    /// gateway older than this field posts usage without it (tokenfuse#282).
    #[serde(default)]
    pub cache_write_1h_tokens: u64,
    /// Number of tool calls the model emitted in this response (I1, an
    /// observed metric only - see docs/21-tool-runs.md). `None` only when the
    /// response body never parsed as JSON at all; a successfully parsed body
    /// with no tool calls is `Some(0)`, never a guess. Deliberately NOT read
    /// by [`ModelPrice::cost`]: this rides alongside the priced token counts
    /// but is not itself priced.
    pub tool_calls: Option<u32>,
}

impl Usage {
    /// Whether this usage holds anything a price book prices: any of the four
    /// token counts nonzero. `tool_calls` is deliberately not read here, for
    /// the same reason [`ModelPrice::cost`] does not read it: it is an
    /// observation that rides alongside the counts, not a count itself.
    ///
    /// This is the question "did the body carry usage" that settlement asks
    /// before it trusts a parsed amount. Asking it as `!= Usage::default()`
    /// stopped being the same question when `tool_calls` was added: a body
    /// with no usage block still parses as JSON, the tool-call counter answers
    /// `Some(0)`, and a struct with every count zero is no longer default. The
    /// gateway settled such a call as parsed, at the cost of zero tokens, which
    /// is zero (tokenfuse#283). The four fields are enumerated here, next to
    /// `cost`'s own list, so a fifth priced field is added to both in one file.
    pub fn carries_priced_tokens(&self) -> bool {
        self.input_tokens > 0
            || self.output_tokens > 0
            || self.cache_read_tokens > 0
            || self.cache_write_tokens > 0
            || self.cache_write_1h_tokens > 0
    }
}

/// Per-model price, in microdollars per million tokens.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct ModelPrice {
    pub input_per_mtok: Microusd,
    pub output_per_mtok: Microusd,
    pub cache_read_per_mtok: Microusd,
    /// The 5-minute cache write, the default TTL.
    pub cache_write_per_mtok: Microusd,
    /// The 1-hour cache write. Anthropic prices it at 2x input where the
    /// 5-minute write is 1.25x, so [`ModelPrice::per_mtok_usd`] derives it as
    /// 1.6x the 5-minute rate, exact for every model in the book; a book
    /// entry names its own with [`ModelPrice::with_cache_write_1h_usd`].
    /// `#[serde(default)]` so a price posted by an older gateway still reads;
    /// a zero here prices a 1-hour write at nothing, which is why the
    /// constructor never leaves it zero (tokenfuse#282).
    #[serde(default)]
    pub cache_write_1h_per_mtok: Microusd,
}

impl ModelPrice {
    /// Build a price from USD-per-Mtok figures (the units providers publish).
    pub fn per_mtok_usd(input: f64, output: f64, cache_read: f64, cache_write: f64) -> Self {
        ModelPrice {
            input_per_mtok: Microusd::from_usd(input),
            output_per_mtok: Microusd::from_usd(output),
            cache_read_per_mtok: Microusd::from_usd(cache_read),
            cache_write_per_mtok: Microusd::from_usd(cache_write),
            cache_write_1h_per_mtok: Microusd::from_usd(cache_write * 1.6),
        }
    }

    /// Name the 1-hour cache-write rate outright, for a book entry whose
    /// provider does not follow the 1.6x ratio.
    pub fn with_cache_write_1h_usd(mut self, cache_write_1h: f64) -> Self {
        self.cache_write_1h_per_mtok = Microusd::from_usd(cache_write_1h);
        self
    }

    /// Price a usage record. Saturating throughout: an absurd token count
    /// prices at the ceiling, never at a negative or a wrapped-small figure.
    ///
    /// The direction matters and is not symmetric. Over-charging an impossible
    /// request refuses it, which is the safe answer for a request nobody can
    /// pay for. Under-charging it serves it, and a negative cost passes every
    /// budget check there is: measured on 2026-09-07, `output_tokens = 1e18`
    /// priced at -3446744073709551616 micro-usd and the gateway forwarded a
    /// call it should have refused. Same reasoning as ADR-8's fallback price.
    ///
    /// **Rounds once, on the sum, toward over-charging (invariant 67).** Each
    /// part's raw numerator (`tokens * price_per_mtok`, not yet divided by
    /// `1_000_000`) is kept in full and summed before any division happens;
    /// only the final total is divided, and a positive remainder rounds that
    /// total UP by one micro-USD, never down. Dividing (and so flooring) each
    /// part on its own, the shape this function had until this fix, under-
    /// charged a call by up to just under one micro-USD per part: a real
    /// `gpt-4o-mini` call (13 input, 2 completion tokens, $0.15/$0.60 per
    /// Mtok) prices to 13 x 0.15 + 2 x 0.60 = 3.15 micro-USD, and the old code
    /// answered 2 (`floor(1.95) + floor(1.20)`), not 4, measured on a live
    /// cluster 2026-09-27 (tokenfuse#341). Rounding per part and rounding the
    /// sum can also disagree even when neither is the old floor: two parts
    /// each worth exactly half a micro-USD floor to zero apiece but sum to
    /// one whole micro-USD, which only rounding the sum, once, ever sees.
    pub fn cost(&self, usage: &Usage) -> Microusd {
        // The raw numerator for one part: `tokens * price_per_mtok`, still
        // scaled by the implicit `/ 1_000_000` every price in this module
        // carries (a "per Mtok" price times a token count that has not yet
        // been divided down to Mtok units). Saturating so that a single
        // absurd part cannot wrap before the parts are ever summed.
        let numerator = |tokens: u64, price: Microusd| -> i128 {
            (tokens as i128).saturating_mul(price.0 as i128)
        };
        // The 1-hour subset is priced at its own rate and taken out of the
        // total so no written token is counted twice; a subset past the total
        // (a provider's bug) leaves nothing on the 5-minute side and prices the
        // subset in full, the over-charging direction.
        let five_minute = usage
            .cache_write_tokens
            .saturating_sub(usage.cache_write_1h_tokens);
        // Every part summed BEFORE dividing, so a fractional remainder in one
        // part is not lost before it has a chance to combine with another's.
        // `saturating_add` on `i128` (whose range is roughly 1.7e38, vastly
        // larger than the largest single `saturating_mul` above can produce)
        // means this sum cannot itself wrap even at five near-maximal parts.
        let total_numerator = numerator(usage.input_tokens, self.input_per_mtok)
            .saturating_add(numerator(usage.output_tokens, self.output_per_mtok))
            .saturating_add(numerator(usage.cache_read_tokens, self.cache_read_per_mtok))
            .saturating_add(numerator(five_minute, self.cache_write_per_mtok))
            .saturating_add(numerator(
                usage.cache_write_1h_tokens,
                self.cache_write_1h_per_mtok,
            ));
        // Clamp before dividing, not after: a negative sum (a misconfigured
        // negative rate, invariant unchanged from before this fix) must floor
        // at zero, never ceil to one.
        let clamped = total_numerator.clamp(0, i128::MAX);
        let quotient = clamped / 1_000_000;
        let remainder = clamped % 1_000_000;
        let ceiled = if remainder > 0 {
            quotient + 1
        } else {
            quotient
        };
        Microusd(ceiled.clamp(0, i64::MAX as i128) as i64)
    }
}

/// A lookup of model name -> price, with an optional conservative fallback for
/// unknown models (ADR-8: unknown model -> price at the most expensive known
/// model, so we never under-charge a run we can't identify).
#[derive(Debug, Clone, Default)]
pub struct PriceBook {
    prices: HashMap<String, ModelPrice>,
    fallback: Option<ModelPrice>,
}

impl PriceBook {
    pub fn new() -> Self {
        PriceBook::default()
    }

    pub fn insert(&mut self, model: impl Into<String>, price: ModelPrice) {
        self.prices.insert(model.into(), price);
    }

    pub fn with(mut self, model: impl Into<String>, price: ModelPrice) -> Self {
        self.insert(model, price);
        self
    }

    /// Set the fallback used for models not present in the book.
    pub fn with_fallback(mut self, price: ModelPrice) -> Self {
        self.fallback = Some(price);
        self
    }

    /// Price for a model: exact match first, then fallback if configured.
    pub fn price(&self, model: &str) -> Option<ModelPrice> {
        self.prices.get(model).copied().or(self.fallback)
    }

    /// Whether the model was priced by an exact entry (vs. the fallback). The
    /// gateway flags fallback-priced calls so reports can surface them.
    pub fn is_known(&self, model: &str) -> bool {
        self.prices.contains_key(model)
    }

    /// Every exact entry in the book, sorted by model name.
    ///
    /// Sorted rather than left in the `HashMap`'s own order because the caller
    /// this exists for (`gateway::constants`) serialises the result into a
    /// committed file that a gate compares byte for byte: an iteration order
    /// that varies per process would make that file disagree with itself on
    /// every run, and the gate would then be noise rather than a check.
    pub fn entries(&self) -> Vec<(&str, ModelPrice)> {
        let mut out: Vec<(&str, ModelPrice)> =
            self.prices.iter().map(|(m, p)| (m.as_str(), *p)).collect();
        out.sort_by(|a, b| a.0.cmp(b.0));
        out
    }

    /// The conservative fallback applied to models with no exact entry
    /// (ADR-8), or `None` when the book has none.
    pub fn fallback(&self) -> Option<ModelPrice> {
        self.fallback
    }

    pub fn cost(&self, model: &str, usage: &Usage) -> Option<Microusd> {
        self.price(model).map(|p| p.cost(usage))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sonnet() -> ModelPrice {
        // Illustrative rates ($/Mtok): input 3, output 15, cache read 0.3, write 3.75.
        ModelPrice::per_mtok_usd(3.0, 15.0, 0.30, 3.75)
    }

    #[test]
    fn cost_sums_all_four_token_kinds() {
        let price = sonnet();
        let usage = Usage {
            input_tokens: 1_000_000,
            output_tokens: 1_000_000,
            cache_read_tokens: 1_000_000,
            cache_write_tokens: 1_000_000,
            ..Default::default()
        };
        // 3 + 15 + 0.30 + 3.75 = 22.05 USD
        assert_eq!(price.cost(&usage), Microusd::from_usd(22.05));
    }

    /// tokenfuse#282, the INT-2 call of the 1.0 proving run: Claude Code
    /// through the gateway on claude-haiku-4-5, 10 input, 192 output and
    /// 140,373 cache-creation tokens, every one of them a 1-hour write.
    /// Anthropic bills a 1-hour cache write at 2x input (2.00 USD/Mtok on
    /// haiku), a 5-minute one at 1.25x (1.25): Claude Code's own figure for
    /// the call was 0.281716 USD; the gateway said 0.176436, the whole write
    /// priced at the 5-minute rate, 37 percent short.
    #[test]
    fn a_one_hour_cache_write_is_priced_at_the_one_hour_rate() {
        let haiku = ModelPrice::per_mtok_usd(1.00, 5.00, 0.10, 1.25);
        let usage = Usage {
            input_tokens: 10,
            output_tokens: 192,
            cache_write_tokens: 140_373,
            cache_write_1h_tokens: 140_373,
            ..Default::default()
        };
        // 10 x 1.00 + 192 x 5.00 + 140,373 x 2.00 per Mtok = 0.000010 + 0.000960 + 0.280746
        assert_eq!(haiku.cost(&usage), Microusd(281_716));
        let five_minute_only = Usage {
            cache_write_1h_tokens: 0,
            ..usage
        };
        assert_eq!(five_minute_only.cache_write_tokens, 140_373);
        // 140,373 x 1.25 + 10 x 1.00 + 192 x 5.00 per Mtok = 176,436.25 micro-USD.
        // Invariant 67 rounds the SUM once, toward over-charging: 176,436.25
        // ceils to 176,437, a figure the old per-part-floor code could never
        // produce (it floored this same part alone to 176,436 and lost the
        // 0.25). This is the one pre-existing exact-value assertion in this
        // file whose number changes under the fix; every other one in this
        // module lands on a whole micro-USD already and is unaffected.
        assert_eq!(haiku.cost(&five_minute_only), Microusd(176_437));
    }

    /// The total stays the total: `cache_write_tokens` counts every written
    /// token and `cache_write_1h_tokens` names the subset of it on the longer
    /// TTL, so a mixed write prices each part at its own rate and nothing is
    /// counted twice.
    #[test]
    fn a_mixed_cache_write_prices_each_ttl_once() {
        let haiku = ModelPrice::per_mtok_usd(1.00, 5.00, 0.10, 1.25);
        let usage = Usage {
            cache_write_tokens: 1_000_000,
            cache_write_1h_tokens: 400_000,
            ..Default::default()
        };
        // 600,000 x 1.25 + 400,000 x 2.00 per Mtok = 0.75 + 0.80
        assert_eq!(haiku.cost(&usage), Microusd::from_usd(1.55));
    }

    /// A 1-hour subset larger than the total is a provider bug; it prices in
    /// the over-charging direction (all of it at the 1-hour rate, nothing
    /// negative), the ADR-8 rule for anything the gateway cannot make sense of.
    #[test]
    fn a_one_hour_subset_past_the_total_never_prices_negative() {
        let haiku = ModelPrice::per_mtok_usd(1.00, 5.00, 0.10, 1.25);
        let usage = Usage {
            cache_write_tokens: 100_000,
            cache_write_1h_tokens: 150_000,
            ..Default::default()
        };
        assert_eq!(haiku.cost(&usage), Microusd::from_usd(0.30));
    }

    /// The 1-hour rate is 1.6x the 5-minute one by default, which is exactly
    /// Anthropic's published ratio (1.25x input against 2x input) for every
    /// model in the book; a book entry may still name its own.
    #[test]
    fn the_one_hour_write_rate_defaults_to_anthropics_ratio_and_can_be_named() {
        let haiku = ModelPrice::per_mtok_usd(1.00, 5.00, 0.10, 1.25);
        assert_eq!(haiku.cache_write_1h_per_mtok, Microusd::from_usd(2.00));
        let sonnet = ModelPrice::per_mtok_usd(3.00, 15.00, 0.30, 3.75);
        assert_eq!(sonnet.cache_write_1h_per_mtok, Microusd::from_usd(6.00));
        let named = haiku.with_cache_write_1h_usd(9.99);
        assert_eq!(named.cache_write_1h_per_mtok, Microusd::from_usd(9.99));
        assert_eq!(named.cache_write_per_mtok, Microusd::from_usd(1.25));
    }

    /// A usage whose only nonzero count is the 1-hour subset still carries
    /// priced tokens (a provider that reported the subset and not the total
    /// would otherwise settle on the estimate as if it had reported nothing).
    #[test]
    fn a_one_hour_only_usage_carries_priced_tokens() {
        let usage = Usage {
            cache_write_1h_tokens: 5,
            ..Default::default()
        };
        assert!(usage.carries_priced_tokens());
    }

    #[test]
    fn cache_is_priced_separately_from_input() {
        let price = sonnet();
        let cached = Usage {
            cache_read_tokens: 1_000_000,
            ..Default::default()
        };
        let fresh = Usage {
            input_tokens: 1_000_000,
            ..Default::default()
        };
        // Cache read must be an order of magnitude cheaper than fresh input.
        assert!(price.cost(&cached) < price.cost(&fresh));
        assert_eq!(price.cost(&cached), Microusd::from_usd(0.30));
    }

    #[test]
    fn large_token_counts_do_not_overflow() {
        let price = ModelPrice::per_mtok_usd(15.0, 75.0, 0.0, 0.0);
        let usage = Usage {
            input_tokens: 5_000_000_000,
            ..Default::default()
        };
        // 5e9 tokens * $15/Mtok = $75,000
        assert_eq!(price.cost(&usage), Microusd::from_usd(75_000.0));
    }

    #[test]
    fn unknown_model_uses_fallback_when_set() {
        let book = PriceBook::new()
            .with("known", sonnet())
            .with_fallback(ModelPrice::per_mtok_usd(15.0, 75.0, 1.5, 18.75));
        assert!(book.is_known("known"));
        assert!(!book.is_known("mystery-model"));
        assert!(book.price("mystery-model").is_some());
    }

    #[test]
    fn unknown_model_without_fallback_is_none() {
        let book = PriceBook::new().with("known", sonnet());
        assert!(book.price("mystery-model").is_none());
    }

    /// I1: `tool_calls` is an observed metric, not a priced dimension - a
    /// response with many tool calls but the same token counts must cost
    /// exactly the same as one with none.
    #[test]
    fn tool_calls_does_not_affect_cost() {
        let price = sonnet();
        let no_tools = Usage {
            input_tokens: 1_000,
            output_tokens: 500,
            tool_calls: Some(0),
            ..Default::default()
        };
        let many_tools = Usage {
            input_tokens: 1_000,
            output_tokens: 500,
            tool_calls: Some(7),
            ..Default::default()
        };
        assert_eq!(price.cost(&no_tools), price.cost(&many_tools));
    }

    #[test]
    fn a_cost_is_never_negative_however_many_tokens_are_claimed() {
        let p = sonnet();
        for tokens in [1e17 as u64, 1e18 as u64, u64::MAX / 2, u64::MAX] {
            let usage = Usage {
                output_tokens: tokens,
                ..Default::default()
            };
            let c = p.cost(&usage);
            assert!(
                c.0 >= 0,
                "output_tokens={tokens} priced at {} micro-usd: a negative cost \
                 passes every budget check there is",
                c.0
            );
        }
    }

    #[test]
    fn an_unpayable_request_saturates_at_the_top_rather_than_wrapping_to_the_bottom() {
        let p = sonnet();
        let huge = Usage {
            output_tokens: u64::MAX,
            ..Default::default()
        };
        let ordinary = Usage {
            output_tokens: 1_000_000,
            ..Default::default()
        };
        assert!(
            p.cost(&huge).0 > p.cost(&ordinary).0,
            "the most expensive request must not be the cheapest"
        );
        assert_eq!(
            p.cost(&huge).0,
            i64::MAX,
            "saturating, not merely non-negative"
        );
    }

    #[test]
    fn every_token_field_saturates_and_the_sum_of_four_maxima_does_not_wrap() {
        let p = sonnet();
        let all = Usage {
            input_tokens: u64::MAX,
            output_tokens: u64::MAX,
            cache_read_tokens: u64::MAX,
            cache_write_tokens: u64::MAX,
            cache_write_1h_tokens: u64::MAX,
            ..Default::default()
        };
        assert_eq!(p.cost(&all).0, i64::MAX);
    }

    #[test]
    fn ordinary_prices_are_exactly_what_they_always_were() {
        // The fix must not move a single real figure. These are the numbers the
        // existing tests in this module already assert, restated here so a future
        // saturating-arithmetic change cannot quietly round them.
        let p = sonnet();
        let u = Usage {
            input_tokens: 1_000_000,
            output_tokens: 1_000_000,
            ..Default::default()
        };
        assert_eq!(p.cost(&u).0, 3_000_000 + 15_000_000);
    }

    /// Every field of `ModelPrice` is `pub`, so a misconfigured negative rate
    /// is constructible on the public surface without going through
    /// `per_mtok_usd`. Without the `clamp(0, ..)` lower bound in `cost`, that
    /// negative rate would produce a negative cost by a second route, the same
    /// failure this fix closes for an overflowing token count.
    #[test]
    fn a_negative_rate_never_produces_a_negative_cost() {
        let p = ModelPrice {
            input_per_mtok: Microusd(-5_000_000),
            output_per_mtok: Microusd(0),
            cache_read_per_mtok: Microusd(0),
            cache_write_per_mtok: Microusd(0),
            cache_write_1h_per_mtok: Microusd(0),
        };
        let usage = Usage {
            input_tokens: 1_000_000,
            ..Default::default()
        };
        assert_eq!(
            p.cost(&usage).0,
            0,
            "a negative rate must clamp to zero, not produce a negative cost"
        );
    }

    // -- invariant 67: the sum rounds once, toward over-charging ------------
    //
    // Defect measured 2026-09-27 on a live cluster: a real `gpt-4o-mini` call,
    // prompt_tokens 13, completion_tokens 2, was answered
    // `x-fuse-cost-usd: 0.000002` (2 micro-USD). The price book prices
    // gpt-4o-mini at $0.15/$0.60 per Mtok, so the exact cost is
    // 13 x 0.15 + 2 x 0.60 = 1.95 + 1.20 = 3.15 micro-USD, which any honest
    // rounding rule must not answer with less than 4. `ModelPrice::cost`
    // floored each of up to five parts separately before summing them, so a
    // call could lose up to just under one micro-USD per part - the safe
    // direction is named in this function's own doc as over-charging, and
    // flooring is the opposite of that, systematically.

    /// The exact case from the live measurement. Red against the unfixed
    /// per-part-floor code, which prices this call at 2 micro-USD
    /// (floor(1.95) + floor(1.20) = 1 + 1): `left: 4 right: 2`.
    #[test]
    fn the_measured_gpt_4o_mini_call_ceils_to_four_micro_usd_not_two() {
        let gpt_4o_mini = ModelPrice::per_mtok_usd(0.15, 0.60, 0.075, 0.15);
        let usage = Usage {
            input_tokens: 13,
            output_tokens: 2,
            ..Default::default()
        };
        // 13 x 150,000 + 2 x 600,000 = 1,950,000 + 1,200,000 = 3,150,000
        // (micro-USD, still x1e6): 3.15 micro-USD, which must ceil to 4, not
        // floor (or floor-per-part) to 2 or 3.
        assert_eq!(
            gpt_4o_mini.cost(&usage).0,
            4,
            "13 in / 2 out on gpt-4o-mini: 3.15 micro-USD must round up to 4"
        );
    }

    /// A guard, in the sense invariant 66 already uses the word: a call whose
    /// every part divides `1_000_000` exactly has nothing to round, and a
    /// wrong rounding rule that only ever adds could still pass this one by
    /// accident. It holds under the unfixed code too (both are floors of an
    /// already-whole number), and it stays here so a later change cannot
    /// start rounding a call that never needed it without this catching it.
    #[test]
    fn a_call_whose_every_part_divides_exactly_rounds_nothing() {
        let price = ModelPrice::per_mtok_usd(3.0, 15.0, 0.30, 3.75);
        let usage = Usage {
            input_tokens: 2_000_000,
            output_tokens: 1_000_000,
            cache_read_tokens: 500_000,
            cache_write_tokens: 400_000,
            ..Default::default()
        };
        // 2,000,000 x 3.00 + 1,000,000 x 15.00 + 500,000 x 0.30 + 400,000 x 3.75
        //   = 6.00 + 15.00 + 0.15 + 1.50 = 22.65 USD, exactly, per part and
        // as a sum: nothing here has a fractional micro-USD to round away.
        assert_eq!(price.cost(&usage), Microusd::from_usd(22.65));
    }

    /// Two parts that are each fractional on their own can still sum to a
    /// whole micro-USD, and rounding must happen on the SUM, once, or this
    /// case is priced wrong in both directions: ceiling each part before
    /// summing over-charges (a mutant this test is designed to catch), and
    /// the original per-part floor under-charges. Each part here is exactly
    /// half a micro-USD (500,000 of the 1,000,000 a Mtok-price is scaled by),
    /// so flooring each part alone (the original defect) prices the call at
    /// 0, ceiling each part alone (a plausible wrong fix) prices it at 2, and
    /// rounding the 1,000,000 (one whole micro-USD) sum once is the only rule
    /// that lands on the true answer, 1.
    #[test]
    fn two_inexact_parts_that_sum_to_a_whole_micro_usd_round_only_once() {
        let price = ModelPrice {
            input_per_mtok: Microusd(500_000),
            output_per_mtok: Microusd(500_000),
            cache_read_per_mtok: Microusd(0),
            cache_write_per_mtok: Microusd(0),
            cache_write_1h_per_mtok: Microusd(0),
        };
        let usage = Usage {
            input_tokens: 1,
            output_tokens: 1,
            ..Default::default()
        };
        // input: 1 x 500,000 = 500,000 (0.5 micro-USD alone); output the same.
        // Summed raw: 1,000,000, which is exactly 1 micro-USD - a whole
        // number that per-part rounding, in either direction, cannot see.
        assert_eq!(
            price.cost(&usage).0,
            1,
            "two half-micro-USD parts sum to exactly one whole micro-USD; \
             rounding must happen on the sum, not on each part"
        );
    }

    /// Every one of the five priced parts contributes a distinct, mutually
    /// prime-ish amount, so dropping any single one from the sum changes the
    /// total - the mutant this test exists to catch (`saturating_add` of one
    /// term quietly deleted, or one term's price zeroed by a copy/paste slip).
    #[test]
    fn every_one_of_the_five_priced_parts_is_summed() {
        let price = ModelPrice::per_mtok_usd(3.0, 15.0, 0.30, 3.75);
        let full = Usage {
            input_tokens: 17,
            output_tokens: 29,
            cache_read_tokens: 41,
            cache_write_tokens: 53,
            cache_write_1h_tokens: 11,
            ..Default::default()
        };
        let total = price.cost(&full).0;
        for (name, tweaked) in [
            (
                "input",
                Usage {
                    input_tokens: 0,
                    ..full
                },
            ),
            (
                "output",
                Usage {
                    output_tokens: 0,
                    ..full
                },
            ),
            (
                "cache_read",
                Usage {
                    cache_read_tokens: 0,
                    ..full
                },
            ),
            (
                "cache_write (five-minute remainder)",
                Usage {
                    cache_write_tokens: full.cache_write_1h_tokens,
                    ..full
                },
            ),
            (
                "cache_write_1h",
                Usage {
                    cache_write_1h_tokens: 0,
                    ..full
                },
            ),
        ] {
            let dropped = price.cost(&tweaked).0;
            assert_ne!(
                dropped, total,
                "zeroing the {name} part must change the total; it did not, \
                 so that part is not reaching the sum"
            );
        }
    }

    /// A large but non-saturating case, chosen so every one of the five raw
    /// numerators (`tokens * price`, before dividing by `1_000_000`) is
    /// itself in the tens of trillions: summing five such numerators in
    /// `i128` before dividing is nowhere near overflowing `i128` (whose
    /// range is roughly 1.7e38), but it is a wider intermediate than the old
    /// code ever built (which divided each part down to at most `i64::MAX`
    /// before summing four already-small `i64`s). This pins that the wider
    /// intermediate still lands on the exact figure a `u128` reference
    /// computation gives, with no overflow, no panic, and no saturation
    /// clipping a number nowhere near the ceiling.
    #[test]
    fn a_large_multi_part_case_sums_exactly_with_no_overflow() {
        let price = ModelPrice::per_mtok_usd(3.0, 15.0, 0.30, 3.75);
        let usage = Usage {
            input_tokens: 10_000_000_000,
            output_tokens: 20_000_000_000,
            cache_read_tokens: 30_000_000_000,
            cache_write_tokens: 40_000_000_000,
            cache_write_1h_tokens: 15_000_000_000,
            ..Default::default()
        };
        // Reference computed independently in u128, not by re-deriving the
        // production formula: each token count times its Mtok price, summed,
        // divided by 1_000_000 with a manual ceiling.
        let five_minute = usage.cache_write_tokens - usage.cache_write_1h_tokens;
        let numerator: u128 = u128::from(usage.input_tokens) * 3_000_000
            + u128::from(usage.output_tokens) * 15_000_000
            + u128::from(usage.cache_read_tokens) * 300_000
            + u128::from(five_minute) * 3_750_000
            + u128::from(usage.cache_write_1h_tokens) * 6_000_000;
        let (q, r) = (numerator / 1_000_000, numerator % 1_000_000);
        let expected = if r > 0 { q + 1 } else { q };
        assert!(
            expected < i64::MAX as u128,
            "test setup error: this case is meant to be large but non-saturating"
        );
        assert_eq!(price.cost(&usage).0 as u128, expected);
    }
}
