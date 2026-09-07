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
    pub cache_write_tokens: u64,
    /// Number of tool calls the model emitted in this response (I1, an
    /// observed metric only - see docs/21-tool-runs.md). `None` only when the
    /// response body never parsed as JSON at all; a successfully parsed body
    /// with no tool calls is `Some(0)`, never a guess. Deliberately NOT read
    /// by [`ModelPrice::cost`]: this rides alongside the priced token counts
    /// but is not itself priced.
    pub tool_calls: Option<u32>,
}

/// Per-model price, in microdollars per million tokens.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct ModelPrice {
    pub input_per_mtok: Microusd,
    pub output_per_mtok: Microusd,
    pub cache_read_per_mtok: Microusd,
    pub cache_write_per_mtok: Microusd,
}

impl ModelPrice {
    /// Build a price from USD-per-Mtok figures (the units providers publish).
    pub fn per_mtok_usd(input: f64, output: f64, cache_read: f64, cache_write: f64) -> Self {
        ModelPrice {
            input_per_mtok: Microusd::from_usd(input),
            output_per_mtok: Microusd::from_usd(output),
            cache_read_per_mtok: Microusd::from_usd(cache_read),
            cache_write_per_mtok: Microusd::from_usd(cache_write),
        }
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
    pub fn cost(&self, usage: &Usage) -> Microusd {
        let part = |tokens: u64, price: Microusd| -> i64 {
            let micros = (tokens as i128).saturating_mul(price.0 as i128) / 1_000_000;
            micros.clamp(0, i64::MAX as i128) as i64
        };
        Microusd(
            part(usage.input_tokens, self.input_per_mtok)
                .saturating_add(part(usage.output_tokens, self.output_per_mtok))
                .saturating_add(part(usage.cache_read_tokens, self.cache_read_per_mtok))
                .saturating_add(part(usage.cache_write_tokens, self.cache_write_per_mtok)),
        )
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
}
