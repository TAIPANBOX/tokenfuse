//! Pre-flight cost estimation (ADR-6).
//!
//! Before forwarding, we need a cost estimate to reserve against the budget. We
//! don't have the provider's tokenizer, so we approximate — cheaply and
//! *conservatively* (a built-in margin), because under-estimating is what lets a
//! runaway slip through. The real cost is reconciled on settle, so the estimate
//! only needs to be a safe upper-ish bound, not exact.

use tokenfuse_core::{Microusd, PriceBook, Usage};

/// Conservative margin applied to the raw estimate (ADR-6: +15%).
const MARGIN: f64 = 1.15;

/// Rough characters-per-token ratio for English-ish text.
const CHARS_PER_TOKEN: u64 = 4;

/// Default assumed output tokens when the request does not cap `max_tokens`.
const DEFAULT_MAX_TOKENS: u64 = 1_024;

/// Estimate the cost of a call from the request body length, the caller's
/// output cap, and how many completions are being asked for.
///
/// `completions` is 1 on the Anthropic wire, which has no such parameter. On
/// OpenAI it is `n`, and every one of those completions is generated and
/// billed, so the output half of the estimate multiplies. A count of zero is
/// read as one: no wire asks for nothing, and treating it as free is how a run
/// that should have been refused gets served.
pub fn estimate_cost(
    prices: &PriceBook,
    model: &str,
    body_len: usize,
    max_tokens: Option<u64>,
    completions: u64,
) -> Option<Microusd> {
    let input_tokens = (body_len as u64) / CHARS_PER_TOKEN;
    let output_tokens = max_tokens
        .unwrap_or(DEFAULT_MAX_TOKENS)
        .saturating_mul(completions.max(1));

    let usage = Usage {
        input_tokens,
        output_tokens,
        ..Default::default()
    };

    prices.cost(model, &usage).map(|raw| {
        // Apply the conservative margin.
        Microusd((raw.0 as f64 * MARGIN).ceil() as i64)
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokenfuse_core::ModelPrice;

    fn book() -> PriceBook {
        PriceBook::new().with("m", ModelPrice::per_mtok_usd(3.0, 15.0, 0.0, 0.0))
    }

    #[test]
    fn estimate_includes_the_conservative_margin() {
        // 4000 bytes -> 1000 input tokens; max_tokens 1000 output.
        // raw = 1000/1e6*3 + 1000/1e6*15 = 0.003 + 0.015 = 0.018 USD
        // with +15% margin -> 0.0207 USD
        let est = estimate_cost(&book(), "m", 4000, Some(1000), 1).unwrap();
        assert_eq!(est, Microusd::from_usd(0.0207));
    }

    #[test]
    fn unknown_model_yields_no_estimate() {
        assert!(estimate_cost(&book(), "unknown", 4000, Some(100), 1).is_none());
    }

    /// `raw.0` can now reach `i64::MAX` (the pricing fix saturates there
    /// rather than wrapping negative), and this margin step multiplies that by
    /// 1.15 in `f64` before casting back to `i64`. Rust's float-to-int `as`
    /// saturates rather than wraps, but that is not taken on faith here: the
    /// number it actually produces is asserted, not merely "is positive".
    #[test]
    fn a_maximal_output_cap_estimates_a_large_positive_number_not_a_wrapped_negative() {
        let est = estimate_cost(&book(), "m", 0, Some(u64::MAX), 1).unwrap();
        assert!(
            est.0 > 0,
            "the estimate for the most expensive request must not be negative, got {}",
            est.0
        );
        assert_eq!(
            est.0,
            i64::MAX,
            "raw.0 saturates at i64::MAX in ModelPrice::cost, and i64::MAX as f64 * 1.15, \
             ceil()'d, cast back to i64, saturates at i64::MAX again: the margin step must not \
             be where the saturation quietly breaks"
        );
    }

    #[test]
    fn missing_max_tokens_falls_back_to_default() {
        let est = estimate_cost(&book(), "m", 0, None, 1).unwrap();
        assert!(est > Microusd::ZERO);
    }

    #[test]
    fn four_completions_cost_four_times_the_output_of_one() {
        let prices = crate::pricebook::default_price_book();
        let one = estimate_cost(&prices, "gpt-4o", 400, Some(1000), 1).unwrap();
        let four = estimate_cost(&prices, "gpt-4o", 400, Some(1000), 4).unwrap();
        // Input is charged once; only the output side multiplies, so four
        // completions cost strictly more than one and strictly less than four
        // whole calls.
        assert!(four.0 > one.0, "four completions must cost more than one");
        assert!(
            four.0 < one.0 * 4,
            "the input half is billed once, not four times"
        );
    }

    #[test]
    fn a_completion_count_of_zero_is_treated_as_one_rather_than_as_free() {
        let prices = crate::pricebook::default_price_book();
        let zero = estimate_cost(&prices, "gpt-4o", 400, Some(1000), 0).unwrap();
        let one = estimate_cost(&prices, "gpt-4o", 400, Some(1000), 1).unwrap();
        assert_eq!(zero, one);
    }

    #[test]
    fn an_absurd_completion_count_saturates_instead_of_wrapping_to_something_cheap() {
        let prices = crate::pricebook::default_price_book();
        let huge = estimate_cost(&prices, "gpt-4o", 400, Some(u64::MAX), u64::MAX).unwrap();
        let one = estimate_cost(&prices, "gpt-4o", 400, Some(1000), 1).unwrap();
        assert!(
            huge.0 > one.0,
            "a wrapped multiplication would make the most expensive request the cheapest"
        );
    }
}
