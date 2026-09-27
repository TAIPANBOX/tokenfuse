Feature: A call's cost is rounded once, on the sum, and only toward over-charging

  Measured 2026-09-27 on a live cluster: a real `gpt-4o-mini` call with
  `prompt_tokens 13`, `completion_tokens 2` was answered
  `x-fuse-cost-usd: 0.000002` (2 micro-USD). The price book prices
  gpt-4o-mini at $0.15/$0.60 per Mtok, so the exact cost is
  13 x 0.15 + 2 x 0.60 = 3.15 micro-USD. `ModelPrice::cost`
  (`crates/core/src/pricing.rs`) divided each of up to five priced parts
  (input, output, cache read, cache write, cache write 1h) by 1,000,000
  separately, flooring each one on its own before summing them, so every
  call lost up to just under one micro-USD per part - systematically, in
  the under-charging direction. This function's own doc already names
  over-charging as the safe direction, because under-charging a call is
  what lets it pass a budget check that a correct price would have refused.

  @decided 2026-09-27: every priced part's raw numerator (`tokens x price`,
  not yet divided) is summed first, in full, and the division by 1,000,000
  happens once, on that sum; a positive remainder rounds the whole sum up
  by one micro-USD. The saturating and clamping behaviour for absurd token
  counts (overflow, a misconfigured negative rate) is unchanged.

  @claude - what this does NOT do: it does not change the estimate margin
  in `estimate.rs`, which already ceils its own multiplication and is
  unaffected wherever its input (the raw cost) was already a whole
  micro-USD; and it does not change any caller that reads an already-
  settled `cost_microusd` off a `CallRecord` (savings, outcomes,
  focus-export, Cloud aggregation), since those read a number this
  function already produced rather than re-deriving it.

  # @test:the_measured_gpt_4o_mini_call_ceils_to_four_micro_usd_not_two
  Scenario: The measured call is priced at four micro-USD, not two
    Given gpt-4o-mini priced at $0.15 input and $0.60 output per Mtok
    And a call reporting 13 input tokens and 2 completion tokens
    When the cost is computed
    Then the exact cost is 3.15 micro-USD
    And the returned cost is 4 micro-USD, the ceiling, not 2 or 3

  # @test:a_call_whose_every_part_divides_exactly_rounds_nothing
  Scenario: A call whose every part is already a whole number of micro-USD is untouched
    Given token counts and prices chosen so every one of the five parts divides 1,000,000 exactly
    When the cost is computed
    Then the total equals the sum of the exact parts, with nothing rounded away or added

  # @test:two_inexact_parts_that_sum_to_a_whole_micro_usd_round_only_once
  Scenario: Two fractional parts that sum to a whole micro-USD are not rounded twice
    Given two parts each worth exactly half a micro-USD on their own
    When the cost is computed
    Then the total is the one whole micro-USD their sum makes, not zero from flooring each part apart and not two from ceiling each part apart

  # @test:every_one_of_the_five_priced_parts_is_summed
  Scenario: Every one of the five priced parts reaches the total
    Given a usage record with a distinct, nonzero count in each of the five priced parts
    When any single part is zeroed out and the cost recomputed
    Then the total changes, proving that part was reaching the sum

  # @test:a_large_multi_part_case_sums_exactly_with_no_overflow
  Scenario: A large multi-part call sums exactly, with no overflow
    Given token counts in the tens of billions across all five priced parts
    When the cost is computed
    Then the result matches an independent u128 reference calculation exactly, with no panic and no saturation clipping a number nowhere near the ceiling

  # @test:a_negative_rate_never_produces_a_negative_cost
  Scenario: A misconfigured negative rate still clamps to zero, not a negative cost
    Given a price with a negative per-Mtok rate, constructible on ModelPrice's public fields
    When the cost is computed
    Then the result is zero, never negative

  # @test:an_unpayable_request_saturates_at_the_top_rather_than_wrapping_to_the_bottom
  # @test:every_token_field_saturates_and_the_sum_of_four_maxima_does_not_wrap
  Scenario: An absurd token count still saturates at the ceiling, never wraps
    Given a usage record with u64::MAX in one or every priced field
    When the cost is computed
    Then the result saturates at i64::MAX, exactly as it did before this fix, never a negative or a wrapped-small figure
