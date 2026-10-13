Feature: The price book holds the vendors' current prices, and a long prompt is priced at its long rate

  The ask, 2026-10-13: bring the built-in price book to the prices the
  vendors list today, and price a vendor's prompt-length tier for real. The
  book held one rate per model, so a model sold at two rates by prompt length
  could only be priced safely at the dearer one, which over-charged every
  short call. Claude Haiku 5.5 had no row at all and settled at the 15 / 75
  fallback, about 150 times its price; Claude Sonnet 5.5's cache hits were
  priced at 0.20 where Anthropic lists 0.10; and a GPT-5.6 cache write was
  priced as plain input, 20 percent under what OpenAI bills.

  The rule: a model may carry one long-prompt rate above a threshold. A call
  whose prompt (input, cache reads and cache writes together) is above the
  threshold is priced whole, output included, at the long rate; at or below
  it, at the base rate.

  # @test:every_vendor_listed_id_prices_at_its_list_rate
  # @test:every_new_vendor_id_prices_at_its_list_rate_never_the_fallback
  # @test:every_long_prompt_tier_is_the_vendors_written_out_by_hand
  Scenario: Every id the vendors list today has a row at the vendor's rate
    Given the ids Anthropic, OpenAI, Google, DeepSeek, Moonshot and Z.ai list on 2026-10-13
    When the gateway prices a call to any of them
    Then it uses that id's own row, written out by hand from the vendor's page
    And an id with a prompt-length tier carries that tier, also written out by hand

  # @test:a_haiku_5_5_short_call_is_priced_at_its_base_rate
  # @test:a_haiku_5_5_long_call_is_priced_at_its_long_rate
  Scenario: Claude Haiku 5.5 is priced at its own rate, not the fallback
    Given a claude-haiku-5-5 call of 1000 input and 500 output tokens
    When the shipped book prices it
    Then it costs 350 micro-USD, not the 52500 the fallback charged
    And a call of 150000 input and 1000 output tokens costs 77500, every token at the long rate

  # @test:sonnet_5_5_cache_hits_are_five_percent_of_input
  Scenario: Claude Sonnet 5.5's cache hits are priced at its own rate
    Given Anthropic prices cache hits on Sonnet 5.5 at 0.05 times input
    When the book prices a Sonnet 5.5 cache read
    Then it is 0.10 USD per million tokens, not the 0.20 Sonnet 5 pays

  # @test:a_prompt_at_the_threshold_is_base_and_one_token_over_is_long
  # @test:cache_reads_and_writes_count_toward_the_prompt
  # @test:the_long_rate_prices_every_part_including_output
  # @test:an_unknown_model_has_no_tier
  Scenario: The threshold is read on the whole prompt and prices the whole call
    Given a model whose long rate starts above 100000 prompt tokens
    When a call's prompt is exactly 100000 tokens
    Then it is priced at the base rate
    And one token more is priced at the long rate, output included
    And cache reads and cache writes count toward the prompt
    And a model with no row has no tier and prices at the fallback

  # @test:a_gpt_6_1_sol_long_call_is_priced_at_its_long_rate
  # @test:a_long_prompt_on_a_tiered_id_settles_at_its_long_rate_through_the_gateway
  Scenario: A long OpenAI call settles at its long rate through the gateway
    Given a gpt-6.1-sol call of 300000 input and 1000 output tokens
    When the gateway forwards it and the provider answers with that usage
    Then the run is charged 1215000 micro-USD, the long rate, not the fallback

  # @test:gemini_2_5_pro_is_priced_by_its_prompt_length
  Scenario: Gemini 2.5 Pro's short calls are priced at the short rate
    Given Gemini 2.5 Pro is listed at 1.25 / 10.00 up to 200K and 2.50 / 15.00 above
    When the book prices a short call and a long one
    Then the short call pays 1.25 / 10.00 and the long one 2.50 / 15.00

  # @test:an_openai_cache_write_is_priced_as_a_write
  # @test:a_streamed_openai_cache_write_is_priced_as_a_write
  # @test:an_openai_usage_without_cache_write_tokens_is_unchanged
  # @test:cached_plus_written_past_the_prompt_floors_input_at_zero_and_keeps_both
  Scenario: A GPT-5.6 cache write is priced as a write
    Given an OpenAI usage whose prompt includes cached tokens and cache-write tokens
    When the gateway reads it, buffered or streamed
    Then the write is priced at the write rate and only the rest of the prompt as input
    And a usage that reports no cache writes is read exactly as before
    And a usage whose cached and written tokens exceed the prompt keeps both and charges no input

  # @test:an_operator_row_replaces_the_base_rate_and_drops_the_tier
  # @test:the_price_book_route_lists_the_tiers_and_an_operator_row_drops_one
  Scenario: An operator's row is the whole price for its id
    Given an operator file with a row for an id that has a built-in long tier
    When the gateway applies it
    Then that id is priced at the operator's row at every prompt length
    And the startup line and the price-book route say the tier was dropped

  # @test:the_fallback_is_at_least_every_row_in_every_column
  Scenario: No row or tier exceeds the fallback except the named ones
    Given the fallback that prices a model nobody listed
    When every row and every long tier is compared with it
    Then only o1's cache read and gpt-6-astra's long input, cache read and cache write exceed it
