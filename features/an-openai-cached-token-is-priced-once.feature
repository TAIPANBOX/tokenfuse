Feature: An OpenAI cached token is priced once, never twice

  OpenAI's usage shape puts the cached subset INSIDE prompt_tokens
  (prompt_tokens_details.cached_tokens); Anthropic's puts it beside
  input_tokens. The gateway's Usage keeps Anthropic's disjoint shape, which
  is what ModelPrice::cost prices, and until 2026-09-14 the OpenAI parser
  copied prompt_tokens whole and cached_tokens on top: every cached token was
  priced at the full input rate and again at the cache-read rate, +14.5 % on
  a 950/128 call and more with a higher hit ratio, landing in the run's
  budget as spend nobody was billed (tokenfuse#267, found by a reader of the
  code on 2026-09-09).

  @decided 2026-09-14: close it in the OpenAI parser, netting the cached
  subset out of the prompt count, so both vendors reach the one shape the
  price book already assumes; a cached count past the prompt count nets to
  zero rather than wrapping.

  # @test:parses_openai_sse_usage
  Scenario: A streamed OpenAI usage chunk lands in the disjoint shape
    Given an OpenAI-door stream whose usage chunk says prompt_tokens 950, completion_tokens 120 and cached_tokens 128
    When the gateway parses the stream
    Then the usage holds 822 input tokens, 128 cache-read tokens and 120 output tokens

  # @test:an_openai_cached_token_is_priced_once_not_twice
  Scenario: The settled figure is what the provider bills
    Given gpt-4o at the book's rates, 2.50 input and 1.25 cached USD per Mtok
    And a call reporting prompt_tokens 950 with cached_tokens 128
    When the gateway prices the usage
    Then it settles 2215 micro-USD, 822 at the input rate plus 128 at the cache-read rate
    And not 2535, the cached 128 priced at both rates

  # @test:an_openai_cached_count_past_the_prompt_count_nets_to_zero_not_wraps
  Scenario: A cached count past the prompt count is a provider bug, not a negative input
    Given a usage reporting prompt_tokens 100 and cached_tokens 150
    When the gateway parses it
    Then input tokens are 0, cache-read tokens 150, and nothing wraps

  # @test:an_openai_usage_without_cached_tokens_is_unchanged
  Scenario: A provider that reports no cached subset is priced as before
    Given a usage with prompt_tokens 950 and completion_tokens 120 and no prompt_tokens_details
    When the gateway parses it
    Then input tokens are 950 and cache-read tokens 0

  # @test:a_later_chunk_without_the_cached_subset_still_nets_it
  Scenario: The cached subset seen on one chunk still nets a later bare prompt count
    Given a stream whose first usage chunk says prompt_tokens 950 with cached_tokens 128
    And whose later usage chunk says prompt_tokens 950 and completion_tokens 120 with no details
    When the gateway parses the stream
    Then the usage holds 822 input tokens and 128 cache-read tokens, not 950 and 128

  @fable 2026-09-18, F05 of the money-path review: the netting ran only when
  the current chunk carried prompt_tokens, and a chunk carrying only the cache
  details was read as Anthropic's shape and ignored, so the double charge came
  back in the other order. The prompt count and the cached subset are now kept
  apart across events and the input is always the one less the other.

  # @test:codex_f05_inv45_cached_details_in_a_later_chunk_are_netted_once
  # @test:a_cached_subset_arriving_after_the_prompt_count_is_netted
  Scenario: A cached subset arriving after the prompt count is netted once
    Given a stream whose first usage chunk says prompt_tokens 950
    And whose later chunk says completion_tokens 0 with cached_tokens 128
    When the gateway prices the usage on gpt-4o
    Then it settles 2215 micro-USD, not 2535

  # @test:codex_f05_inv45_details_only_chunk_is_not_discarded
  # @test:a_details_only_object_is_openai_shaped_not_anthropic
  Scenario: A chunk carrying only the cache details is not discarded at shape detection
    Given a stream whose first usage chunk says prompt_tokens 950
    And whose later chunk carries only prompt_tokens_details with cached_tokens 128
    When the gateway prices the usage on gpt-4o
    Then it settles 2215 micro-USD, not 2375

  # @test:the_netting_holds_across_three_events_whatever_the_final_event_carries
  # @test:a_details_only_event_before_any_prompt_count_waits_for_the_prompt
  # @test:a_later_zero_completion_count_keeps_the_earlier_positive_one
  Scenario: The netting holds in every order the two figures can arrive in
    Given the prompt count and the cached subset on separate chunks, in either order, with or without a final complete usage object
    And a later chunk whose completion count is zero
    When the gateway parses the stream
    Then the usage holds 822 input tokens and 128 cache-read tokens, and an earlier positive output count is kept

  # @test:a_body_mixing_both_vendors_shapes_is_read_per_object
  Scenario: A body mixing both vendors' shapes is read object by object
    Given a body carrying Anthropic's message_start, OpenAI's prompt count and cache details on separate chunks, an Anthropic output delta and a total_tokens object
    When the gateway parses it
    Then each object is read by its own fields, the netting holds, and total_tokens prices nothing
