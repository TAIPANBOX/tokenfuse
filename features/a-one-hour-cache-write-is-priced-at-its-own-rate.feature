Feature: A one-hour cache write is priced at the one-hour rate

  Anthropic bills a 5-minute cache write at 1.25x input and a 1-hour cache
  write at 2x input, and the usage object says which under cache_creation
  (ephemeral_5m_input_tokens, ephemeral_1h_input_tokens) beside the total
  cache_creation_input_tokens. The gateway read the total and priced all of
  it at the 5-minute rate. INT-2 of the 1.0 proving run (2026-09-13, Claude
  Code through the v0.5.0 gateway on claude-haiku-4-5): one call with 10
  input, 192 output and 140,373 cache-creation tokens, all 1-hour, was
  metered at 0.176436 USD against Claude Code's own 0.281716, 37 percent
  short; ADR-8 says the book never under-charges a run it cannot identify
  (tokenfuse#282).

  @decided 2026-09-14: keep the total for the trace, carry the 1-hour subset
  beside it, price the subset at a 1-hour rate the book derives as 1.6x the
  5-minute one (Anthropic's exact ratio, every model) and publishes as its
  own column; the OpenAI entries keep one write rate, since no OpenAI usage
  reports a 1-hour subset and the published book must not show a rate no
  provider charges.

  # @test:a_one_hour_cache_write_is_priced_at_the_one_hour_rate
  Scenario: The INT-2 call, to the microdollar
    Given claude-haiku-4-5 at 1.00 input, 5.00 output, 0.10 cache read and 1.25 cache write USD per Mtok
    And a usage of 10 input, 192 output and 140,373 cache-creation tokens, every one on the 1-hour TTL
    When the gateway prices the usage
    Then it settles 281,716 micro-USD, what Claude Code itself computed
    And the same usage with no 1-hour subset settles 176,436, the old figure

  # @test:a_mixed_cache_write_prices_each_ttl_once
  Scenario: A write split across both TTLs prices each part once
    Given a usage of 1,000,000 cache-creation tokens of which 400,000 are on the 1-hour TTL
    When the gateway prices the usage on haiku
    Then it settles 1.55 USD: 600,000 at 1.25 plus 400,000 at 2.00 per Mtok

  # @test:a_one_hour_subset_past_the_total_never_prices_negative
  Scenario: A subset past the total is a provider bug and prices in the over-charging direction
    Given a usage of 100,000 cache-creation tokens and a 1-hour subset of 150,000
    When the gateway prices the usage on haiku
    Then it settles 0.30 USD, the subset at the 1-hour rate and nothing negative

  # @test:the_one_hour_write_rate_defaults_to_anthropics_ratio_and_can_be_named
  Scenario: The 1-hour rate is derived as Anthropic's ratio and a book entry may name its own
    Given a price built from Anthropic's four published rates
    Then its 1-hour write rate is 1.6x the 5-minute one, 2.00 on haiku and 6.00 on sonnet
    And a book entry can name a different 1-hour rate outright

  # @test:parses_the_one_hour_cache_write_subset_from_a_message_start
  Scenario: The parser keeps the total and the 1-hour subset
    Given a message_start whose usage says cache_creation_input_tokens 140,373 with ephemeral_1h_input_tokens 140,373
    When the gateway parses the stream
    Then the usage holds 140,373 cache-write tokens and a 1-hour subset of 140,373

  # @test:a_cache_write_without_a_ttl_breakdown_is_all_five_minute
  Scenario: A usage without the breakdown is a 5-minute write in full
    Given a usage with cache_creation_input_tokens 500 and no cache_creation object
    When the gateway parses it
    Then the 1-hour subset is 0 and the write is priced as before

  # @test:a_one_hour_only_usage_carries_priced_tokens
  Scenario: A usage whose only nonzero count is the 1-hour subset still carries priced tokens
    Given a usage with a 1-hour subset and every other count zero
    Then the gateway treats it as parsed usage, never as a body with no usage
