Feature: A per-key refusal and a fallback price are on the bus

  agent-passport SPEC 6.2 registers rate_limited (medium) and price_fallback
  (low) under tokenfuse. A 429 for a caller over its own limit, and a call
  priced at the fallback because the model has no price-book row, each go on
  the bus without flooding it.

  @decided 2026-11-23: both types, their bands and their data, as SPEC 6.2
  registers them. Invariant 148.

  # @test:a_caller_over_its_rate_is_one_rate_limited_event_a_minute
  Scenario: A caller over its rate is one rate_limited event a minute
    Given a key allowed one call a second
    When the caller calls four times inside one second, naming another agent each time
    Then three calls are refused 429
    And one rate_limited at medium names the key id, the limit rps and its value
    And it is filed under no agent, since a static key proves none, with the named agent only as its principal
    And the key's value is nowhere on the line

  # @test:refusals_inside_the_minute_are_counted_and_reported_after_it
  Scenario: Refusals inside the minute are counted and reported after it
    Given a source that was reported a moment ago
    When it is refused twice more inside the minute and once after it
    Then the refusal after the minute is reported with two not written since

  # @test:a_model_with_no_price_row_is_one_price_fallback_per_model
  Scenario: A model with no price-book row is one price_fallback per model
    Given two models the price book has no row for
    When an agent calls the first model twice and the second once
    Then two price_fallback events at low name each model, the door and the fallback rates

  # @test:a_model_the_book_prices_writes_no_price_fallback
  Scenario: A model the price book prices writes nothing
    When an agent calls a model the price book has a row for
    Then no price_fallback is written

  # @test:a_call_naming_no_agent_is_counted_and_the_model_stays_unreported
  Scenario: A call that names no agent is counted and its model stays unreported
    When a call with no agent uses a model with no price-book row
    Then no price_fallback is written and the price-book route counts one unreported
    And the next call naming an agent on that model writes the event

  # @test:price_fallback_events_are_capped_per_minute_for_the_whole_gateway
  Scenario: Fallback events are capped per minute for the whole gateway
    Given a gateway that has written its cap of price_fallback events this minute
    When a call uses another model with no price-book row
    Then no event is written and that model stays unreported
    And the next minute writes it
