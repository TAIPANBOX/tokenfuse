Feature: A caller is bounded per key on the LLM doors
  An operator can bound each caller's rate and calls in flight, and a call over
  either is refused 429 before anything is reserved.

  # @test:a_key_over_its_rate_is_refused_429_and_another_key_is_not
  Scenario: A key over its rate is refused and another key is not
    Given a limit of one call a second with a burst of one
    When one key calls twice within the second and another key calls once
    Then the key's second call is refused 429 with Retry-After and the other key is admitted

  # @test:a_call_counts_against_concurrency_until_its_body_has_gone_out
  Scenario: A streamed call is in flight until its body has gone out
    Given a limit of one call in flight
    When a key's streamed answer is still streaming and the key calls again
    Then the second call is refused, and once the first body is read the key is admitted again

  # @test:with_no_limits_set_nothing_is_refused
  Scenario: Nothing set, nothing limited
    Given no limit set
    When one key calls twenty times
    Then every call is admitted

  # @test:the_bucket_holds_the_burst_and_refills_at_the_rate
  Scenario: The bucket refills at the rate
    Given a rate of two a second and a burst of three
    When three calls arrive at once and a fourth half a second later
    Then the fourth is admitted and a fifth at that moment is refused

  # @test:unusable_values_refuse_to_start_naming_the_variable
  Scenario: A value that cannot be read stops the gateway
    Given a rate of zero, a burst with no rate, or a fractional concurrency
    When the values are read
    Then each is refused naming its variable
