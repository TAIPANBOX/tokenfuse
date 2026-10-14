Feature: A gateway admits nothing a budget governs until it has read its control plane

  Measured 2026-10-14 on forge: after a Docker restart the gateway started 60 ms
  before its control plane, could not read run spend or the unit month, and then
  admitted a call for a unit over its monthly cap and a call on a run past its
  budget.

  @decided 2026-10-14: a budgeted run or a capped unit is never admitted on state
  that was not seeded; the gateway keeps asking the control plane until it
  answers, and says on the bus when the seed is missing. Invariant 103.

  # @test:a_gateway_that_starts_before_its_control_plane_admits_nothing_a_budget_governs
  Scenario: A control plane that is not up yet makes a budgeted call wait
    Given a gateway in enforce whose control plane is not listening when it starts
    And the control plane knows a run past its budget and a unit past its month's cap
    When an agent calls on that run, or as that unit
    Then the gateway answers 503 seed_pending, retryable, with retry-after
    And one dependency_failed per run names the control plane and the seed

  # @test:a_gateway_that_starts_before_its_control_plane_admits_nothing_a_budget_governs
  Scenario: The seed lands when the control plane comes up, and the money it knows is enforced
    Given the same gateway, still asking
    When the control plane starts listening on the address the gateway was given
    Then the run past its budget is refused 402 budget_exceeded
    And the unit past its cap is refused 402 unit_budget_exceeded
    And a run the control plane killed is refused 402 killed
    And a run the control plane knows nothing against is admitted
    And one line says the seed landed

  # @test:shadow_forwards_while_the_seed_is_missing_and_says_so
  Scenario: Shadow forwards and says what enforce would have refused
    Given a gateway in shadow whose control plane is not up
    When an agent calls with a budget
    Then the call is forwarded
    And x-fuse-would-block names seed_pending
    And the bus records it as allowed ungoverned

  # @test:a_control_plane_that_answers_at_startup_opens_the_gate_before_the_first_call
  Scenario: A control plane that is up at startup costs nothing
    Given a gateway whose control plane answers at startup
    When the first call arrives
    Then it meets the seeded state, with no 503 and no late seed

  # @test:a_closed_gate_names_its_reason_until_it_opens
  # @test:the_reported_runs_are_bounded
  # @test:backoff_doubles_from_a_quarter_second_and_stops_at_five
  Scenario: The retry is bounded and so is what it remembers
    Given the seed is missing
    When the gateway retries
    Then it waits a quarter second, doubling, never more than five seconds
    And it reports each run once, remembering at most a bounded set

  # @test:a_late_seed_lands_beside_a_restored_reservation
  # @test:a_seed_never_overwrites_a_window_already_counting
  Scenario: A late unit seed lands beside a reservation the restart put back
    Given a unit with a retained reservation restored at startup and no settled spend
    When the month's seed lands late
    Then the month's spend is set beside the reservation and the next call is checked against both
    And a unit with settled spend is never overwritten
