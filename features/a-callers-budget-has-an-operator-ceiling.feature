Feature: An operator can cap the run budget a caller declares for itself

  The budget of a run comes from the x-fuse-budget-usd header the agent sends,
  and an open run takes the budget of its latest call, so with no client keys
  the per-run ceiling is whatever the agent declares and its next call can
  widen it. Widening stays, because it is the one release valve for a
  reservation kept after an unknown outcome. TOKENFUSE_MAX_RUN_BUDGET_USD
  bounds it: a budget the caller or a default chose is clamped to the ceiling,
  and a budget an operator set in the Cloud is not.

  # @test:no_run_budget_ceiling_is_set_when_nothing_is_configured
  # @test:with_no_ceiling_the_declared_budget_stands
  Scenario: Nothing configured changes nothing
    Given TOKENFUSE_MAX_RUN_BUDGET_USD is unset or empty
    When an agent declares a budget of 1000 dollars and reserves 1.50
    Then the run opens at 1000 dollars and the call is admitted
    And the response carries no x-fuse-budget-clamped header

  # @test:a_declared_budget_above_the_operators_ceiling_opens_the_run_at_the_ceiling
  Scenario: A declared budget above the ceiling opens the run at the ceiling
    Given the ceiling is 1.00 dollar
    When an agent declares a budget of 1000 dollars and reserves 1.50
    Then the run opens at 1.00 dollar
    And the call is refused with 402 budget_exceeded
    And the response says x-fuse-budget-clamped: 1.00

  # @test:widening_an_open_run_stops_at_the_ceiling
  Scenario: Widening an open run stops at the ceiling
    Given the ceiling is 1.00 dollar and a run is open at 0.50
    When the agent's next call declares 1000 dollars
    Then the run's budget becomes 1.00 dollar and never 1000
    And a reservation above 1.00 is refused with 402

  # @test:a_cloud_budget_above_the_ceiling_is_honoured_unclamped
  Scenario: A Cloud budget is the operator's word and is not clamped
    Given the ceiling is 1.00 dollar
    And the Cloud sets this run's budget to 1000 dollars
    When an agent calls and reserves 1.50
    Then the run opens at 1000 dollars and the call is admitted
    And the response carries no x-fuse-budget-clamped header

  # @test:the_builtin_default_and_the_policy_default_are_clamped_too
  Scenario: The default budgets are clamped as well
    Given the ceiling is 1.00 dollar
    When an agent declares no budget at all
    Then the run opens at 1.00 dollar rather than the built-in 5 dollars
    And a policy default above the ceiling is clamped the same way

  # @test:the_clamp_header_is_present_only_on_a_clamped_call
  # @test:the_clamp_header_rides_a_streamed_answer_and_a_refusal
  Scenario: The clamp header exists only on a call that was clamped
    Given the ceiling is 1.00 dollar
    When an agent declares 0.25, exactly 1.00, or more than 1.00
    Then only the call declaring more than 1.00 carries x-fuse-budget-clamped
    And a streamed answer and a refusal carry it too

  # @test:the_clamp_is_logged_once_per_run
  # @test:the_clamp_log_notes_a_run_once_and_stays_bounded
  Scenario: The clamp is logged once per run and the log cannot grow without bound
    Given the ceiling is 1.00 dollar
    When one run makes four clamped calls and another makes one
    Then the operator's log has one line for each run
    And the set of runs remembered is capped

  # @test:a_run_budget_ceiling_is_read_as_exact_microdollars
  Scenario: The ceiling is read as exact dollars
    Given TOKENFUSE_MAX_RUN_BUDGET_USD is "4.35" or "0.000001"
    When the gateway reads it
    Then the ceiling is 4,350,000 or 1 microdollars with no floating-point error

  # @test:a_run_budget_ceiling_nobody_can_read_is_refused_not_ignored
  # @test:an_unreadable_ceiling_exits_2_and_names_the_variable
  Scenario: A ceiling nobody can read stops the gateway before it serves
    Given TOKENFUSE_MAX_RUN_BUDGET_USD is "0", "-1", "1e9", "abc", "1.2.3" or a 400-digit string
    When the gateway starts
    Then it exits with status 2 and names the variable
    And it never starts with no ceiling

  # @test:the_binary_applies_the_ceiling_to_a_declared_budget
  Scenario: The running binary applies the ceiling over HTTP
    Given the gateway binary started with the ceiling at 1.00 dollar and the stub provider
    When a client declares 1000 dollars and reserves 1.50
    Then the answer is 402 with x-fuse-budget-clamped: 1.00
    And the same call against a binary with no ceiling is admitted
