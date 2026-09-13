Feature: Shadow mode records the refusal it did not make

  The README has promised since the first release that the budget starts in
  shadow mode and "records what it would block but changes nothing". Until
  2026-09-13 that held for max_steps and budget_per_step and not for the run
  budget itself: a shadow week left no header, no event and plain allow rows
  for every call enforce would have refused, so an operator sizing a budget
  before turning enforce on had nothing to read but the ledger total. RUN-6
  of the 1.0 proving run found it on the released v0.5.0 image.

  @decided 2026-09-13: the fix copies the firewall's own precedent, a
  breaker_shadow event beside breaker_tripped with the same data and a mode
  field, plus the existing x-fuse-would-block header, computed by the same
  rule the checked reserve applies (on the in-process ledger; the raft read
  is advisory). The Parquet row stays an allow row, and the unit monthly cap
  is not covered yet; invariant 42 names both.

  # @test:shadow_over_run_budget_is_forwarded_and_says_so
  Scenario: A shadow call over the run budget is forwarded and says so
    Given a gateway in shadow mode and a run with a 0.02 USD budget
    And two calls have spent 0.021 USD on it
    When a third call arrives
    Then the call is forwarded with HTTP 200
    And the response carries x-fuse-would-block naming budget_exceeded
    And the bus carries exactly one breaker_shadow event, severity medium, mode shadow
    And the bus carries no breaker_tripped event

  # @test:warn_over_run_budget_is_forwarded_and_says_so
  Scenario: Warn mode does the same and names its mode
    Given a gateway in warn mode over the same spent run
    When the over-budget call arrives
    Then it is forwarded, the header is set, and the breaker_shadow event says mode warn

  # @test:shadow_at_exactly_the_budget_is_not_flagged
  Scenario: Meeting the budget exactly is not exceeding it
    Given a shadow run whose spend plus the next estimate equals the budget to the microdollar
    When that call arrives
    Then no would-block header and no breaker_shadow event are produced

  # @test:shadow_flags_the_parent_budget_a_child_would_exhaust
  Scenario: A child that would exhaust its parent is flagged with the parent named
    Given a parent run with a 0.02 USD budget and children with generous budgets of their own
    When the second child call would push the parent over
    Then the child is forwarded and the header and event name the parent run

  # @test:shadow_appends_the_budget_reason_to_an_existing_would_block
  Scenario: The budget reason is appended to a header that already had one
    Given a shadow run that max_steps already flags on every call
    When an over-budget call arrives
    Then the header still starts with the max_steps reason and also names budget_exceeded

  # @test:enforce_over_run_budget_emits_breaker_tripped_and_no_shadow
  Scenario: Enforce never emits the shadow event
    Given a gateway in enforce mode over the same spent run
    When the over-budget call arrives
    Then it is refused with 402 and exactly one breaker_tripped, and no breaker_shadow

  # @test:would_exceed_mirrors_reserve_without_reserving
  Scenario: The shadow question is the checked reserve's question
    Given a ledger with a parent and a child run
    When the shadow path asks whether an estimate would exceed
    Then it names the same run the checked reserve refuses on, reserves nothing, and draws the same strict line
