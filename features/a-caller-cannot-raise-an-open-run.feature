Feature: A caller can cap its own run's budget but cannot widen it once the run is open

  The budget a run declares in x-fuse-budget-usd used to be written on every call, so
  an agent could raise its own run's budget on its next call, bounded only by the
  operator's ceiling. The budget a run opens with is now the budget it keeps: a caller
  may lower an open run's budget and never raise it. A budget an operator set in the
  Cloud is still the operator's word, and moves the run either way.

  # @test:a_raise_on_an_open_run_is_refused_and_the_run_keeps_its_budget
  Scenario: A raise on an open run is refused and the run keeps its budget
    Given a run was opened by a call that declared a budget of 0.50 dollar
    When the agent's next call declares a budget of 1000 dollars
    Then the call is not refused for the declaration
    And the run's budget stays 0.50 dollar
    And a reservation of 1.50 dollars is refused with 402

  # @test:a_lower_budget_on_an_open_run_is_accepted
  Scenario: A lower declaration on an open run is taken
    Given a run was opened by a call that declared a budget of 5 dollars
    When the agent's next call declares a budget of 0.50 dollar
    Then the run's budget becomes 0.50 dollar

  # @test:a_call_that_declares_nothing_cannot_raise_an_open_run
  Scenario: A call that declares no budget cannot raise a run opened lower
    Given a run was opened by a call that declared a budget of 0.50 dollar
    When the agent's next call declares no budget
    Then the run's budget stays 0.50 dollar

  # @test:a_cloud_budget_moves_an_open_run_in_both_directions
  Scenario: A Cloud budget raises or lowers an open run whatever the caller declared
    Given a run was opened by a call that declared a budget of 0.50 dollar
    When the operator sets the run's Cloud budget to 5 dollars
    Then the run's budget becomes 5 dollars
    When the operator sets the run's Cloud budget to 0.25 dollar
    Then the run's budget becomes 0.25 dollar

  # @test:a_refused_raise_is_logged_once_per_run
  Scenario: A refused raise is said once per run
    Given a run was opened by a call that declared a budget of 0.50 dollar
    When the agent's next three calls each declare a budget of 1000 dollars
    Then the gateway logs one line that it refused to raise the run's budget

  # @test:a_raise_past_the_ceiling_is_refused_on_an_open_run
  Scenario: A raise past the operator ceiling is refused too
    Given the operator ceiling is 1.00 dollar and a run is open at 0.50 dollar
    When the agent's next call declares 1000 dollars
    Then the run's budget stays 0.50 dollar

  # @test:the_caller_budget_is_the_lowest_declared_across_a_sweep
  Scenario: Across any sequence of declarations the run holds the lowest it was declared at
    Given a run is opened and then called many times with varying declared budgets
    When each declaration is applied
    Then the run's budget after each call is the lowest declared so far

  # @test:a_closed_run_reopened_by_a_caller_is_a_new_run_at_the_declared_budget
  Scenario: A reopened run takes the budget its new declaration gives it
    Given a run was closed
    When a caller opens it again declaring 2 dollars
    Then the reopened run's budget is 2 dollars and nothing was refused

  # @test:anthropic_buffered_answer_names_the_refused_raise_and_the_kept_budget
  Scenario: A refused raise is named on a buffered answer on the Anthropic door
    Given a run was opened by a call that declared a budget of 0.50 dollar
    When the agent's next call declares a budget of 1000 dollars
    Then the answer carries x-fuse-budget: raise-refused; kept=0.50

  # @test:openai_streamed_answer_names_the_refused_raise_and_the_kept_budget
  Scenario: A refused raise is named on a streamed answer on the OpenAI door
    Given a run was opened by a call that declared a budget of 0.50 dollar on the OpenAI door
    When the agent's next streamed call declares a budget of 1000 dollars
    Then the streamed answer carries x-fuse-budget: raise-refused; kept=0.50

  # @test:the_header_rides_a_refusal_that_the_kept_budget_then_causes
  Scenario: The header rides the 402 that the kept budget then causes
    Given a run was opened by a call that declared a budget of 0.50 dollar
    When the agent's next call declares 1000 dollars and reserves 1.50 dollars
    Then the call is refused with 402 and the refusal carries x-fuse-budget: raise-refused; kept=0.50

  # @test:no_header_when_no_raise_was_refused
  Scenario: A lower declaration is not reported as a refusal
    Given a run was opened by a call that declared a budget of 0.50 dollar
    When the agent's next call declares a budget of 0.25 dollar
    Then the answer carries no x-fuse-budget header
