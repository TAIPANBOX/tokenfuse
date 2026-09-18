Feature: The unit month survives a restart when a control plane knows it

  Measured 2026-09-17 on the appliance proving run (tokenfuse#293): after
  docker compose down and up, and after two reboots of the box, the gateway's
  unit ledger restarted from zero while the control plane still showed
  month_spent_microusd 2145 for unit aws. A central cap of 0.001 USD on that
  unit, polled every three seconds, refused nothing for 79 seconds because the
  gateway's own tally for the month was about 0.0007; a cap of 0.0005, below
  that tally, refused at once. So a monthly cap held only since the last
  restart while the control plane knew the real month.

  @decided 2026-09-18: the gateway never refuses to start because the control
  plane cannot be reached.

  @claude on the shape: one GET /v1/units before the listener binds, bounded
  by a timeout, seeds every unit of the current month; the figure is the
  org's, the count from here on is this gateway's own. Invariant 52.

  # @test:the_unit_month_is_seeded_from_the_control_plane
  # @test:a_seed_for_the_current_month_is_the_units_committed_spend
  Scenario: A restarted gateway starts the month where the control plane left it
    Given a control plane whose /v1/units shows unit aws at 2145 micro-USD this month
    When a gateway with that control plane configured starts
    Then the unit ledger's committed spend for aws this month is 2145 micro-USD before the first call
    And one line names the month and the units seeded

  # @test:a_restarted_gateway_enforces_a_central_cap_against_the_months_seeded_tally
  # @test:a_later_reservation_is_refused_at_the_seeded_tally
  Scenario: A central cap below the month's spend refuses the next call at once
    Given a gateway seeded at 2145 micro-USD for a unit whose file cap is 1 USD
    When a central override of 0.001 USD for that unit arrives
    Then the unit's next call is refused with 402 unit_budget_exceeded naming 0.001 as the budget and 0.002145 as the spend
    And with the override gone the same call is admitted against the file cap and its cost lands on top of the seed

  # @test:a_control_plane_that_cannot_be_reached_at_startup_leaves_the_month_at_zero_and_warns_once
  # @test:a_control_plane_that_does_not_answer_in_time_leaves_the_month_at_zero
  # @test:a_control_plane_that_refuses_the_seed_is_one_warning_naming_the_status
  Scenario: A control plane that cannot be asked leaves the month at zero and says so
    Given a control plane that is unreachable, silent past the timeout, or refusing the request
    When the gateway starts
    Then it starts anyway, every unit's month at zero
    And one warning says the month could not be seeded and why

  # @test:a_seed_for_another_month_is_skipped
  # @test:a_row_without_a_month_is_skipped_and_counted
  # @test:the_unassigned_bucket_is_never_seeded
  Scenario: Only this month's rows seed, and the unassigned bucket is not a unit
    Given /v1/units rows for another month, rows from a control plane that predates the month columns, and the unassigned row
    When the gateway seeds
    Then none of them changes a unit's tally, and the line counts what was skipped

  # @test:a_seed_never_overwrites_a_window_already_counting
  # @test:a_seed_on_an_uncapped_unit_is_found_by_a_later_override
  # @test:a_seeded_month_rolls_over_like_any_other_spend
  # @test:seeded_tallies_refuse_exactly_at_the_cap_across_a_sweep
  Scenario: A seed is spend, not a cap, and behaves like spend
    Given a seeded unit
    When the month rolls, or an override caps a unit the file left uncapped, or a reservation is already outstanding
    Then the seed rolls with the month, is found by the later cap, and never overwrites a window already counting

  # @test:a_units_body_that_is_not_json_seeds_nothing
  # @test:a_negative_month_figure_is_refused_as_hostile
  # @test:an_oversized_units_body_is_refused_before_it_is_parsed
  # @test:hostile_units_bodies_never_panic_and_never_seed
  Scenario: A body the control plane did not write seeds nothing
    Given an answer that is not JSON, carries a negative figure, or is larger than the bound
    When the gateway seeds
    Then nothing is applied and the gateway starts
