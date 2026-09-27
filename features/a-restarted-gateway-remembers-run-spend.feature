Feature: A restarted gateway remembers what a run has already spent

  Measured 2026-09-27 on the forge k3d lab (tokenfuse v1.4.0): run
  genaryx-copilot had a Cloud budget of USD 0.05 and USD 0.0547 spent in the
  Cloud (109%), yet the gateway, restarted earlier that day, kept answering;
  when the budget was later set to USD 0.001 the 402 said spent_usd
  0.029466, exactly the spend since the gateway's last restart. The gateway
  already seeds the per-unit month ledger from the Cloud at startup
  (invariant 52); it did not seed per-run spend, so any restart silently
  reset every run's budget accounting to zero.

  @claude on the shape, invariant 70: one GET /v1/runs?since_millis=... before
  the listener binds, windowed to runs active in the last 24 hours and bounded
  in bytes like the unit seed, stages every run's Cloud-known spend in a
  pending map; the first time this process opens that run fresh, the pending
  amount is credited once and removed, before that run's own reservation is
  checked against its budget. A run this gateway never opens is never
  credited at all, and a second call on an already-open run never re-applies
  the seed.

  # @test:pending_run_spend_is_seeded_from_the_control_plane
  Scenario: A restarted gateway stages every recent run's Cloud-known spend
    Given a control plane whose GET /v1/runs shows two active runs with spend and one killed run
    When a gateway with that control plane configured starts
    Then the two active runs' spend is staged to apply on their first call here
    And the killed run's spend is skipped and counted
    And one line names how many runs were staged and how many were skipped

  # @test:a_restarted_gateway_refuses_a_run_the_cloud_reported_already_at_its_budget
  Scenario: A run already at its Cloud-reported spend refuses its very next call
    Given a run whose Cloud-reported spend is 109% of its budget
    When this gateway, restarted, opens that run for the first time and estimates any nonzero cost
    Then the call is refused 402 before the provider is ever reached
    And the run's committed spend is exactly the seeded figure, nothing more

  # @test:a_restarted_gateway_admits_a_run_the_cloud_reported_comfortably_under_budget
  Scenario: A run comfortably under its Cloud-reported spend is admitted, seed plus cost
    Given a run whose Cloud-reported spend is small next to its budget
    When this gateway opens that run for the first time and makes a call
    Then the call is admitted
    And the run's committed spend is the seed plus that call's own settled cost

  # @test:seeded_spend_and_two_later_settlements_add_exactly_once_each
  Scenario: Seed and later settlements add exactly once each, never twice
    Given a seeded run and an identical unseeded control run
    When each is called twice with the same requests
    Then the seeded run's spend after each call equals the seed plus the control run's own spend at that point
    And no call re-applies the seed

  # @test:a_cloud_budget_parent_opened_on_first_sight_is_also_seeded
  Scenario: A parent opened from its Cloud budget on first sight is seeded too
    Given a parent run this gateway has not opened, with a Cloud-managed budget and Cloud-reported spend
    When a child names that parent on its first call
    Then the parent is opened at its Cloud budget and its Cloud-reported spend is credited
    And the child's own settled cost lands on top of it

  # @test:a_control_plane_that_cannot_be_reached_seeds_no_runs_and_warns_once
  # @test:a_run_seed_that_does_not_answer_in_time_seeds_nothing
  # @test:a_run_seed_that_the_control_plane_refuses_seeds_nothing
  Scenario: A control plane that cannot be asked leaves every run's spend at zero and says so
    Given a control plane that is unreachable, silent past the timeout, or refusing the request
    When the gateway starts
    Then it starts anyway, with nothing staged to seed
    And one warning says the run spend could not be seeded and why

  # @test:a_runs_body_that_is_not_json_seeds_nothing
  # @test:an_oversized_runs_body_is_refused_before_it_is_parsed
  # @test:hostile_runs_bodies_never_panic_and_never_seed
  Scenario: A hostile or oversized answer never seeds anything and never panics
    Given a /v1/runs body that is not JSON, or one larger than the seed's byte cap, or one shaped by an adversary
    When the gateway seeds
    Then nothing is staged from it, and the seed never panics

  # @test:a_killed_run_is_never_seeded
  # @test:a_run_with_no_cloud_row_is_never_seeded
  Scenario: A killed run is never seeded, and a run with no Cloud row is never seeded
    Given a /v1/runs answer marking one run killed and saying nothing about another
    When the gateway seeds
    Then the killed run is skipped and counted
    And the unmentioned run has nothing staged for it at all
