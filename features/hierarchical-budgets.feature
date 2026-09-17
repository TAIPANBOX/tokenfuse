Feature: Hierarchical budgets check every ancestor, and a reservation settles where it was admitted

  The README has promised since the first release that a sub-agent's spend is
  checked against every ancestor, all-or-nothing. The 2026-09-18 money-path
  review and the second-model pass over it found five places where that was
  not so: a child naming a parent this gateway had not opened was checked
  against nothing above itself, with no header, no event and no log; a parent
  declared after a run's first call was ignored for the run's life while every
  trace row claimed it; settle walked the run tree again, so a parent that
  appeared between a child's reserve and its settle lost another call's
  reservation; settle after close_run was a silent no-op that left every
  ancestor's reserved counter inflated for good; and a walk that reached the
  64-ancestor cap admitted against the truncated set. At a budget of i64::MAX
  the saturating sum turned an overflow into an allowed equality.

  @decided 2026-09-17: a child naming a parent this gateway has not opened is
  refused in enforce, unless the parent has a Cloud-managed budget, in which
  case the parent is opened at that budget on first sight; the policy default
  never opens a parent; shadow and warn forward the call and record the
  refusal as a would-block. A parent is adopted only by a run that has no
  parent yet and against which nothing has ever been admitted, its own or a
  descendant's; any other change of parent is a 400, not a money refusal, and
  the trace row records the relationship the ledger accepted. A reservation
  carries its chain and settles on it exactly once. Invariant 49.

  # @test:missed1_a_child_naming_an_unopened_parent_is_checked_against_nothing
  # @test:a_child_of_an_unopened_parent_is_refused_and_reserves_nothing
  # @test:a_child_naming_a_parent_this_gateway_has_not_opened_is_refused
  Scenario: A child naming a parent this gateway has not opened is refused
    Given a gateway in enforce mode and no run named parent
    When a child call declares parent as its x-fuse-parent-run-id
    Then it is refused with 402 budget_exceeded naming the parent that is not open
    And nothing is reserved on the child, and the parent still does not exist
    And the trace row and one breaker_tripped carry the reason

  # @test:a_cloud_budget_on_the_parent_opens_it_and_admits_the_child
  Scenario: A parent with a Cloud-managed budget is opened at that budget on first sight
    Given a Cloud budget of 0.0115 USD set for a parent that has not called yet
    When a child declaring that parent calls twice
    Then the first call is admitted and the parent appears with that budget and the child's spend
    And the second call is refused because the parent's budget is exceeded, naming the parent

  # @test:a_child_of_an_unopened_parent_is_admitted_once_the_parent_opens
  Scenario: Once the parent opens, the child is checked against it
    Given a child that was refused because its parent was not open
    When the parent opens with a budget of 500000 micro-USD
    Then the child's next reservation is admitted against both and rolls up into the parent
    And a reservation that would exceed the parent is refused naming the parent

  # @test:shadow_records_an_unopened_parent_as_a_would_block_and_accounts_the_leaf
  Scenario: Shadow and warn forward the child and record the refusal
    Given a gateway in shadow or warn mode
    When a child declares a parent that is not open
    Then the call is forwarded with 200 and x-fuse-would-block names the parent that is not open
    And one breaker_shadow event carries the same reason and the mode
    And the child's own spend is recorded, and the parent still does not exist

  # @test:a_parent_declared_after_a_descendants_admission_is_refused
  Scenario: A parent declared after a descendant has reserved is refused
    Given a run with no parent whose own steps are zero
    And a child of that run that has reserved through it
    When the run declares a parent
    Then the declaration is refused, because a reservation was admitted against the run
    And the child's later spend still lands on the run and never on the declared parent

  # @test:a_parent_declared_before_any_admission_is_adopted
  # @test:missed2_a_parent_declared_after_the_first_call_is_ignored
  Scenario: A parent declared before any admission is adopted
    Given a run opened without a parent against which nothing was ever admitted
    When it declares a parent whose budget is smaller than its own
    Then the parent is adopted and the run's next reservations are checked against it

  # @test:a_changed_parent_is_refused_and_the_held_one_stays
  # @test:a_changed_parent_is_a_400_and_the_trace_keeps_the_accepted_parent
  Scenario: A changed parent is a 400 and the trace keeps the accepted parent
    Given a run that rolls up into one parent
    When a later call declares a different parent, then omits the header, then names the run itself
    Then the different parent is refused with 400 invalid_request naming the held and the declared parent
    And the call that omits the header proceeds against the held parent and its row records it
    And the self-declaration is refused with 400 as well
    And a refused declaration changes nothing, the budget included

  # @test:a_reservation_settles_on_the_chain_it_was_admitted_against
  # @test:codex_f02_late_parent_does_not_release_another_calls_reservation
  Scenario: A reservation settles on the chain it was admitted against
    Given a child admitted in shadow while its parent was not open
    And the parent then opens and reserves 800000 of its own 1000000
    When the child settles
    Then the parent's own reservation is still 800000 and its spend is still zero
    And the child's next reservation rolls up into the parent

  # @test:a_closed_run_keeps_the_counters_a_late_settlement_needs
  # @test:missed6_settle_after_close_run_leaves_the_parent_reserved
  Scenario: Closing a run keeps the counters a late settlement needs
    Given a child with a reservation in flight under a parent
    When the child is closed and the reservation then settles
    Then the parent's reservation is released and the parent is charged the actual spend
    And the closed child shows the same spend, admits nothing new, and a second settlement changes nothing

  # @test:an_old_settlement_never_touches_a_reopened_runs_counters
  Scenario: An old settlement never touches a reopened run
    Given a child closed with a reservation in flight, then reopened under another parent
    When the old reservation settles
    Then the original parent is charged and released, the new parent is untouched
    And the reopened child's counters stay at zero

  # @test:a_second_settlement_of_one_reservation_is_an_observable_no_op
  # @test:codex_f10_settlement_replay_does_not_charge_twice_or_release_a_sibling
  Scenario: A second settlement of one reservation changes nothing
    Given two reservations on one run
    When the first settles twice
    Then the run is charged once, the sibling's reservation is untouched, and the second settle says it was not outstanding

  # @test:codex_held_children_race_against_one_parent_with_exact_accounting
  # @test:racing_children_with_a_late_parent_are_refused_until_it_opens
  Scenario: Racing children against one parent, with and without a late parent
    Given sixteen children racing to reserve through a parent that is not open
    When they race, and then the parent opens with 17 micro-USD and they race again
    Then the first race grants nothing and the second grants exactly five, and the parent settles exactly 15

  # @test:codex_f01_every_ancestor_budget_includes_the_65th_run
  # @test:a_walk_that_reaches_the_depth_cap_refuses_and_names_the_unchecked_ancestor
  # @test:a_65_deep_chain_is_refused_at_the_door_naming_the_unchecked_root
  Scenario: A walk that reaches the depth cap refuses rather than truncates
    Given a chain of sixty-five runs, every one with a budget that would admit the call
    When the leaf reserves, and through the door as well
    Then it is refused naming the leaf, the last run walked and the unchecked root, and nothing is reserved anywhere
    And a chain of sixty-four is admitted on every one of them

  # @test:codex_f09_saturated_budget_cannot_grant_past_its_ceiling
  # @test:a_saturated_unit_cap_cannot_grant_past_its_ceiling
  Scenario: A saturated budget admits nothing past its ceiling
    Given a run and a unit whose budget is the largest representable amount, fully spent
    When one more micro-USD is asked for
    Then it is refused, because a sum that cannot be represented fits no budget

  # @test:raft_backend_refuses_a_changed_or_late_parent_from_its_local_read
  Scenario: The raft ledger refuses a changed or late parent from what it can see
    Given a single-node raft ledger holding a run under one parent and a parentless run
    When a different parent, a late parent and a self-parent are declared
    Then each is refused from the local read, and the older state machine is otherwise unchanged
