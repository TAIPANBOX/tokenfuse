Feature: An observed closure reaches the Cloud

  A closure with observed evidence settled a retained reservation only in
  the gateway's own run and unit ledgers. In Cloud mode a restart then lost
  the closed cost: the journal no longer held the reservation, and the run
  and unit seeds the gateway takes from the control plane had never seen the
  spend. The ask (D8.1): an observed closure takes the path settled spend
  takes to the Cloud, so the seeds after a restart include it, exactly once;
  a no-charge closure adds no spend.

  # @test:an_observed_closure_reaches_the_cloud_once_and_the_restart_seeds_include_it
  Scenario: The observed cost survives a restart through the Cloud seeds
    Given a gateway pushing to a control plane, with one call retained on a child run
    When a person closes it as observed at 4321 micro-USD and the gateway restarts on the same data directory
    Then the control plane received one allow row for the child at 4321 under the call's agent and unit
    And the restarted gateway's run seed names the child at 4321 and its unit seed includes 4321
    And the child's next call is checked against 4321 plus its own cost

  # @test:an_observed_closure_writes_one_allow_row_with_the_calls_attribution
  # @test:a_retained_reservation_journals_the_calls_attribution
  Scenario: The closure's row is the row a settled call writes, under the call's attribution
    Given a retained call journaled with its agent, key, unit and parent
    When it is closed as observed
    Then one allow row at the observed cost is handed to the sink with that attribution

  # @test:a_replay_answers_the_recorded_result_and_a_conflict_changes_nothing
  # @test:racing_closures_of_one_reservation_apply_exactly_once
  # @test:a_closure_on_disk_is_never_restored_and_its_operation_answers_after_a_restart
  Scenario: One closure writes one row, however often it is asked for
    Given an observed closure that was applied
    When the same operation is sent again, in this process or after a restart, or sixteen closures race
    Then no second row is written

  # @test:a_no_charge_closure_writes_no_row
  # @test:a_no_charge_closure_sends_no_row_to_the_cloud
  Scenario: A no-charge closure adds no spend
    Given a retained call closed as no_charge
    Then no row is written and the control plane receives nothing for that run

  # @test:a_line_from_before_the_attribution_field_keeps_its_revision
  # @test:a_record_from_before_the_attribution_field_files_its_unit_from_the_unit_half
  Scenario: A journal line written before this change still closes
    Given a retained line with no attribution, written by an older gateway
    Then it reads with the same revision, so a closure minted against it still names it
    And its observed row takes the unit from its unit half and names no agent
