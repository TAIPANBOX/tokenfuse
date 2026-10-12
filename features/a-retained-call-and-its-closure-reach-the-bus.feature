Feature: A retained call and its closure reach the bus

  A call handed to the provider that ended before any answer came back is
  retained: its money stays reserved on the run and on the unit until a
  person closes it with evidence. Until this change the only record of that
  was a warning in the gateway's log and a count on the runs endpoint, and a
  closure wrote nothing to the agent-event bus at all, so nobody was told
  that money was waiting for a person, or that a person had released it.
  The ask (D10): both go on the bus, the retained call at medium so a person
  acts soon, and the closure at high because it lifts a money control.

  # @test:a_call_the_provider_held_when_the_caller_left_writes_one_call_retained
  # @test:a_retained_call_and_its_closure_each_reach_the_bus_once_and_a_restart_adds_neither
  Scenario: A retained call is reported once, with what a person needs to close it
    Given a gateway writing agent-events
    When a call by an agent, on behalf of a user, is handed to the provider and ends before any answer
    Then one call_retained is written at medium under that agent, that run and that chain
    And it names the reservation, the amount held, the unit, the model, and whether it was journaled and listed
    And the settled call before it is not reported as retained

  # @test:a_retained_call_past_the_registry_cap_is_journaled_and_says_it_is_not_listed
  Scenario: A retained call says whether it survives a restart and whether it can be closed from the list
    Given the list of retained reservations is full and a journal is configured
    When one more call is retained
    Then its call_retained says it was journaled and is not listed

  # @test:a_retained_call_and_its_closure_each_reach_the_bus_once_and_a_restart_adds_neither
  Scenario: A restart that restores a retained reservation reports nothing new
    Given a retained call already reported on the bus
    When the gateway restarts on the same data directory and restores it from the journal
    Then no second call_retained is written for it

  # @test:a_retained_call_that_names_no_agent_is_skipped_and_counted_never_invented
  # @test:a_retained_call_that_names_no_agent_is_skipped_and_counted_in_the_log
  # @test:a_closure_of_a_record_that_names_no_agent_is_skipped_and_counted
  Scenario: An agent is never invented
    Given a retained call, or a closed record, that names no agent
    Then the call is still retained and the record still closes
    And no event is written for either, and each skip is counted

  # @test:an_applied_closure_writes_one_retained_closed_with_its_evidence
  # @test:a_no_charge_closure_writes_one_retained_closed_settled_at_zero
  # @test:a_retained_call_and_its_closure_each_reach_the_bus_once_and_a_restart_adds_neither
  Scenario: A closure is reported once, at high, with its evidence
    Given a retained reservation
    When a person closes it with observed evidence, or with the provider's confirmation of no charge
    Then one retained_closed is written at high under the call's agent and run
    And it names the reservation, the revision, the operation, the evidence kind, the amount settled, the evidence reference and the unit

  # @test:a_replay_a_conflict_and_a_second_operation_write_no_second_retained_closed
  # @test:a_closure_answered_again_after_a_restart_writes_no_second_retained_closed
  # @test:a_retained_call_and_its_closure_each_reach_the_bus_once_and_a_restart_adds_neither
  Scenario: A retry of an applied closure is not a second closure
    Given a closure that was applied
    When the same operation is sent again, in this process or after a restart, or another operation asks for the same reservation
    Then no second retained_closed is written

  # @test:a_stale_revision_or_an_unwritable_journal_writes_no_retained_closed
  # @test:a_retained_call_and_its_closure_each_reach_the_bus_once_and_a_restart_adds_neither
  Scenario: A refused closure is not on the bus
    Given a retained reservation
    When a closure is refused for a forged token or a stale revision, or because the journal could not take it
    Then no retained_closed is written

  # @test:every_event_type_reaches_the_artifact_with_its_own_severity
  Scenario: The bands are fixed per type
    Then call_retained is medium and retained_closed is high, in the code and in the published constants
