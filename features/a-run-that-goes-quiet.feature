Feature: A run that goes quiet is an incident

  A customer agent's node was killed mid-run, at step 7 of a sixty-call run,
  and nothing said so: the run stayed on the console at step 7 with a stale
  last-seen time, no event reached the bus at five seconds or at sixty, and
  no incident was raised. The same when the node's packets were dropped for
  forty seconds. Every detector fired on activity; nothing fired on absence.
  Measured 2026-09-17 on the appliance proving run (tokenfuse#296).

  The control plane never learns that a run finished, so silence alone cannot
  tell a dead node from a run that ended without saying so. What it can know
  is the run's own cadence, and the signals that a run is over: a kill, a
  refusal, an outcome tag on the last call.

  Background:
    Given a control plane with the stall floor at five minutes
    And a run the control plane has seen calling at least twice

  # @test:a_run_silent_past_the_threshold_is_stalled_once_and_not_again
  Scenario: A node killed mid-run becomes an incident once the floor passes
    Given the run stopped calling at step 7
    When the sweep runs before five minutes of silence
    Then nothing is raised
    When the sweep runs at five minutes of silence
    Then one run_stalled incident is raised, at severity medium
    And a later sweep raises nothing more, because the incident is the record

  # @test:a_stall_threshold_of_zero_turns_the_detector_off
  # @test:stall_minutes_env_zero_is_off_blank_is_default_and_junk_is_refused
  # @test:the_sweep_task_is_spawned_only_when_the_detector_is_on
  Scenario: The floor is configurable, five minutes by default, and zero turns it off
    Given TOKENFUSE_CLOUD_STALL_MINUTES is unset
    Then the floor is five minutes
    Given TOKENFUSE_CLOUD_STALL_MINUTES is 0
    Then no cadence is remembered, no sweep is scheduled and nothing is raised
    Given TOKENFUSE_CLOUD_STALL_MINUTES is not a whole number of minutes
    Then the value is refused, said, and the default used

  # @test:a_run_that_moved_again_is_not_stalled
  # @test:a_stall_is_not_re_raised_when_the_run_moves_and_goes_quiet_again
  Scenario: Movement clears nothing and repeats nothing
    Given the run made a call before the floor passed
    When the sweep runs
    Then nothing is raised
    Given the run was already reported stalled and then called again
    When it goes quiet again past the floor
    Then no second incident is raised: the one on the console is the record

  # @test:the_stall_incident_names_the_run_the_agent_the_last_call_and_the_silence
  # @test:an_unattributed_stalled_run_is_on_the_console_with_no_agent_invented
  # @test:a_stalled_run_pushes_went_quiet_not_running_hot
  Scenario: The incident says who went quiet, when, and for how long
    When a run_stalled incident is raised
    Then it names the run and the agent, and invents no agent for a run that has none
    And its summary carries the last call time in RFC 3339 and the silence in seconds
    And a device is told the agent went quiet, not that it is running hot

  # @test:a_run_that_pauses_by_habit_is_not_stalled_at_the_floor
  # @test:a_run_with_one_call_has_no_cadence_and_is_not_stalled
  Scenario: A recent cadence is the run's own, not a fixed number
    Given a run whose calls are ten minutes apart
    When it has been silent for six minutes
    Then nothing is raised, because six minutes is inside its own habit
    When it has been silent for longer than ten minutes
    Then one run_stalled incident is raised
    Given a run that called once
    Then it has no cadence and is never called stalled

  # @test:a_run_whose_last_call_was_refused_is_stopped_not_stalled
  # @test:a_run_that_tagged_its_outcome_ended_and_is_not_stalled
  # @test:a_killed_run_is_not_stalled
  Scenario: A run that was stopped, or said it was done, is not stalled
    Given a run whose last call the gateway refused, or whose last call carried
      an outcome tag, or that an operator killed
    When it goes quiet past the floor
    Then nothing is raised
    And a refused run whose retry was then allowed is watched again

  # @test:a_stalled_run_reaches_the_console_and_the_stream_and_not_yet_the_wire
  # @test:a_stalled_run_is_listed_on_the_incidents_endpoint_for_a_viewer
  # @test:a_stalled_run_reaches_the_sse_stream
  Scenario: Exported like the other incidents, so the notifier can say an agent went quiet
    When a run_stalled incident is raised
    Then it is on the incidents endpoint and on the live stream
    And until the type is on the wire it is not exported, and the log says so

  # @test:a_restart_does_not_raise_a_stall_for_a_run_it_never_watched
  # @test:an_out_of_order_record_counts_the_call_and_moves_nothing_else
  # @test:a_forged_future_stamp_does_not_hold_the_detector_off
  # @test:the_stall_map_is_bounded_by_recency_not_by_panic
  # @test:a_hostile_record_stream_never_panics_and_never_double_reports
  Scenario: A restart, a late record, a forged stamp and a flood report nothing they should not
    Given a control plane that loaded a snapshot holding runs it never saw calling
    When the sweep runs
    Then nothing is raised, because a cadence is something this process saw
    Given a record that arrives out of order, a record stamped in the future,
      and more runs than the cadence map holds
    Then the late record counts a call and moves nothing else, the future stamp
      cannot hold the detector off, and the map evicts by recency rather than panics
