Feature: A call forwarded under identity warn mode is marked wherever it is read

  With TOKENFUSE_IDENTITY_STRICT=warn the gateway forwards a call whose
  credential may not speak as the agent id it named, and says so only in the
  response's x-fuse-identity header. Its trace row, its FOCUS export row and
  the Cloud's figures read exactly like an honest allowed call under the
  claimed id, so a FinOps console, the identity graph and the Cloud could not
  tell the two apart. The finer reason for a refusal in enforce mode was in the
  403 and the agent event, never in the trace.

  The ask: add a trace and wire marker for a warn-mode identity mismatch
  carrying the would-block reason beside the key, carry it into the FOCUS
  export by the append-only rule and into the Cloud, and show it on the
  dashboard next to the refused state.

  @claude 2026-10-08, under delegated authority: one nullable trace column,
  identity_reason, set on every row of a call warn mode forwarded and on a
  refusal for identity; one FOCUS column, x_identity_reason, appended last.
  A forwarded call stays an admitted, spent row filed under the id it
  claimed, because warn mode records what it would do without doing it; the
  marker is how a reader tells it apart. The Cloud shows a reason only when
  it is one of the gateway's own five words.

  # @test:a_warn_mode_identity_mismatch_is_marked_in_the_trace_and_the_export
  Scenario: A call warn mode forwarded carries the reason it would have been refused
    Given a gateway in warn mode and a key that presents an agent id it is not bound to
    When the call is forwarded and the trace is exported to FOCUS
    Then its row says x_identity_reason agent_id_not_allowed, x_blocked false, and its key
    And an honest call's row says x_identity_reason empty

  # @test:a_refusal_for_identity_names_its_reason_in_the_export
  Scenario: A refusal for identity names which check refused it
    Given a gateway in enforce mode and the same mismatched call
    When it is refused and the trace is exported to FOCUS
    Then x_block_reason is identity_mismatch and x_identity_reason is agent_id_not_allowed

  # @test:the_wire_carries_an_identity_finding_only_when_there_is_one
  Scenario: The Cloud is told the finding, and nothing changes for other calls
    Given a record with an identity finding and one without
    When the gateway pushes them to the Cloud
    Then the first carries identity_reason and the second carries no such key

  # @test:a_warn_mode_identity_mismatch_is_counted_on_the_run_and_the_fleet
  # @test:a_warn_mode_identity_mismatch_reaches_the_runs_and_summary_reads
  Scenario: The Cloud counts the forwarded mismatches on the run and the fleet
    Given a run with one honest call and two calls forwarded under warn mode
    When /v1/runs and /v1/summary are read
    Then the run reports two identity-warned calls, its latest reason and nothing refused
    And the summary counts two identity-warned calls

  # @test:an_identity_reason_outside_the_vocabulary_is_never_shown
  Scenario: A reason the gateway never gives is never shown
    Given a record whose identity_reason is markup
    When the run is read
    Then the call is counted and the reason shown is empty
