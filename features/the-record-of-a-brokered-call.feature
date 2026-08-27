Feature: A brokered tool call is recorded whether or not a policy judged it

  Whether a POLICY judged an action is a separate fact from whether the action
  OCCURRED, and an audit trail that keeps only the first has no rows at all for
  the deployment that configured no policy. That is the default deployment.

  Measured 2026-08-27 on the release binary, twice, before and after. With
  Wardryx unset, a live `tools/call` that the broker forwarded successfully
  produced ZERO records in `TOKENFUSE_EVENTS_PATH`, because `emit_tool_call`
  was reachable only from inside `if st.wardryx.mode != WardryxMode::Off`. The
  same call against the same binary built from this branch produces one, whose
  decision reads `allowed-ungoverned`.

  The word is not new and is deliberately not `allow`. The dependency plane uses
  it for an outage that was let through, and the firewall's own check endpoint
  answers `governed: false` for a box where nothing was asked. Recording a
  governance gap as a permission is the mistake all three refuse.

  Background:
    Given an MCP credential-broker with an events path configured
    And a `tools/call` the broker will forward to a real upstream

  # @test:a_brokered_tool_call_is_recorded_when_no_policy_gate_is_configured
  Scenario: The default deployment keeps an audit trail
    Given no policy decision point configured at all
    When an agent calls a tool through the broker
    Then the call is served
    And one tool_call record is written, saying nothing judged it rather than
      saying a policy allowed it

  # @test:a_governed_tool_call_is_recorded_once_and_not_twice
  Scenario: One call is one record
    Given a policy decision point that allows
    When an agent calls a tool through the broker
    Then exactly one tool_call record is written, carrying the decision the
      policy gave, because a doubled trail says the agent called the tool twice

  # @test:a_refusal_the_policy_decided_is_still_recorded_exactly_once
  Scenario: The refusals keep their records
    Given a policy decision point that denies, and then one that holds for
      approval
    When an agent calls a tool through the broker
    Then the call is refused and never reaches the upstream
    And the refusal is recorded exactly once, naming what the policy decided,
      because a refusal is the most interesting record there is

  # @test:a_call_refused_before_it_is_brokered_is_not_recorded_as_a_tool_call
  Scenario: A call that never happened is not written down as one
    Given a call carrying a raw secret the DLP filter blocks, and one naming a
      secret this agent is not scoped for
    When each is refused before the upstream is contacted
    Then no tool_call record is written for either, because a record of a call
      the upstream never received sends an auditor after an action nobody took

  # @test:a_brokered_call_that_names_nobody_is_counted_as_skipped_not_never_attempted
  Scenario: A call attributable to nobody is counted rather than passed over
    Given a call with no agent header and no delegation token to read one from
    When it is brokered
    Then no agent id is invented for it, so no record is written
    And the exporter counts and warns about the skip, because an operator can
      read a counter and cannot read a branch that was never entered
