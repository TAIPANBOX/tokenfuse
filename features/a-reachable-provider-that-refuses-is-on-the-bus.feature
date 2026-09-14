Feature: A reachable provider that refuses the call is on the bus

  A provider that is reachable and refusing (a 429, a 400 for a retired model
  id) had its status passed through and the call settled at zero, both
  right, and nothing written to the bus: dependency_failed fired from the
  transport-error arm only. Measured 2026-09-07 on v0.4.3 with a stub
  answering 429, 400 and 200: three drills, every status right, every
  expected notifier mail missed, so a drill could not tell a notifier that
  was down from a gateway that was silent (tokenfuse#260).

  @decided 2026-09-14: one dependency_failed per refusal, at a new stage
  `response` (the answer arrived, and it was a refusal), effect call_failed,
  the status and the model in detail; emitted where the status is first
  known on both managed paths, so a streamed refusal does not wait for the
  settle guard. The money rules stay what they were.

  # @test:a_reachable_provider_that_refuses_is_recorded_on_the_bus
  Scenario: A buffered 429 is on the bus
    Given a provider answering 429 with no usage
    When a budgeted run calls the Messages door
    Then the caller gets the 429 unchanged and nothing is charged
    And one dependency_failed lands on the bus: provider, stage response, effect call_failed, high
    And its detail names HTTP 429 and the model

  # @test:a_reachable_provider_that_refuses_a_stream_is_recorded_on_the_bus
  Scenario: A streamed 400 is on the bus without waiting for the guard
    Given a provider answering 400 to a streaming request
    When the run calls the Messages door with stream true
    Then the response carries x-fuse-stream passthrough, so it went through the streaming path
    And one dependency_failed lands on the bus at stage response with the 400 in its detail

  # @test:a_refusal_with_usage_is_still_billed_and_now_recorded
  Scenario: A refusal that reports usage is billed as before, and recorded
    Given a provider answering 500 with a usage block for what it generated
    When a budgeted run calls the Messages door
    Then the reported usage is billed, the rule since #167
    And one dependency_failed lands on the bus all the same

  # @test:a_healthy_call_reports_no_dependency_failure
  Scenario: A working day still writes nothing
    Given a provider answering 200
    When a run calls the Messages door
    Then no dependency_failed is written
