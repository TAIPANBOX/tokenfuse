Feature: A brokered tool call names its run on the bus

  Measured 2026-10-14 on forge: the MCP broker's tool_call events named no
  run, so an egress policy per run or per agent could not be written from the
  bus.

  @decided 2026-10-14: the record carries the caller's run id when the request
  has one. Invariant 108.

  # @test:a_brokered_tool_call_record_carries_the_callers_run_id
  Scenario: The run the caller named is on the record, and none is invented
    Given a broker with no policy gate, and one whose gate allows the call
    When an agent calls a tool naming run-egress-7, and again naming no run
    Then the first tool_call record names run-egress-7
    And the second names no run
