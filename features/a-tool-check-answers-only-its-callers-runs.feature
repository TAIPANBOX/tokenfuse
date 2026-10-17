Feature: The tool-call check answers only for the caller's own runs

  The agent-security review of 2026-10-17 (finding F-024) measured that
  POST /v1/fuse/check-tool-call answered a caller with no credential, for a run
  another caller had opened, with that run's taint labels, on a gateway whose
  client keys were on. The labels say what the run read.

  @decided 2026-10-17: close the agent-security findings of that review,
  starting with defaults and small fixes, on the hybrid architecture. For this
  finding: the route requires a client key whenever client keys are configured
  and answers only for runs that belong to the caller's identity; without
  client keys it keeps today's behaviour, documented. A run belongs to the
  client key whose metered call first named it (@claude), and a check about a
  run the caller does not own is answered deny with nothing of the run in it
  (@claude). The MCP broker asks with the caller's own client key, and a
  refusal from the check is not a permission (@claude).

  # @test:with_client_keys_a_check_without_a_key_is_refused
  # @test:with_client_keys_a_check_with_no_key_is_refused_before_anything_is_read
  Scenario: No key, no answer
    Given client keys are configured
    When a check arrives with no x-fuse-key
    Then it is refused with 401 and the answer names nothing the run read

  # @test:with_client_keys_a_check_with_an_unknown_key_is_refused
  Scenario: An unknown key, no answer
    Given client keys are configured
    When a check arrives with a key nobody configured
    Then it is refused with 401

  # @test:a_check_about_another_keys_run_says_nothing_about_it
  Scenario: Another caller's run is not described
    Given key A opened a run that read the web
    When key B asks whether a tool may run in that run
    Then the answer is deny
    And it carries no label and no rule of that run

  # @test:the_owner_of_a_run_is_answered_as_before
  Scenario: The owner is answered as before
    Given key A opened a run that read the web
    When key A asks whether run_shell may run in it
    Then the answer is deny by no-exec-after-untrusted, carrying web

  # @test:without_client_keys_the_check_is_unchanged
  # @test:without_client_keys_a_check_is_answered_as_before
  Scenario: A gateway with no client keys authenticates nobody, here too
    Given no client keys are configured
    When any caller asks about a run
    Then it is answered as before

  # @test:the_broker_asks_the_gateway_with_the_callers_client_key
  Scenario: The broker asks with the caller's key
    Given the MCP broker's taint gate points at the gateway
    When a caller presents x-fuse-key to the broker
    Then the broker's check carries that key

  # @test:a_check_the_gateway_refuses_to_answer_is_not_read_as_permission
  Scenario: A refused check is not a permission
    Given the gateway answers the broker's check with 401
    And the broker's taint gate fails closed
    When a tool call arrives
    Then the call is refused, naming the status, and nothing is forwarded
