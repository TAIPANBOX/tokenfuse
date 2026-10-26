Feature: A message the broker cannot judge is never forwarded

  The broker judges a call by reading `method` from one JSON-RPC object. A
  JSON-RPC batch is an array of messages, so it has no `method` of its own:
  every check keyed on `tools/call` was skipped, and the array went to the
  upstream as it came. That skipped the policy decision, the identity check,
  the drift refusal, the taint gate, the raw-secret scan of the arguments and
  the tool_call record, and a batched `tools/list` answer was never scanned
  for poisoned descriptions.

  Measured 2026-10-26 against the v1.19.0 release: a batch of two
  `tools/call`, admitted by an agent token, reached the upstream with no
  policy decision and no tool_call record. v1.20.0 has the same code path.

  The Model Context Protocol removed batching in its 2025-06-18 revision, and
  its HTTP transport carries one message per POST. So the broker refuses a
  batch whole, with the JSON-RPC Invalid Request code and nothing forwarded,
  rather than judging each element. A client that still sends batches has to
  send each message on its own.

  Background:
    Given an MCP credential-broker whose policy gate is enforcing
    And an upstream that records every message it receives

  # @test:a_batch_of_tool_calls_is_refused_and_nothing_reaches_the_upstream
  Scenario: A batch of tool calls is refused over HTTP
    Given a policy that denies every tool
    When an attributed caller posts a batch of two tool calls
    Then the answer is HTTP 400 with the Invalid Request code and no id
    And the refusal says it refused a batch
    And the upstream received nothing
    And the policy point was never asked

  # @test:the_stdio_transport_refuses_a_batch_too
  Scenario: The stdio transport refuses the same batch
    Given the broker runs over stdio, where no caller is attributed
    When the same batch arrives as one line
    Then the one answer is the Invalid Request code with no id
    And the upstream received nothing

  # @test:a_message_the_broker_cannot_read_as_one_request_is_refused
  Scenario: A message that is not one readable request is refused
    When a caller posts a bare string, a number, null, or an object whose
      method is not a string
    Then each is refused with HTTP 400 and the Invalid Request code
    And the upstream received none of them

  # @test:a_single_request_and_a_clients_response_still_reach_the_upstream
  Scenario: One request, and a client's answer to the server, still pass
    Given a policy that allows the tool
    When an attributed caller posts one tool call
    And then posts its answer to a request the server made, with an id and a
      result and no method
    Then the tool call is decided once and answered
    And the upstream received both messages, the answer exactly as sent
