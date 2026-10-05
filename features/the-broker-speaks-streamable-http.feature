Feature: The MCP broker reaches servers built on the official MCP Python SDK

  An MCP server on the official Python SDK answered the broker 406 Not
  Acceptable. The streamable HTTP transport requires a client to accept both
  application/json and text/event-stream, and the broker named neither, so it
  sent its HTTP client's default "*/*", which SDK 1.x does not read as either.
  The broker now sends the Accept the specification requires. Because it now
  says it accepts an event stream, it also reads one: the SDK answers with a
  stream by default, and the broker relays the response it finds there.

  # @test:a_server_that_refuses_a_wildcard_accept_answers_the_broker
  # @test:the_accept_header_names_json_and_event_stream
  Scenario: A server that refuses a wildcard Accept answers the broker
    Given an upstream MCP server that answers 406 unless Accept names application/json and text/event-stream
    When an agent sends initialize and then a tools/call through the broker
    Then both get a result and neither gets an error
    And the Accept the server saw is "application/json, text/event-stream"

  # @test:an_event_stream_reply_is_answered_with_its_response_frame
  # @test:an_event_stream_reply_yields_the_response_to_this_request
  Scenario: A reply sent as an event stream is answered with its response
    Given an upstream that answers a tools/call as text/event-stream
    And the stream carries a progress notification and a server request reusing the call's id before the response
    When an agent makes the call through the broker
    Then the agent gets the response, with the call's id
    And not the notification and not the server's request

  # @test:an_event_stream_without_the_response_is_an_error_naming_the_request
  # @test:a_response_to_another_request_is_not_this_ones
  Scenario: A stream that never answers the request is an error, not a guess
    Given an upstream whose event stream carries no response to the call
    When an agent makes the call through the broker
    Then the agent gets a JSON-RPC error naming the request id it sent

  # @test:a_secret_in_an_event_stream_reply_is_redacted
  # @test:a_poisoned_tool_list_in_an_event_stream_is_blocked
  Scenario: A streamed reply goes through the same checks as a JSON one
    Given an upstream that answers as text/event-stream
    When its tool result carries a cloud access key
    Then the agent sees the key redacted
    When its tools/list carries a poisoned description and scanning blocks
    Then the agent gets the poisoning refusal

  # @test:a_json_reply_is_read_as_json_with_or_without_a_content_type
  # @test:hostile_reply_bodies_never_panic
  Scenario: A JSON reply is read as before, and no reply body brings the broker down
    Given an upstream that answers with JSON, with or without a content type
    Then the broker reads it exactly as it always did
    And random bytes under either content type are an error, never a crash
