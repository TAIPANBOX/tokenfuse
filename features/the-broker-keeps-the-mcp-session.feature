Feature: The MCP broker keeps the session a stateful MCP server opens

  An MCP server on the official Python SDK runs stateful by default: it hands
  out an Mcp-Session-Id on initialize and refuses every later call that does
  not carry it. The broker passed neither the id nor the negotiated protocol
  version along, so such a server answered initialize and then refused
  everything after it with 400 Bad Request. A notification, which must get no
  answer at all, came back as a JSON-RPC error instead.

  The broker now carries the session in both directions. Over HTTP the client
  holds it: the id the server issued reaches the client bound to that server
  and to the credential that opened it, and comes back to that server only.
  Over stdio there is no header to carry it, so the broker holds it itself.

  # @test:a_stateful_server_keeps_its_session_through_the_broker
  # @test:the_protocol_version_reaches_the_upstream
  Scenario: A stateful server keeps its session through the broker
    Given an upstream MCP server that issues a session on initialize and refuses any call without it
    When an agent initializes, sends notifications/initialized, lists tools and calls one through the broker
    Then the agent receives a session id with the initialize result
    And every later call reaches the server inside that session, with the protocol version the agent sent
    And the list and the call both get results

  # @test:a_session_from_one_upstream_is_never_sent_to_another
  Scenario: A session belongs to the upstream that issued it
    Given two named upstreams behind one broker
    When an agent presents the session the first upstream issued while selecting the second
    Then the broker answers 404 Not Found
    And the second upstream receives nothing

  # @test:a_session_opened_by_one_credential_is_refused_to_another
  Scenario: A session belongs to the credential that opened it
    Given a broker with two client keys
    When a session opened with the first key is presented with the second
    Then the broker answers 404 Not Found and the upstream receives nothing
    And the same session presented with the first key still works

  # @test:a_session_id_the_broker_did_not_issue_is_refused
  # @test:a_bound_session_survives_only_its_own_binding
  # @test:hostile_session_ids_never_panic_and_never_unwrap
  Scenario: A session id the broker did not issue is refused, never forwarded
    Given an upstream that issues sessions
    When an agent presents the upstream's raw session id, or a tampered one, or random bytes
    Then the broker answers 404 Not Found and the upstream receives nothing

  # @test:an_upstream_that_forgot_the_session_sends_the_agent_back_to_initialize
  Scenario: A session the server has forgotten sends the agent back to initialize
    Given an upstream that answers 404 to a session it no longer knows
    When an agent calls through the broker with that session
    Then the agent gets 404 Not Found, which tells an MCP client to initialize again

  # @test:a_notification_is_accepted_with_no_body
  # @test:a_refused_notification_is_an_error_status_without_an_id
  # @test:a_notification_the_broker_refuses_itself_is_an_error_status_too
  Scenario: A notification gets no JSON-RPC answer over HTTP
    Given an upstream that accepts a notification with 202 and no body
    When an agent sends a notification through the broker
    Then the agent gets 202 Accepted with no body
    And when the upstream or the broker refuses it, the agent gets an error status, not a 200

  # @test:the_stdio_transport_holds_the_session_itself
  # @test:a_new_stdio_initialize_replaces_the_held_session
  Scenario: Over stdio the broker holds the session itself
    Given a broker on stdio in front of an upstream that issues sessions
    When an agent initializes, sends a notification, lists tools and calls one over stdio
    Then the upstream sees its own session id and the negotiated protocol version on every call after initialize
    And the agent reads exactly one line per request and none for the notification
    And a second initialize goes out without the old session, and the calls after it carry the new one
