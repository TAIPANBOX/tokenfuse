Feature: A gateway that authenticates nobody beyond loopback says so

  The agent-security review of 2026-10-17 (finding F-010) read that the shipped
  image binds 0.0.0.0:4100 and, with TOKENFUSE_CLIENT_KEYS unset, serves anyone
  who can reach the port, with nothing at startup to say so.

  @decided 2026-10-17: close the agent-security findings of that review,
  starting with defaults and small fixes, on the hybrid architecture. For this
  part of the finding: when client authentication is off and the bind address
  is not loopback, the gateway prints a loud warning at startup and its health
  detail says so. Keeping the plain /healthz answer byte-identical is @claude,
  because every launcher probes it.

  # @test:an_open_bind_with_no_client_keys_is_said_at_startup
  Scenario: Startup says it
    Given TOKENFUSE_CLIENT_KEYS is unset
    When the gateway starts bound to 0.0.0.0
    Then its output says client authentication is OFF and names TOKENFUSE_CLIENT_KEYS

  # @test:the_health_detail_says_the_gateway_is_open_to_the_network
  Scenario: The health detail says it
    Given TOKENFUSE_CLIENT_KEYS is unset and the bind is 0.0.0.0
    When an operator asks for /healthz?detail=1
    Then the answer is JSON with client_auth off, bind not_loopback and a warning naming TOKENFUSE_CLIENT_KEYS

  # @test:the_plain_health_answer_is_unchanged_on_any_bind
  Scenario: The plain health answer does not move
    When a launcher probes /healthz on either bind
    Then the answer is ok

  # @test:a_loopback_bind_with_no_client_keys_is_not_warned_about
  Scenario: Loopback is not warned about
    Given TOKENFUSE_CLIENT_KEYS is unset
    When the gateway starts bound to 127.0.0.1
    Then nothing says client authentication is OFF

  # @test:client_keys_on_an_open_bind_are_not_warned_about
  Scenario: Client keys on an open bind are not warned about
    Given TOKENFUSE_CLIENT_KEYS is set
    When the gateway starts bound to 0.0.0.0
    Then nothing says client authentication is OFF
