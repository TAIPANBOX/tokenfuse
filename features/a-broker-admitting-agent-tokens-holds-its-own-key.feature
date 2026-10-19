Feature: A broker that admits agent tokens holds its own key for the taint check

  The MCP broker relays a call an agent token admitted to the gateway's
  tool-call check only beside a gateway key of its own. A review of the
  agent-token door found that a broker configured with agent tokens and a taint
  gateway but no key of its own sent the check no credential at all, a gateway
  with client keys answered 401, and the taint fail mode, open by default, then
  let the call through with nothing judging it.

  @decided 2026-10-17: the agent-security review's findings close in their
  wave. @claude 2026-10-19, how this one closes: such a broker refuses to
  start, before it listens,
  naming TOKENFUSE_MCP_TAINT_GATEWAY_KEY_FILE.

  The choices inside it are @claude: the refusal holds in accept and in require
  and whatever the taint fail mode says, since under the closed fail mode the
  same configuration refuses every call a token admits; a broker with no taint
  gateway, or with agent tokens off, needs no key of its own and starts as it
  did.

  # @test:agent_tokens_and_a_taint_gateway_without_the_brokers_key_stop_the_broker
  # @test:agent_tokens_and_a_taint_gateway_need_the_brokers_own_key
  Scenario: Agent tokens and a taint gateway without the broker's own key refuse to start
    Given the agent-token door is on, in accept or in require
    And TOKENFUSE_MCP_TAINT_GATEWAY names a gateway
    When the broker starts with no TOKENFUSE_MCP_TAINT_GATEWAY_KEY_FILE
    Then it exits 2 before it listens
    And the refusal names TOKENFUSE_MCP_TAINT_GATEWAY_KEY_FILE and the two variables that ask for it

  # @test:with_the_brokers_own_key_the_broker_starts
  # @test:agent_tokens_and_a_taint_gateway_need_the_brokers_own_key
  Scenario: With its own key the broker starts
    Given the agent-token door is on and a taint gateway is named
    When the broker starts with TOKENFUSE_MCP_TAINT_GATEWAY_KEY_FILE naming a file that holds its key
    Then it listens

  # @test:agent_tokens_with_no_taint_gateway_need_no_broker_key
  Scenario: With no taint gateway there is nothing to relay a token to
    Given the agent-token door is on and no taint gateway is named
    When the broker starts with no key of its own
    Then it listens

  # @test:a_taint_gateway_with_agent_tokens_off_needs_no_broker_key
  Scenario: With agent tokens off the taint gateway is asked as it always was
    Given the agent-token door is off and a taint gateway is named
    When the broker starts with no key of its own
    Then it listens, and each call is asked about with its caller's own key
