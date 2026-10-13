Feature: The OWASP MCP Top 10 rows say only what a test holds

  Where the ask came from. The compliance catalog cites OWASP's Agentic
  Applications list and nothing from the MCP Top 10. The ask was to add the MCP
  rows where a test in this repository proves the control works, in the same
  honest grades every other row uses, and to record what is refused. Nothing
  here was reconstructed from memory: the list was read from the OWASP project's
  own repository on 2026-10-13, and owasp.org itself refused the connection from
  the build machine that day.

  What this does not claim. A row here is a claim about what a control does,
  not that a company is compliant with the list. Each claim below is held by a
  named test, and a claim with no test is not written down at all.

  # @test:the_owasp_mcp_top_10_is_declared_and_its_rows_quote_the_fetched_titles
  Scenario: Every MCP row quotes an item of the fetched list by its own title
    Given the catalog cites the OWASP MCP Top 10 in several places
    When each citation is read
    Then each one names an item id and that item's title as the list gives it
    And the list is declared with its 2025 edition

  # @test:hostile_listings_without_a_stock_phrase_are_found
  Scenario: A poisoned tool listing is found without a stock phrase
    Given a tool description that tells the model to run another tool first
    When the broker scans the listing
    Then the scan reports it, although no stock phrase appears in it

  # @test:a_drifted_tool_is_refused_before_anything_is_forwarded
  Scenario: A tool changed after approval cannot be called
    Given a tool whose definition has changed since the lock was pinned
    When an agent calls that tool
    Then the call is refused and nothing reaches the upstream

  # @test:an_injection_in_a_trusted_source_is_still_an_injection
  Scenario: Instructions inside a trusted source still gate the tools that follow
    Given a tool result that carries instructions, from a source classed as trusted
    When the next dangerous tool call is asked for
    Then the run is refused, because the content is an injection and not a fact about its source

  # @test:a_brokered_tool_call_is_recorded_when_no_policy_gate_is_configured
  Scenario: A brokered tool call is written down even with no policy engine
    Given a broker with no policy plane configured
    When an agent's tool call is brokered to the upstream
    Then the call is recorded once with the agent it was made for

  # @test:a_captured_proof_replayed_at_the_live_door_reaches_nothing_the_second_time
  Scenario: A captured door proof is worth one call
    Given a proof of possession captured from a harmless call
    When the same proof is presented again to the broker
    Then the second use is refused and nothing more reaches the upstream

  # @test:with_only_xaa_configured_a_call_with_no_credential_is_refused
  Scenario: A broker with only the token door configured refuses an anonymous caller
    Given the access-token door is the only door configured
    When a call arrives with no credential at all
    Then the call is refused

  # @test:an_open_bind_with_no_keys_refuses_to_start
  Scenario: A broker bound to a public address with no credential does not start
    Given the broker is asked to listen on a non-loopback address
    And no credential is configured
    When it starts
    Then it refuses to start and names the missing configuration

  # @test:a_scoped_secret_is_refused_for_a_different_agent_and_nothing_is_forwarded
  Scenario: A secret scoped to one agent is refused to another, and the call goes nowhere
    Given a secret whose scope names one agent
    When a different agent's call asks for that secret
    Then the whole call is refused and nothing is forwarded

  # @test:a_tool_scoped_secret_is_refused_for_a_different_tool
  Scenario: A secret scoped to one tool is refused for another tool
    Given a secret whose scope names one tool
    When a call to a different tool asks for that secret
    Then the whole call is refused

  # @test:a_secret_handle_reaches_the_pdp_as_the_handle_and_never_as_the_value
  Scenario: The policy engine is shown the handle, never the secret
    Given a call that names a vault secret by its handle
    When the broker asks the policy engine about the call
    Then the policy engine sees the handle and the upstream sees the value

  # @test:redacts_secret_in_response
  Scenario: A secret that comes back in a reply is redacted before it is relayed
    Given an upstream whose reply contains a credential
    When the broker relays the reply to the agent
    Then the credential is redacted in what the agent receives

  # @test:the_owasp_mcp_items_refused_are_cited_by_no_control
  Scenario: Items the product does not address are not claimed
    Given three items of the list that no control in this product holds
    When the catalog is read
    Then no row cites any of them

  # @test:the_mcp_auth_and_scope_rows_are_partial_because_their_limits_are_real
  Scenario: The broker's door and secret scopes are Partial, never Enforced
    Given both the door and the secret scopes are opt-in
    When the two rows are read
    Then each is graded Partial
