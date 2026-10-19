Feature: The policy plane is given the agent token that admitted the call

  Wardryx is told how the door knew the agent (invariant 124), but it trusts the
  gateway's word for who the agent is. The decision of 2026-10-19 is that the
  policy decision point verifies the agent's token itself.

  @decided 2026-10-19: the policy decision point verifies the agent's token itself
  instead of trusting the gateway's word for who the agent is. Paraphrased here.

  The choices inside it are @claude, under delegated authority: the token is sent
  exactly as presented, with the DPoP proof that came with it in a field of its own; both are sent only for a call an
  agent token admitted, never for a static-key call; a token over 4 KiB is not
  sent (a policy that needs it then denies, since the plane finds none); and the
  field is omitted rather than null when there is no token, so a wardryx that
  predates it sees the same body as before.

  # @test:the_wire_body_carries_the_agent_token_only_when_the_call_had_one
  # @test:a_proof_for_the_policy_plane_is_the_dpop_header_within_the_cap
  # @test:the_policy_plane_is_sent_the_agent_token_when_a_token_admitted_the_call
  # @test:a_static_key_call_is_never_sent_an_agent_token
  # @test:the_broker_sends_the_agent_token_to_the_pdp
  # @test:the_broker_sends_no_agent_token_for_a_static_key_call
  # @test:a_token_for_the_policy_plane_is_bounded_at_4_kib
  # @test:a_token_for_the_policy_plane_is_only_an_agent_token
  Scenario: A token-admitted call sends the token to the policy plane
    Given the agent-token door admits an agent's call
    When the call reaches the policy decision point
    Then the decide request carries the agent's token exactly as presented
    And it carries the DPoP proof that came with it, as presented, in its own field

  # @test:a_static_key_call_is_never_sent_an_agent_token
  # @test:the_broker_sends_no_agent_token_for_a_static_key_call
  Scenario: A static-key call sends no token
    Given a call admitted by a static client key
    When the call reaches the policy decision point
    Then the decide request has no agent_token member

  # @test:an_oversized_agent_token_is_admitted_but_not_forwarded
  # @test:a_token_for_the_policy_plane_is_bounded_at_4_kib
  Scenario: A token over the size cap is admitted and not forwarded
    Given an agent's token larger than 4 KiB
    When the agent calls with it
    Then the call is admitted
    And the decide request has no agent_token member

  # @test:the_broker_sends_the_agent_token_to_the_pdp
  Scenario: The broker's policy question carries the token too
    Given the MCP broker admits an agent by its token
    When the broker asks the policy plane about a tools/call
    Then the decide request carries the agent's token

  # @test:a_token_admitted_allow_is_not_served_to_a_client_key_call
  Scenario: A verdict reached on a token is not served to a static-key call
    Given the policy plane answered an agent token's call for an agent and its tools
    When a static-key call for the same agent and tools arrives inside the cache TTL
    Then the policy plane is asked again for the static-key call
