Feature: An agent's own token is the door credential

  The agent-security review of 2026-10-17 (findings F-001 and F-005) found an
  agent's identity was a header the caller wrote, at every door, on every
  launcher, so a credential could not stop one agent and a policy could not tell
  a proven agent from a claimed one.

  @decided 2026-10-18: every agent gets its own short-lived credential from
  vouchryx, verified offline at every door; the agent and its unit come from that
  credential and never from a header; static client keys keep working beside it
  until a later release dates their end, and launchers accept both; and the
  policy plane is told how the door knew the agent.

  The choices inside it are @claude: the switch is TOKENFUSE_AGENT_TOKENS (off,
  accept, require); a token is verified against the delegation door's own issuer,
  key set, audience and origin; a proof of possession is single-use and must name
  the token it came with; a token is refused beside a client key; and the MCP
  broker relays a token to the tool-call check beside its own key.

  # @test:an_agent_token_verifies_and_carries_its_unit_and_org
  # @test:an_agent_token_is_admitted_and_the_record_names_its_agent_and_unit
  Scenario: An agent token is admitted and the record names its agent and unit
    Given the agent-token door accepts tokens
    When an agent calls with its own token and a proof that names it
    Then the call is admitted with no client key
    And the record files it under the token's agent and the token's unit

  # @test:a_header_naming_another_agent_beside_its_token_is_refused_whatever_the_strict_mode
  # @test:the_broker_refuses_a_header_naming_another_agent_than_its_token
  # @test:a_token_contradicted_by_its_header_or_the_identity_map_is_a_mismatch
  Scenario: A header naming another agent than the token is refused
    Given strict identity is off
    When an agent token arrives with x-fuse-agent-id naming another agent
    Then the call is refused as an identity mismatch, at the LLM door and at the MCP broker

  # @test:an_identity_map_binding_the_agent_to_another_unit_is_refused
  Scenario: The identity map cannot move the agent to another unit
    Given an identity map that binds the agent to another unit than its token carries
    When the agent calls with its token
    Then the call is refused as a unit that contradicts the map

  # @test:a_delegation_token_is_never_an_agent_token_and_the_reverse
  Scenario: A delegation token is not an agent token, and the reverse
    Given a token whose header type is not at+jwt
    When it is presented as an agent token
    Then it is refused, and an at+jwt token is refused as a delegation chain

  # @test:an_agent_tokens_audience_is_required_and_exact
  # @test:agent_tokens_on_need_the_door_a_named_audience_and_a_list_that_fails_closed
  # @test:agent_tokens_with_an_empty_audience_stop_the_gateway_before_it_serves
  Scenario: An empty audience accepts nothing
    Given the agent-token door is on
    When no audience is configured, or a token names another audience or another issuer
    Then the process refuses to start, or the token is refused

  # @test:an_agent_token_expires_at_its_leeway_and_not_before
  # @test:an_agent_token_issued_in_the_future_is_refused_past_the_leeway
  Scenario: A token is good for its life plus thirty seconds of clock drift
    Given an agent token that lives five minutes
    When it is presented 29 seconds after it expired, or issued 30 seconds ahead
    Then it is admitted, and one second further either way it is refused

  # @test:a_proof_that_does_not_name_this_token_is_refused
  # @test:a_proof_that_does_not_name_the_agent_token_is_refused_at_the_door
  # @test:an_agent_token_needs_its_holders_proof_and_a_binding
  Scenario: The proof must be the holder's and must name the token
    Given an agent token bound to its holder's key
    When the proof is missing, signed by another key, or names no token or another token
    Then the call is refused

  # @test:a_replayed_agent_token_proof_is_refused_the_second_time
  # @test:the_broker_refuses_a_replayed_agent_token_proof
  # @test:with_agent_tokens_on_a_delegation_proof_is_single_use_and_names_its_token
  # @test:with_agent_tokens_on_a_delegation_proof_is_single_use_too
  Scenario: A proof is used once
    Given the agent-token door is on
    When the same proof arrives a second time, with an agent token or a delegation token
    Then the second call is refused

  # @test:a_revoked_agent_token_is_refused_by_its_subject_or_its_jti
  # @test:a_revoked_agent_is_refused_at_the_door
  Scenario: A revoked agent is stopped at the door
    Given vouchryx's revocation list names the agent
    When the agent calls with a token issued before the revocation
    Then the call is refused

  # @test:an_agent_token_beside_a_client_key_is_refused
  # @test:the_broker_refuses_an_agent_token_beside_a_client_key
  Scenario: Two credentials on one call are refused
    Given the agent-token door is on
    When a call carries an agent token and a client key
    Then it is refused, never admitted by either

  # @test:accept_keeps_static_keys_working_beside_agent_tokens
  # @test:with_agent_tokens_off_an_agent_token_is_not_a_door_credential
  Scenario: Accept keeps static keys, and off changes nothing
    Given the door accepts tokens, or is off
    When a static key calls, and an agent token calls
    Then under accept both are admitted as two principals, and with the door off a token alone opens nothing

  # @test:require_refuses_a_static_key_and_admits_an_agent_token
  # @test:require_refuses_the_brokers_static_key_and_admits_a_token
  Scenario: Require refuses every static key
    Given the door requires tokens
    When a static client key calls the LLM door or the MCP broker
    Then it is refused and told the scheme it needs, and an agent token is admitted

  # @test:a_run_an_agent_token_opened_is_refused_to_a_static_key
  Scenario: A run an agent token opened belongs to the agent
    Given an agent token opened a run
    When a static key names that run
    Then the call is refused as a run owned elsewhere

  # @test:the_openai_door_admits_an_agent_token_proved_for_its_own_path
  Scenario: The OpenAI door takes the token too
    Given the gateway serves the OpenAI door
    When an agent calls it with its token and a proof for that door's path
    Then the call is admitted under the token's agent

  # @test:the_broker_admits_an_agent_token_and_tells_the_pdp_who_and_how
  # @test:the_policy_plane_is_told_how_the_door_knew_the_agent
  # @test:the_identity_source_is_the_door_that_admitted_the_call
  Scenario: The policy plane is told how the door knew the agent
    Given the policy hook enforces
    When an agent token, a client key, and no credential each make a call
    Then wardryx is told agent-token, client-key and none, and a token is attested as dpop-key

  # @test:the_tool_check_answers_an_agent_token_about_its_own_run
  Scenario: The tool-call check answers an agent about its own run
    Given an agent token opened a run
    When the agent asks the tool-call check about it with its token and a proof for that route
    Then it is answered, and another principal asking about the run is told deny and nothing else

  # @test:the_tool_check_answers_a_relayed_agent_token_about_its_runs_only
  # @test:the_broker_relays_an_agent_token_to_the_taint_gateway_with_its_own_key
  # @test:a_relayed_agent_token_skips_the_proof_and_nothing_else
  Scenario: The MCP broker relays the token to the tool-call check
    Given the MCP broker admitted a call by an agent token
    When it asks the gateway's tool-call check about the call's run
    Then it sends its own key and the token, the check answers about the token's runs only, and any other key beside a token is refused

  # @test:a_mistyped_agent_tokens_switch_stops_the_gateway_before_it_serves
  # @test:agent_tokens_with_no_delegation_door_stop_the_broker_before_it_serves
  # @test:the_agent_tokens_switch_reads_three_words_and_refuses_a_fourth
  # @test:agent_tokens_off_still_start_the_gateway
  Scenario: A switch the process cannot act on stops it before it serves
    Given TOKENFUSE_AGENT_TOKENS names a word it does not know, or a door with nothing to verify with
    When the gateway or the broker starts
    Then it exits 2 naming what is missing, and off starts as before
