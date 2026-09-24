Feature: The MCP broker accepts a vouchryx Cross App Access bearer token

  @claude 2026-09-24, a decision taken under delegated authority, open to
  reversal: a vouchryx-issued Cross App Access (XAA) access token, presented
  as a bearer credential, is a third way into the MCP broker, judged on its
  own and before the two existing doors. Unlike a shared secret or a proof of
  possession, it proves who is calling by a signature this broker verifies
  offline, so it is treated as a third door rather than folded into either
  existing one.

  What this deliberately does not claim. It does not bind the request to a
  key: this is a bearer credential, and a token carrying a key-binding claim
  is refused rather than accepted with the binding ignored, because this
  door never has a proof of that key to check. It does not check the token's
  scope against anything yet. It does not authenticate this broker to the
  upstream MCP server, the same limit the other two doors already carry. And
  a delegation token proving whom a call acts for is not the same thing as a
  credential proving the call may be served at all: presenting one alone
  does not open this door.

  Background:
    Given an MCP credential-broker with TOKENFUSE_MCP_ACCEPT_XAA=on and a
      TOKENFUSE_MCP_RESOURCE configured
    And a vouchryx issuer this broker trusts, named by TOKENFUSE_DELEGATION_ISSUER
      and TOKENFUSE_DELEGATION_JWKS

  # @test:the_resource_metadata_names_vouchryx
  Scenario: A client discovers where to get a token
    When it asks for the broker's protected-resource metadata
    Then the response names the configured resource and the trusted issuer

  # @test:the_resource_metadata_is_also_served_at_the_resources_own_path
  Scenario: The metadata is also reachable at the resource's own path
    Given the configured resource has its own path
    When a client asks for the metadata at that path's own well-known suffix
    Then it gets the same answer as the bare well-known path

  # @test:the_well_known_paths_404_when_xaa_is_off
  Scenario: Turning the door off removes the metadata entirely
    Given TOKENFUSE_MCP_ACCEPT_XAA is off
    When a client asks for the protected-resource metadata
    Then it gets the same 404 it would have gotten before this door existed

  # @test:a_401_points_at_the_resource_metadata
  Scenario: A refused call is told where to go
    When a call is refused for any reason at this broker
    Then its response carries a header naming where the metadata is served

  # @test:a_401_carries_no_www_authenticate_when_xaa_is_off
  Scenario: The pointer only appears once there is somewhere for it to point
    Given TOKENFUSE_MCP_ACCEPT_XAA is off
    When a call is refused for any reason
    Then its response carries no such header

  # @test:a_vouchryx_token_is_attributed_to_its_agent
  Scenario: A well-formed token reaches the upstream as its own agent
    Given a token the trusted issuer minted for this broker's resource
    When the client calls a tool with it
    Then the call reaches the upstream MCP server
    And the policy engine is told the chain and that it was proven
    And the record of the call carries the chain but no delegation proof,
      because a bearer credential has no holder for a proof to name

  # @test:a_token_for_another_resource_is_refused_at_the_broker
  Scenario: A token minted for a different resource is refused
    Given a token the trusted issuer minted for a different resource
    When the client presents it here
    Then the call is refused

  # @test:with_only_xaa_configured_a_call_with_no_credential_is_refused
  Scenario: Presenting nothing is not the same as the door being unconfigured
    Given no other door is configured on this broker
    When a call arrives with no credential at all
    Then it is refused, exactly as it would be if a shared secret were the
      only door configured

  # @test:with_xaa_on_a_delegation_token_alone_does_not_open_the_door
  Scenario: A chain proof is not a door credential
    Given no other door is configured on this broker
    When a call presents only a delegation token proving whom it acts for
    Then it is still refused, because proving who a call is for is a
      different question from whether the call may be served at all

  # @test:a_bound_token_presented_as_bearer_is_refused
  Scenario: A token bound to a key is not a bearer credential
    Given a token carrying a key-binding claim
    When it is presented here with no proof of that key
    Then it is refused

  # @test:an_exchange_token_presented_as_bearer_is_refused
  Scenario: A delegation token is not an access token
    Given a token with no client identifier claim, shaped like a delegation
      token rather than an access token
    When it is presented at this door
    Then it is refused

  # @test:a_revocation_naming_the_agent_in_an_access_tokens_chain_refuses_it
  Scenario: Revoking the agent, not only the person, is honoured
    Given the agent named in a token's chain has been revoked
    When the token is presented here
    Then it is refused

  # @test:an_algorithm_taken_from_the_header_is_refused_for_an_access_token
  Scenario: The signing algorithm comes from the key, never from the token
    Given a token whose header claims an algorithm the issuer's key does not use
    When it is presented here
    Then it is refused before any signature bytes are even checked

  # @test:a_failed_xaa_bearer_never_falls_through_to_a_valid_bearer_key
  Scenario: A broken token does not fall back to a weaker door
    Given a call carrying both a broken XAA token and a valid shared-secret
      credential
    When it is presented
    Then it is refused, and the shared-secret credential is never consulted

  # @test:a_bearer_credential_alongside_x_fuse_key_is_refused
  Scenario: Two credentials at once is confusion, not a choice to make for the caller
    Given a call carrying a well-formed XAA token and a shared-secret
      credential together
    When it is presented
    Then it is refused

  # @test:a_declared_chain_that_disagrees_with_the_xaa_token_is_refused
  Scenario: A caller may not talk over its own credential
    Given a token naming one chain
    When the caller also declares a different chain in a header
    Then the call is refused

  # @test:a_declared_chain_that_matches_the_xaa_tokens_chain_is_admitted
  Scenario: Agreeing is not the same as disagreeing
    Given a token naming a chain
    When the caller also declares that exact same chain in a header
    Then the call is admitted, because a chain that only repeats what the
      token already proved is not a contradiction

  # @test:a_chain_over_the_cap_is_refused_at_the_xaa_door_too
  Scenario: The chain-length limit holds at this door too
    Given a token this door verifies successfully
    When the caller also declares a chain far longer than the Agent Passport
      limit
    Then the call is refused with the same over-length answer every door gives,
      not the door's own refusal

  # @test:the_bearer_scheme_is_case_insensitive
  Scenario: The credential scheme is read the way the standard defines it
    Given a well-formed token
    When it is presented with the bearer scheme written in any mix of case
    Then the call is admitted

  # @test:xaa_off_leaves_an_authorization_bearer_request_exactly_as_before
  Scenario: Turning the door off restores the old behaviour exactly
    Given TOKENFUSE_MCP_ACCEPT_XAA is off
    When a call carries a bearer-scheme credential
    Then it is treated exactly as it was before this door existed

  # @test:a_bad_accept_xaa_value_refuses_to_start
  Scenario: A misspelt setting refuses to start rather than guessing
    Given TOKENFUSE_MCP_ACCEPT_XAA is set to something other than the two
      recognised values
    When the broker starts
    Then it refuses to start and names the variable

  # @test:xaa_on_with_no_delegation_issuer_configured_refuses_to_start
  Scenario: Turning the door on needs an issuer to verify against
    Given TOKENFUSE_MCP_ACCEPT_XAA is on and no delegation issuer is configured
    When the broker starts
    Then it refuses to start and names what is missing

  # @test:xaa_on_together_with_require_proof_refuses_to_start
  Scenario: Closing one bearer door does not reopen another
    Given the broker requires a proof of possession on its other door
    When TOKENFUSE_MCP_ACCEPT_XAA is also turned on
    Then the broker refuses to start and names both settings

  # @test:accept_xaa_on_with_no_resource_exits_2_and_names_the_variable
  Scenario: The real binary is what proves the wiring, not only the logic
    Given the real broker binary, not a test double
    When it is started with the door on and no resource named
    Then it exits with the same failure code every other startup refusal
      gives and names the missing variable
