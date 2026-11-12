Feature: A person's delegation rides beside the agent's own token

  Under TOKENFUSE_AGENT_TOKENS=require the agent's own token is the door
  credential and acts for nobody, and a delegation token is not a door
  credential, so an agent acting on behalf of a person had no door at all.
  The person's identity must reach the policy plane through the gateway as a
  proven chain, so that rules about the root principal, the chain's depth and
  unproven chains judge the person and not a claim.

  The choices are @claude, under delegated authority: the delegation travels in
  x-fuse-delegation with its own proof in x-fuse-delegation-dpop; it must be
  bound to the agent token's key, name the agent as its last actor, name itself
  in its proof, use its proof once and pass the revocation list; and the second
  header is refused wherever there is no agent token to hold it to.

  # @test:a_delegation_beside_an_agent_token_is_proven_and_names_the_person
  # @test:under_require_a_persons_delegation_beside_the_agent_token_reaches_the_pdp_proven
  # @test:the_broker_tells_the_pdp_a_persons_delegation_beside_the_agent_token_is_proven
  Scenario: An agent acting for a person reaches the policy plane with the person's chain proven
    Given TOKENFUSE_AGENT_TOKENS is require
    And an agent presents its own token in Authorization with its proof
    And it presents the person's delegation in x-fuse-delegation with a proof that names it
    When it calls the LLM door or the MCP broker
    Then the call is admitted
    And the policy plane is told the chain is proven, the person first and the agent last

  # @test:the_openai_door_takes_a_persons_delegation_beside_the_agent_token
  Scenario: The OpenAI door takes the delegation with proofs made for its own path
    Given TOKENFUSE_AGENT_TOKENS is require
    When an agent calls the OpenAI door with its token and the person's delegation beside it
    Then the policy plane is told the chain is proven

  # @test:under_require_a_delegation_alone_is_still_not_a_door_credential
  Scenario: A delegation alone still opens no door
    Given TOKENFUSE_AGENT_TOKENS is require
    When a caller presents only a delegation in Authorization
    Then the call is refused as needing an agent token

  # @test:a_delegation_bound_to_another_key_than_the_agent_token_is_refused
  # @test:a_delegation_bound_to_another_key_is_refused_beside_the_agent_token
  # @test:the_broker_refuses_a_delegation_bound_to_another_key_beside_the_agent_token
  Scenario: A delegation issued to another holder is refused
    Given an agent presents its own token
    When the delegation beside it is bound to a different key
    Then the call is refused as a delegation refusal

  # @test:a_delegation_whose_last_actor_is_not_the_agent_is_refused
  # @test:a_delegation_that_authorises_another_agent_is_refused_beside_the_agent_token
  Scenario: A delegation that authorises another agent cannot be borrowed
    Given an agent presents its own token
    When the delegation beside it names another agent as its last actor
    Then the call is refused as a delegation refusal

  # @test:a_revoked_delegation_beside_an_agent_token_is_refused
  # @test:a_revoked_person_stops_the_agent_acting_for_them
  Scenario: Withdrawing the person stops the agent acting for them
    Given the revocation list names the person
    When the agent calls with its token and the person's delegation
    Then the call is refused
    And the same agent calling for nobody is still admitted

  # @test:a_delegation_proof_must_name_the_delegation
  # @test:a_delegation_proof_is_single_use_beside_an_agent_token
  # @test:a_repeated_delegation_header_is_refused
  Scenario: The delegation's proof is its own, used once
    Given an agent presents its own token and the person's delegation
    When the delegation's proof names no token, names the agent token, is missing, was used before, or either header is sent twice
    Then the call is refused

  # @test:a_declared_chain_that_contradicts_the_delegation_beside_an_agent_token_is_refused
  Scenario: A declared chain that disagrees with the delegation is refused
    Given an agent presents its own token and the person's delegation
    When x-fuse-on-behalf-of names a different chain
    Then the call is refused rather than reconciled

  # @test:a_delegation_header_with_no_agent_token_is_refused
  # @test:a_delegation_header_beside_a_static_key_is_refused
  # @test:the_broker_refuses_a_delegation_header_beside_a_static_key
  # @test:a_bearer_credential_alongside_a_delegation_header_is_refused
  # @test:a_filled_delegation_slot_is_never_read_as_empty
  Scenario: The second header is refused where no agent token can hold it
    Given a call admitted by a static key, an XAA token or nothing
    When it carries x-fuse-delegation, even blank
    Then the call is refused rather than the delegation dropped

  # @test:with_no_delegation_beside_it_an_agent_tokens_chain_stays_a_claim
  Scenario: Without a delegation an agent's declared chain stays a claim
    Given an agent presents only its own token
    When it declares a chain in x-fuse-on-behalf-of
    Then the policy plane is told the chain is not proven
