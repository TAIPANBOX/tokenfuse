Feature: The attestation the policy plane is told comes from the door

  The agent-security review of 2026-10-17 (finding F-005) read that both doors
  copied the caller's x-fuse-attestation-method header into the question they
  put to wardryx, so a deny_if_unattested policy admitted any caller that wrote
  spiffe-svid, and the decision record said the agent was attested.

  @decided 2026-10-17: close the agent-security findings of that review,
  starting with defaults and small fixes, on the hybrid architecture. For this
  finding: the attestation method is derived from the door that authenticated
  the call and the client header is ignored, with one log line. The mapping is
  @claude and uses only the agent-passport 4.3 words: a proof of possession of a
  key on the request (a DPoP-bound delegation, or the broker's proof door) is
  dpop-key; a bearer credential (a client key, an XAA token) and no credential
  are none, because holding a shared secret binds no workload.

  # @test:a_client_attestation_header_never_reaches_the_pdp
  # @test:the_broker_never_tells_the_pdp_an_attestation_the_caller_wrote
  Scenario: A header the caller wrote never reaches the PDP
    Given the wardryx hook enforces
    When a call with no proof of possession sends x-fuse-attestation-method spiffe-svid
    Then the PDP is told none

  # @test:a_call_with_no_proof_is_sent_as_none_not_left_out
  Scenario: Nothing proven is said, not left out
    Given the wardryx hook enforces
    When a call carries no proof and no header
    Then the PDP is told none

  # @test:a_proven_delegation_is_attested_as_dpop_key_whatever_the_header_says
  Scenario: A DPoP-bound delegation is attested as dpop-key
    Given the gateway verifies delegation tokens
    When a call carries a delegation token and its proof of possession
    And it also sends x-fuse-attestation-method spiffe-svid
    Then the PDP is told dpop-key

  # @test:a_call_admitted_by_a_proof_of_possession_is_attested_as_dpop_key
  Scenario: The broker's proof door is attested as dpop-key
    Given the MCP broker's only door is the proof door
    When a client presents its proof and a header naming spiffe-svid
    Then the PDP is told dpop-key
