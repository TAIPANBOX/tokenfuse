Feature: A refused delegation proof is not answered as a missing client credential

  A vouchryx-issued, DPoP-bound delegation token presented at either door
  (the LLM proxy's `/v1/messages` and `/v1/chat/completions`, and the MCP
  broker's classic door) is judged by `chainproof::resolve`. Until this was
  found live on 2026-09-27, a refused chain answered with the SAME 401 a
  missing or wrong `x-fuse-key` gets: "this gateway requires a client
  credential in the `x-fuse-key` header" - true of nothing the caller did,
  on a gateway that never configured client keys at all.

  The wire still must not distinguish WHICH refusal it was (a forged
  signature, an expired or revoked token, a token bound to a key the caller
  does not hold, or a declared chain that contradicted the verified one):
  narrating that to the caller is an oracle. What changed is that the single,
  cause-free answer now says a delegation proof was refused, with its own
  `type`, and never names `x-fuse-key` or a client credential.

  The OPERATOR's log is not held to the wire's silence: it used to fold all
  nine `tokenfuse_delegation::Refusal` causes into one `reason=BadToken`, so
  a revoked token and a forged one read identically. The log line now names
  the precise cause, never the token itself.

  # @test:a_refused_delegation_token_is_not_told_to_fix_a_client_credential
  Scenario: A forged delegation token on the LLM door is not told to fix x-fuse-key
    Given a gateway with a delegation issuer configured and no client keys at all
    When a request presents a delegation token signed by a key the issuer never published
    Then the answer is 401 with type "delegation_refused"
    And its reason names no client credential and no x-fuse-key header

  # @test:a_refused_delegation_token_at_the_mcp_door_is_not_told_to_fix_a_client_credential
  Scenario: The same refusal on the MCP broker's classic door is answered the same way
    Given an MCP broker with a delegation issuer configured and no client keys at all
    When a request presents a delegation token signed by a key the issuer never published
    Then the answer is 401 with type "delegation_refused"
    And its reason names no client credential and no x-fuse-key header

  # @test:a_revoked_token_and_a_forged_one_are_logged_by_their_own_cause
  Scenario: The operator's log tells a revoked token from a forged one
    Given a gateway with a delegation issuer and a revocation list naming one token revoked
    When that revoked token is presented, and separately a token signed by an unpublished key
    Then the log names the revoked token's cause as Revoked
    And the log names the forged token's cause as BadSignature, distinctly
