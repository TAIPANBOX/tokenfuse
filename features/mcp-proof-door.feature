Feature: The MCP broker's door takes a key instead of a password

  Where the ask came from, and what it did not come with. There is no verbatim
  @yurii sentence behind this one, and pretending otherwise would be the worst
  failure the provenance rule has. It is block B5 of
  agent-identity-plan-2026-08-25.md, which is `@claude`: "CIMD
  (draft-ietf-oauth-client-id-metadata-document) and DPoP in the MCP credential
  broker". Two judgements were named as open in the ask itself and are answered
  in the scenarios below rather than assumed: whether a client id is worth a
  network fetch on a request path, and what DPoP here does NOT do.

  What was there before. Invariant 20 closed who may reach the broker's port.
  Invariant 23 closed which secret they may pull once inside. The credential ON
  the door stayed TOKENFUSE_MCP_KEYS, a shared secret in a header, which lives
  in a deployment manifest, an environment variable, a shell history, a CI log
  and every request on the wire, and which is the whole of the identity for
  whoever captures it. That is an odd thing to guard a vault with, and the
  vault is exactly what is behind it.

  What this deliberately does not claim. It does not authenticate the agent to
  the upstream MCP server; the broker forwards with whatever the vault injects
  and the upstream sees the broker. It is not a delegation check and says
  nothing about whom a caller acts for. It does not narrow which secret may be
  pulled, which is a separate axis. And it does nothing against a client whose
  private key has been taken, because a key an attacker holds is exactly as
  good as a password an attacker holds.

  Background:
    Given an MCP credential-broker with a vault of real secrets
    And a client that has published its own metadata document at an https
      client_id URL, naming its public key

  # @test:a_call_carrying_a_proof_of_possession_reaches_the_upstream
  Scenario: A client gets in without ever having been given a secret
    Given the operator has allowlisted that client's document
    When the client calls a tool and proves it holds the matching private key
    Then the call is served
    And the secret handle is resolved and reaches the upstream
    And at no point did the operator mint, hand over or store a shared secret

  # @test:a_call_with_no_proof_reaches_nothing_when_the_proof_door_is_the_only_one
  Scenario: A caller with nothing to present reaches nothing
    Given the proof door is the only one configured
    When a call arrives with no proof
    Then it is refused
    And no handle is resolved and no upstream is contacted, because a refusal
      that still forwards is not a refusal

  # @test:a_captured_proof_replayed_at_the_live_door_reaches_nothing_the_second_time
  Scenario: A captured request is worth exactly one request
    Given every call to this broker is a POST to the same path, so binding a
      proof to a method and a URL pins almost nothing
    When somebody captures a proof from a harmless call and presents it again
    Then the second use is refused
    And only the first ever reached the upstream

  # @test:a_proof_from_a_key_no_client_published_is_refused
  Scenario: The identity is the key, not something the caller says
    Given a stranger holding a perfectly good key of their own
    When they present a proof signed with it
    Then it is refused, because no configured client published that key
    And the caller was never asked, and never able, to name which client it is

  # @test:a_broken_proof_is_never_downgraded_to_the_bearer_door
  Scenario: A broken proof is a refusal, never a fall back to the password
    Given both doors are configured while clients move across
    And an attacker holding a stolen x-fuse-key credential
    When they send that credential together with a proof that does not verify
    Then the call is refused
    And the stolen credential did not rescue it, because a caller that presents
      a proof is judged by it

  # @test:with_both_doors_configured_a_bearer_key_and_no_proof_still_gets_in
  Scenario: Adding the first client breaks none of the others
    Given both doors are configured
    When an existing client calls with its shared secret and no proof
    Then it is still served, exactly as it was yesterday

  # @test:both_doors_configured_says_out_loud_that_the_bearer_one_is_still_open
  Scenario: The weaker door announces that it is still open
    Given both doors are configured and nothing has closed the older one
    When the broker starts
    Then it says out loud that a captured x-fuse-key header is still a way in
    And it names the variable that ends that

  # @test:require_proof_closes_the_bearer_door_without_removing_the_keys
  Scenario: The migration ends when the operator says so
    Given every client now presents a proof
    When the operator requires proof
    Then a shared secret alone stops being enough
    And the clients presenting proofs are unaffected

  # @test:a_proof_for_another_path_or_another_moment_is_refused
  Scenario: A proof made elsewhere or at another time is not one for this call
    When a proof names a different path, or was minted far from now
    Then it is refused

  # @test:an_http_client_id_is_refused_rather_than_quietly_accepted
  Scenario: A client id is an https URL or it is not a client id
    When a document names its client_id over plain http
    Then the broker refuses to start rather than admit it

  # @test:a_blank_spec_is_off_and_a_malformed_one_refuses_rather_than_reading_as_off
  Scenario: A typo is not the same thing as "off"
    Given the operator has configured client documents and made a mistake in
      them
    When the broker starts
    Then it refuses to start
    And it does not fall back to whatever the other door happened to be doing,
      at the moment the operator believed they had just tightened this one

  # @test:a_proof_door_counts_as_something_on_the_door
  Scenario: The stronger credential counts as a credential
    Given a broker bound to a non-loopback address
    And only the proof door configured, with no shared secret at all
    When it starts
    Then it is not refused for want of the weaker credential

  # @test:the_documents_are_read_from_a_file_when_the_spec_is_a_path
  Scenario: The client id is never dereferenced by this process
    Given the operator's deploy fetched each client's document and wrote them
      to a file
    When the broker reads that file at startup
    Then it admits those clients
    And it made no network request of its own, on this request or any other,
      because a door whose availability is somebody else's website is not a
      door this broker is willing to have
