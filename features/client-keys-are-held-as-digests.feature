Feature: The gateway holds a client key as a digest and compares a presented secret exactly

  A configured client key is not kept in the clear in the gateway's lookup map, and the
  declassify key is compared in constant time (CLAUDE.md invariant 134, F-023).

  # @test:the_configured_secret_is_never_kept_in_the_map
  Scenario: A configured secret does not appear in the lookup map
    Given TOKENFUSE_CLIENT_KEYS names a secret and a key id
    When the gateway's client key table is printed
    Then the secret does not appear in the output

  # @test:resolves_a_known_secret_and_rejects_an_unknown_one
  Scenario: A known key resolves to its key id and an unknown one resolves to nothing
    Given TOKENFUSE_CLIENT_KEYS names two secrets
    When a caller presents one of them
    Then it resolves to that key's id
    When a caller presents a secret that is not configured
    Then it resolves to nothing

  # @test:secret_eq_accepts_only_the_identical_secret
  Scenario: A presented secret must be the configured one exactly
    Given a configured secret
    When a presented secret differs by one character, is a prefix, is longer, or is absent
    Then it is not accepted
    And only the identical secret is accepted
