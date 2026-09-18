Feature: A delegation chain longer than the shared cap is refused at the door, whether or not anybody verifies chains

  Issue #297, measured 2026-09-17 on the appliance proving run: with no
  delegation issuer configured, which is every launcher's default, a call
  carrying forty comma-separated agent:// entries in x-fuse-on-behalf-of was
  forwarded and answered 200, and nothing reached the bus. The header was
  about 1.5 KiB, inside the 4 KiB sanity cap on its raw bytes, and nothing
  counted its entries.

  agent-passport SPEC 5.1 bounds the chain at 32 entries and requires it to be
  acyclic as a normative property of the chain ITSELF; proving a chain (5.2)
  is optional and additive. The v0.2 envelope pins maxItems: 32 on
  on_behalf_of and agent-conform runs the record's validator on every line,
  so a gateway that forwards a forty-entry chain and writes it into every
  event of that request has produced records the bus cannot hold: green at
  the door, quarantined at the record, the shape invariant 35 already refuses
  for a PROVEN chain. The delegation crate refuses the same length inside a
  token, so without this the two doors of one gateway disagreed about one
  number depending on whether an issuer was configured.

  @claude 2026-09-18, the reading this change takes, open to being overruled:
  the entry cap holds regardless of verification. A chain of more than 32 entries is refused on parse with 400,
  a body naming the cap and the count sent, and one identity_mismatch event
  carrying the length and the cap in data and NOT the chain, before anything
  is reserved or forwarded. The cap is the delegation crate's own constant,
  read rather than retyped. The 4 KiB byte cap on the raw header is unchanged
  and still ignores the header as absent; the acyclic and scheme rules are
  still applied to tokens only, and that limit is written down rather than
  implied. The run-ancestry walk over x-fuse-parent-run-id has a separate cap
  of 64 ancestors across requests (invariant 49), untouched here: one bounds
  who a call acts for, the other bounds which runs a call rolls up into.

  # @test:a_chain_of_forty_entries_is_refused_before_anything_is_forwarded
  Scenario: Forty entries with no issuer configured
    Given a gateway with no delegation issuer configured
    When a call carries an x-fuse-on-behalf-of chain of forty entries
    Then it is refused with 400 and the body names the cap of 32 entries and the forty sent
    And nothing is reserved on the run and nothing reaches the provider
    And one identity_mismatch event is on the bus carrying the length and the cap, and not the chain

  # @test:a_chain_at_exactly_the_cap_is_forwarded_and_recorded_unchanged
  Scenario: Exactly 32 entries is the cap, not over it
    Given a gateway with no delegation issuer configured
    When a call carries a chain of exactly 32 entries
    Then it is forwarded and the chain rides into the trace unchanged
    And no identity_mismatch event is written

  # @test:a_chain_over_the_cap_is_refused_at_the_mcp_door_too
  Scenario: The MCP door applies the same cap
    Given an MCP broker with no delegation issuer configured
    When a tools/call carries a chain of 33 entries
    Then it is refused with the same 400, the upstream sees nothing, and the same event is on the bus

  # @test:the_header_cap_is_the_delegation_crates_cap_and_not_a_second_number
  Scenario: One number, not two
    Given the cap the delegation crate applies to a token's chain
    When the gateway parses the header chain
    Then it refuses at the same number, 32, the shared spec's, read from that crate and never retyped
