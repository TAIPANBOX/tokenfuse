Feature: The door and the record count the same thing

  agent-passport SPEC 5.1 says "Maximum chain depth is 32 entries", and section
  5 calls the members of `on_behalf_of` entries: the root, usually a human, is
  the first of them. So the bound is on the assembled chain.

  This crate builds that chain out of an RFC 8693 token, where the subject is
  deliberately NOT an actor, so the mapping is `[sub] + reverse(act)`. Measured
  2026-08-27 with agent-conform against a real emitted line: the cap was applied
  to the ACTOR list, so a token carrying 32 actors verified here and produced a
  33-entry chain that agent-conform, the v0.2 and v0.3 envelope schemas and
  agent-stack-go's `chain.Validate` all refuse:

      maxItems: got 33, want 32
      exceeds max depth: 33 entries

  Nothing was broken inside this crate. Every one of those doors was right and
  this one was wrong by one, in a unit nobody had written down. A token verified
  at the door and every record it produced was quarantined, which is the worst
  shape available: the enforcement point reports success and the audit trail
  quietly does not exist.

  THIS CHANGES WHAT THE DOOR ACCEPTS. A delegation token carrying 32 actors was
  verified before this change and is refused as malformed after it. The tokens
  it now refuses are exactly the tokens whose records were being thrown away, so
  no working audit trail is lost, but a door's answer has changed and that is an
  enforcement change rather than a tidy-up.

  # @test:no_chain_this_door_builds_is_longer_than_the_record_accepts
  Scenario: Nothing verifies here that the record will not hold
    Given tokens carrying every actor count from one to two past the cap
    When each is presented with a good proof at this door
    Then either it is refused, or the chain it produces fits in 32 entries, and
      never a chain built for a consumer to quarantine

  # @test:the_subject_counts_towards_the_cap_because_the_spec_counts_entries
  Scenario: The subject is an entry, so it counts
    Given a token naming a subject, which is every token this door accepts
    When it carries 31 actors and then 32
    Then the first verifies into exactly 32 entries with the root still first,
      and the second is refused as malformed
