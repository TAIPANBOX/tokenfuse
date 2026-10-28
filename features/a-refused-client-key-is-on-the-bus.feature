Feature: A call refused for its client key is on the bus

  Measured 2026-10-14 on forge: no key, an unknown key and the other door's key
  all drew the same 401 and wrote nothing an operator's tools could see.

  @decided 2026-10-14: a refused client key goes on the bus with a fingerprint
  of what was presented, never the key, and rate-limited so a scan cannot flood
  it. Invariant 105.

  # @test:a_missing_key_and_an_unknown_key_are_on_the_bus_by_reason
  # @test:the_data_names_the_reason_and_never_carries_the_key
  Scenario: The operator learns which cause it was, the caller does not
    Given a gateway that requires a client key
    When one call presents no key and another an unknown one
    Then both get the same 401 with the same body
    And the bus carries one identity_mismatch each, reason missing_key and unknown_key
    And the unknown one carries a sha256 fingerprint and the key itself appears nowhere

  # @test:the_fingerprint_is_a_prefix_of_the_sha256_and_never_the_key
  Scenario: The fingerprint matches a key the operator issued without revealing one
    Given a presented key
    Then its fingerprint is sha256 and the first sixteen hex digits of its digest

  # @test:the_same_key_tried_again_and_again_is_one_event
  # @test:one_source_is_reported_once_a_minute_with_what_it_held_back
  Scenario: One client retrying one wrong key is one event a minute
    Given fifty refusals of the same key from the same claimed agent within a minute
    Then the bus carries one event, and the next one counts what was held back

  # @test:a_scan_of_many_keys_cannot_flood_the_bus
  # @test:the_whole_gateway_reports_at_most_sixty_a_minute
  # @test:the_sources_remembered_are_bounded
  Scenario: A scan of many keys is seen without flooding the bus
    Given two hundred different keys tried within a minute
    Then at most sixty events say so, and the limiter's memory stays bounded

  # @test:a_good_key_writes_no_refusal
  Scenario: A good key writes no refusal
    Given a call with a key the gateway knows
    Then no refusal is on the bus

  # @test:a_scan_that_names_no_agent_is_on_the_bus_too
  Scenario: A scan that names no agent is on the bus too
    Given calls that present unknown keys or none and name no agent
    Then each is on the bus under the reserved subject for an unidentified caller
    And the event says no agent was claimed

  # The same rule at the door that requires an agent token. @claude 2026-10-28:
  # a reading of invariant 105, not a new decision. Measured 2026-10-28 on a
  # v1.20.1 gateway with TOKENFUSE_AGENT_TOKENS=require: an unknown key and no
  # key were answered with the 401 of that door and reached the bus not at all,
  # while the same calls at the open door were on it.

  # @test:under_require_a_missing_key_and_an_unknown_key_are_on_the_bus_by_reason
  Scenario: Under require, the operator learns which cause it was, the caller does not
    Given a gateway that requires an agent token and lists no static key
    When one call presents no key and another an unknown one
    Then both get the 401 that door always gave, byte for byte, and the same body
    And the bus carries one identity_mismatch each, reason missing_key and unknown_key
    And the unknown one carries a sha256 fingerprint and the key itself appears nowhere

  # @test:under_require_the_record_has_the_shape_the_open_door_gives
  Scenario: Under require, the record is the one the open door writes
    Given the same two calls sent to a gateway that requires an agent token and to one that does not
    Then both buses carry the same fields, the same reason words and the same data

  # @test:under_require_the_same_key_tried_again_and_again_is_one_event
  # @test:under_require_a_scan_of_many_keys_cannot_flood_the_bus
  Scenario: Under require, a scan is seen without flooding the bus
    Given fifty refusals of one key, or two hundred different keys, within a minute
    Then the bus carries one event for the one key and at most sixty for the scan

  # @test:under_require_a_scan_that_names_no_agent_is_on_the_bus_too
  # @test:under_require_with_no_client_keys_a_call_with_no_credential_is_on_the_bus_too
  Scenario: Under require, a call that names no agent is on the bus under the reserved subject
    Given calls that present unknown keys or none, naming no agent, with client keys configured or not
    Then each is on the bus under the reserved subject for an unidentified caller

  # @test:under_require_a_listed_key_writes_no_refusal
  # @test:under_require_a_known_key_that_is_not_listed_is_never_filed_as_an_unknown_one
  Scenario: Under require, a call that is not refused for an unknown key is not filed as one
    Given a call with a key the operator lists, and another with a key the gateway knows but the operator does not list
    Then the listed one writes no refusal
    And the unlisted one is refused as before and is not on the bus as an unknown key, nor is its fingerprint
