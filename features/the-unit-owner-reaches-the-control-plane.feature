Feature: The unit's owner reaches the control plane's owner view

  Measured 2026-09-17 on the appliance proving run (tokenfuse#295): both
  identity maps on the box named an owner per unit, in the docs/20 shape.
  After 272 calls across four agents, GET /v1/owners returned one row,
  unassigned, and the console's Money view the same, while /v1/units
  attributed every call correctly. The unit was known; the owner on the unit
  was never carried.

  @decided 2026-09-18: the trace's CallRecord keeps its sixteen Parquet
  columns and compat/1.0.json is untouched; the owner rides the telemetry the
  gateway already pushes as one additive field.

  @claude on precedence: a record's owner is the unit's, resolved from
  operator configuration, and outranks the caller-declared chain; the chain
  fills the gap, so a deployment naming no unit owner aggregates exactly as
  before. Invariant 54.

  # @test:a_units_owner_is_kept_verbatim
  # @test:a_blank_owner_normalizes_to_absent
  # @test:owner_absent_on_an_old_map_is_none_and_unit_owners_is_empty
  Scenario: The identity map's unit owner is read
    Given an identity map whose units name an owner, one whose owner is blank, and one written before the field existed
    When each map is loaded
    Then the named owner is kept verbatim, the blank one reads as absent, and the old map names no owners

  # @test:the_wire_record_carries_the_units_owner_beside_every_existing_field
  # @test:a_unit_without_an_owner_and_a_record_without_a_unit_carry_an_empty_owner
  Scenario: Every pushed record carries its unit's owner
    Given a gateway whose identity map names an owner for the unit a call resolved to
    When the call's record is pushed to the control plane
    Then the record carries owner beside every field it carried before
    And a record whose unit names nobody, or that resolved to no unit, carries an empty owner

  # @test:a_row_carrying_a_unit_owner_lands_under_it_in_owners
  # @test:deserializes_owner_and_defaults_it_for_an_older_gateway
  Scenario: The control plane attributes the run to the unit's owner
    Given a batch whose records carry an owner
    When the control plane ingests it
    Then /v1/owners rolls the spend up under that owner and nothing lands under unassigned
    And a record from an older gateway without the field still ingests

  # @test:the_units_owner_outranks_the_callers_chain
  # @test:a_row_without_a_unit_owner_falls_back_to_the_chains_root_human
  # @test:owners_roll_up_by_the_root_human_and_keep_an_unassigned_bucket
  Scenario: The configured owner outranks the declared chain, and the chain fills the gap
    Given a record naming both a unit owner and a delegation chain with a human at its root
    When the control plane ingests it
    Then the run answers to the unit's owner
    And a record with no unit owner answers to the chain's root human as before, and one with neither stays unassigned
