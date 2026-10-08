Feature: A call refused for identity is exported under the credential that made it

  Measured 2026-10-07 on a home-lab run with client keys, an identity map and
  strict identity in enforce: a caller presenting the key forge-imposter and
  the agent id of another agent (routers/flint) was refused 403
  identity_mismatch, which is correct. The agent events named the key. The
  FOCUS export did not: it wrote the refused row with ResourceId and
  x_agent_id set to the CLAIMED id and carried neither the key nor the
  reason, so a FinOps console reading it showed the victim with two blocked
  calls it never made.

  The ask: the export carries the key the call was made with and the reason
  it was refused, as two new columns that old trace files still read, and a
  row refused for identity is never filed under the unauthenticated id it
  claimed.

  @claude 2026-10-08, under delegated authority: such a row is filed under
  the credential, ResourceId and ResourceName "key:<key_id>", and x_agent_id
  is empty, because a console reads x_agent_id first and ResourceId second.
  With no client keys there is no credential to name and both are empty.
  The claimed id stays in the Parquet trace and in the identity_mismatch
  agent event, which are where an investigation of the attempt starts.

  # @test:an_identity_refused_row_is_filed_under_the_credential_not_the_claim
  # @test:an_impersonation_refused_at_the_door_exports_under_the_credential_that_made_it
  Scenario: The measured impersonation is filed under the key that made it
    Given a key bound to its own agent presents another agent's id
    And strict identity refuses the call with identity_mismatch
    When the trace is exported to FOCUS
    Then the refused row's ResourceId and ResourceName are "key:" and the key id
    And its x_agent_id is empty
    And its x_key_id is the key and its x_block_reason is identity_mismatch
    And the claimed agent id appears in no column of the export

  # @test:an_identity_refused_row_with_no_credential_names_no_resource
  Scenario: With no client keys a refusal for identity is filed under nobody
    Given a gateway with no client keys, so every row's key is empty
    And a call refused for identity
    When the trace is exported to FOCUS
    Then its ResourceId, ResourceName and x_agent_id are empty, not the claimed id

  # @test:every_row_carries_the_key_it_was_made_with
  Scenario: Every row names the key it was made with
    Given calls allowed, served from cache and blocked for budget, each with its key
    And one call made with no key
    When the trace is exported to FOCUS
    Then each row's x_key_id is its own key, and empty for the call with none
    And a budget block by an authenticated caller stays filed under its agent

  # @test:a_blocked_row_names_its_reason_and_any_other_row_names_none
  Scenario: The block reason is named exactly when the Breaker blocked
    Given one row for each of the nine Breaker reasons
    And rows that were allowed, served from cache, or refused by the policy plane
    When the trace is exported to FOCUS
    Then each blocked row's x_block_reason is its own wire string
    And every other row's x_block_reason is empty

  # @test:a_trace_written_before_key_id_existed_still_exports
  Scenario: A trace written before the key column existed still exports
    Given a trace directory holding a segment written before key_id existed
    And a current segment beside it
    When the trace is exported to FOCUS
    Then both rows are exported and the old row's x_key_id is empty

  # @test:hostile_claims_and_keys_never_reach_the_resource_columns
  Scenario: Hostile ids never reach the resource columns and the file stays readable
    Given 200 seeded refused rows whose claimed ids and keys hold commas, quotes, CR, LF and non-ASCII letters
    When the trace is exported to FOCUS and read back
    Then every row round-trips with its own key in x_key_id
    And no claimed id is in ResourceId, ResourceName or x_agent_id

  # @test:the_focus_export_columns_are_published_in_export_order
  Scenario: The export's columns are published for the consumers that read them
    Given the constants contract other repositories read instead of retyping
    When it is generated
    Then it lists the FOCUS export's 28 columns in export order, the two new ones last
