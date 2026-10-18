Feature: A run belongs to the principal that opened it

  The agent-security review of 2026-10-17 left a residual after its first
  wave: on the metered doors a caller holding client key B could name a run
  key A had opened, spend in it, and read its labels in a taint 403; and a run
  of B's declaring A's run as its parent rolled B's spend into A's budget and
  inherited A's labels. After a restart the first caller to name a run owned
  it.

  @decided 2026-10-17: close the agent-security findings of that review,
  starting with defaults and small fixes, on the hybrid architecture (identity
  from vouchryx, key custody and a record witness off the request path). For
  this residual, as designed for the wave: a run belongs to the principal that
  opened it, a call naming a run opened under another principal is refused 403
  without revealing that run's labels, a parent run must be the caller's own
  or delegated to it, owners survive a restart, and without client keys
  behaviour is unchanged and documented. The principal is the credential the
  door verified, `key:<key_id>` for a static key and `tok:<subject>` for an
  agent token; the delegation for static keys is a `may_parent` list in the
  identity map, on the parent owner's key (@claude, the direction). A refusal
  writes no trace row, so another caller cannot make a run look refused
  (@claude).

  # @test:another_keys_run_is_refused_and_says_nothing_about_it
  # @test:a_foreign_run_is_refused_whatever_the_modes
  Scenario: Another key's run is refused and says nothing about it
    Given key A opened a run that read the web
    When key B sends a call naming that run
    Then the answer is 403 identity_mismatch, reason run_owned_elsewhere
    And it carries no label and no budget figure of that run
    And nothing was reserved or spent in that run, whatever the budget and firewall modes

  # @test:the_owner_is_still_answered_on_its_own_run
  Scenario: The owner is answered as before
    Given key A opened a run
    When key A calls on it again
    Then it is admitted as before

  # @test:a_child_naming_another_keys_run_as_parent_is_refused_and_inherits_nothing
  Scenario: A child cannot name another key's run as its parent
    Given key A opened a run that read the web
    When key B opens a run declaring A's run as its parent
    Then the answer is 403 identity_mismatch, reason parent_owned_elsewhere
    And nothing is opened, nothing is spent from A's budget, and B's run inherits no label

  # @test:a_child_under_its_own_keys_parent_is_admitted_and_inherits_as_before
  Scenario: A child of the caller's own run inherits as before
    Given key A opened a run that read the web
    When key A opens a child run under it
    Then the child is admitted and carries the parent's web label

  # @test:the_identity_map_may_let_one_key_parent_anothers_runs
  # @test:may_parent_lets_the_listed_key_parent_and_no_other
  Scenario: The identity map may let one key's runs parent another's
    Given the identity map lists key B under key A's may_parent
    When key B opens a run declaring A's run as its parent
    Then it is admitted

  # @test:may_parent_runs_one_way_only
  Scenario: may_parent runs one way only
    Given the identity map lists key B under key A's may_parent and nothing under key B
    When key A opens a run declaring B's run as its parent
    Then the answer is 403, reason parent_owned_elsewhere

  # @test:a_blank_or_wildcard_may_parent_entry_is_refused
  Scenario: A blank or wildcard may_parent entry is refused at load
    Given an identity map whose may_parent lists a blank entry or a pattern
    When the gateway loads it
    Then it refuses, naming may_parent

  # @test:a_parent_held_by_the_ledger_is_checked_when_the_header_is_omitted
  Scenario: The parent the ledger holds is checked, not only the header
    Given key B's run rolls up into a parent nobody owned when it was declared
    And key A has since opened that parent and owns it
    When key B calls on its run without the parent header
    Then the answer is 403, reason parent_owned_elsewhere

  # @test:a_refusal_for_another_principals_run_is_one_identity_mismatch_on_the_bus
  Scenario: The refusal is on the bus, filed under the caller
    Given key A opened a run
    When key B is refused for naming it
    Then one identity_mismatch event names key B's agent, its key and the run in its data
    And the event is not filed under the run another principal owns

  # @test:run_owners_survive_a_gateway_restart
  # @test:a_claim_is_journaled_and_replayed_first_owner_wins
  Scenario: Owners survive a restart
    Given a gateway with client keys and a data dir, and key A opened a run
    When the gateway is killed and started again on the same data dir
    Then key B is still refused on that run and key A is still answered

  # @test:a_truncated_journal_replays_every_whole_line_and_never_a_torn_one
  # @test:hostile_journal_bytes_never_panic_and_never_invent_an_owner
  # @test:startup_rewrites_the_journal_with_one_line_per_run
  Scenario: A torn journal loses only its torn line
    Given a run-owner journal cut at any byte
    When it is replayed and appended to
    Then every whole line is read, the torn one is skipped, and a later record never fuses with it
    And startup rewrites the journal with one line per run, the first owner of each

  # @test:an_unreadable_run_owner_journal_refuses_to_start
  # @test:an_unreadable_journal_is_an_error_and_a_missing_one_is_empty
  Scenario: A journal that cannot be read stops the gateway
    Given the run-owner journal exists and cannot be read
    When the gateway starts
    Then it exits 2 naming the journal, before the listener binds

  # @test:without_a_data_dir_run_ownership_is_said_to_be_process_local
  Scenario: Without a data dir, ownership is said to be process-local
    Given client keys and no data dir
    When the gateway starts
    Then it says run ownership is process-local

  # @test:without_client_keys_any_caller_may_name_any_run_as_before
  # @test:without_client_keys_run_ownership_is_said_to_be_off
  # @test:an_empty_principal_claims_nothing
  # @test:a_map_without_may_parent_lets_no_key_parent_another
  Scenario: Without client keys nothing changes, and the gateway says so
    Given no client keys are configured
    When any caller names any run or parent
    Then it is admitted as before and no owner is recorded
    And the gateway says at startup that run ownership is off

  # @test:a_key_and_a_token_with_the_same_name_are_different_principals
  # @test:a_first_claim_owns_the_run_and_a_second_principal_is_elsewhere
  Scenario: A key and a token with the same name are different principals
    Given a run opened under the client key named ops
    When an agent token whose subject is ops names the run
    Then it is another principal's run
