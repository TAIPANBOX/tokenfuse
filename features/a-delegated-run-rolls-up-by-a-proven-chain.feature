Feature: A run rolls up into a parent another agent owns when a proven chain names that agent
  Invariant 120's delegated arm for agent tokens.

  # @test:a_proven_chain_naming_the_parent_owners_agent_rolls_up
  Scenario: A proven chain naming the parent's agent rolls up
    Given a parent run opened by the runbook agent's own token
    When the triage agent's token calls with a person's delegation proving user, runbook, triage
    Then the child run rolls up into the parent

  # @test:the_parent_owner_two_hops_up_the_chain_rolls_up
  Scenario: Any ancestor in the proven chain counts
    Given a parent run opened by the runbook agent
    When the proven chain is user, runbook, middle, triage
    Then the child run rolls up into the parent

  # @test:a_held_parent_is_still_delegated_when_the_header_is_omitted
  Scenario: The parent the ledger holds is judged the same way
    Given a child run that rolled up into a runbook-owned parent
    When the next call omits the parent header
    Then the call is admitted

  # @test:a_claimed_chain_naming_the_parent_owner_is_refused
  Scenario: A claimed chain is not proof
    Given a parent run opened by the runbook agent
    When the triage agent names runbook only in x-fuse-on-behalf-of
    Then the call is refused for its parent

  # @test:a_proven_chain_that_does_not_name_the_parent_owner_is_refused
  Scenario: A proven chain that does not name the owner is refused
    Given a parent run opened by another agent
    When the proven chain names runbook
    Then the call is refused for its parent

  # @test:a_near_match_of_the_owners_agent_is_refused
  Scenario: A near match is not the owner
    Given a parent run opened by agent://acme/runbook-ops
    When the proven chain names agent://acme/runbook
    Then the call is refused for its parent

  # @test:a_key_owned_parent_is_not_delegated_by_a_chain
  Scenario: A key-owned parent is not delegated by a chain
    Given a parent run opened with a static client key
    When the triage agent calls with a proven chain
    Then the call is refused for its parent

  # @test:a_grandchild_without_the_delegation_is_refused_under_the_owners_run
  Scenario: A delegation once given is not a standing pass
    Given a child run that rolled up into a runbook-owned parent by a proven chain
    When the same agent opens a grandchild under it without the delegation
    Then the grandchild is refused

  # @test:a_held_parent_without_the_delegation_is_refused
  Scenario: The held parent is judged at every call
    Given a child run that rolled up by a proven chain
    When its next call carries no delegation
    Then the call is refused

  # @test:an_owner_that_is_a_prefix_of_a_chain_entry_is_refused
  Scenario: A prefix is not the owner
    Given a parent run opened by agent://acme/run
    When the proven chain names agent://acme/runbook
    Then the call is refused for its parent
