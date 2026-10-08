Feature: The Cloud files a call refused for identity under the credential that made it

  An audit of the Cloud after v1.7.0 found two faults beside the one invariant
  81 closed in the FOCUS export. The Cloud's list of decisions it trusts as
  evidence held seven of the nine Breaker reasons, so /v1/compliance never
  counted a refusal for identity or a unit's cap, and the stall detector read
  such a refusal as a run still going. And the Cloud still filed a call
  refused identity_mismatch under the agent id the caller CLAIMED: /v1/agents
  gave the impersonation's run to its victim, /v1/spend counted the refusal as
  the victim's blocked call, the Owners card counted the victim among the key
  owner's agents, and fanout_explosion could raise an incident naming the
  victim. The gateway's CloudSink has always sent the credential (key_id)
  beside every record; the Cloud dropped it.

  The ask: fix both, file identity refusals under key:<key_id> in the Cloud
  as the FOCUS export already does, and make the evidence list unable to fall
  behind the gateway's reasons again.

  @claude 2026-10-08, under delegated authority: the run and the per-day
  spend bucket are filed under key:<key_id> (under nobody when client keys
  are off), never the claimed id; a refusal never takes over a run an
  admitted call already named, since a run id is the caller's choice; a
  credential is not an agent, so it is never counted among an owner's agents
  and never named on an incident or an agent event.

  # @test:known_decisions_cover_every_breaker_reason
  # @test:refusals_for_identity_and_a_units_cap_are_compliance_evidence
  Scenario: Every Breaker reason the gateway publishes is evidence in the Cloud
    Given the Breaker reasons the gateway publishes in its constants contract
    When the Cloud decides which recorded decisions are evidence
    Then every published reason is evidence, identity_mismatch and unit_budget_exceeded included
    And nothing but those reasons and the two admitted outcomes is
    And refusals for identity and for a unit's cap are counted in /v1/compliance

  # @test:a_run_refused_for_identity_is_stopped_not_stalled
  Scenario: A run refused for identity was stopped, not stalled
    Given a run whose every call was refused for identity
    When the run then goes quiet past the stall floor
    Then no run_stalled incident is raised for it

  # @test:an_identity_refusal_is_not_filed_under_the_agent_it_claimed
  # @test:an_identity_refusal_pushed_by_a_gateway_is_filed_under_its_key
  Scenario: The impersonation's run is the credential's in /v1/agents
    Given a victim agent that made one run of its own
    And a key that claimed the victim's id and was refused for identity twice
    When the gateway pushes those records to /v1/ingest
    Then /v1/agents gives the victim exactly its own run
    And the refused run is filed under "key:" and the key id, with nothing spent

  # @test:an_identity_refusal_is_the_credentials_blocked_call_in_spend
  Scenario: The refusal is the credential's blocked call in /v1/spend
    Given the same victim and the same refused impersonation on one day
    When /v1/spend is read for that day
    Then the victim shows its own call and no blocked call
    And "key:" and the key id shows two blocked calls and nothing spent

  # @test:an_identity_refusal_with_no_credential_is_filed_under_nobody
  Scenario: With client keys off a refusal for identity is filed under nobody
    Given a refusal for identity whose record names no key
    When /v1/spend, /v1/agents and /v1/runs are read
    Then it is filed under the empty bucket and never under the claimed id

  # @test:a_refusal_for_identity_never_overwrites_the_agent_an_admitted_call_named
  Scenario: A refusal never takes over a run an admitted call named
    Given a run an admitted call made as the planner
    And a refusal for identity that names the same run id
    When the run is read
    Then it is still the planner's

  # @test:a_key_owners_agents_never_include_the_agent_her_key_impersonated
  Scenario: A key owner's agents never include the agent her key impersonated
    Given an owner who runs one agent of her own
    And her key claimed another agent's id and was refused for identity
    When /v1/owners is read
    Then she has two runs and one agent

  # @test:an_impersonation_never_raises_a_fanout_explosion_naming_its_victim
  Scenario: An impersonation never raises a fanout_explosion naming its victim
    Given a victim agent whose habit is two runs a window
    And twelve runs opened by a key claiming the victim's id, each refused for identity
    When the Cloud detects incidents
    Then no incident names the victim

  # @test:a_run_filed_under_a_credential_names_no_agent_for_its_events
  Scenario: A run filed under a credential names no agent on its events
    Given a run filed under a key because it was refused for identity
    When an incident or a kill for that run is exported as an agent event
    Then the event names no agent, neither the key nor the claimed id
