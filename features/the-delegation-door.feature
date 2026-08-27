Feature: One binary, two processes, and the same door in both

  The proxy (`serve`) and the MCP broker (`mcp_broker`) are separate process
  invocations. Each reads its own environment and builds its own state, and
  both call `chainproof::resolve` with code that reads the same at either site.

  Measured 2026-08-26: `chainproof::from_env()` was called in the broker and
  nowhere else. The proxy's config was `None` on every request, so every chain
  it forwarded to the PDP was a claim while the code at its door read as though
  it were verified. Nothing said so, because what was missing was a line nobody
  had written.

  # @test:the_policy_an_operator_falls_into_is_the_safe_one
  Scenario: An operator who names only a list gets the safe policy
    Given a revocation URL and no other revocation setting
    When the process reads its environment
    Then it polls at a fifth of the maximum age and refuses an unanswerable
      miss, so four consecutive failed polls are needed before the fail mode
      is asked anything at all

  # @test:a_list_to_poll_with_no_door_to_check_is_refused
  Scenario: A check that could never fire is refused rather than started
    Given a revocation list to poll and no delegation issuer
    When the process reads its environment
    Then it refuses to start, because nothing verifies a token and the list
      would be polled forever while every call walked in as a claim

  # @test:a_setting_that_cannot_be_read_is_refused_rather_than_guessed
  Scenario: A misspelt setting is refused rather than guessed
    Given a fail mode written `close` rather than `closed`
    When the process reads its environment
    Then it refuses to start, because an operator who asks for the safe mode
      and silently gets it anyway cannot be told apart from one who asks and
      is ignored

  # @test:a_max_age_of_zero_or_less_is_a_policy_and_not_a_mistake
  Scenario: Only a hit counts is a policy somebody can choose
    Given a maximum age of zero or less
    When the process reads its environment
    Then it is accepted as written, because it says every list is stale on
      arrival and only a hit answers, which is a deployment's decision to make

  # @test:with_no_feed_the_hook_answers_not_revoked
  Scenario: A door polling nothing refuses nothing
    Given no revocation URL was named
    When a token is checked
    Then it is not revoked, which is the check being off rather than a verdict

  # @test:the_hook_answers_from_the_list_the_poller_installed
  Scenario: A revoked token stops working at the door
    Given a poller that installed a list naming a token
    When that token is checked
    Then it is refused, and a token the list does not name is not

  # @test:a_door_that_has_never_fetched_refuses_under_the_default
  Scenario: A door that never fetched would refuse everything, so it must not start
    Given a cache no snapshot was ever installed into
    When a token is checked
    Then it is refused under the default fail mode, which is why the first
      fetch happens at startup and a failure there exits rather than serving

  # @test:a_proven_chain_files_the_record_when_no_header_names_an_agent
  Scenario: A detected attack on a proven caller reaches the record
    Given a request whose delegation token proves it acts for an agent
    And no `x-fuse-agent-id` header at all
    When an injection is detected in a tool result
    Then the record is written and filed under the agent the token proved,
      because the identity was in the request all along, inside a credential
      this gateway verified

  # @test:a_claimed_chain_does_not_file_the_record
  Scenario: A chain the caller merely declared is not an identity
    Given a request declaring a chain in a header and presenting no token
    When an injection is detected
    Then nothing is filed under that chain, because a caller who can write the
      header can write the chain

  # @test:a_proven_chain_carries_what_proved_it
  Scenario: The record says which token proved the chain
    Given a chain a delegation token proved
    When the record is written
    Then it carries the token's id, the key it was bound to, the issuer this
      deployment verified against, and when the proof stopped being one

  # @test:a_claimed_chain_carries_no_proof
  Scenario: An unproven chain says nothing about being proven
    Given a chain nobody proved
    When the record is written
    Then no proof sits beside it, because an absent proof means not proven

  # @test:the_brokers_tool_call_record_carries_the_chain_and_what_proved_it
  Scenario: The MCP door's audit record says whose delegation it was
    Given a `tools/call` whose delegation token proves it acts for an agent
    And no `x-fuse-agent-id` header
    When the call is brokered
    Then a tool_call record is written, carrying the chain and the token that
      proved it, and its decision says the gate could not judge it rather than
      saying a policy allowed it

  # @test:the_bare_scheme_is_not_an_agent
  Scenario: A scheme with nothing after it is not an identity
    Given a proven chain whose last name is the bare `agent://`
    When a record looks for whom to file under
    Then it finds nobody, because a scheme is not an identity

  # @test:a_token_for_one_agent_and_a_header_for_another_is_a_mismatch
  Scenario: A token for one agent and a header for another
    Given a caller presenting the triage agent's delegation token
    And a header naming itself a different agent
    When strict identity is enforced
    Then the call is refused and recorded as an identity mismatch, because a
      credential that vouches for one agent does not let a caller act as
      another, and the key binding check cannot see it since one key may
      legitimately speak for several agents

  # @test:a_header_that_agrees_with_the_proven_chain_is_not_a_mismatch
  Scenario: Agreement is not a contradiction
    Given a caller whose header names the same agent its token proves
    When strict identity is enforced
    Then the call proceeds and nothing is recorded as a mismatch

  # @test:a_token_for_one_agent_and_a_header_for_another_is_refused_at_the_mcp_door
  Scenario: The same contradiction, at the MCP door
    Given a `tools/call` presenting one agent's delegation token
    And a header naming a different agent
    When strict identity is enforced
    Then it is refused with both names in the reason, so a caller knows which
      of the two to fix, and the mismatch is recorded whichever transport the
      call arrived on

  # @test:the_mode_an_operator_falls_into_is_enforce
  Scenario: The identity mode an operator falls into
    Given a deployment that names no identity strictness
    When it starts
    Then it enforces, because a check that does nothing until somebody sets a
      variable is a deployment governed on paper, and `off` is one explicit
      variable away

  # @test:a_deployment_that_opted_into_nothing_is_unaffected
  Scenario: Turning it on changes nothing for those who opted into nothing
    Given a deployment with no client keys and no delegation issuer
    When a plain request arrives under the new default
    Then it is not refused, because a mismatch needs something to mismatch
      with and both sources are opt-in

  # @test:a_deployment_that_opted_in_is_now_held_to_it
  Scenario: And everything for those who did
    Given a deployment with a delegation issuer configured
    When a caller presents one agent's token and names another in the header
    Then it is refused under the new default, with no variable set
