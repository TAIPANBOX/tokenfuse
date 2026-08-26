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
