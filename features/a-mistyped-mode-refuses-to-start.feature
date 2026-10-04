Feature: A mistyped budget mode refuses to start instead of enforcing nothing

  TOKENFUSE_MODE decides whether a budget actually stops a call. A value the
  gateway could not read used to start it in shadow, so an operator who typed
  the word slightly wrong ran a gateway that blocked nothing while believing
  it blocked. A value nobody can read is now a refusal to start, the same
  answer TOKENFUSE_IDENTITY_STRICT already gives.

  # @test:the_policy_mode_is_shadow_when_nothing_is_configured
  Scenario: Nothing configured is still shadow
    Given TOKENFUSE_MODE is unset or empty
    When the gateway starts
    Then the budget mode is shadow

  # @test:every_named_policy_mode_is_honoured_in_any_case
  Scenario: A named mode is honoured whatever its case
    Given TOKENFUSE_MODE is "Enforce"
    When the gateway starts
    Then the budget mode is enforce

  # @test:a_mistyped_policy_mode_is_refused_not_read_as_shadow
  Scenario: A mistyped mode stops the gateway before it serves
    Given TOKENFUSE_MODE is "enfroce"
    When the gateway starts
    Then it exits with status 2
    And the message names the value and the three it accepts
