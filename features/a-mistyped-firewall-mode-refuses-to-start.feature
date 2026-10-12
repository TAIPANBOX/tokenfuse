Feature: A mistyped firewall mode refuses to start instead of enforcing nothing

  TOKENFUSE_FIREWALL decides whether the agent firewall refuses anything at all.
  A value the gateway could not read used to start it in the default mode, so an
  operator who typed "enfroce" ran a gateway that refused nothing while
  believing it refused. A value nobody can read is now a refusal to start, the
  same answer TOKENFUSE_MODE already gives (CLAUDE.md invariant 72).

  # @test:the_firewall_mode_is_left_alone_when_nothing_is_configured
  Scenario: Nothing configured leaves the mode to the policy file or the default
    Given TOKENFUSE_FIREWALL is unset, empty or only spaces
    When the gateway reads its firewall mode
    Then no mode is forced and the policy file's mode or the default stands

  # @test:every_named_firewall_mode_is_honoured_in_any_case
  Scenario: A named mode is honoured whatever its case
    Given TOKENFUSE_FIREWALL is "ENFORCE"
    When the gateway reads its firewall mode
    Then the firewall mode is enforce

  # @test:a_mistyped_firewall_mode_is_refused_not_ignored
  Scenario: A mistyped mode is refused and the value is named
    Given TOKENFUSE_FIREWALL is "enfroce"
    When the gateway reads its firewall mode
    Then the read is refused and the refusal carries the value "enfroce"

  # @test:a_valid_firewall_mode_overrides_the_policy_file
  Scenario: A valid variable still wins over the policy file's own mode
    Given a policy file says "shadow" and TOKENFUSE_FIREWALL is "enforce"
    When the gateway reads its firewall mode
    Then the firewall mode is enforce

  # @test:a_mistyped_firewall_mode_stops_the_gateway_before_it_serves
  Scenario: A mistyped mode stops the real gateway before it listens
    Given TOKENFUSE_FIREWALL is "enfroce"
    When the gateway starts
    Then it exits with status 2 without listening
    And the message names TOKENFUSE_FIREWALL, the value, and the three words it accepts

  # @test:an_empty_firewall_mode_still_starts_the_gateway
  Scenario: An empty mode starts the real gateway as before
    Given TOKENFUSE_FIREWALL is set to an empty string
    When the gateway starts
    Then it listens
