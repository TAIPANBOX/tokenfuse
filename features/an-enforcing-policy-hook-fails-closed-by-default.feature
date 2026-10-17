Feature: An enforcing policy hook fails closed unless an operator chose open

  The agent-security review of 2026-10-17 (finding F-006) measured on the bare
  binary that with TOKENFUSE_WARDRYX_MODE=enforce and no failmode, a call the
  policy denied while wardryx was up was allowed four seconds after wardryx
  stopped, answered x-fuse-wardryx: allow. With a 50 ms deadline, a busy policy
  plane is enough to turn every deny and hold into an allow.

  @decided 2026-10-17: close the agent-security findings of that review,
  starting with defaults and small fixes, on the hybrid architecture. For this
  finding: when the wardryx mode is enforce and TOKENFUSE_WARDRYX_FAILMODE is
  unset, the failmode is closed; an explicit open still works and is said at
  startup. Leaving shadow's default where it was is @claude: shadow blocks
  nothing whatever the failmode says.

  # @test:enforce_with_no_failmode_fails_closed
  # @test:an_enforcing_gateway_with_no_failmode_refuses_while_its_pdp_is_down
  Scenario: Enforce with no failmode refuses while the policy plane is down
    Given TOKENFUSE_WARDRYX_MODE is enforce and TOKENFUSE_WARDRYX_FAILMODE is unset
    And wardryx cannot be reached
    When an agent sends a call
    Then the call is refused with 403
    And the startup line names failmode Closed

  # @test:enforce_with_a_blank_failmode_fails_closed_too
  Scenario: A blank failmode is unset
    Given TOKENFUSE_WARDRYX_FAILMODE holds only spaces under enforce
    Then the failmode is closed

  # @test:an_explicit_open_still_opens_under_enforce
  # @test:an_explicit_open_still_opens_and_is_said_at_startup
  Scenario: An explicit open is one variable away and is said
    Given TOKENFUSE_WARDRYX_MODE is enforce and TOKENFUSE_WARDRYX_FAILMODE is open
    And wardryx cannot be reached
    When an agent sends a call
    Then the call is let through
    And the startup output names TOKENFUSE_WARDRYX_FAILMODE=open

  # @test:shadow_with_no_failmode_is_unchanged
  Scenario: Shadow keeps its default
    Given TOKENFUSE_WARDRYX_MODE is shadow and TOKENFUSE_WARDRYX_FAILMODE is unset
    Then the failmode is open, as before
