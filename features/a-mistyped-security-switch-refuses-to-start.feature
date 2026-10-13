Feature: A mistyped security switch refuses to start instead of falling to a weaker mode

  Several environment switches decide how much protection a gateway or broker
  applies: the DLP scanners, the MCP tool-listing scan, the taint gate's fail
  mode, the wardryx policy hook and its fail mode, and the two "require" flags on
  the broker's doors. Before 2026-10-13 each of them mapped an unreadable value
  to a weaker mode with a catch-all arm, so a typo for "block" or "closed" or
  "enforce" ran the process with the protection off while its operator believed
  it was on. A value nobody can read is now a refusal to start, the same answer
  TOKENFUSE_MODE and TOKENFUSE_FIREWALL already give (CLAUDE.md invariants 72
  and 94). Unset or empty keeps each switch's own default.

  Upgrade note: a deployment with a mistyped value that used to start will now
  exit 2 before it listens. A value written in capitals (`ENFORCE`) is now read
  as the word it spells, which for TOKENFUSE_WARDRYX_MODE means enforcement turns
  on where it used to be silently off. `yes`, `on` and `no` are refused for the
  two "require" flags, which read as off before.

  # @test:dlp_pii_refuses_a_mistyped_word
  Scenario: A mistyped TOKENFUSE_DLP_PII is refused, not read as off
    Given TOKENFUSE_DLP_PII is "blcok"
    When the gateway reads its PII mask mode
    Then the read is refused naming the variable, the value and "off|shadow|mask|block"
    And an unset or empty value still means off

  # @test:mcp_dlp_refuses_a_mistyped_word
  Scenario: A mistyped TOKENFUSE_MCP_DLP is refused, not read as shadow
    Given TOKENFUSE_MCP_DLP is "blcok"
    When the broker reads its secret scanner mode
    Then the read is refused naming the variable, the value and "off|shadow|block"
    And an unset value still means shadow

  # @test:mcp_dlp_pii_refuses_a_mistyped_word
  Scenario: A mistyped TOKENFUSE_MCP_DLP_PII is refused, not read as off
    Given TOKENFUSE_MCP_DLP_PII is "blcok"
    When the broker reads its PII mask mode
    Then the read is refused naming the variable, the value and "off|shadow|mask|block"
    And an unset value still means off

  # @test:mcp_scan_refuses_a_mistyped_word
  Scenario: A mistyped TOKENFUSE_MCP_SCAN is refused, not read as warn
    Given TOKENFUSE_MCP_SCAN is "blcok"
    When the broker reads its tool-listing scan mode
    Then the read is refused naming the variable, the value and "off|warn|block"
    And an unset value still means warn

  # @test:mcp_taint_failmode_refuses_a_mistyped_word
  Scenario: A mistyped TOKENFUSE_MCP_TAINT_FAILMODE is refused, not read as open
    Given TOKENFUSE_MCP_TAINT_FAILMODE is "clsoed"
    When the broker reads the taint gate's fail mode
    Then the read is refused naming the variable, the value and "open|closed"
    And an unset value still means open

  # @test:wardryx_mode_refuses_a_mistyped_word
  Scenario: A mistyped TOKENFUSE_WARDRYX_MODE is refused, not read as off
    Given TOKENFUSE_WARDRYX_MODE is "enfroce"
    When the gateway or the broker reads the wardryx hook's mode
    Then the read is refused naming the variable, the value and "off|shadow|enforce"
    And an unset value still means off, and "ENFORCE" means enforce

  # @test:wardryx_failmode_refuses_a_mistyped_word
  Scenario: A mistyped TOKENFUSE_WARDRYX_FAILMODE is refused, not read as open
    Given TOKENFUSE_WARDRYX_FAILMODE is "clsoed"
    When the gateway or the broker reads the wardryx fail mode
    Then the read is refused naming the variable, the value and "open|closed"
    And an unset value still means open

  # @test:require_proof_refuses_a_mistyped_word
  Scenario: A mistyped TOKENFUSE_MCP_REQUIRE_PROOF is refused, not read as off
    Given TOKENFUSE_MCP_REQUIRE_PROOF is "yes"
    When the broker reads whether a proof is required
    Then the read is refused naming the variable, the value and "0|false|1|true"
    And an unset value still means off, and "0" and "false" still mean off

  # @test:require_secret_scopes_refuses_a_mistyped_word
  Scenario: A mistyped TOKENFUSE_MCP_REQUIRE_SECRET_SCOPES is refused, not read as off
    Given TOKENFUSE_MCP_REQUIRE_SECRET_SCOPES is "yes"
    When the broker reads whether secret scopes are required
    Then the read is refused naming the variable, the value and "0|false|1|true"
    And an unset value still means off, and "0" and "false" still mean off

  # @test:a_mistyped_dlp_pii_stops_the_gateway_before_it_serves
  Scenario: A mistyped PII mode stops the real gateway before it listens
    Given TOKENFUSE_DLP_PII is "blcok"
    When the gateway starts
    Then it exits with status 2 without listening
    And the message names TOKENFUSE_DLP_PII, the value, and the words it accepts

  # @test:a_mistyped_mcp_scan_stops_the_broker_before_it_serves
  Scenario: A mistyped scan mode stops the real broker before it listens
    Given TOKENFUSE_MCP_SCAN is "blcok"
    When the MCP broker starts
    Then it exits with status 2 without listening
    And the message names TOKENFUSE_MCP_SCAN, the value, and the words it accepts

  # @test:an_empty_dlp_pii_still_starts_the_gateway
  Scenario: An empty PII mode starts the real gateway as before
    Given TOKENFUSE_DLP_PII is set to an empty string
    When the gateway starts
    Then it listens

  # @test:an_empty_mcp_scan_still_starts_the_broker
  Scenario: An empty scan mode starts the real broker as before
    Given TOKENFUSE_MCP_SCAN is set to an empty string
    When the MCP broker starts
    Then it listens

  # @test:measurement_switches_keep_unknown_as_off_by_decision
  Scenario: The measurement switches keep reading an unknown value as off
    Given TOKENFUSE_CACHE or TOKENFUSE_TOOLS_PRUNE is "enfroce"
    When the gateway reads the measurement mode
    Then it is off, by decision, because a measurement toggle has no stricter reading
