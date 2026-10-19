Feature: The gateway enforces by default, and observation is a named choice

  An unconfigured gateway used to be a pass-through: budgets were shadowed, the
  taint firewall was shadowed, nothing judged a tool call, and the admin routes
  answered anyone on loopback. An operator who followed a quickstart got an
  observer, not a control. TOKENFUSE_PROFILE makes the choice explicit: governed
  is the default, observe reproduces the old defaults with one loud line, and
  every per-feature variable an operator sets still wins over either profile
  (CLAUDE.md invariant 136).

  # @test:the_profile_nobody_set_is_governed
  Scenario: An unset profile means governed
    Given TOKENFUSE_PROFILE is unset, empty or only spaces
    When the gateway reads its profile
    Then the profile is governed

  # @test:an_unknown_profile_value_is_refused_naming_both_profiles
  Scenario: A profile the gateway cannot read stops it before it serves
    Given TOKENFUSE_PROFILE is "gov"
    When the gateway starts
    Then it exits with code 2 before listening, naming TOKENFUSE_PROFILE, governed and observe

  # @test:under_the_governed_profile_a_call_over_its_budget_is_refused
  Scenario: Governed enforces the run budget when the operator set no budget mode
    Given TOKENFUSE_PROFILE is unset and TOKENFUSE_MODE is unset
    When a call declares a run budget far below its estimate
    Then the call is refused with 402 before it is forwarded

  # @test:an_explicit_policy_mode_wins_over_the_governed_default
  Scenario: An explicit budget mode is never overridden by the profile
    Given TOKENFUSE_PROFILE is unset and TOKENFUSE_MODE is "shadow"
    When a call declares a run budget far below its estimate
    Then the call is forwarded and the refusal is only recorded

  # @test:under_the_observe_profile_a_call_over_its_budget_is_forwarded
  Scenario: Observe keeps the old budget default and says it enforces nothing
    Given TOKENFUSE_PROFILE is "observe" on a loopback bind
    When a call declares a run budget far below its estimate
    Then the call is forwarded and the gateway says at startup that observe enforces nothing

  # @test:under_the_governed_profile_the_wardryx_hook_enforces_when_a_pdp_is_named
  Scenario: A named policy plane is enforced with a closed failmode by default
    Given TOKENFUSE_PROFILE is unset, TOKENFUSE_WARDRYX_URL is set and TOKENFUSE_WARDRYX_MODE is unset
    When the gateway starts
    Then the policy hook starts in enforce with failmode closed, and the startup line says the source was the profile

  # @test:under_the_governed_profile_the_firewall_enforces_by_default
  Scenario: Governed firewall is enforce when neither a variable nor a policy file sets it
    Given TOKENFUSE_PROFILE is unset, TOKENFUSE_FIREWALL and TOKENFUSE_FIREWALL_CONFIG are unset
    When a tool that writes is checked in a run that read the web
    Then the check is denied

  # @test:under_the_governed_profile_the_admin_routes_refuse_loopback_without_a_key
  Scenario: The admin routes need a key on loopback too under governed
    Given TOKENFUSE_PROFILE is unset, TOKENFUSE_ADMIN_KEYS is unset and the bind is loopback
    When a client lists runs
    Then the answer is 403 admin_keys_required

  # @test:allow_open_obs_still_restores_the_open_admin_routes_under_governed
  Scenario: The observability escape hatch still works under governed
    Given TOKENFUSE_PROFILE is unset, TOKENFUSE_ADMIN_KEYS is unset and TOKENFUSE_ALLOW_OPEN_OBS is "1"
    When a client lists runs
    Then the answer is 200

  # @test:under_the_governed_profile_declassify_refuses_without_its_key
  Scenario: Declassification is closed under governed unless its key is configured
    Given TOKENFUSE_PROFILE is unset and TOKENFUSE_DECLASSIFY_KEY is unset
    When a client asks to clear a run's taint
    Then the clearance is refused and the answer names TOKENFUSE_DECLASSIFY_KEY

  # @test:under_the_governed_profile_a_non_loopback_bind_without_client_auth_refuses_to_start
  Scenario: Governed refuses to start on a wide bind that authenticates nobody
    Given TOKENFUSE_PROFILE is unset, the bind is 0.0.0.0, and neither TOKENFUSE_CLIENT_KEYS nor TOKENFUSE_AGENT_TOKENS is set
    When the gateway starts
    Then it exits with code 2 before listening, naming the three ways out

  # @test:under_the_observe_profile_a_non_loopback_bind_starts_with_the_warning
  Scenario: Observe starts a wide bind with client auth off and keeps the warning
    Given TOKENFUSE_PROFILE is "observe", the bind is 0.0.0.0 and no client authentication is set
    When the gateway starts
    Then it listens and prints the invariant 119 warning

  # @test:a_loopback_bind_under_the_governed_profile_starts_without_client_keys
  Scenario: A loopback gateway under governed starts without client keys
    Given TOKENFUSE_PROFILE is unset and the bind is 127.0.0.1
    When the gateway starts
    Then it listens

  # @test:the_startup_line_names_each_governed_setting_and_where_it_came_from
  Scenario: The startup line says which profile is in effect and where each setting came from
    Given TOKENFUSE_PROFILE is unset and TOKENFUSE_MODE is "warn"
    When the gateway starts
    Then one line names the profile and each governed setting with its source, profile or env

  # @test:the_health_detail_names_the_profile
  Scenario: The health detail reports the profile
    Given the gateway runs under the governed profile
    When a client asks for the health detail
    Then the answer carries profile governed

  # @test:an_explicit_firewall_mode_wins_over_the_governed_default
  Scenario: An explicit firewall mode is never overridden by the profile
    Given TOKENFUSE_PROFILE is unset and TOKENFUSE_FIREWALL is "shadow"
    When a tool that writes is checked in a run that read the web
    Then the check is allowed and the would-block is recorded

  # @test:an_explicit_policy_hook_mode_wins_over_the_governed_default
  Scenario: An explicit policy hook mode is never overridden by the profile
    Given TOKENFUSE_PROFILE is unset, TOKENFUSE_WARDRYX_URL is set and TOKENFUSE_WARDRYX_MODE is "shadow"
    When the gateway starts
    Then the policy hook starts in shadow

  # @test:an_explicit_policy_hook_failmode_wins_over_the_governed_default
  Scenario: An explicit policy hook failmode is never overridden by the profile
    Given TOKENFUSE_PROFILE is unset, TOKENFUSE_WARDRYX_URL is set and TOKENFUSE_WARDRYX_FAILMODE is "open"
    When the gateway starts
    Then the policy hook starts with failmode open

  # @test:an_explicit_declassify_key_is_required_under_governed
  Scenario: A configured declassification key is required, as before
    Given TOKENFUSE_PROFILE is unset and TOKENFUSE_DECLASSIFY_KEY is set
    When a client asks to clear a run's taint without the key
    Then the clearance is refused and the answer says the key is required

  # @test:the_governed_broker_enforces_its_policy_hook_once_a_plane_is_named
  Scenario: The MCP broker enforces its policy hook under governed once a plane is named
    Given TOKENFUSE_PROFILE is governed and TOKENFUSE_WARDRYX_URL names a policy plane
    When the MCP broker starts
    Then its startup line says the policy hook is enforce from the profile, with failmode Closed

  # @test:a_policy_plane_deny_refuses_a_tool_call_under_the_governed_profile
  Scenario: A policy plane's deny refuses a tool call under the governed broker
    Given TOKENFUSE_PROFILE is governed and the policy plane denies the tool
    When an agent calls that tool through the broker
    Then the call is refused with -32004 and nothing reaches the upstream

  # @test:an_explicit_shadow_hook_still_forwards_under_the_governed_broker
  Scenario: An explicit shadow policy hook still forwards under the governed broker
    Given TOKENFUSE_PROFILE is governed and TOKENFUSE_WARDRYX_MODE is "shadow"
    When an agent calls a tool the policy plane denies
    Then the call is forwarded to the upstream

  # @test:the_governed_broker_with_no_policy_plane_says_so
  Scenario: A governed broker with no policy plane says its hook is off and why
    Given TOKENFUSE_PROFILE is governed and TOKENFUSE_WARDRYX_URL is unset
    When the MCP broker starts
    Then its startup line says the policy hook is off because there is no URL

  # @test:a_policy_file_with_no_mode_is_enforce_under_governed
  Scenario: A policy file that names no mode is enforce under governed
    Given TOKENFUSE_PROFILE is governed and a policy file names no mode
    When the gateway starts and a tool that writes is checked after a web read
    Then the startup line says firewall enforce from the profile and the check is denied

  # @test:a_policy_file_with_no_mode_stays_off_under_observe
  Scenario: A policy file that names no mode stays off under observe
    Given TOKENFUSE_PROFILE is observe and a policy file names no mode
    When the gateway starts and a tool that writes is checked after a web read
    Then the startup line says firewall off from the file and the check is allowed

  # @test:a_policy_file_that_names_shadow_is_not_overridden_under_governed
  Scenario: A policy file that names a mode is never overridden by the profile
    Given TOKENFUSE_PROFILE is governed and a policy file names shadow
    When the gateway starts
    Then the startup line says firewall shadow from the file
