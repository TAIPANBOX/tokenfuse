Feature: The control plane answers only the browser origins it was given

  Measured by the agent-security review of 2026-10-17: the control plane sent
  Access-Control-Allow-Origin: * on every response, so any web page an operator
  had open could read the fleet from the browser. Invariant 131.

  @decided 2026-10-17: the browser origins the control plane answers are a
  named list, loopback by default, and a list the operator sets replaces it.

  # @test:an_origin_nobody_named_gets_no_allow_origin_header
  Scenario: A page on a site nobody named is not told it may read the response
    Given a control plane with no origin list configured
    When a page on evil.example asks for a health answer
    Then the response carries no Access-Control-Allow-Origin header

  # @test:a_loopback_origin_is_reflected_exactly_and_marked_vary
  # @test:every_loopback_host_and_any_port_is_allowed_by_default
  Scenario: The local dashboard keeps working with nothing configured
    Given a control plane with no origin list configured
    When the dashboard on localhost, 127.0.0.1 or [::1] on any port asks
    Then the response names that origin exactly and says a cache must key on Origin

  # @test:a_preflight_from_an_origin_nobody_named_is_204_without_allow_origin
  # @test:a_preflight_from_a_loopback_origin_is_allowed
  Scenario: A preflight from a refused origin is answered with no permission
    When a browser sends a preflight from an origin nobody named
    Then the answer is 204 with no Access-Control-Allow-Origin

  # @test:a_configured_list_replaces_the_loopback_default
  Scenario: An operator who names a dashboard origin gives up loopback
    Given the origin list names https://dash.example.com
    When that origin asks, it is answered
    And when localhost asks, it is not

  # @test:a_request_with_no_origin_gets_no_cors_header
  Scenario: A server-to-server caller sends no Origin and gets no CORS header
    When a gateway calls the health route with no Origin header
    Then the response carries no CORS header at all

  # @test:a_malformed_cors_origin_stops_the_control_plane_before_it_listens
  # @test:a_wildcard_cors_origin_is_refused_not_honoured
  Scenario: A list the control plane cannot read stops it before it listens
    Given TOKENFUSE_CLOUD_CORS_ORIGINS holds an entry that is not an origin
    When the control plane starts
    Then it exits 2 naming that entry and never listens

  # @test:unset_or_blank_is_loopback_only_and_refuses_nothing
  # @test:an_entry_must_be_an_exact_origin
  # @test:one_bad_entry_refuses_the_whole_list
  # @test:a_configured_list_matches_exactly_and_case_insensitively_on_the_host
  # @test:loopback_is_http_and_one_of_three_hosts_on_any_port
  Scenario: An origin is matched exactly, scheme and port included
    Given an origin list of exact origins
    Then a different scheme, port or subdomain of the same name is not allowed
