Feature: A delegation credential never reaches an upstream provider

  A caller presenting a vouchryx delegation token as `Authorization: DPoP
  <token>` plus a `dpop` proof is proving whom a call acts for, never handing
  over a provider credential. `FORWARD_HEADERS` carries `authorization` for
  the OpenAI door's own pass-through provider key (`Authorization: Bearer
  <key>`), and until this fix that one allowlist entry let a DPoP-scheme
  Authorization ride along too, whether or not the gateway's own delegation
  door had resolved it into a proven chain. Measured 2026-09-27 on the forge
  k3d lab: Anthropic answered "401 Invalid bearer token" because it had
  received the delegation token, not a provider key.

  # @test:a_dpop_scheme_authorization_is_never_forwarded_to_upstream
  Scenario: A DPoP-scheme Authorization is stripped before the real HTTP client sends it
    Given a request carrying "Authorization: DPoP <token>" and a "dpop" proof header
    When HttpProvider::send forwards the request upstream
    Then the upstream never receives an authorization header
    And the upstream never receives a dpop header

  # @test:http_provider_forwards_a_bearer_authorization_to_upstream
  Scenario: A genuine provider key keeps working unchanged
    Given a request carrying "Authorization: Bearer sk-test-openai-key"
    When HttpProvider::send forwards the request upstream
    Then the upstream receives that same Bearer authorization header unchanged

  # @test:dpop_scheme_check_is_case_insensitive
  Scenario: The DPoP scheme is recognised whatever its case
    Given an Authorization header whose scheme is spelled DPoP, dpop, DPOP, Dpop, or dPoP
    Then it is read as the DPoP auth-scheme
    But a Bearer or DPoPX scheme is not

  # @test:a_resolved_dpop_delegation_credential_never_reaches_the_provider
  Scenario: A delegation credential the gateway resolved still never reaches the provider
    Given a delegation issuer is configured and a caller presents a proven DPoP chain
    When the request is served through the real proxy handler
    Then the gateway admits the call as managed
    And the real upstream never receives the Authorization or dpop headers

  # @test:a_dpop_authorization_the_gateway_never_resolved_still_does_not_reach_the_provider
  Scenario: A DPoP Authorization the delegation door never resolved still does not reach the provider
    Given no delegation issuer is configured at all
    And a caller presents an Authorization header with a DPoP scheme
    When the request is served through the real proxy handler
    Then chainproof::resolve reads the chain as merely claimed
    And the real upstream still never receives the Authorization or dpop headers

  # @test:a_dpop_authorization_never_reaches_the_provider_on_the_openai_door_either
  Scenario: The same rule holds on the OpenAI door
    Given a caller presents a DPoP-scheme Authorization to POST /v1/chat/completions
    When the request is served through the real router
    Then the real upstream never receives the Authorization header

  # @test:a_resolved_delegation_credential_never_reaches_the_mcp_upstream
  Scenario: The MCP broker's own forward never carried these headers either
    Given the MCP broker resolves a caller's delegation credential
    When it forwards the tools/call to the real MCP server
    Then the upstream MCP server never receives the Authorization or dpop headers
