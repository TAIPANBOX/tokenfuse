Feature: Admin keys guard the gateway's observability and kill routes

  `GET /v1/runs`, `POST /v1/runs/{id}/kill`, `GET /v1/keys`,
  `GET /v1/policy-plane` and `GET /v1/agent-ids` were registered with no
  authentication at all. The comment beside them said the gateway binds
  loopback by default, which is true and was not the whole picture: the
  shipped Dockerfile sets `TOKENFUSE_ADDR=0.0.0.0:4100`, and a deployment
  that publishes that port hands anyone who can reach it every run's budget
  and spend, every key id, every agent identity, and a kill switch for any
  run.

  The fix mirrors the MCP broker's door (CLAUDE.md invariant 20): nothing
  configured on a loopback bind changes nothing; nothing configured on a
  non-loopback bind refuses every request to these five routes; a configured
  `TOKENFUSE_ADMIN_KEYS` bearer key is required regardless of the bind; and
  an explicit `TOKENFUSE_ALLOW_OPEN_OBS=1` opts back into the old open
  behaviour without silencing the startup warning.

  Background:
    Given a gateway serving the LLM proxy and the five admin routes

  # @test:an_open_bind_with_no_admin_keys_refuses_kill_and_runs
  Scenario: A wide-open bind with nothing configured refuses the dangerous routes
    Given the gateway is bound to a non-loopback address
    And no TOKENFUSE_ADMIN_KEYS is configured
    When a caller requests GET /v1/runs or POST /v1/runs/{id}/kill
    Then the gateway answers 403 with {"error": "admin_keys_required"}

  # @test:a_loopback_bind_with_no_admin_keys_keeps_the_routes_open
  Scenario: The default loopback bind is unchanged
    Given the gateway is bound to loopback, its default
    And no TOKENFUSE_ADMIN_KEYS is configured
    When a caller requests any of the five admin routes
    Then the gateway answers exactly as it did before this gate existed

  # @test:a_configured_admin_key_opens_the_routes_and_a_wrong_one_does_not
  Scenario: A configured key is required regardless of the bind
    Given TOKENFUSE_ADMIN_KEYS names one key
    When a caller presents that key as an Authorization Bearer token
    Then the gateway answers the request normally
    But a caller presenting a different key, or no key at all, gets 401 with {"error": "unauthorized"}

  # @test:the_allow_open_obs_opt_out_is_honoured_and_logged
  Scenario: An operator can opt back into the old open behaviour
    Given the gateway is bound to a non-loopback address
    And no TOKENFUSE_ADMIN_KEYS is configured
    And TOKENFUSE_ALLOW_OPEN_OBS=1 is set
    When a caller requests any of the five admin routes
    Then the gateway answers normally, with no refusal
    And a startup warning still names TOKENFUSE_ADMIN_KEYS as the safer fix

  # @test:healthz_and_messages_are_never_behind_the_admin_gate
  Scenario: The LLM proxy is never behind this gate
    Given the gateway is bound to a non-loopback address with nothing configured, so the five admin routes are refusing every request
    When a caller requests GET /healthz or POST /v1/messages
    Then the gateway answers normally, unaffected by the admin routes being closed
