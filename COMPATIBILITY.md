# Compatibility

`TAIPANBOX/tokenfuse` promises the surface below from its 1.0 (`compat/1.0.json`, held by `scripts/compat-surface.sh` on every push). A frozen name is not removed or renamed within a major; an additive thing may appear as a minor; an experimental thing may change in any release.

Status: frozen at 1.0.0 (2026-09-14): the surface below is the promise of this major, written in the release commit and held by the gate from that commit on; every entry was measured by the 1.0 proving run (R0 to R3) on the v0.5.0 and v0.5.1 images it froze

## Frozen

### agentevent.types (19)

- `budget_exhausted`
- `sustained_loop`
- `spend_spike`
- `fanout_explosion`
- `budget_threshold`
- `run_killed`
- `breaker_tripped`
- `dlp_block`
- `taint_block`
- `mcp_drift`
- `identity_mismatch`
- `unit_cap_exceeded`
- `policy_deny`
- `tool_call`
- `dependency_failed`
- `taint_shadow`
- `taint_raised`
- `taint_cleared`
- `breaker_shadow`
- held in: `contracts/tokenfuse-constants.json`, `crates/core/src/agent_event.rs`

### breaker.reasons (9)

- `budget_exceeded`
- `policy_violation`
- `loop_detected`
- `killed`
- `wasm_policy`
- `taint_blocked`
- `dlp_blocked`
- `unit_budget_exceeded`
- `identity_mismatch`
- held in: `contracts/tokenfuse-constants.json`, `crates/core/src/breaker.rs`

### cli.binaries (2)

- `tokenfuse`
- `tokenfuse-cloud`
- held in: `components.json`

### cli.subcommands (16)

- `--version`
- `-V`
- `--help`
- `-h`
- `top`
- `sql`
- `backtest`
- `savings`
- `compliance`
- `mcp-scan`
- `focus-export`
- `firewall`
- `outcomes`
- `constants`
- `mcp-broker`
- `--openapi`
- held in: `crates/gateway/src/main.rs`, `crates/cloud/src/main.rs`

### env (83)

- `TOKENFUSE_ADDR`
- `TOKENFUSE_ADMIN_KEYS`
- `TOKENFUSE_AGENT_ID_MODE`
- `TOKENFUSE_ALLOW_OPEN_OBS`
- `TOKENFUSE_ALLOW_STUB`
- `TOKENFUSE_CACHE`
- `TOKENFUSE_CACHE_EMBEDDER`
- `TOKENFUSE_CLIENT_KEYS`
- `TOKENFUSE_DATA_DIR`
- `TOKENFUSE_DECLASSIFY_KEY`
- `TOKENFUSE_DELEGATION_AUDIENCE`
- `TOKENFUSE_DELEGATION_ISSUER`
- `TOKENFUSE_DELEGATION_JWKS`
- `TOKENFUSE_DELEGATION_REVOCATIONS`
- `TOKENFUSE_DELEGATION_REVOCATIONS_FAILMODE`
- `TOKENFUSE_DELEGATION_REVOCATIONS_INTERVAL_MS`
- `TOKENFUSE_DELEGATION_REVOCATIONS_MAX_AGE_SECS`
- `TOKENFUSE_DELEGATION_URL`
- `TOKENFUSE_DLP`
- `TOKENFUSE_DLP_PII`
- `TOKENFUSE_EVENTS_PATH`
- `TOKENFUSE_FIREWALL`
- `TOKENFUSE_FIREWALL_CONFIG`
- `TOKENFUSE_IDENTITY_MAP`
- `TOKENFUSE_IDENTITY_STRICT`
- `TOKENFUSE_MAX_BODY_BYTES`
- `TOKENFUSE_MCP_ADDR`
- `TOKENFUSE_MCP_ALLOW_OPEN_BIND`
- `TOKENFUSE_MCP_CLIENT_IDS`
- `TOKENFUSE_MCP_DLP`
- `TOKENFUSE_MCP_DLP_PII`
- `TOKENFUSE_MCP_KEYS`
- `TOKENFUSE_MCP_LOCK`
- `TOKENFUSE_MCP_PROOF_URL`
- `TOKENFUSE_MCP_REQUIRE_PROOF`
- `TOKENFUSE_MCP_REQUIRE_SECRET_SCOPES`
- `TOKENFUSE_MCP_SCAN`
- `TOKENFUSE_MCP_SCAN_CONNECT_TIMEOUT_SECS`
- `TOKENFUSE_MCP_SCAN_MAX_BODY_BYTES`
- `TOKENFUSE_MCP_SCAN_TIMEOUT_SECS`
- `TOKENFUSE_MCP_SECRETS`
- `TOKENFUSE_MCP_SECRET_SCOPES`
- `TOKENFUSE_MCP_STDIO`
- `TOKENFUSE_MCP_TAINT_FAILMODE`
- `TOKENFUSE_MCP_TAINT_GATEWAY`
- `TOKENFUSE_MCP_UPSTREAM`
- `TOKENFUSE_MCP_UPSTREAMS`
- `TOKENFUSE_MODE`
- `TOKENFUSE_OTLP_ENDPOINT`
- `TOKENFUSE_REQUIRE_RUN_ID`
- `TOKENFUSE_ROUTER`
- `TOKENFUSE_ROUTER_RULES`
- `TOKENFUSE_UPSTREAM`
- `TOKENFUSE_UPSTREAM_CONNECT_TIMEOUT_SECS`
- `TOKENFUSE_URL`
- `TOKENFUSE_WARDRYX_CACHE_TTL_MS`
- `TOKENFUSE_WARDRYX_FAILMODE`
- `TOKENFUSE_WARDRYX_KEY`
- `TOKENFUSE_WARDRYX_MODE`
- `TOKENFUSE_WARDRYX_TIMEOUT_MS`
- `TOKENFUSE_WARDRYX_URL`
- `TOKENFUSE_WIRE`
- `TOKENFUSE_CLOUD_ALERT_PCT`
- `TOKENFUSE_CLOUD_ALLOW_DEVKEY`
- `TOKENFUSE_CLOUD_AUDIT_SIGNING_KEY`
- `TOKENFUSE_CLOUD_DATA`
- `TOKENFUSE_CLOUD_HOST`
- `TOKENFUSE_CLOUD_INCIDENT_BUDGET_BLOCKS`
- `TOKENFUSE_CLOUD_INCIDENT_FANOUT_MULTIPLE`
- `TOKENFUSE_CLOUD_INCIDENT_FANOUT_RUNS`
- `TOKENFUSE_CLOUD_INCIDENT_LOOP_REPEATS`
- `TOKENFUSE_CLOUD_INCIDENT_SPEND_PER_MIN_USD`
- `TOKENFUSE_CLOUD_INCIDENT_SPIKE_MULTIPLE`
- `TOKENFUSE_CLOUD_KEY`
- `TOKENFUSE_CLOUD_KEYS`
- `TOKENFUSE_CLOUD_OIDC_ADMIN_ROLE`
- `TOKENFUSE_CLOUD_OIDC_AUDIENCE`
- `TOKENFUSE_CLOUD_OIDC_ISSUER`
- `TOKENFUSE_CLOUD_OIDC_JWKS`
- `TOKENFUSE_CLOUD_OIDC_ORG_CLAIM`
- `TOKENFUSE_CLOUD_OIDC_ROLES_CLAIM`
- `TOKENFUSE_CLOUD_REPLAY_EVENTS`
- `TOKENFUSE_CLOUD_URL`
- held in: `components.json`

### formats.constants (1)

- `taipanbox.dev/tokenfuse-constants/v1`
- held in: `contracts/tokenfuse-constants.json`, `crates/gateway/src/constants.rs`

### formats.trace_parquet (16)

- `ts_millis`
- `run_id`
- `model`
- `decision`
- `input_tokens`
- `output_tokens`
- `cost_microusd`
- `step`
- `agent_id`
- `saved_microusd`
- `parent_run_id`
- `on_behalf_of`
- `outcome`
- `key_id`
- `unit`
- `tool_calls`
- held in: `contracts/tokenfuse-constants.json`, `crates/gateway/src/sink.rs`

### http.cloud_headers (5)

- `x-fuse-runs-window`
- `x-fuse-device`
- `x-fuse-nonce`
- `x-fuse-ts`
- `x-fuse-sig`
- held in: `crates/cloud/src/http.rs`

### http.cloud_routes (33)

- `/`
- `/healthz`
- `/openapi.json`
- `/v1/ingest`
- `/v1/runs`
- `/v1/spend`
- `/v1/agents`
- `/v1/units`
- `/v1/owners`
- `/v1/savings`
- `/v1/summary`
- `/v1/alerts`
- `/v1/series`
- `/v1/stream`
- `/v1/runs/{run}/kill`
- `/v1/kills`
- `/v1/runs/{run}/budget`
- `/v1/budgets`
- `/v1/units/{id}/budget`
- `/v1/unit-budgets`
- `/v1/incidents`
- `/v1/incidents/{id}/ack`
- `/v1/findings`
- `/v1/compliance`
- `/v1/compliance/evidence`
- `/v1/audit`
- `/v1/audit/verify`
- `/v1/audit/manifest`
- `/v1/replay/{run}`
- `/v1/pair/new`
- `/v1/pair`
- `/v1/devices/{id}/apns`
- `/v1/devices/{id}/activity`
- held in: `crates/cloud/src/http.rs`

### http.request_headers (13)

- `x-fuse-run-id`
- `x-fuse-parent-run-id`
- `x-fuse-agent-id`
- `x-fuse-budget-usd`
- `x-fuse-on-behalf-of`
- `x-fuse-key`
- `x-fuse-taint`
- `x-fuse-task-type`
- `x-fuse-outcome`
- `x-fuse-approval-token`
- `x-fuse-attestation-method`
- `x-fuse-declassify-key`
- `x-fuse-mcp-upstream`
- held in: `crates/gateway/src/proxy.rs`, `crates/gateway/src/clientkeys.rs`, `crates/gateway/src/declassify.rs`, `crates/gateway/src/mcpbroker.rs`

### http.response_headers (16)

- `x-fuse-mode`
- `x-fuse-step`
- `x-fuse-stream`
- `x-fuse-cost-usd`
- `x-fuse-spent-usd`
- `x-fuse-would-block`
- `x-fuse-wardryx`
- `x-fuse-identity`
- `x-fuse-router`
- `x-fuse-dlp`
- `x-fuse-taint`
- `x-fuse-cache`
- `x-fuse-similarity`
- `x-fuse-saved-usd`
- `x-fuse-price`
- `x-fuse-approval-id`
- held in: `crates/gateway/src/proxy.rs`

### http.routes (10)

- `/healthz`
- `/v1/messages`
- `/v1/chat/completions`
- `/v1/runs`
- `/v1/runs/{id}/kill`
- `/v1/keys`
- `/v1/policy-plane`
- `/v1/agent-ids`
- `/v1/fuse/check-tool-call`
- `/v1/fuse/declassify`
- held in: `crates/gateway/src/lib.rs`

### images (3)

- `tokenfuse`
- `tokenfuse-control-plane`
- `tokenfuse-dashboard`
- held in: `README.md`

### listen.defaults (2)

- `127.0.0.1:4100`
- `127.0.0.1:4200`
- held in: `components.json`, `crates/gateway/src/main.rs`

### sdk.python (15)

- `DEFAULT_GATEWAY`
- `gateway_url`
- `messages_url`
- `chat_completions_url`
- `openai_base_url`
- `run_headers`
- `raise_for_fuse`
- `check_response`
- `FuseError`
- `BudgetExceeded`
- `LoopDetected`
- `PolicyViolation`
- `Killed`
- `TaintBlocked`
- `DlpBlocked`
- held in: `sdk/python/tokenfuse/__init__.py`

## Additive within a major

- a new BreakerReason wire string, a new agent-event type or a new x-fuse header: appended, published in contracts/tokenfuse-constants.json by scripts/constants.sh (invariant 14), never renamed
- the agent-event envelope schema this emitter writes (taipanbox.dev/agent-event/v0.2 today): it moves with agent-passport's SPEC in its own release (SPEC 6.2/6.4), not with this repository's
- a Parquet trace column: appended, nullable on read (invariant 6); a column is never removed or retyped within this major
- a model in the price book (contracts/tokenfuse-constants.json#price_book): a model may be added or repriced in a minor; the fallback rate and the microusd_per_mtok unit stay
- a new subcommand, a new TOKENFUSE_ environment name behind a new feature, a new Cloud route: a minor
- the JS SDK (npm tokenfuse) exports the Python names in camelCase (gatewayUrl, messagesUrl, chatCompletionsUrl, openaiBaseUrl, runHeaders, DEFAULT_GATEWAY, VERSION); sdk/js/test.js calls every one, so they are held by that test rather than by this gate, whose literal rule cannot see an unquoted JS identifier

## Experimental

- raft HA (crates/cluster, the cluster feature, TOKENFUSE_CLUSTER_*): compiled out of every shipped image; the twelve names are read only by a build nobody publishes (components.json's the_ha_capability_is_compiled_out_of_every_shipped_binary)
- WASM policies (feature wasm, TOKENFUSE_WASM_POLICY): in no shipped image
- APNs push from the Cloud (feature apns, the five TOKENFUSE_APNS_* names): in no shipped image; the device-pairing routes it serves are frozen because the shipped Cloud answers them
- radar (crates/radar, the eBPF sensor): its own workspace and CI job, Linux-only, emits no shared envelope yet (invariant 21)
- the FinOps model router (TOKENFUSE_ROUTER, TOKENFUSE_ROUTER_RULES) and the semantic cache (TOKENFUSE_CACHE, TOKENFUSE_CACHE_EMBEDDER): the variable names are frozen, their rule syntax and the x-fuse-router / x-fuse-cache header values are not
- TOKENFUSE_KEYS and TOKENFUSE_EVENTS appear in components.json and are read by nothing (a test fixture in clientkeys.rs and a hint string in firewallcli.rs); TOKENFUSE_VERSION and TOKENFUSE_GIT_SHA are build-time stamps, not configuration: none of the four is promised
- the max_tokens clamp against the remaining budget that docs/02 ADR-4 describes does not exist (docs/26 section 8); the pre-flight estimate reads the field and never rewrites it

## Support

The newest minor gets every fix; the previous minor gets security-relevant fixes for 90 days after the newer one is tagged. Before this repository's 1.0, only `main` is supported.
