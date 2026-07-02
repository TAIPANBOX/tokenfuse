# TokenFuse — Taint Model: Specification

> Phase 4 (enforcement), but the source_taint field in the trace dates back to Phase 1. Status: designed 2026-07-02. This is the core of the "agent runtime firewall" category.

## B.1. Threat Model

Prompt injection at the level of ACTIONS, not words: we don't try to recognize "bad text" (a losing race), instead we guarantee that after contact with an untrusted source, the agent is physically unable to perform a dangerous action without a human in the loop. This closes OWASP ASI01, exfiltration chains, and poisoned MCP tools.

## B.2. Labels, Not Levels

Taint = a set of labels (label set). Labels: `web`, `email`, `file_upload`, `external_repo`, `mcp:<server>`, `user_input`, `secrets` ("read secrets"), `unclassified` (unknown source = untrusted).

Source classification is done via a matcher config:

```yaml
sources:
  - match: { tool: "web_search" }                          labels: [web]
  - match: { tool: "fetch_url" }                           labels: [web]
  - match: { mcp_server: "github-mcp" }                    labels: [external_repo]
  - match: { tool: "read_file", args.path: "/uploads/**" } labels: [file_upload]
  - match: { tool: "vault_read" }                          labels: [secrets]
  default: { labels: [unclassified] }
```

## B.3. Propagation Rules (conservative, provable)

The unit of tracking is a message in the run's history (`origin` in the trace — that's why source_taint was built in from Phase 1).

| # | Rule |
|---|---|
| P1 | A tool result inherits the labels of its source |
| P2 | Model output produced with tainted context inherits the union of all labels in that context; a run accumulates taint monotonically — labels never disappear on their own |
| P3 | A subagent inherits the parent's taint by default (we don't trace textual provenance). Exception: sanitization gates |
| P4 | A new run = a clean set; a "quarantined sub-run" is a legitimate way to process dirty data |

Deliberately WITHOUT partial tracking (which paragraph came from where) — this is intractable at the proxy level and gives false precision. A coarse, monotonic model provides clear guarantees.

## B.4. Sanitization Gates (the only 3 ways to remove a label)

1. **Human-approve:** a human reviewed the content → the label is removed for the run (Slack buttons, the same flow as W3).
2. **Structured extraction gate (CaMeL-style):** tainted text → an extractor with a strict JSON schema ("number/enum/date only") → the valid structured result is declassified by policy: injection cannot get through something like `{"price": 42.10}`.
3. **Allowlist transformations:** predeclared deterministic functions (regex, date parsing).

## B.5. Capabilities

Tools are classified by a matcher according to their capabilities: `exec`, `write_prod`, `send_message` (email/Slack/external POST), `financial`, `read_secrets`, `spawn_agent`, `network_egress`.

## B.6. Policy Format

```yaml
taint_policy: default-agent-firewall
mode: enforce                      # shadow | warn | enforce
rules:
  - name: no-exec-after-untrusted
    when:  { context_has_any: [web, email, file_upload, unclassified] }
    deny:  { capability: [exec, write_prod, financial] }
    action: require_approval       # block | require_approval | sanitize_gate

  - name: anti-exfiltration        # the most important rule
    when:  { context_has_all: [secrets] }
    deny:  { capability: [send_message, network_egress] }
    action: block                  # secrets + outbound egress = never

  - name: quarantine-unknown-mcp
    when:  { context_has_any: [unclassified] }
    deny:  { capability: [send_message, spawn_agent] }
    action: block

sanitizers:
  - name: extract-price
    type: schema_extraction
    schema: { type: number }
    declassifies: [web]

approval:
  channel: "slack:#agent-approvals"
  timeout: 10m
  on_timeout: block                # silence = denial
```

## B.7. Enforcement Points (three levels, honestly)

The model REQUESTS a tool call in its response, but the client EXECUTES it. Therefore:

| Level | Mechanism | Guarantee |
|---|---|---|
| 1. LLM proxy (advisory) | the gateway sees tool_use in the response → on violation, replaces it with a `fuse_denied` block + alert; the SDK throws an exception | a client without the SDK can ignore this — we document it |
| 2. SDK hook (hard) | the executor calls `POST /v1/fuse/check-tool-call` before execution | hard guarantee, requires our SDK |
| 3. MCP gateway (hard, Phase 4) | the tool is invoked through our MCP proxy → blocked at execution time | full guarantee; the main argument for why the MCP gateway is a natural extension of the taint model |

## B.8. Attack Scenarios This Closes

1. Injection on a web page → `web` label → exec requires approval → the human rejects it.
2. Exfiltration: context has `secrets` + injection asks to "send to attacker.com" → anti-exfiltration → block, no exceptions.
3. Poisoned MCP tool: unknown server → `unclassified` → quarantine.
4. Rug pull: a tool's description changes between sessions → (MCP gateway) the server → `unclassified` until re-approved.

## B.9. Default Decisions (locked in)

A monotonic label-set model without partial tracking → unclassified = untrusted → anti-exfiltration is enabled out of the box and cannot be disabled in enforce mode → shadow mode for the remaining rules during the first week → sanitization only through the 3 explicit gates.

## B.10. Limitations (honestly)

- The advisory level without an MCP gateway/SDK can be bypassed; full guarantees only apply at levels 2–3.
- Conservativeness → false positives; the release valve is the gates in B.4 and the approval flow.
- The model is label-based, not content-based; semantic content analysis is a DLP module (Ring 3.2) — the two complement each other.
