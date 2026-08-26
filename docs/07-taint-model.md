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

---

## B.11. What is actually built, 2026-08-26

Everything above is the design from 2026-07-02. This section is the honest
state of the code, so a reader can tell a specification from a shipped thing.
`@measured 2026-08-26` unless marked otherwise: each row was read off the
tree, and the enforcement rows were driven through a release binary with a
live upstream.

| Spec | State |
|---|---|
| B.2 source classification | Built, as a JSON policy file. Multiple labels per source, per the spec's `labels: [...]`. Matching is on tool NAME only: `mcp_server` and `args.path` globs are not built. |
| B.3 P1, P2 monotonic accumulation | Built. |
| B.3 P3 subagent inherits the parent's taint | **Not built.** Taint is keyed by `run_id` alone, so a sub-run starts clean. |
| B.3 P4 a new run is a clean set | Built, by the same keying. |
| B.4 sanitization gates | **None of the three is built.** A label, once acquired, is carried for the life of the run. |
| B.5 capabilities | Built as a `tool -> capability` map, configurable. The built-in policy names three of the spec's seven: `exec`, `write`, `network_egress`. |
| B.6 policy file | Built, in JSON rather than YAML (see below). `mode` and named `rules` with `when_any`/`deny`. `action:` is not built: every rule blocks. `require_approval` and `sanitize_gate` do not exist, so `sanitizers:` and `approval:` are unimplemented. |
| B.7 level 1, proxy advisory | Built. |
| B.7 level 2, SDK `POST /v1/fuse/check-tool-call` | **Not built.** No such endpoint exists. |
| B.7 level 3, MCP gateway enforcement | **Not built** for taint. The broker has its own Wardryx gate, which is a different decision. |
| B.9 anti-exfiltration on and undisableable | Built, in enforce mode, including against a policy file that omits it. |
| B.9 the firewall on by default | **No.** `TOKENFUSE_FIREWALL` still defaults to `off`, so out of the box this subsystem protects nothing. Turning it on is an operator decision and stays one. |

### JSON, not YAML

The spec's examples are YAML and the loader takes JSON. `serde_yaml` has been
unmaintained since 2024, and taking an abandoned parser for the configuration
of a security control is a worse trade than asking an operator to write
braces. It is also what this repository already does for the other artifact it
pins, the MCP tool lock. The SHAPE is B.2/B.5/B.6's.

```json
{
  "mode": "shadow",
  "sources":      { "crm_lookup": ["customer_data", "pii"] },
  "capabilities": { "wire_transfer": "financial" },
  "rules": [
    { "name": "no-payments-after-customer-data",
      "when_any": ["customer_data"],
      "deny": ["financial"] }
  ]
}
```

- `TOKENFUSE_FIREWALL_CONFIG=<path>` loads it. Unset, the built-in starter
  policy applies, so nothing changes for a box that has not opted in.
- `TOKENFUSE_FIREWALL = off | shadow | enforce` sets the mode and **wins over
  the file's own `mode`**: turning enforcement down is what an operator does in
  a hurry, and it should not need write access to a file.
- A file **replaces** the built-in policy rather than merging into it, so `{}`
  is a firewall that classifies nothing and refuses nothing. Merging would mean
  a rule you deleted is still live.
- **Except anti-exfiltration**, which B.9 locks on: a file that omits it gets
  it back, first in the order, in enforce mode only.
- A named config that cannot be read, does not parse, has an unknown mode, an
  unnamed rule, or a misspelled key **aborts the process with exit 2** and
  names the field. A gateway running the starter policy while its operator
  believes their own rules are live is worse than one that is plainly off.

### What it writes

Three event types on the shared bus. Before 2026-08-26 there was one, and
shadow mode wrote nothing at all.

| type | band | when |
|---|---|---|
| `taint_raised` | `low` | a run acquired a label it did not have. Fires once per label per run, since taint is monotonic. |
| `taint_shadow` | `medium` | the filter would have refused and did not, because the mode is shadow. The action was PERMITTED. |
| `taint_block` | `high` | the filter refused. |

Both verdict types carry the same `data`: `stage`, `mode`, `rule`, `labels`,
`requested`, `denied`, `tools`. `denied` says a category was refused; `tools`
says which door was tried. `taint_raised` carries `stage`, `added`,
`from_tools`, `carrying`.

### Reading it back

```
tokenfuse firewall --events <ndjson> [--run <id>] [--agent <id>] [--json]
```

Answers how runs became untrusted and from which tools, what each rule
decided, what the agents tried to do, at which stage, and the one an operator
runs a shadow week to get: what turning enforcement on over that window would
have refused, across how many runs and agents, and who would notice most.
