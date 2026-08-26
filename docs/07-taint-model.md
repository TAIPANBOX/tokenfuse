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
| B.3 P3 subagent inherits the parent's taint | Built 2026-08-26. Resolved on every request by walking the declared parent chain, so a parent that becomes untrusted AFTER its child started is picked up on the child's next call. |
| B.3 P4 a new run is a clean set | Built, by the same keying. |
| B.4 sanitization gates | **None of the three is built.** A label, once acquired, is carried for the life of the run. |
| B.10's "semantic content analysis complements this" | Built 2026-08-26, as a taint SOURCE and never as a decision. See below. |
| B.5 capabilities | Built as a `tool -> capability` map, configurable. The built-in policy names three of the spec's seven: `exec`, `write`, `network_egress`. |
| B.6 policy file | Built, in JSON rather than YAML (see below). `mode` and named `rules` with `when_any`/`deny`. `action:` is not built: every rule blocks. `require_approval` and `sanitize_gate` do not exist, so `sanitizers:` and `approval:` are unimplemented. |
| B.7 level 1, proxy advisory | Built. |
| B.7 level 2, SDK `POST /v1/fuse/check-tool-call` | Built 2026-08-26. Judges and does not accumulate. Always HTTP 200 with the decision in the body. |
| B.7 level 3, MCP gateway enforcement | Built 2026-08-26, as a CLIENT of level 2. `tokenfuse mcp-broker` is a separate process invocation with no taint state of its own, so it asks the gateway rather than judging; one judge, reached from both doors. Off unless `TOKENFUSE_MCP_TAINT_GATEWAY` names one. |
| B.9 anti-exfiltration on and undisableable | Built, in enforce mode, including against a policy file that omits it. |
| B.9 the firewall on by default | **`shadow` since 2026-08-26**, `off` before it. Shadow refuses nothing, so no request that worked yesterday fails today; what it does is write. `TOKENFUSE_FIREWALL=off` restores the old silence exactly. `enforce` stays an operator decision. |

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
| `taint_raised` | `low` | a run acquired a label it did not have. Fires once per label per run, since taint is monotonic. `data.stage` says where from: `request_history` (a tool was called), `request_header` (the caller declared it), `parent_run` (an ancestor carried it), `tool_result` (a document said something instruction-shaped, with `data.signals` naming which patterns). |
| `taint_shadow` | `medium` | the filter would have refused and did not, because the mode is shadow. The action was PERMITTED. |
| `taint_block` | `high` | the filter refused. |

Both verdict types carry the same `data`: `stage`, `mode`, `rule`, `labels`,
`requested`, `denied`, `tools`. `denied` says a category was refused; `tools`
says which door was tried. `taint_raised` carries `stage`, `added`,
`from_tools`, `carrying`.

### The three enforcement points, and what each is worth

| door | who asks | what it is worth |
|---|---|---|
| `/v1/messages` | nobody; the gateway judges the model's answer | advisory. The gateway replaces the response with a 403; a client that ignores it runs the tool anyway. |
| `POST /v1/fuse/check-tool-call` | an executor, before running a tool | hard, for a client that acts on the answer, which is the only reason it asked. |
| `tokenfuse mcp-broker` | nobody; the broker judges before forwarding | hard for anything that goes through the broker at all, whether or not it asks. |

Level 2's answer distinguishes three things and not two: `allow` because
nothing objected, `allow` because the firewall is OFF (`governed: false`), and
`allow` because it is in shadow and a rule DID object (`would_block` present).
A client that folded those together would report "the gateway permitted this"
for a box where nothing was asked, which is `dependency_failed`'s
`allowed_ungoverned` mistake one plane over.

Level 3 is a client of level 2 and not a second judge. The broker is a separate
process invocation with its own state, so a taint map of its own would be a
second answer about one run, and an operator reading a refusal at one door and
a permission at the other would have no way to tell which was right. It needs
`x-fuse-run-id` on the call, because taint is per run and MCP carries no run
identity; without one, `TOKENFUSE_MCP_TAINT_FAILMODE=closed` refuses and the
default lets it through. A gateway it cannot reach is recorded as
`dependency_failed` naming the policy plane, exactly as the LLM path records
its own unreachable PDP.

### Which instruction a turn carried

Both taint families carry `data.prompt_hash`: `sha384:<hex>` over the LAST user
message's text, or absent when the turn had none.

The last message and not the history, because hashing the conversation produces
a value that changes every turn and groups nothing. What this answers is "did
these four incidents come from one instruction" and "did the instruction change
at the turn things went wrong", and only the newest instruction has that
property.

A hash and only a hash. Identical instructions collapse, a changed one is
visible at the turn it changed, and an instruction somebody still has can be
confirmed against it. What it cannot do is tell you what the text said, which
is the point: nothing here holds content, so nothing here needs erasing. It is
on the ACQUISITION as well as on the verdict, because the turn a run became
untrusted and the turn it tried something are usually not the same turn, and an
investigation reads both.

**It does not reach trailryx's `basis.prompt_hash`, and that is correct.** That
field is typed metadata, which is unerasable by design, and this value arrives
in `data`, which trailryx's mapper is forbidden from reading into a typed
field. So it lands in the payload plane with the rest of `data`, behind the key
whose destruction erases it. A hash of a prompt is a pseudonymous identifier of
content that may be personal, and putting one where erasure cannot reach is the
mistake that store's own documentation warns about for `agent_id`.

### The injection detector, and why it may not decide anything

`crates/core/src/injection.rs`, built 2026-08-26. It reads tool results, and
when a document is written like an instruction to the model it adds one label,
`suspected_injection`. That is all it does. The capability gate refuses, exactly
as it does for `web`.

**It may not decide, and the reason is not caution.** A text classifier is
talked around, because the attacker writes the text: anything that reads the
text and then chooses `allow` or `deny` has handed the attacker a vote in its
own verdict. As a taint source it has no such vote. Taint is monotonic, so the
attacker's words can only make the gate STRICTER and never looser; defeating
the detector returns you to the coarse label model, it does not get you past
it. A false positive costs one refused dangerous action. A false negative costs
nothing that was not already being lost.

**What it adds, given the label model already exists.** A run that called
`web_search` is already untrusted and this adds nothing there. It earns its
place in one case, and it is the common one: **a source the operator classified
as TRUSTED, carrying something the world put in it.** An internal ticket
system, a wiki, a support inbox, a repository the team owns. The source map is
a statement about the PIPE; injections arrive in the WATER. Second, it says
WHY: before it, an operator read "blocked, context was [web]" and could not
tell whether anything had actually tried anything.

**Signals are names, never text.** `instruction_override`,
`role_impersonation`, `exfiltration_request`, `secret_solicitation`,
`tool_directive`, `hidden_text`. A name is a fact about the SHAPE of a document
and carries none of its content, which is what lets it travel on a bus that
holds no content, into the record and into an alert. Measured on a live run
against a ticket containing an override, an exfiltration ask and a tool
directive: three signals on the event, zero words of the ticket anywhere in the
NDJSON.

**It scans tool results and not the user's own message.** A user message is the
operator speaking, and a security engineer typing "check whether it will ignore
all previous instructions" would otherwise taint their own run for doing their
job. The cost is named rather than hidden: an operator who PASTES an untrusted
document into their own message is not covered.

**Its label gets a rule when nothing else denies it, in enforce mode only.**
`@claude`, and different from anti-exfiltration's floor, which B.9 locks. A
policy file written before this detector existed could not have mentioned the
label, so reading its silence as consent would give every such operator a
detector producing a label nothing acts on, which is the exact case it exists
for. A rule of their own naming the label wins, so narrowing it is one line;
`"detect_injection": false` turns the scan off entirely, because a floor with
no exit is one somebody escapes by turning the whole firewall off.

Regex only. No ML, no external call, no network, the same discipline as the DLP
scanner, and English-only. Deliberately uncapped: a cap would be a silent false
negative in the middle of a long document, which is where somebody hiding an
instruction would put it, and the gateway has already parsed those bytes as
JSON, so a linear sweep over them is cheaper than the parse that produced them.

It is defeatable by anybody who reads that file, which is public. That is
acceptable only because it cannot lower a gate.

### Reading it back

```
tokenfuse firewall --events <ndjson> [--run <id>] [--agent <id>] [--json]
```

Answers how runs became untrusted and from which tools, what each rule
decided, what the agents tried to do, at which stage, and the one an operator
runs a shadow week to get: what turning enforcement on over that window would
have refused, across how many runs and agents, and who would notice most.
