# 25 - the delegation door: who a call is acting for, and whether anybody checked

Doc 24 is about proving **which client** is calling. This is the other half:
which **person or agent** that client says it is acting for, whether that claim
was verified, and what happens when the authority behind it is withdrawn.

## 1. What the door is

Both processes forward a chain of principals to the PDP: the human at the root,
then each agent that delegated onward. Wardryx makes its decision partly from
that chain, and `max_chain_depth` is a rule about its length.

Until 2026-08-26 the chain came from the `x-fuse-on-behalf-of` header. That is
worth saying plainly: **the depth limit capped a number the caller chose**, and
a caller who wanted a shorter chain sent one. `chainproof::resolve` is what
ended that. It verifies a delegation token, compares the chain the token proves
against the chain the header declared, and hands the PDP one of three answers:

| answer | what it means |
|---|---|
| `Proven` | a token verified, and the declared chain matched it |
| `Claimed` | no issuer configured, or no token presented: the header stands, and the record says it was never proved |
| `Refused` | a token was presented and did not verify, or contradicted the header |

`Claimed` is not a failure. It is what this gateway sent for its whole life, and
what changed is that it now says so rather than looking identical to a verified
one.

A declared chain is bounded before any of that runs (2026-09-18, tokenfuse#297).
`chainproof::declared_chain` is the one parser both doors read the header
through, and a chain of more than `MAX_CHAIN_ENTRIES` (32, read from the
delegation crate, agent-passport SPEC 5.1's number) is refused with
`400 invalid_request` / `on_behalf_of_over_cap` and one `identity_mismatch`
carrying the length and the cap, whether or not an issuer is configured: the
record refuses a longer chain, so forwarding one would write events the bus
cannot hold. Measured 2026-09-17 with no issuer, forty entries were forwarded
and answered 200 with nothing on the bus. Two other caps are not this one: the
4 KiB sanity cap on the raw header, older, which ignores the header as absent
rather than refusing; and the ledger's 64-ancestor cap over
`x-fuse-parent-run-id` (invariant 49), which bounds which runs a call rolls up
into across requests, not whom one request acts for.

## 2. It runs in both processes, which is now checked

The proxy (`serve`) and the MCP broker (`mcp_broker`) are separate process
invocations of one binary. Each reads its own environment and builds its own
state, and the two doors call `chainproof::resolve` with code that reads the
same at both sites.

Measured 2026-08-26: `chainproof::from_env()` was called in `mcp_broker` and
nowhere else, so the proxy's config was `None` on every request and every chain
it forwarded was a claim. Nothing said so. The call sites were identical, the
tests passed at both, and the difference lived a thousand lines away in a
function no diff had touched.

`scripts/both-processes-configure-the-same-doors.sh` is what now says so. It
finds every `from_env` call in `main.rs` by reading the source rather than from
a list of its own, and a door configured in one process must either be
configured in the other or carry a `process-local:` reason at the call site.
Two doors legitimately carry one: the broker has no prompt firewall and no model
router, because it never sees a prompt and picks no model.

## 3. Revocation, and the fail mode

A token that verifies is a token that was minted. Whether the authority behind
it still exists is a separate question, and vouchryx has served
`GET /v1/revocations` with an `as_of` cursor since the day it was written.
Measured 2026-08-26: nothing polled it, and both doors passed a closure that
answered `false`.

The split is deliberate and it is invariant 29: the **fetch** is out of band, in
a background task, and the **check** is local and synchronous. A revocation
check that cost a round trip would be one nobody could afford per request.

**Age decides what a MISS means and never what a HIT means.** Nothing un-revokes
a token, so a hit stands at any age. A miss is an inference from the list being
complete, completeness is what expires, and past the maximum age the fail mode
answers instead.

**The fail mode defaults to closed**, which is the opposite of the estate's two
other answers to "a dependency is unreachable", on purpose. An unreachable PDP
says nothing, so opening decides a question no answer was coming for. An
unreachable revocation list says one narrow thing: this authority can no longer
be confirmed to exist. Open there is also an attack primitive rather than only
an outage, because it makes "revoking ends the right to act" conditional on one
service being reachable, and it does it silently.

Three things bound the damage: the check is off entirely unless a URL is named,
a working poller refuses nothing at all, and vouchryx mints at a five-minute
TTL, so the outage this can cause is bounded by the same clock the control is.

**A door that has never fetched the list refuses to start.** It holds nothing,
and under the default it would turn away every delegated call while its log said
the door was on. That is the failure `firewall::from_env` and
`chainproof::from_env` both already exit 2 rather than enter.

## 4. Configuration

| Variable | Meaning |
|---|---|
| `TOKENFUSE_DELEGATION_ISSUER` | The exact `iss` to trust. Not a prefix. |
| `TOKENFUSE_DELEGATION_JWKS` | Path to a FILE holding the issuer's JWKS, read once at startup. |
| `TOKENFUSE_DELEGATION_JWKS_URL` | Absolute http(s) URL serving the issuer's JWKS. Fetched at startup, which must succeed, then polled, and a successful poll replaces the set whole. A failed poll keeps the keys already held. Needs `TOKENFUSE_DELEGATION_ISSUER`. Set together with `TOKENFUSE_DELEGATION_JWKS` it refuses to start. |
| `TOKENFUSE_DELEGATION_JWKS_INTERVAL_MS` | Poll interval for the URL form. Default 60000. |
| `TOKENFUSE_DELEGATION_AUDIENCE` | The `aud` this deployment answers to. Empty accepts any, which is a real single-tenant choice and is distinct from unset. |
| `TOKENFUSE_DELEGATION_URL` | The absolute origin this process is reached at, so a proof's `htu` has something to compare against. |
| `TOKENFUSE_DELEGATION_REVOCATIONS` | Absolute http(s) URL of the revocation list. Unset means no polling and no refusals. |
| `TOKENFUSE_DELEGATION_REVOCATIONS_INTERVAL_MS` | Poll interval. Default 12000, a fifth of the maximum age, so four consecutive failures are needed before a miss stops being answered from the list. |
| `TOKENFUSE_DELEGATION_REVOCATIONS_MAX_AGE_SECS` | How old a held list may be and still answer a miss. Default 60. Zero or negative means only a hit counts, which is a real policy and is not corrected. |
| `TOKENFUSE_DELEGATION_REVOCATIONS_FAILMODE` | `open` or `closed`. Default closed. |

The first three of the delegation set are required together: two of three is not
a weaker configuration but an ambiguous one, and it exits 2. So does a
revocation URL with no issuer, which asks for a check that can never fire.

A misread setting is refused rather than guessed, `closed` misspelt `close`
included. An operator who asks for the safe mode and silently gets it anyway is
indistinguishable from one who asks and is ignored.

## 5. What the record says

Since 2026-08-26 the events this door writes are on schema
`taipanbox.dev/agent-event/v0.2`, and a proven chain carries SPEC 5.2's
`delegation_proof` beside it:

```json
{"schema":"taipanbox.dev/agent-event/v0.2","type":"taint_raised",
 "agent_id":"agent://acme/triage",
 "on_behalf_of":["user://acme/alice","agent://acme/triage"],
 "delegation_proof":{"jti":"tok-live-1","jkt":"UHQRs9p3...","iss":"https://vouchryx.acme.example","exp":1787779200},
 "data":{"stage":"tool_result","signals":["instruction_override"]}}
```

Which token, bound to which key, from which issuer, valid until when. The token
itself never travels: it is a live credential and this is a replicated,
hash-chained record that outlives it. **Absent means NOT proven**, never proven
somewhere else, so an old consumer that ignores the member under-trusts.

`iss` is the issuer this deployment VERIFIED against, read from the config
rather than off the token, because the two were matched exactly and recording
the token's own claim would record what it said about itself.

**The subject is the header, or the agent a proven chain named.** Before this,
`agent_id` came only from `x-fuse-agent-id`, so a request carrying a verified
chain and no header had its security events dropped entirely. A claimed chain
is never read this way: a caller who can write the header can write the chain.
Neither is a leaf that is not an `agent://` URI, since a token with no `act`
names a person.

This governs the RECORD only. The identity map, the unit a call is billed to,
the strict-mode binding check and what the PDP is told all still read the
header.

### What the record still cannot tell you

Two limits, stated because an auditor reading the JSON above would otherwise
assume otherwise.

**The proof vouches for the CHAIN, and the subject is now checked against it.**
A caller sending `x-fuse-agent-id` that names a different agent than its token
proves is an `agent_id_contradicts_proven_chain` mismatch, on the same
`TOKENFUSE_IDENTITY_STRICT` dial as the key-binding check: recorded under
`warn`, refused under `enforce`, ignored when the dial is off, which is the
default and what every existing deployment sees. The key-binding check could not
catch this, because one key may legitimately speak for several agents.

**Both doors, and both transports.** The MCP door reads the same variable
through the same `StrictMode::from_env`, so the two cannot drift into parsing
one dial two ways, and the refusal exists for HTTP (403, naming both agents) and
for stdio (JSON-RPC `-32009`, distinct from `-32007` "no agent id at all"
because a caller fixing that one by sending a header would make this one worse).
The record is written on either transport.

**A store may erase the proof.** trailryx partitions a record into typed
metadata it keeps and a payload plane a per-event key destroys, and until it
gives `delegation_proof` a typed home the proof rides in the erasable half while
the chain does not. SPEC 5.2 reads a chain with no proof beside it as not proven,
so an erasure there downgrades a proven chain silently. `estate-gates` C12 holds
this as a cross-repo finding.

## 6. Not proven

- **Nothing has run a live poll against vouchryx.** The poller, the startup
  fetch and the refusal paths have tests; the round trip against the real
  service has not been measured.
- **The proxy door has never been exercised end to end with a real token.** It
  is now configured, and `chainproof`'s own tests cover the resolution, but the
  live request that would prove the wiring has not been made.
- **`prompt_hash` is null on a `taint_raised` at the `tool_result` stage**, a
  separate pre-existing gap found on 2026-08-26 and not fixed here.

## 7. An agent's own token as the door credential

Everything above is about a chain: whom a call acts for. Since wave 1 of the
agent-security work, vouchryx also mints each enrolled agent a five-minute
access token of its own (`client_credentials` with DPoP): header `typ: at+jwt`,
`sub` and `client_id` the agent, one audience, bound to a key the agent holds,
carrying its `unit` and `org`. With the agent-token door on, that token is a
door credential (CLAUDE.md invariants 123 and 124).

| Variable | Meaning |
|---|---|
| `TOKENFUSE_AGENT_TOKENS` | `off` (default): nothing changes. `accept`: a token is a door credential and every static client key keeps working beside it. `require`: every static client key is refused. Any other word refuses to start. |
| `TOKENFUSE_MCP_TAINT_GATEWAY_KEY_FILE` | The MCP broker only: a file holding the broker's own gateway client key (key id `broker` in the gateway's `TOKENFUSE_CLIENT_KEYS`), used only to relay a token to the gateway's tool-call check. Required when the agent-token door is on and `TOKENFUSE_MCP_TAINT_GATEWAY` names a gateway: without it the broker refuses to start (CLAUDE.md invariant 129), because a token's call would reach the check with no credential and fall to `TOKENFUSE_MCP_TAINT_FAILMODE`. |

On, the process needs the delegation door above (issuer, JWKS, origin), a
non-empty `TOKENFUSE_DELEGATION_AUDIENCE`, and a revocation list that fails
closed, or it refuses to start naming what is missing.

A call presents `Authorization: DPoP <token>` and a `DPoP` proof made for this
request that names the token (`ath`). The door checks the type, the key the
`kid` names and the algorithm from its type, the issuer, the audience exactly,
the expiry with 30 seconds of leeway, that the subject is an agent and equals
`client_id`, that the token acts for nobody, the binding, the proof, the
revocation list, and that the proof was not used before. A token beside an
`x-fuse-key` is refused. What it admits is filed under `tok:<agent>`: the
record's key, the run's owner, the agent and the unit all come from the token,
and a header naming another agent, or an identity map that binds the agent to
another unit, is refused in every strict mode. The policy plane is told
`identity_source: agent-token` (`client-key` for a static key, `none` with no
credential).

With the door on, a delegation proof at this chain door is single-use too, and
one that names a token must name the one it came with.

What it does not do: a delegation token is still not a door credential, so
under `require` a delegated call is refused. The key set is read at startup, so
a vouchryx key rotation needs a restart. The replay cache is per process.
Nothing here has run against a live vouchryx; the tests mint what vouchryx
mints (`tokenfuse_delegation::testing::agent_token`).
