# 26 - the OpenAI door: the same enforcement, a second wire shape

Doc 02 has said since the first planning pass that an OpenAI-compatible
`/v1/chat/completions` is planned, and the README has said twice that it is not
built. This is the design that closes that. It is a **second front door on one
gateway**, not a translator and not a router.

Status when this was written (`@measured 2026-09-07`, reading the source): the
router serves `/v1/messages` and no other LLM route; there is no `Provider`
enum, no per-vendor request shaping, and no code path that reshapes a body
between vendors. What already exists is one-directional tolerance: the usage
parser reads both the Anthropic and the OpenAI response shapes
(`provider.rs:250-298`), the tool-call counter reads both
(`provider.rs:157-248`), the price book carries `gpt-4o`, `gpt-4o-mini` and
`o1` beside the Anthropic models (`pricebook.rs:15-98`), and the upstream
header allowlist already forwards `openai-organization` and `openai-beta`
(`provider.rs:309-318`).

## 1. What is being built, and what is deliberately not

**Built.** `POST /v1/chat/completions`, served by the same handler and the same
enforcement pipeline as `/v1/messages`, against an upstream that speaks the
OpenAI wire. An OpenAI SDK, an Ollama or vLLM client, or anything that appends
`/chat/completions` to a base URL, points at TokenFuse with a base-URL swap and
gets budgets, loop detection, DLP, the policy call and the Breaker.

**Not built, and this is a decision rather than a gap** (`@yurii 2026-09-07`,
asked directly): no translation between the two wire shapes. The gateway does
not turn an OpenAI request into an Anthropic one or back. A gateway process
forwards to one upstream endpoint, and the door a caller uses must match the
shape that upstream speaks. Translation is a different product, it is where the
market already has free implementations, and it would put a permanent
two-vendor API-drift chase inside the enforcement path.

Also not in scope: a provider registry or model-to-provider routing (the
existing FinOps `Router` rewrites a model name, which is a different thing);
extending the price book beyond what a test needs; and any change to the bytes
the Anthropic door emits.

## 2. The shape becomes an explicit thing

Today `messages()` reads the body as a bare `serde_json::Value` and pulls
Anthropic-shaped fields out of it ad hoc across a 1,200-line function. Adding a
second shape by copying that function would double the enforcement path, which
is the one thing invariant 2 exists to prevent.

So the shape becomes a value. A new module `crates/gateway/src/wire.rs` holds:

```
pub enum Wire { Anthropic, OpenAi }
```

and owns every operation whose answer depends on the shape:

| operation | Anthropic | OpenAI |
|---|---|---|
| model | `model` | `model` |
| output-token limit | `max_tokens` | `max_completion_tokens`, then `max_tokens` |
| completions requested | always 1 | `n`, default 1 |
| stream flag | `stream` | `stream` |
| system text | `system`, string or content-block array | the `system`/`developer` role in `messages` |
| tools text | `tools` | `tools` |
| semantic-cache core | existing `semantic_core` | existing `semantic_core` |
| body prepared for upstream | unchanged | `stream_options.include_usage = true` when streaming and absent |
| refusal body | today's bytes, unchanged | the OpenAI error envelope |

`messages()` becomes a shared handler taking a `Wire`. The existing helpers
(`parse_request`, `system_text`, `tools_text`, `semantic_core`) move behind it
rather than being rewritten. Nothing in the pipeline's ORDER changes: auth,
parse, run-id, budget resolve, taint pre-note, open_run, agent-id grammar,
delegation chain, identity map, model router, kill check, DLP, cache, estimate,
policy evaluate and loop detect, wasm policy, Wardryx, unit budget, run budget,
taint accumulate, forward, settle.

## 3. Two doors, one upstream, and a loud refusal

`TOKENFUSE_UPSTREAM` names one full endpoint URL and always has
(`provider.rs`: `client.post(&self.endpoint)`). A process therefore serves one
upstream shape.

`TOKENFUSE_WIRE` declares which: `anthropic` or `openai`. Unset, it is inferred
from the upstream URL path (`/chat/completions` means OpenAI, `/messages` means
Anthropic) and defaults to `anthropic`, which is what every existing
deployment already is. The inference is a convenience; the variable is the
answer when the URL says nothing.

**The door that does not match answers 400 before anything is reserved**, with
a body that names the variable to set and the value it currently has. It does
not forward. A gateway that opened a run, reserved budget and shipped an
OpenAI body to an Anthropic endpoint would turn a configuration mistake into a
provider error and a settled reservation, and the operator would read the
upstream's complaint instead of ours.

## 4. Three things in the money path, and why this is tier T3

A wrong answer here is silent: the call succeeds, the budget is simply wrong.

**`n` multiplies the output estimate.** `n` asks for that many completions and
is billed for all of them. An estimate that ignores it is low by a factor of
`n`, so a run that should have been refused is served, and every gate stays
green. The codebase already knows the field exists: `ToolCallCounter` handles
`n > 1` explicitly (`provider.rs:173-176`). `estimate_cost` gains the
multiplier; the Anthropic path passes 1 and its arithmetic is unchanged.

**The output limit moved, and on some models the old name is refused.**
Verified against the provider's own reference (`developers.openai.com`,
`api-reference/chat/create`, read 2026-09-07), which says of `max_tokens`:
"This value is now deprecated in favor of `max_completion_tokens`, and is not
compatible with o-series models", and of the new name that it is "An upper
bound for the number of tokens that can be generated for a completion,
including visible output tokens and reasoning tokens".

Two consequences, and the second is the one I did not have on the first pass.
Reading only the old name on a modern request yields `None`, the estimate falls
to `DEFAULT_MAX_TOKENS` (1024), and a request that asked for 100k output tokens
is priced as if it asked for 1k. And on an o-series model the old name is not
merely deprecated but incompatible, so a caller that reaches us with only
`max_tokens` set is sending something the provider will reject: we price it,
reserve for it, and the upstream refuses. Read the new name first, fall back to
the old.

Because `max_completion_tokens` counts reasoning tokens as well as visible
ones, it is the right bound to price against on a reasoning model: the invisible
half is billed and the number already includes it.

When both names are present and disagree, take `max_completion_tokens` and
price the larger of the two. `@claude`: this is our decision, not a reading of
documented provider behaviour, and the estimate errs upward because
under-charging is the failure this tier exists to prevent.

**Usage in a stream has to be asked for.** Verified on the same page:
setting `stream_options.include_usage` means "an additional chunk will be
streamed before the `data: [DONE]` message. The `usage` field on this chunk
shows the token usage statistics for the entire request, and the `choices`
field will always be an empty array. **All other chunks will also include a
`usage` field, but with a null value.**"

Without it, `settle_amount` records `CostBasis::EstimateNoUsage` and the run
settles on the pre-flight estimate: honest, visible in the record, and wrong by
whatever the estimate was wrong by, on every streamed call an ordinary SDK
makes. So the gateway injects the option when the request streams and did not
set it (`@yurii 2026-09-07`).

The emphasised sentence is a hazard the first draft of this design missed, and
it lands on code that already exists. `merge_usage` reads
`v.get("usage").filter(|u| u.is_object())` (`provider.rs:256`), so a `usage`
that is `null` is skipped rather than parsed as an empty usage: **today's parser
already survives this, by construction rather than by intent.** That makes it
exactly the kind of behaviour that a later refactor removes without noticing, so
it gets a named test of its own (§6) rather than being left to luck. The final
chunk's empty `choices` array is likewise harmless to `ToolCallCounter`, which
iterates whatever is there.

Injecting mutates the caller's request, which the gateway already does in two
places (DLP masking, model rewrite), so the mechanism and its precedent exist.
The visible consequence is that the client receives one extra final SSE chunk
carrying usage. **This is documented in the README and in this doc rather than
being quietly true**, because a caller that hand-parses the stream will see it.
If the caller already set the option, its value is left alone, including when
it set it to `false`.

## 5. The refusal an SDK can read

**The first draft of this section was wrong, and the correction is worth
keeping**, because it changes why we do this rather than whether. It said an
OpenAI SDK surfaces `error.message`, so our body, which has no `message`, would
raise an error with an empty message. Checked against the client's own source
(`openai/openai-python`, `main`, read 2026-09-07), that is not what happens:

- `_base_client.py` builds the human-readable text as
  `f"Error code: {response.status_code} - {body}"`, where `body` is the **whole
  parsed JSON object**. Our `run_id`, `reason` and figures are therefore already
  in the message a user sees.
- `_client.py::_make_status_error` then does
  `data = body.get("error", body) if is_mapping(body) else body`, so it **does**
  unwrap our `error` object,
- and `_exceptions.py` reads `body.get("code")`, `body.get("param")` and
  `body.get("type")` off it. Our `type` already lands on `exc.type`; `code` and
  `param` come back `None`.

So the real reasons to render OpenAI's envelope are narrower and still good:
`message` and `code` are what the convention carries and what other clients
(Node, LangChain, LiteLLM, anything hand-rolled over `curl`) read, and a body
that satisfies the convention costs us nothing.

The OpenAI door therefore adds `message` (a sentence naming the run and what
stopped it), `code` (the same wire string as `type`) and `param: null`, and
keeps our own fields alongside. Extra members are ignored by the SDKs and keep
the body a superset of what the record already contains.

**Status codes and headers do not change**, and the check above says they are
already right: 402 for the budget family, 403 for the auth family, `x-fuse:
blocked` and `x-fuse-run-id` on both. In the client's taxonomy a 403 becomes
`PermissionDeniedError`, which is what a DLP, taint or identity refusal is; 402
is not special-cased and falls through to the generic `APIStatusError`, which is
correct, since no standard exception class means "your budget stopped this" and
inventing a mapping for it is not ours to do.

**Invariant 2 is untouched and is the proof.** The golden test
`breaker_error_response_matches_budget_error_byte_for_byte` asserts the
Anthropic refusal is byte-identical across refactors, for all five 402 reasons.
It is not modified, not parameterised and not moved. If the shape refactor
disturbs the Anthropic bytes, that test says so.

## 6. What is proven, and how

Tier **T3**: the change is in the money path and a wrong answer is silent.

**Scenarios first, in `features/the-openai-door.feature`**, each bound to a
named test in both directions by `scripts/features-are-bound.sh`.

**Every new test is run against the unbuilt code first and must go red there.**
The report records the failure it produced.

**Hostile input**, because the body arrives from outside the process: a body
that is not an object; `n` absent, zero, negative, a string, and absurdly
large; `max_completion_tokens` as a string and as a float; both output-limit
fields present and disagreeing; `stream_options` present as a string, as null,
and as an object with a non-boolean `include_usage`; a `messages` array that is
empty, and one whose entries are not objects.

**Two named tests for behaviour that works today only by construction**, both
about the injected `include_usage`: one asserting that a streamed response whose
non-final chunks carry `"usage": null` settles on parsed usage from the final
chunk and never on an empty `Usage`, and one asserting the final chunk's empty
`choices` array leaves the tool-call count untouched. Neither is a new feature;
both pin behaviour a refactor could remove silently.

**Mutation testing of the product code**, which is what T3 adds. Each fault is
planted deliberately and an existing test must catch it:

| mutant | what it would cost in production |
|---|---|
| drop the `n` multiplier from the estimate | budgets pass a run that costs `n` times the estimate |
| read `max_tokens` before `max_completion_tokens` | a 100k-token request priced as 1k |
| skip the `include_usage` injection | every streamed run settles on an estimate |
| overwrite an `include_usage` the caller already set | the caller's own choice silently changed |
| serve the mismatched door instead of refusing | a reservation opened against an upstream that will refuse |
| treat a `null` `usage` chunk as parsed usage | every streamed run settles at zero |

**A gate with teeth.** `scripts/gates-have-teeth.sh` gains a case for whatever
gate this adds, and the case plants that gate's own fault and requires the
failure.

**Coverage** is reported with the delta and with the uncovered paths that
matter, next to the red-first evidence, because a percentage that rose while no
new assertion can fail is not coverage.

## 7. Configuration

| variable | values | default | meaning |
|---|---|---|---|
| `TOKENFUSE_WIRE` | `anthropic`, `openai` | inferred from `TOKENFUSE_UPSTREAM`, else `anthropic` | which front door this process serves |

No other variable changes. `TOKENFUSE_UPSTREAM`, `TOKENFUSE_ALLOW_STUB` and the
rest keep their meanings, and an existing deployment that sets neither new
variable behaves exactly as it does today.

## 8. Not proven, and what this design does not claim

- **It does not make TokenFuse multi-provider.** One process, one upstream, one
  shape. Two processes are two configurations.
- **It does not clamp `max_tokens`.** `docs/02` step 3 and ADR-4 both describe
  a clamp of the output limit against the remaining budget. `@measured
  2026-09-07`: no such code exists in `proxy.rs`; the field is read for the
  estimate and never rewritten. That is a separate decision, either build it or
  correct the doc, and this work neither fixes nor worsens it.
- **The response-side firewall judgement still runs only on the buffered
  path.** `stream_managed` has no `taint::evaluate`. That asymmetry predates
  this work and is not addressed by it.
- **No performance claim.** The enforcement decision's measured cost belongs to
  the existing path; nothing here is benchmarked until it is.
- **The OpenAI models in the price book are whatever ships today.** Pricing
  accuracy for models nobody added is the fallback's job (ADR-8: an unknown
  model is priced at the most expensive known one).
