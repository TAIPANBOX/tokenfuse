# Framework recipes: one base URL, three headers, a 402 you can see

Every agent framework that can talk to OpenAI or Anthropic can talk to this
gateway instead, because the gateway serves the same two doors:
`/v1/chat/completions` (the OpenAI wire) and `/v1/messages` (the Messages
wire). The recipe for each framework is the same three lines in its own
vocabulary:

1. **The base URL** points at the gateway instead of the provider.
2. **Three headers** ride on every call: `x-fuse-run-id` (which run this is),
   `x-fuse-budget-usd` (what the run may spend), `x-fuse-agent-id` (who is
   asking). Where a framework has no per-request header hook, the run id can
   also come from the gateway's identity map (`docs/20-identity-map.md`): one
   API key per agent.
3. **Nothing else changes.** The provider key still travels in the same header
   it always did; the gateway forwards it and never stores it.

Each script in this directory calls its framework in a loop until the gateway
refuses with `402 budget_exceeded`, then prints how that framework surfaced
the refusal and exits 0. A recipe that is never refused exits 1: a budget that
was not enforced is the failure these scripts exist to catch.

## Run them

Start a gateway on each door in front of a free local provider. Ollama serves
both wires from one process:

```bash
ollama pull qwen2.5:3b

docker run -d --name tf-openai -p 4101:4100 \
  -e TOKENFUSE_MODE=enforce -e TOKENFUSE_WIRE=openai \
  -e TOKENFUSE_UPSTREAM=http://host.docker.internal:11434/v1/chat/completions \
  ghcr.io/taipanbox/tokenfuse:v0.5.0

docker run -d --name tf-messages -p 4102:4100 \
  -e TOKENFUSE_MODE=enforce \
  -e TOKENFUSE_UPSTREAM=http://host.docker.internal:11434/v1/messages \
  ghcr.io/taipanbox/tokenfuse:v0.5.0
```

Then, from this directory:

```bash
TOKENFUSE_URL=http://127.0.0.1:4101 TOKENFUSE_MESSAGES_URL=http://127.0.0.1:4102 ./run-all.sh
```

`run-all.sh` builds one virtualenv per framework from `requirements/` (the
versions are pinned; a recipe that floats its framework version proves
nothing about the version you install) and turns off each framework's usage
telemetry before it runs anything. Knobs: `MODEL` (default `qwen2.5:3b`),
`BUDGET_USD` (default `0.006`), `MAX_TOKENS` (default `48`), `VENVS`.

A model the price book does not list (every Ollama model) is priced at the
most expensive known model, and the response says so in `x-fuse-price:
fallback`. The budget in these recipes is sized to that: with it, the third
call on the OpenAI door is the one refused. Against a listed model, raise
`BUDGET_USD` or lower it until you see the refusal where you expect it.

## The recipes

| Framework | Pinned | Door(s) | Base URL parameter | Where the headers go | Script |
|---|---|---|---|---|---|
| LangChain | `langchain-openai` 1.6.2, `langchain-anthropic` 1.7.2 | both | `ChatOpenAI(base_url=...)`; `ChatAnthropic(anthropic_api_url=...)` | `default_headers=` on either model object | `langchain_openai_door.py`, `langchain_messages_door.py` |
| OpenAI Agents SDK | `openai-agents` 0.22.2 | OpenAI | `AsyncOpenAI(base_url=...)` into `OpenAIChatCompletionsModel` | `ModelSettings(extra_headers=...)` per agent or per run | `openai_agents.py` |
| PydanticAI | `pydantic-ai-slim` 2.43.0 | both | `OpenAIProvider(base_url=...)`, `AnthropicProvider(base_url=...)` | an `httpx2.AsyncClient(headers=...)` passed as `http_client=` | `pydantic_ai_openai_door.py`, `pydantic_ai_messages_door.py` |
| CrewAI | `crewai` 1.15.21 (Python 3.10 to 3.13) | OpenAI | `LLM(base_url=...)` | `LLM(extra_headers=...)`, handed down to LiteLLM | `crewai_recipe.py` |
| AutoGen | `autogen-ext` 0.7.5 (maintenance mode) | OpenAI | `OpenAIChatCompletionClient(base_url=...)` | `default_headers=` | `autogen_openai_door.py` |
| Semantic Kernel | `semantic-kernel` 1.44.1 | OpenAI | an injected `AsyncOpenAI(base_url=...)` client | `default_headers=` on that client | `semantic_kernel_recipe.py` |
| LiteLLM | `litellm` 1.100.1 | both | `api_base=` | `extra_headers=`; the same two keys in a proxy's `litellm_params` | `litellm_recipe.py` |
| Haystack | `haystack-ai` 3.1.1 | OpenAI | `OpenAIChatGenerator(api_base_url=...)` | `http_client_kwargs={"headers": ...}` | `haystack_recipe.py` |
| Claude Code | the CLI | Messages | `ANTHROPIC_BASE_URL` | `ANTHROPIC_CUSTOM_HEADERS` (`Name: Value`, one per line) | see below |

**Claude Code.** No script: two environment variables make the CLI itself a
governed agent. When the base URL is not `api.anthropic.com`, Claude Code
turns off MCP tool search and Remote Control, which is documented on its side.

```bash
export ANTHROPIC_BASE_URL=http://127.0.0.1:4100
export ANTHROPIC_CUSTOM_HEADERS="x-fuse-run-id: my-session-1
x-fuse-budget-usd: 2.00
x-fuse-agent-id: agent://example.org/claude-code/me"
claude
```

**Telemetry.** CrewAI, Haystack and the OpenAI Agents SDK post usage or
traces to a third party unless told not to. `run-all.sh` sets
`CREWAI_DISABLE_TELEMETRY`, `OTEL_SDK_DISABLED`, `HAYSTACK_TELEMETRY_ENABLED`
and `OPENAI_AGENTS_DISABLE_TRACING` first, and the scripts that can do it in
code do it there too. Copy that into your own setup: a governance proxy in
front of an agent that phones home from the side is a half-measure.

**Two things that look like gateway faults and are not.** An async client
reused across separate `asyncio.run()` calls fails its second call with a
connection error; keep one event loop for the run (the AutoGen and Semantic
Kernel scripts show how). The 2026 OpenAI and Anthropic SDKs depend on
`httpx2`, not `httpx`; the PydanticAI scripts import whichever is present.

## What was measured

@measured `TOKENFUSE_URL=http://127.0.0.1:4101 TOKENFUSE_MESSAGES_URL=http://127.0.0.1:4102 ./run-all.sh` 2026-09-13,
on a Mac with Python 3.14.7, both gateways the `v0.5.0` image in front of
Ollama `qwen2.5:3b`: every recipe above reached its 402 (OpenAI door on the
third call at a 0.006 USD budget, Messages door on the seventh or eighth,
because Ollama's Messages door reports smaller usage for the same prompt).
CrewAI ran in a `python:3.13-slim` container and its refusal named the run id
the recipe had put in `extra_headers`, so the header reaches the gateway
through LiteLLM. Not measured: the CI matrix. The gateway's offline stub
refuses to start on the OpenAI wire on purpose, so a CI job needs a real
OpenAI-shaped upstream; that is the open item for this directory.
