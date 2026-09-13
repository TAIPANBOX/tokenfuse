"""OpenAI Agents SDK through the OpenAI door. The client gets the gateway as
`base_url`; `ModelSettings.extra_headers` carries the run id and budget, so
nothing about the client has to change per run. Tracing is turned off: it
would otherwise post spans to OpenAI's own endpoint."""

from importlib.metadata import version

from agents import Agent, ModelSettings, OpenAIChatCompletionsModel, Runner, set_tracing_disabled
from openai import AsyncOpenAI

import _common as c

NAME = "openai-agents"
rid = c.run_id(NAME)
c.banner("openai-agents", version("openai-agents"), "/v1/chat/completions", rid)
set_tracing_disabled(True)

client = AsyncOpenAI(base_url=f"{c.GATEWAY}/v1", api_key="ollama", max_retries=0)
agent = Agent(
    name="recipe",
    instructions="Answer in one word.",
    model=OpenAIChatCompletionsModel(model=c.MODEL, openai_client=client),
    model_settings=ModelSettings(extra_headers=c.fuse_headers(NAME, rid), max_tokens=c.MAX_TOKENS),
)

raise SystemExit(c.until_refused(lambda: Runner.run_sync(agent, c.PROMPT).final_output))
