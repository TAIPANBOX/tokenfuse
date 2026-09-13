"""AutoGen (autogen-ext, maintenance mode; Microsoft Agent Framework is its
successor) through the OpenAI door. `base_url` is "required if the model is
not hosted on OpenAI"; `default_headers` is "useful for authentication" and
carries the run here. `model_info` is required for a model the client does
not know."""

import asyncio
from importlib.metadata import version

from autogen_core.models import ModelInfo, UserMessage
from autogen_ext.models.openai import OpenAIChatCompletionClient

import _common as c

NAME = "autogen"
rid = c.run_id(NAME)
c.banner("autogen-ext", version("autogen-ext"), "/v1/chat/completions", rid)

client = OpenAIChatCompletionClient(
    model=c.MODEL,
    base_url=f"{c.GATEWAY}/v1",
    api_key="ollama",
    default_headers=c.fuse_headers(NAME, rid),
    max_tokens=c.MAX_TOKENS,
    max_retries=0,
    model_info=ModelInfo(vision=False, function_calling=False, json_output=False,
                         family="unknown", structured_output=False),
)


async def once():
    return (await client.create([UserMessage(content=c.PROMPT, source="user")])).content


raise SystemExit(asyncio.run(c.until_refused_async(once)))
