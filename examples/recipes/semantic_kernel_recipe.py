"""Semantic Kernel (Python) through the OpenAI door. The kernel takes an
`OpenAIChatCompletion` service built on an injected `AsyncOpenAI` client, and
the client is where the base URL and the headers live."""

import asyncio
from importlib.metadata import version

from openai import AsyncOpenAI
from semantic_kernel import Kernel
from semantic_kernel.connectors.ai.open_ai import OpenAIChatCompletion, OpenAIChatPromptExecutionSettings

import _common as c

NAME = "semantic-kernel"
rid = c.run_id(NAME)
c.banner("semantic-kernel", version("semantic-kernel"), "/v1/chat/completions", rid)

client = AsyncOpenAI(base_url=f"{c.GATEWAY}/v1", api_key="ollama",
                     default_headers=c.fuse_headers(NAME, rid), max_retries=0)
kernel = Kernel()
kernel.add_service(OpenAIChatCompletion(ai_model_id=c.MODEL, async_client=client))
settings = OpenAIChatPromptExecutionSettings(max_tokens=c.MAX_TOKENS)


async def once():
    return str(await kernel.invoke_prompt(c.PROMPT, settings=settings))


raise SystemExit(asyncio.run(c.until_refused_async(once)))
