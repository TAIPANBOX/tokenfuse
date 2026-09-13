"""PydanticAI through the OpenAI door. The provider takes the gateway as
`base_url`; the headers ride on an `httpx.AsyncClient` handed in as
`http_client`, which is httpx's own `headers=`."""

from importlib.metadata import version

try:
    import httpx2 as httpx  # the 2026 SDKs depend on httpx2
except ImportError:  # pragma: no cover
    import httpx
from pydantic_ai import Agent
from pydantic_ai.models.openai import OpenAIChatModel
from pydantic_ai.providers.openai import OpenAIProvider

import _common as c

NAME = "pydantic-ai"
rid = c.run_id(NAME)
c.banner("pydantic-ai-slim", version("pydantic-ai-slim"), "/v1/chat/completions", rid)

provider = OpenAIProvider(
    base_url=f"{c.GATEWAY}/v1",
    api_key="ollama",
    http_client=httpx.AsyncClient(headers=c.fuse_headers(NAME, rid)),
)
agent = Agent(OpenAIChatModel(c.MODEL, provider=provider), model_settings={"max_tokens": c.MAX_TOKENS})

raise SystemExit(c.until_refused(lambda: agent.run_sync(c.PROMPT).output))
