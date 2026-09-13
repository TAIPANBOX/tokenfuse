"""PydanticAI through the Messages door: the same shape with the Anthropic
provider and model classes."""

from importlib.metadata import version

try:
    import httpx2 as httpx  # the 2026 SDKs depend on httpx2
except ImportError:  # pragma: no cover
    import httpx
from pydantic_ai import Agent
from pydantic_ai.models.anthropic import AnthropicModel
from pydantic_ai.providers.anthropic import AnthropicProvider

import _common as c

NAME = "pydantic-ai-messages"
rid = c.run_id(NAME)
c.banner("pydantic-ai-slim", version("pydantic-ai-slim"), "/v1/messages", rid)

provider = AnthropicProvider(
    base_url=c.GATEWAY,
    api_key="ollama",
    http_client=httpx.AsyncClient(headers=c.fuse_headers(NAME, rid)),
)
agent = Agent(AnthropicModel(c.MODEL, provider=provider), model_settings={"max_tokens": c.MAX_TOKENS})

raise SystemExit(c.until_refused(lambda: agent.run_sync(c.PROMPT).output))
