"""Haystack through the OpenAI door (its Anthropic generator documents no base
URL, so the Messages door is not offered here). `api_base_url` is the gateway;
`http_client_kwargs` reaches the underlying client's headers. Haystack's
usage telemetry posts to a third party; the runner sets
HAYSTACK_TELEMETRY_ENABLED=False first."""

from importlib.metadata import version

from haystack.components.generators.chat import OpenAIChatGenerator
from haystack.dataclasses import ChatMessage
from haystack.utils import Secret

import _common as c

NAME = "haystack"
rid = c.run_id(NAME)
c.banner("haystack-ai", version("haystack-ai"), "/v1/chat/completions", rid)

generator = OpenAIChatGenerator(
    model=c.MODEL,
    api_base_url=f"{c.GATEWAY}/v1",
    api_key=Secret.from_token("ollama"),
    http_client_kwargs={"headers": c.fuse_headers(NAME, rid)},
    generation_kwargs={"max_tokens": c.MAX_TOKENS},
    max_retries=0,
)


def once():
    return generator.run([ChatMessage.from_user(c.PROMPT)])["replies"][0].text


raise SystemExit(c.until_refused(once))
