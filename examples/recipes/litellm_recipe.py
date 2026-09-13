"""LiteLLM through both doors. `api_base` points at the gateway and
`extra_headers` carries the run; the same two arguments in a LiteLLM proxy's
`litellm_params` do the same job for everything behind that proxy, CrewAI
included. The OpenAI door runs first, the Messages door second when
TOKENFUSE_MESSAGES_URL is set."""

import os
from importlib.metadata import version

import litellm

import _common as c

litellm.telemetry = False
litellm.suppress_debug_info = True

NAME = "litellm"
rid = c.run_id(NAME)
c.banner("litellm", version("litellm"), "/v1/chat/completions", rid)


def openai_door():
    return litellm.completion(
        model=f"openai/{c.MODEL}",
        api_base=f"{c.GATEWAY}/v1",
        api_key="ollama",
        messages=[{"role": "user", "content": c.PROMPT}],
        max_tokens=c.MAX_TOKENS,
        extra_headers=c.fuse_headers(NAME, rid),
        num_retries=0,
    ).choices[0].message.content


code = c.until_refused(openai_door)

messages_url = os.environ.get("TOKENFUSE_MESSAGES_URL")
if messages_url:
    rid2 = c.run_id(NAME + "-messages")
    print(f"[litellm {version('litellm')}] door=/v1/messages gateway={messages_url} run={rid2}")

    def messages_door():
        return litellm.completion(
            model=f"anthropic/{c.MODEL}",
            api_base=messages_url,
            api_key="ollama",
            messages=[{"role": "user", "content": c.PROMPT}],
            max_tokens=c.MAX_TOKENS,
            extra_headers=c.fuse_headers(NAME + "-messages", rid2),
            num_retries=0,
        ).choices[0].message.content

    code = code or c.until_refused(messages_door)

raise SystemExit(code)
