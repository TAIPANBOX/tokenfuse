"""LangChain through the Messages door. `ChatAnthropic` reads
`anthropic_api_url` (or ANTHROPIC_BASE_URL); `default_headers` is
"used for every API call", which is exactly where a run id belongs."""

from importlib.metadata import version

from langchain_anthropic import ChatAnthropic

import _common as c

NAME = "langchain-messages"
rid = c.run_id(NAME)
c.banner("langchain-anthropic", version("langchain-anthropic"), "/v1/messages", rid)

llm = ChatAnthropic(
    model=c.MODEL,
    anthropic_api_url=c.GATEWAY,
    api_key="ollama",
    default_headers=c.fuse_headers(NAME, rid),
    max_tokens=c.MAX_TOKENS,
    max_retries=0,
)

raise SystemExit(c.until_refused(lambda: llm.invoke(c.PROMPT).content))
