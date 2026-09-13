"""LangChain through the OpenAI door. `ChatOpenAI(base_url=...)` is the whole
integration; `default_headers` carries the run id and budget on every call."""

from importlib.metadata import version

from langchain_openai import ChatOpenAI

import _common as c

NAME = "langchain"
rid = c.run_id(NAME)
c.banner("langchain-openai", version("langchain-openai"), "/v1/chat/completions", rid)

llm = ChatOpenAI(
    model=c.MODEL,
    base_url=f"{c.GATEWAY}/v1",
    api_key="ollama",
    default_headers=c.fuse_headers(NAME, rid),
    max_tokens=c.MAX_TOKENS,
    max_retries=0,
)

raise SystemExit(c.until_refused(lambda: llm.invoke(c.PROMPT).content))
