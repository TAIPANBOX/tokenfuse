"""CrewAI through the OpenAI door. `LLM(base_url=...)` is documented; a
per-request header is not (crewAIInc/crewAI#3177 is the open request), so
this recipe passes `extra_headers` and lets the run say whether CrewAI hands
it down to LiteLLM. If it does not, attribution falls back to the gateway's
identity map (docs/20): one API key per agent, a budget per agent.

CrewAI's telemetry posts to its own endpoint; the runner sets
CREWAI_DISABLE_TELEMETRY=true and OTEL_SDK_DISABLED=true first."""

from importlib.metadata import version

from crewai import LLM, Agent, Crew, Task

import _common as c

NAME = "crewai"
rid = c.run_id(NAME)
c.banner("crewai", version("crewai"), "/v1/chat/completions", rid)

llm = LLM(
    model=f"openai/{c.MODEL}",
    base_url=f"{c.GATEWAY}/v1",
    api_key="ollama",
    max_tokens=c.MAX_TOKENS,
    extra_headers=c.fuse_headers(NAME, rid),
)
agent = Agent(role="answerer", goal="answer in one word", backstory="terse", llm=llm, verbose=False)
task = Task(description=c.PROMPT, expected_output="one word", agent=agent)
crew = Crew(agents=[agent], tasks=[task], verbose=False)

raise SystemExit(c.until_refused(lambda: str(crew.kickoff())))
