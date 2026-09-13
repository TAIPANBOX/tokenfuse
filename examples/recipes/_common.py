"""Shared by every recipe in this directory: the gateway address, the three
x-fuse headers a run carries, and the loop that calls until the gateway
refuses.

A recipe SUCCEEDS when the refusal arrives. Each call goes through the
framework's own client with the gateway as its base URL, so the 402 shows up
as that framework's own exception; the loop prints it and exits 0. A recipe
that is never refused exits 1, because a budget nobody enforced is the
failure these recipes exist to catch.
"""

import os
import sys
import time

GATEWAY = os.environ.get("TOKENFUSE_URL", "http://127.0.0.1:4100").rstrip("/")
MODEL = os.environ.get("MODEL", "qwen2.5:3b")
BUDGET_USD = os.environ.get("BUDGET_USD", "0.006")
MAX_TOKENS = int(os.environ.get("MAX_TOKENS", "48"))
MAX_CALLS = int(os.environ.get("MAX_CALLS", "8"))
PROMPT = "Reply with the single word OK."


def run_id(name: str) -> str:
    return f"recipe-{name}-{int(time.time())}"


def fuse_headers(name: str, rid: str) -> dict:
    """The per-run headers. Everything the gateway needs to meter a run is
    here: which run this is, what it may spend, and who is asking."""
    return {
        "x-fuse-run-id": rid,
        "x-fuse-budget-usd": BUDGET_USD,
        "x-fuse-agent-id": f"agent://recipes.example/{name}",
    }


def banner(framework: str, version: str, door: str, rid: str) -> None:
    print(f"[{framework} {version}] door={door} gateway={GATEWAY} model={MODEL} "
          f"run={rid} budget_usd={BUDGET_USD} max_tokens={MAX_TOKENS}")


def _looks_like_402(exc: BaseException) -> bool:
    for attr in ("status_code", "status", "code"):
        if getattr(exc, attr, None) == 402:
            return True
    resp = getattr(exc, "response", None)
    if getattr(resp, "status_code", None) == 402:
        return True
    text = str(exc)
    return "402" in text or "budget_exceeded" in text


def _report(i: int, exc: BaseException) -> int:
    cause = exc.__cause__ or exc.__context__
    if _looks_like_402(exc) or (cause is not None and _looks_like_402(cause)):
        print(f"call {i}: REFUSED 402 budget_exceeded, raised as "
              f"{type(exc).__module__}.{type(exc).__name__}: {str(exc)[:300]}")
        return 0
    print(f"call {i}: error {type(exc).__module__}.{type(exc).__name__}: {str(exc)[:400]}")
    return 1


def _never() -> int:
    print(f"never refused after {MAX_CALLS} calls: the budget was not enforced", file=sys.stderr)
    return 1


def until_refused(call) -> int:
    """Call until the gateway says 402. Returns the process exit code."""
    for i in range(1, MAX_CALLS + 1):
        try:
            text = call()
        except Exception as exc:  # noqa: BLE001 - every framework wraps it differently
            return _report(i, exc)
        print(f"call {i}: ok  {str(text).strip()[:60]!r}")
    return _never()


async def until_refused_async(call) -> int:
    """The same loop for an async client. One event loop for the whole run:
    a client whose connection pool was opened under one `asyncio.run` cannot
    be reused under the next, and the second call then fails as a connection
    error that has nothing to do with the gateway."""
    for i in range(1, MAX_CALLS + 1):
        try:
            text = await call()
        except Exception as exc:  # noqa: BLE001
            return _report(i, exc)
        print(f"call {i}: ok  {str(text).strip()[:60]!r}")
    return _never()
