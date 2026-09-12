# tokenfuse (Python SDK)

Thin, dependency-free helpers to route an agent's LLM calls through the
[TokenFuse](https://github.com/TAIPANBOX/tokenfuse) gateway and turn its `402`
blocks into typed exceptions.

TokenFuse is a **drop-in proxy**: you don't rewrite your agent, you point your
provider client at the gateway and attach a few headers.

## Install

```bash
pip install tokenfuse-sdk
```

The distribution is named `tokenfuse-sdk` (the plain `tokenfuse` name was taken on
PyPI), but you still **import it as `tokenfuse`**.

## Use

```python
import anthropic, tokenfuse

client = anthropic.Anthropic(
    base_url=tokenfuse.gateway_url(),                    # http://127.0.0.1:4100
    default_headers=tokenfuse.run_headers("run-42", budget_usd=5.0, task_type="code-review"),
)

try:
    msg = client.messages.create(model="claude-sonnet", max_tokens=1024, messages=[...])
except tokenfuse.BudgetExceeded as e:
    print(f"run {e.run_id}: spent ${e.spent_usd} of ${e.budget_usd}")
except tokenfuse.LoopDetected as e:
    print(f"runaway loop on {e.run_id}: {e.reason}")
```

For raw HTTP clients (`requests` / `httpx`), call `tokenfuse.check_response(resp)`
after the request, or `tokenfuse.raise_for_fuse(status_code, body)`.

### The OpenAI door

A gateway started with an OpenAI-shaped upstream (`TOKENFUSE_UPSTREAM` ending in
`/v1/chat/completions`, or `TOKENFUSE_WIRE=openai`) serves OpenAI-shaped clients.
One process, one wire shape; the same headers and the same exceptions:

```python
import openai, tokenfuse

client = openai.OpenAI(
    base_url=tokenfuse.openai_base_url(),                # http://127.0.0.1:4100/v1
    default_headers=tokenfuse.run_headers("run-42", budget_usd=5.0),
)
```

The 402 body the OpenAI door returns carries the same `error.type` as the
Anthropic one, so `raise_for_fuse` maps both doors to the same exception classes.
Versions: from 0.5.0 this package versions with the gateway.

## Exceptions

All inherit `tokenfuse.FuseError` (fields: `run_id`, `budget_usd`, `spent_usd`,
`policy_id`, `reason`):

- `BudgetExceeded`: the run's budget would be exceeded
- `LoopDetected`: a runaway loop was detected
- `PolicyViolation`: a policy limit was hit
- `Killed`: an operator killed the run
