#!/usr/bin/env bash
# Run every recipe, each in its own virtualenv, against a gateway on each door.
#
#   TOKENFUSE_URL           the OpenAI-door gateway (default http://127.0.0.1:4100)
#   TOKENFUSE_MESSAGES_URL  the Messages-door gateway; the Messages recipes are skipped when unset
#   VENVS                   where the per-recipe virtualenvs live (default ./.venvs)
#   MODEL, BUDGET_USD, MAX_TOKENS pass through to the recipes (see _common.py)
#
# Telemetry is turned off for the frameworks that post usage to a third party
# by default. A governance product's own examples must not phone home.
set -u
cd "$(dirname "$0")"
VENVS="${VENVS:-./.venvs}"
export TOKENFUSE_URL="${TOKENFUSE_URL:-http://127.0.0.1:4100}"
export CREWAI_DISABLE_TELEMETRY=true OTEL_SDK_DISABLED=true
export HAYSTACK_TELEMETRY_ENABLED=False
export OPENAI_AGENTS_DISABLE_TRACING=1
export LITELLM_TELEMETRY=False DO_NOT_TRACK=1
export ANONYMIZED_TELEMETRY=False

venv_python() { # requirements-name
  local v="$VENVS/$1"
  if [ ! -x "$v/bin/python" ]; then
    python3 -m venv "$v" && "$v/bin/pip" install -q -r "requirements/$1.txt" || return 1
  fi
  echo "$v/bin/python"
}

fail=0
run() { # requirements-name recipe.py [door]
  local py; py="$(venv_python "$1")" || { echo "== $2: venv for $1 could not be built"; fail=1; return; }
  echo "== $2"
  if [ "${3:-}" = "messages" ]; then
    [ -n "${TOKENFUSE_MESSAGES_URL:-}" ] || { echo "skipped: TOKENFUSE_MESSAGES_URL unset"; return; }
    TOKENFUSE_URL="$TOKENFUSE_MESSAGES_URL" "$py" "$2" || fail=1
  else
    "$py" "$2" || fail=1
  fi
  echo
}

run langchain        langchain_openai_door.py
run langchain        langchain_messages_door.py   messages
run openai-agents    openai_agents.py
run pydantic-ai      pydantic_ai_openai_door.py
run pydantic-ai      pydantic_ai_messages_door.py messages
run autogen          autogen_openai_door.py
run semantic-kernel  semantic_kernel_recipe.py
run litellm          litellm_recipe.py
run haystack         haystack_recipe.py
# CrewAI 1.15.x needs Python < 3.14; run it where such a Python exists (see README.md).
if [ "${CREWAI_PYTHON:-}" != "" ]; then
  echo "== crewai_recipe.py (CREWAI_PYTHON=$CREWAI_PYTHON)"
  "$CREWAI_PYTHON" crewai_recipe.py || fail=1
else
  echo "== crewai_recipe.py"; echo "skipped: set CREWAI_PYTHON to a Python 3.10 to 3.13 interpreter with requirements/crewai.txt installed"
fi
exit $fail
