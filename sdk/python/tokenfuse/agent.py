"""Agent token helper (wave 1 T5). Stub: the behaviour lands in the next commit."""

from __future__ import annotations

__all__ = ["AgentAuth", "AgentTokenError"]


class AgentTokenError(Exception):
    """The token request or a door's answer could not be completed."""


class AgentAuth:
    def __init__(self, issuer, key, **kwargs):
        raise NotImplementedError("AgentAuth is not implemented yet")
