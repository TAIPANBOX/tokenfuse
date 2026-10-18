"use strict";

// Agent token helper (wave 1 T5). Stub: the behaviour lands in the next commit.

class AgentTokenError extends Error {}

function createAgentFetch() {
  throw new Error("createAgentFetch is not implemented yet");
}

module.exports = { AgentTokenError, createAgentFetch };
