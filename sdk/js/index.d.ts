export declare const VERSION: string;
export declare const DEFAULT_GATEWAY: string;

/** Base URL to hand to a provider client's `baseURL`. */
export declare function gatewayUrl(gateway?: string): string;

/** Full URL of the Anthropic-style messages endpoint. */
export declare function messagesUrl(gateway?: string): string;

/** Full URL of the OpenAI-style chat completions endpoint (the OpenAI door). */
export declare function chatCompletionsUrl(gateway?: string): string;

/** `baseURL` for an OpenAI-compatible client: the gateway root plus `/v1`. */
export declare function openaiBaseUrl(gateway?: string): string;

export interface RunHeaderOptions {
  budgetUsd?: number;
  taskType?: string;
  parentRunId?: string;
  tags?: Record<string, string>;
}

/**
 * Build the `X-Fuse-*` attribution headers for a run. Only `runId` is required,
 * and it is required: a gateway refuses a call it cannot account for with
 * `400 metering_required` unless the operator set `TOKENFUSE_REQUIRE_RUN_ID=0`,
 * which restores the old unmanaged pass-through.
 */
export declare function runHeaders(
  runId: string,
  opts?: RunHeaderOptions,
): Record<string, string>;

/** Thrown when vouchryx refuses the agent token request. Its message carries no token or key. */
export declare class AgentTokenError extends Error {}

export interface AgentFetchOptions {
  /** The vouchryx issuer, for example https://vouchryx.example.com. */
  issuer: string;
  /** The agent's ES256 (P-256) private key, as PEM or a KeyObject. */
  key: string | Buffer | import("node:crypto").KeyObject;
  /** The agent id, for example agent://acme/triage, with clientSecret (the enrolment key). */
  clientId?: string;
  clientSecret?: string;
  /** Returns the projected workload token at the time it is called. */
  workloadToken?: () => string;
  /** Sent as the token request's resource. */
  audience?: string;
  /** The fetch to use; defaults to the global fetch. */
  fetch?: typeof fetch;
  /** The clock in milliseconds, used to measure the token's age. */
  now?: () => number;
}

export type AgentFetch = (
  input: string | URL,
  init?: Parameters<typeof fetch>[1],
) => ReturnType<typeof fetch>;

/** A fetch that signs each request with the agent's token and a fresh DPoP proof. */
export declare function createAgentFetch(options: AgentFetchOptions): AgentFetch;
