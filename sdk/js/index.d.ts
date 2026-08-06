export declare const VERSION: string;
export declare const DEFAULT_GATEWAY: string;

/** Base URL to hand to a provider client's `baseURL`. */
export declare function gatewayUrl(gateway?: string): string;

/** Full URL of the Anthropic-style messages endpoint. */
export declare function messagesUrl(gateway?: string): string;

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
