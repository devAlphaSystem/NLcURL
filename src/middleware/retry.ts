/**
 * Retry middleware.
 *
 * Implements configurable retry logic with exponential backoff.
 */

import type { RetryConfig } from '../core/request.js';
import { NLcURLResponse } from '../core/response.js';
import { AbortError, TimeoutError, ConnectionError } from '../core/errors.js';

export interface RetryContext {
  attempt: number;
  lastError?: Error;
  lastResponse?: NLcURLResponse;
}

function shouldRetryDefault(error: Error | null, statusCode?: number): boolean {
  if (error instanceof ConnectionError || error instanceof TimeoutError) return true;
  if (statusCode !== undefined && [429, 500, 502, 503, 504].includes(statusCode)) return true;
  return false;
}

/**
 * Execute a request function with retry logic.
 */
export async function withRetry(
  config: RetryConfig | undefined,
  execute: (ctx: RetryContext) => Promise<NLcURLResponse>,
): Promise<NLcURLResponse> {
  const count = config?.count ?? 3;
  const baseDelay = config?.delay ?? 1000;
  const backoff = config?.backoff ?? 'exponential';
  const jitterMax = config?.jitter ?? 200;
  const retryOn = config?.retryOn ?? shouldRetryDefault;

  let lastError: Error | undefined;
  let lastResponse: NLcURLResponse | undefined;

  for (let attempt = 0; attempt <= count; attempt++) {
    // Wait before retry (skip first attempt)
    if (attempt > 0) {
      const factor = backoff === 'exponential'
        ? Math.pow(2, attempt - 1)
        : attempt;
      const delay = baseDelay * factor;
      const jitter = Math.random() * jitterMax;
      await sleep(delay + jitter);
    }

    try {
      const response = await execute({ attempt, lastError, lastResponse });

      // Check if response status warrants retry
      if (attempt < count && retryOn(null, response.status)) {
        lastResponse = response;
        continue;
      }

      return response;
    } catch (err) {
      // Never retry aborted requests
      if (err instanceof AbortError) throw err;

      const error = err instanceof Error ? err : new Error(String(err));
      if (attempt < count && retryOn(error)) {
        lastError = error;
        continue;
      }

      throw err;
    }
  }

  // Should not reach here, but if it does, throw the last error
  if (lastError) throw lastError;
  return lastResponse!;
}

function sleep(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms));
}
