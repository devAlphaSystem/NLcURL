import type { RetryConfig } from "../core/request.js";
import { NLcURLResponse } from "../core/response.js";
import { AbortError, TLSError, TimeoutError, ConnectionError, ProtocolError } from "../core/errors.js";
import { type Logger, getDefaultLogger } from "../utils/logger.js";
import { getRetryAfterMs } from "./retry-after.js";

const RETRYABLE_H2_ERROR_CODES = new Set([1, 2, 7, 8, 11, 13]);

/** Context passed to each retry attempt. */
export interface RetryContext {
  /** Current attempt number (1-based). */
  attempt: number;
  /** Error from the previous attempt, if any. */
  lastError?: Error;
  /** Response from the previous attempt, if any. */
  lastResponse?: NLcURLResponse;
}

function shouldRetryDefault(error: Error | null, statusCode?: number): boolean {
  if (error instanceof ConnectionError || error instanceof TimeoutError || error instanceof TLSError) return true;
  if (error instanceof ProtocolError && error.errorCode !== undefined && RETRYABLE_H2_ERROR_CODES.has(error.errorCode)) return true;
  if (statusCode !== undefined && [429, 500, 502, 503, 504].includes(statusCode)) return true;
  return false;
}

/**
 * Execute a request function with configurable retry logic.
 *
 * @param {RetryConfig|undefined} config - Retry configuration.
 * @param {(ctx: RetryContext) => Promise<NLcURLResponse>} execute - Function that performs the request attempt.
 * @param {Logger} [logger] - Optional logger for retry events.
 * @returns {Promise<NLcURLResponse>} Final HTTP response after all retries.
 */
export async function withRetry(config: RetryConfig | undefined, execute: (ctx: RetryContext) => Promise<NLcURLResponse>, logger?: Logger): Promise<NLcURLResponse> {
  const log = logger ?? getDefaultLogger();
  const count = config?.count ?? 3;
  const baseDelay = config?.delay ?? 1000;
  const backoff = config?.backoff ?? "exponential";
  const jitterMax = config?.jitter ?? 200;
  const retryOn = config?.retryOn ?? shouldRetryDefault;

  let lastError: Error | undefined;
  let lastResponse: NLcURLResponse | undefined;

  for (let attempt = 0; attempt <= count; attempt++) {
    if (attempt > 0) {
      const factor = backoff === "exponential" ? Math.min(32, Math.pow(2, attempt - 1)) : attempt;
      const delay = baseDelay * factor;
      const jitter = Math.random() * jitterMax;
      log.debug(`retry attempt ${attempt}/${count} after ${Math.round(delay + jitter)}ms`);
      await sleep(delay + jitter);
    }

    try {
      const response = await execute({ attempt, lastError, lastResponse });

      if (attempt < count && retryOn(null, response.status)) {
        const retryAfterMs = getRetryAfterMs(response.headers);
        if (retryAfterMs !== undefined && retryAfterMs > 0) {
          const cappedDelay = Math.min(retryAfterMs, 300_000);
          log.debug(`retry respecting Retry-After: ${Math.round(cappedDelay)}ms`);
          await sleep(cappedDelay);
        }
        lastResponse = response;
        continue;
      }

      return response;
    } catch (err) {
      if (err instanceof AbortError) throw err;

      const error = err instanceof Error ? err : new Error(String(err));
      if (attempt < count && retryOn(error)) {
        lastError = error;
        continue;
      }

      throw err;
    }
  }

  if (lastError) throw lastError;
  return lastResponse!;
}

function sleep(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms));
}
