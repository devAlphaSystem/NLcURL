
import type { RetryConfig } from '../core/request.js';
import { NLcURLResponse } from '../core/response.js';
import { AbortError, TLSError, TimeoutError, ConnectionError, ProtocolError } from '../core/errors.js';

const RETRYABLE_H2_ERROR_CODES = new Set([1, 2, 7, 11]);

/**
 * Carries context about the current retry attempt that is passed to the
 * `execute` callback on each invocation.
 *
 * @typedef  {Object}          RetryContext
 * @property {number}          attempt       - Zero-based attempt index (0 = first try).
 * @property {Error}           [lastError]   - The error thrown by the previous attempt, if any.
 * @property {NLcURLResponse}  [lastResponse] - The response from the previous attempt, if any.
 */
export interface RetryContext {
  attempt: number;
  lastError?: Error;
  lastResponse?: NLcURLResponse;
}

function shouldRetryDefault(error: Error | null, statusCode?: number): boolean {
  if (error instanceof ConnectionError || error instanceof TimeoutError || error instanceof TLSError) return true;
  if (error instanceof ProtocolError && error.errorCode !== undefined && RETRYABLE_H2_ERROR_CODES.has(error.errorCode)) return true;
  if (statusCode !== undefined && [429, 500, 502, 503, 504].includes(statusCode)) return true;
  return false;
}

/**
 * Executes `execute` up to `config.count + 1` times with configurable
 * back-off and jitter between attempts. Transparent to `AbortError` — those
 * propagate immediately without retry.
 *
 * @param {RetryConfig | undefined} config  - Retry parameters; `undefined` uses library defaults.
 * @param {(ctx: RetryContext) => Promise<NLcURLResponse>} execute - The operation to attempt.
 * @returns {Promise<NLcURLResponse>} The first successful response.
 * @throws {AbortError}  Immediately if the operation is aborted.
 * @throws {Error}       Re-throws the last error if all attempts are exhausted.
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

      if (attempt < count && retryOn(null, response.status)) {
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
