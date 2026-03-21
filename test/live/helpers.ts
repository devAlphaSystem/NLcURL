/**
 * Shared helpers for live / real-life tests.
 *
 * These tests hit REAL public endpoints over the network.
 * They may fail due to transient network issues, server changes, or rate limiting.
 * They are NOT meant for CI — run them manually with `npm run test:live`.
 */
import { strict as assert } from "node:assert";
import type { TestContext } from "node:test";
import type { NLcURLResponse } from "../../src/core/response.js";

/** Default timeout for live network requests (15 seconds). */
export const LIVE_TIMEOUT = 15_000;

/** Extended timeout for slow endpoints (30 seconds). */
export const SLOW_TIMEOUT = 30_000;

/** Assert response is a successful 2xx. */
export function assertOk(resp: NLcURLResponse, context?: string): void {
  const msg = context ? `${context}: ` : "";
  assert.ok(resp.status >= 200 && resp.status < 300, `${msg}Expected 2xx status, got ${resp.status} ${resp.statusText} for ${resp.url}`);
}

/** Assert response has a specific header (case-insensitive key). */
export function assertHeader(resp: NLcURLResponse, header: string, context?: string): string {
  const key = header.toLowerCase();
  const val = resp.headers[key];
  const msg = context ? `${context}: ` : "";
  assert.ok(val !== undefined, `${msg}Expected header "${header}" in response from ${resp.url}`);
  return val;
}

/** Assert body is non-empty. */
export function assertBody(resp: NLcURLResponse, context?: string): void {
  const msg = context ? `${context}: ` : "";
  assert.ok(resp.rawBody.length > 0, `${msg}Expected non-empty body from ${resp.url}`);
}

/** Skip a test with a reason (for conditional skipping). */
export function skip(reason: string): never {
  const err = new Error(reason);
  err.name = "SkipError";
  throw err;
}

/**
 * Retry an async function up to `maxRetries` times if it throws a TLS-related error.
 * This compensates for intermittent AEAD / handshake failures in the stealth TLS engine.
 */
export async function withTlsRetry<T>(fn: () => Promise<T>, maxRetries = 3): Promise<T> {
  let lastError: unknown;
  for (let attempt = 0; attempt <= maxRetries; attempt++) {
    try {
      return await fn();
    } catch (err: unknown) {
      lastError = err;
      if (!isTlsInfraError(err) || attempt === maxRetries) throw err;
      await new Promise((r) => setTimeout(r, 1000 * 2 ** attempt));
    }
  }
  throw lastError;
}

/** Returns true if an error is a known stealth TLS infrastructure issue. */
export function isTlsInfraError(err: unknown): boolean {
  const msg = err instanceof Error ? err.message : String(err);
  return msg.includes("AEAD decryption failed") || msg.includes("Connection closed during handshake") || msg.includes("Server sent alert") || msg.includes("ECONNRESET");
}

/**
 * Previously wrapped stealth tests to skip on TLS infrastructure errors.
 * The underlying TLS bugs have been fixed — this is now a passthrough.
 * Kept for backward compatibility with existing test call sites.
 */
export function skipIfTlsBroken(fn: (t: TestContext) => Promise<void>) {
  return fn;
}
