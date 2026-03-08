/**
 * @module validation
 * @description Provides reusable runtime validation helpers for all public API
 * entry points. Functions throw {@link NLcURLError} with code `ERR_VALIDATION`
 * when an input fails a check. These guards protect every trust boundary
 * between caller-supplied data and internal library logic.
 */
import { NLcURLError } from "./errors.js";

const VALID_METHODS = new Set(["GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"]);
const VALID_HTTP_VERSIONS = new Set(["1.1", "2", "3"]);
const VALID_DNS_FAMILIES = new Set([4, 6]);
const VALID_BACKOFF = new Set(["linear", "exponential"]);

const HEADER_NAME_RE = /^[!#$%&'*+\-.0-9A-Za-z^_`|~]+$/;

const HEADER_VALUE_FORBIDDEN_RE = /[\x00-\x08\x0a-\x1f\x7f]/;

/**
 * Validates a single HTTP header name per RFC 7230 §3.2.6.
 * Must be a non-empty token consisting solely of tchar characters.
 */
export function validateHeaderName(name: string): void {
  if (!name || !HEADER_NAME_RE.test(name)) {
    fail(`Invalid HTTP header name: "${name.substring(0, 40)}"`);
  }
}

/**
 * Validates a single HTTP header value per RFC 7230 §3.2.6.
 * Must not contain control characters (0x00-0x08, 0x0A-0x1F, 0x7F).
 * HTAB (0x09) is allowed per spec.
 */
export function validateHeaderValue(name: string, value: string): void {
  if (HEADER_VALUE_FORBIDDEN_RE.test(value)) {
    fail(`HTTP header "${name}" contains forbidden control characters`);
  }
}

/**
 * Throws an `ERR_VALIDATION` error with the supplied message.
 *
 * @param {string} message - Description of the validation failure.
 * @throws {NLcURLError} Always.
 */
function fail(message: string): never {
  throw new NLcURLError(message, "ERR_VALIDATION");
}

/**
 * Asserts that `value` is a non-empty string.
 *
 * @param {unknown} value - The value to check.
 * @param {string}  label - Parameter name for the error message.
 * @throws {NLcURLError} If the value is not a non-empty string.
 */
export function assertNonEmptyString(value: unknown, label: string): asserts value is string {
  if (typeof value !== "string" || value.length === 0) {
    fail(`${label} must be a non-empty string`);
  }
}

/**
 * Asserts that `value` is a positive finite number.
 *
 * @param {unknown} value - The value to check.
 * @param {string}  label - Parameter name for the error message.
 * @throws {NLcURLError} If the value is not a positive finite number.
 */
export function assertPositiveNumber(value: unknown, label: string): asserts value is number {
  if (typeof value !== "number" || !Number.isFinite(value) || value <= 0) {
    fail(`${label} must be a positive finite number`);
  }
}

/**
 * Asserts that `value` is a non-negative finite integer.
 *
 * @param {unknown} value - The value to check.
 * @param {string}  label - Parameter name for the error message.
 * @throws {NLcURLError} If the value is not a non-negative integer.
 */
export function assertNonNegativeInt(value: unknown, label: string): asserts value is number {
  if (typeof value !== "number" || !Number.isInteger(value) || value < 0) {
    fail(`${label} must be a non-negative integer`);
  }
}

/**
 * Asserts that `value` is a member of the allowed set.
 *
 * @param {unknown}    value   - The value to check.
 * @param {Set<T>}     allowed - Set of permitted values.
 * @param {string}     label   - Parameter name for the error message.
 * @throws {NLcURLError} If the value is not in the allowed set.
 */
export function assertEnum<T>(value: unknown, allowed: Set<T>, label: string): asserts value is T {
  if (!allowed.has(value as T)) {
    const names = [...allowed].map(String).join(", ");
    fail(`${label} must be one of: ${names}`);
  }
}

/**
 * Asserts that `value` is a plain object (not `null`, not an array, not a
 * class instance other than `Object`).
 *
 * @param {unknown} value - The value to check.
 * @param {string}  label - Parameter name for the error message.
 * @throws {NLcURLError} If the value is not a plain object.
 */
export function assertPlainObject(value: unknown, label: string): asserts value is Record<string, unknown> {
  if (value === null || typeof value !== "object" || Array.isArray(value)) {
    fail(`${label} must be a plain object`);
  }
}

/**
 * Validates the URL string and its protocol for HTTP requests.
 *
 * @param {string}     url              - The URL string to validate.
 * @param {Set<string>} [allowedSchemes] - Permitted protocol schemes.
 * @throws {NLcURLError} If the URL is invalid or uses an unsupported protocol.
 */
export function validateUrl(url: string, allowedSchemes = new Set(["http:", "https:"])): void {
  if (typeof url !== "string" || url.length === 0) {
    fail("url must be a non-empty string");
  }
  let parsed: URL;
  try {
    parsed = new URL(url);
  } catch {
    fail(`Invalid URL: ${url}`);
    return;
  }
  if (!allowedSchemes.has(parsed.protocol)) {
    fail(`Unsupported URL protocol: ${parsed.protocol}`);
  }
}

/**
 * Validates per-phase timeout configuration. Each field must be a positive
 * finite number when present.
 *
 * @param {unknown} timeout - A flat timeout number or per-phase object.
 * @throws {NLcURLError} If any timeout value is invalid.
 */
export function validateTimeout(timeout: unknown): void {
  if (timeout === undefined || timeout === null) return;
  if (typeof timeout === "number") {
    if (!Number.isFinite(timeout) || timeout <= 0) {
      fail("timeout must be a positive finite number");
    }
    return;
  }
  if (typeof timeout === "object" && !Array.isArray(timeout)) {
    const obj = timeout as Record<string, unknown>;
    for (const key of ["connect", "tls", "response", "total"] as const) {
      if (obj[key] !== undefined) {
        if (typeof obj[key] !== "number" || !Number.isFinite(obj[key] as number) || (obj[key] as number) <= 0) {
          fail(`timeout.${key} must be a positive finite number`);
        }
      }
    }
    return;
  }
  fail("timeout must be a number or a TimeoutConfig object");
}

/**
 * Validates all user-supplied fields of an outgoing request descriptor.
 * Called at the entry of every public request function before any processing.
 *
 * @param {Record<string, unknown>} input - The raw request descriptor.
 * @throws {NLcURLError} If any field fails validation.
 */
export function validateRequest(input: Record<string, unknown>): void {
  if (input["method"] !== undefined) {
    assertEnum(input["method"], VALID_METHODS, "method");
  }
  if (input["headers"] !== undefined && input["headers"] !== null) {
    assertPlainObject(input["headers"], "headers");
  }
  if (input["httpVersion"] !== undefined) {
    assertEnum(input["httpVersion"], VALID_HTTP_VERSIONS, "httpVersion");
  }
  if (input["dnsFamily"] !== undefined) {
    assertEnum(input["dnsFamily"], VALID_DNS_FAMILIES, "dnsFamily");
  }
  if (input["maxRedirects"] !== undefined) {
    assertNonNegativeInt(input["maxRedirects"], "maxRedirects");
  }
  validateTimeout(input["timeout"]);
  if (input["impersonate"] !== undefined && input["impersonate"] !== null) {
    assertNonEmptyString(input["impersonate"], "impersonate");
  }
  if (input["proxy"] !== undefined && input["proxy"] !== null) {
    assertNonEmptyString(input["proxy"], "proxy");
  }
}

/**
 * Validates session-level configuration. Called once in the
 * {@link NLcURLSession} constructor.
 *
 * @param {Record<string, unknown>} config - The raw session config.
 * @throws {NLcURLError} If any field fails validation.
 */
export function validateSessionConfig(config: Record<string, unknown>): void {
  if (config["baseURL"] !== undefined && config["baseURL"] !== null) {
    assertNonEmptyString(config["baseURL"], "baseURL");
  }
  if (config["headers"] !== undefined && config["headers"] !== null) {
    assertPlainObject(config["headers"], "headers");
  }
  if (config["httpVersion"] !== undefined) {
    assertEnum(config["httpVersion"], VALID_HTTP_VERSIONS, "httpVersion");
  }
  if (config["dnsFamily"] !== undefined) {
    assertEnum(config["dnsFamily"], VALID_DNS_FAMILIES, "dnsFamily");
  }
  if (config["maxRedirects"] !== undefined) {
    assertNonNegativeInt(config["maxRedirects"], "maxRedirects");
  }
  validateTimeout(config["timeout"]);
  if (config["impersonate"] !== undefined && config["impersonate"] !== null) {
    assertNonEmptyString(config["impersonate"], "impersonate");
  }
  if (config["proxy"] !== undefined && config["proxy"] !== null) {
    assertNonEmptyString(config["proxy"], "proxy");
  }
  if (config["retry"] !== undefined && config["retry"] !== null) {
    validateRetryConfig(config["retry"] as Record<string, unknown>);
  }
}

/**
 * Validates the retry configuration object.
 *
 * @param {Record<string, unknown>} config - The raw retry config.
 * @throws {NLcURLError} If any retry setting is invalid.
 */
export function validateRetryConfig(config: Record<string, unknown>): void {
  if (config["count"] !== undefined) {
    assertNonNegativeInt(config["count"], "retry.count");
  }
  if (config["delay"] !== undefined) {
    assertPositiveNumber(config["delay"], "retry.delay");
  }
  if (config["jitter"] !== undefined) {
    if (typeof config["jitter"] !== "number" || !Number.isFinite(config["jitter"] as number) || (config["jitter"] as number) < 0) {
      fail("retry.jitter must be a non-negative finite number");
    }
  }
  if (config["backoff"] !== undefined) {
    assertEnum(config["backoff"], VALID_BACKOFF, "retry.backoff");
  }
}

/**
 * Validates rate limit configuration.
 *
 * @param {Record<string, unknown>} config - The raw rate limit config.
 * @throws {NLcURLError} If any rate limit parameter is invalid.
 */
export function validateRateLimitConfig(config: Record<string, unknown>): void {
  assertPositiveNumber(config["maxRequests"], "maxRequests");
  assertPositiveNumber(config["windowMs"], "windowMs");
  if (!Number.isInteger(config["maxRequests"])) {
    fail("maxRequests must be an integer");
  }
}

/**
 * Validates a WebSocket URL (must use `ws:` or `wss:` protocol).
 *
 * @param {string} url - The WebSocket URL to validate.
 * @throws {NLcURLError} If the URL is invalid or uses a non-WebSocket protocol.
 */
export function validateWebSocketUrl(url: string): void {
  validateUrl(url, new Set(["ws:", "wss:"]));
}
