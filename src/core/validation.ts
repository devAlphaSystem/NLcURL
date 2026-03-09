import * as net from "node:net";
import { NLcURLError } from "./errors.js";

const VALID_METHODS = new Set(["GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"]);
const VALID_HTTP_VERSIONS = new Set(["1.1", "2", "3"]);
const VALID_DNS_FAMILIES = new Set([4, 6]);
const VALID_BACKOFF = new Set(["linear", "exponential"]);

const HEADER_NAME_RE = /^[!#$%&'*+\-.0-9A-Za-z^_`|~]+$/;

const HEADER_VALUE_FORBIDDEN_RE = /[\x00-\x08\x0a-\x1f\x7f]/;

/** Maximum URL length to prevent resource exhaustion. */
const MAX_URL_LENGTH = 65535;

/**
 * WHATWG fetch standard dangerous port blocklist.
 * https://fetch.spec.whatwg.org/#bad-port
 */
const DANGEROUS_PORTS = new Set([1, 7, 9, 11, 13, 15, 17, 19, 20, 21, 22, 23, 25, 37, 42, 43, 53, 77, 79, 87, 95, 101, 102, 103, 104, 109, 110, 111, 113, 115, 117, 119, 123, 135, 139, 143, 161, 179, 389, 427, 465, 512, 513, 514, 515, 526, 530, 531, 532, 540, 548, 554, 556, 563, 587, 601, 636, 993, 995, 1719, 1720, 1723, 2049, 3659, 4045, 4190, 5060, 5061, 6000, 6566, 6665, 6666, 6667, 6668, 6669, 6697, 10080]);

/**
 * Check if an IP address (v4 or v6) is in a private/reserved range.
 * This covers RFC 1918, RFC 4193, loopback, link-local, broadcast, etc.
 */
function isPrivateIP(ip: string): boolean {
  if (net.isIPv4(ip)) {
    const parts = ip.split(".").map(Number);
    const [a, b] = parts;
    if (a === 10) return true;
    if (a === 172 && b! >= 16 && b! <= 31) return true;
    if (a === 192 && b === 168) return true;
    if (a === 127) return true;
    if (a === 0) return true;
    if (a === 169 && b === 254) return true;
    if (a === 100 && b! >= 64 && b! <= 127) return true;
    if (a === 192 && b === 0 && parts[2] === 0) return true;
    if (a === 198 && (b === 18 || b === 19)) return true;
    if (a! >= 224) return true;
    return false;
  }

  if (net.isIPv6(ip)) {
    const normalized = ip.toLowerCase();
    if (normalized === "::1") return true;
    if (normalized === "::") return true;
    if (normalized.startsWith("fe80:")) return true;
    if (normalized.startsWith("fc") || normalized.startsWith("fd")) return true;
    if (normalized.startsWith("::ffff:")) {
      const inner = normalized.slice(7);
      if (net.isIPv4(inner)) return isPrivateIP(inner);
    }
    return false;
  }

  return false;
}

/**
 * Validates a URL for SSRF safety: checks port blocklist, private IP ranges,
 * and URL length. Call this before making outbound requests.
 *
 * @param {string} url - The URL to validate.
 * @param {object} [options] - Validation options.
 * @param {boolean} [options.allowPrivateIPs] - Skip private IP checks (default: false).
 * @param {boolean} [options.allowDangerousPorts] - Skip port blocklist (default: false).
 * @throws {NLcURLError} If the URL targets a dangerous port or private IP.
 */
export function validateUrlSafety(url: string, options?: { allowPrivateIPs?: boolean; allowDangerousPorts?: boolean }): void {
  if (url.length > MAX_URL_LENGTH) {
    fail(`URL exceeds maximum length of ${MAX_URL_LENGTH} characters`);
  }

  let parsed: URL;
  try {
    parsed = new URL(url);
  } catch {
    fail(`Invalid URL: ${url.substring(0, 100)}`);
    return;
  }

  if (!options?.allowDangerousPorts && parsed.port) {
    const port = parseInt(parsed.port, 10);
    if (DANGEROUS_PORTS.has(port)) {
      fail(`Request to dangerous port ${port} is blocked`);
    }
  }

  if (!options?.allowPrivateIPs) {
    const hostname = parsed.hostname;
    const bare = hostname.startsWith("[") && hostname.endsWith("]") ? hostname.slice(1, -1) : hostname;
    if (net.isIP(bare) && isPrivateIP(bare)) {
      fail(`Request to private/reserved IP address ${bare} is blocked`);
    }
  }
}

/**
 * Validates that a header name conforms to RFC 7230 token syntax.
 *
 * @param {string} name - The header name to validate.
 * @throws {NLcURLError} If the name contains invalid characters.
 */
export function validateHeaderName(name: string): void {
  if (!name || !HEADER_NAME_RE.test(name)) {
    fail(`Invalid HTTP header name: "${name.substring(0, 40)}"`);
  }
}

/**
 * Validates that a header value does not contain forbidden control characters.
 *
 * @param {string} name - The header name (used in the error message).
 * @param {string} value - The header value to validate.
 * @throws {NLcURLError} If the value contains CR, LF, NUL, or other forbidden characters.
 */
export function validateHeaderValue(name: string, value: string): void {
  if (HEADER_VALUE_FORBIDDEN_RE.test(value)) {
    fail(`HTTP header "${name}" contains forbidden control characters`);
  }
}

function fail(message: string): never {
  throw new NLcURLError(message, "ERR_VALIDATION");
}

/**
 * Asserts that the value is a non-empty string.
 *
 * @param {unknown} value - The value to check.
 * @param {string} label - A human-readable label for error messages.
 * @throws {NLcURLError} If the value is not a non-empty string.
 */
export function assertNonEmptyString(value: unknown, label: string): asserts value is string {
  if (typeof value !== "string" || value.length === 0) {
    fail(`${label} must be a non-empty string`);
  }
}

/**
 * Asserts that the value is a positive finite number.
 *
 * @param {unknown} value - The value to check.
 * @param {string} label - A human-readable label for error messages.
 * @throws {NLcURLError} If the value is not a positive finite number.
 */
export function assertPositiveNumber(value: unknown, label: string): asserts value is number {
  if (typeof value !== "number" || !Number.isFinite(value) || value <= 0) {
    fail(`${label} must be a positive finite number`);
  }
}

/**
 * Asserts that the value is a non-negative integer.
 *
 * @param {unknown} value - The value to check.
 * @param {string} label - A human-readable label for error messages.
 * @throws {NLcURLError} If the value is not a non-negative integer.
 */
export function assertNonNegativeInt(value: unknown, label: string): asserts value is number {
  if (typeof value !== "number" || !Number.isInteger(value) || value < 0) {
    fail(`${label} must be a non-negative integer`);
  }
}

/**
 * Asserts that the value belongs to a predefined set of allowed values.
 *
 * @template T
 * @param {unknown} value - The value to check.
 * @param {Set<T>} allowed - The set of allowed values.
 * @param {string} label - A human-readable label for error messages.
 * @throws {NLcURLError} If the value is not in the allowed set.
 */
export function assertEnum<T>(value: unknown, allowed: Set<T>, label: string): asserts value is T {
  if (!allowed.has(value as T)) {
    const names = [...allowed].map(String).join(", ");
    fail(`${label} must be one of: ${names}`);
  }
}

/**
 * Asserts that the value is a plain object (not null, not an array).
 *
 * @param {unknown} value - The value to check.
 * @param {string} label - A human-readable label for error messages.
 * @throws {NLcURLError} If the value is not a plain object.
 */
export function assertPlainObject(value: unknown, label: string): asserts value is Record<string, unknown> {
  if (value === null || typeof value !== "object" || Array.isArray(value)) {
    fail(`${label} must be a plain object`);
  }
  const obj = value as Record<string, unknown>;
  if (Object.hasOwn(obj, "__proto__") || Object.hasOwn(obj, "constructor") || Object.hasOwn(obj, "prototype")) {
    fail(`${label} contains forbidden prototype pollution keys`);
  }
}

/**
 * Validates that a URL string is well-formed and uses one of the allowed schemes.
 *
 * @param {string} url - The URL to validate.
 * @param {Set<string>} [allowedSchemes] - Permitted URL schemes. Defaults to `http:` and `https:`.
 * @throws {NLcURLError} If the URL is invalid or uses a disallowed scheme.
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
  if (parsed.username || parsed.password) {
    fail("URL must not contain embedded credentials (username:password)");
  }
}

/**
 * Validates a timeout value, accepting either a positive number or a TimeoutConfig object.
 *
 * @param {unknown} timeout - The timeout value to validate.
 * @throws {NLcURLError} If the timeout is not a valid number or TimeoutConfig.
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
        if (typeof obj[key] !== "number" || !Number.isFinite(obj[key]) || obj[key] <= 0) {
          fail(`timeout.${key} must be a positive finite number`);
        }
      }
    }
    return;
  }
  fail("timeout must be a number or a TimeoutConfig object");
}

/**
 * Validates all fields of a request descriptor.
 *
 * @param {Record<string, unknown>} input - The request fields to validate.
 * @throws {NLcURLError} If any field value is invalid.
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
 * Validates all fields of a session configuration object.
 *
 * @param {Record<string, unknown>} config - The session config fields to validate.
 * @throws {NLcURLError} If any field value is invalid.
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
 * Validates retry configuration fields.
 *
 * @param {Record<string, unknown>} config - The retry config fields to validate.
 * @throws {NLcURLError} If any field value is invalid.
 */
export function validateRetryConfig(config: Record<string, unknown>): void {
  if (config["count"] !== undefined) {
    assertNonNegativeInt(config["count"], "retry.count");
  }
  if (config["delay"] !== undefined) {
    assertPositiveNumber(config["delay"], "retry.delay");
  }
  if (config["jitter"] !== undefined) {
    if (typeof config["jitter"] !== "number" || !Number.isFinite(config["jitter"]) || config["jitter"] < 0) {
      fail("retry.jitter must be a non-negative finite number");
    }
  }
  if (config["backoff"] !== undefined) {
    assertEnum(config["backoff"], VALID_BACKOFF, "retry.backoff");
  }
}

/**
 * Validates rate limit configuration fields.
 *
 * @param {Record<string, unknown>} config - The rate limit config fields to validate.
 * @throws {NLcURLError} If maxRequests or windowMs is invalid.
 */
export function validateRateLimitConfig(config: Record<string, unknown>): void {
  assertPositiveNumber(config["maxRequests"], "maxRequests");
  assertPositiveNumber(config["windowMs"], "windowMs");
  if (!Number.isInteger(config["maxRequests"])) {
    fail("maxRequests must be an integer");
  }
}

/**
 * Validates that a URL uses the `ws:` or `wss:` scheme for WebSocket connections.
 *
 * @param {string} url - The URL to validate.
 * @throws {NLcURLError} If the URL is invalid or uses a non-WebSocket scheme.
 */
export function validateWebSocketUrl(url: string): void {
  validateUrl(url, new Set(["ws:", "wss:"]));
}
