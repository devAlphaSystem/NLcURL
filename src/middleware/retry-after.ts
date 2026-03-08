/**
 * Parse a Retry-After header value into milliseconds.
 *
 * @param {string} value - Raw Retry-After header (seconds or HTTP date).
 * @returns {number|undefined} Delay in milliseconds, or `undefined` if unparseable.
 */
export function parseRetryAfter(value: string): number | undefined {
  if (!value) return undefined;

  const trimmed = value.trim();

  if (/^\d+$/.test(trimmed)) {
    const seconds = parseInt(trimmed, 10);
    if (Number.isFinite(seconds) && seconds >= 0) {
      return seconds * 1000;
    }
  }

  const date = new Date(trimmed);
  if (!Number.isNaN(date.getTime())) {
    const delayMs = date.getTime() - Date.now();
    return Math.max(0, delayMs);
  }

  return undefined;
}

/**
 * Extract the retry delay from response headers.
 *
 * @param {Record<string, string>} headers - Response headers.
 * @returns {number|undefined} Delay in milliseconds, or `undefined` if no Retry-After header.
 */
export function getRetryAfterMs(headers: Record<string, string>): number | undefined {
  const value = headers["retry-after"];
  if (!value) return undefined;
  return parseRetryAfter(value);
}
