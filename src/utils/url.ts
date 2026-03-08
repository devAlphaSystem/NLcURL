/**
 * Resolve a relative URL against an optional base.
 *
 * @param {string | undefined} base - Base URL string.
 * @param {string} relative - Relative or absolute URL string.
 * @returns {string} Resolved absolute URL string.
 */
export function resolveURL(base: string | undefined, relative: string): string {
  if (!base) return relative;
  try {
    return new URL(relative, base).toString();
  } catch {
    return relative;
  }
}

/**
 * Append query parameters to a URL string.
 *
 * @param {string} url - Base URL string.
 * @param {Record<string, string | number | boolean>} [params] - Key-value pairs to append.
 * @returns {string} URL string with appended query parameters.
 */
export function appendParams(url: string, params?: Record<string, string | number | boolean>): string {
  if (!params || Object.keys(params).length === 0) return url;

  const parsed = new URL(url);
  for (const [key, value] of Object.entries(params)) {
    if (value === undefined || value === null) continue;
    parsed.searchParams.append(key, String(value));
  }
  return parsed.toString();
}

/**
 * Parse a URL string into a `URL` object.
 *
 * @param {string} raw - Raw URL string.
 * @returns {URL} Parsed `URL` instance.
 */
export function parseURL(raw: string): URL {
  return new URL(raw);
}

/**
 * Extract the origin (scheme + hostname + port) from a URL.
 *
 * @param {string} url - Absolute URL string.
 * @returns {string} Origin string (e.g. `"https://example.com:443"`).
 */
export function originOf(url: string): string {
  const u = new URL(url);
  const port = u.port || (u.protocol === "https:" ? "443" : "80");
  return `${u.protocol}//${u.hostname}:${port}`;
}

/**
 * Extract the hostname for TLS SNI from a URL.
 *
 * @param {string} url - Absolute URL string.
 * @returns {string} Hostname string.
 */
export function sniHost(url: string): string {
  return new URL(url).hostname;
}

/**
 * Extract the hostname and port from a URL.
 *
 * @param {string} url - Absolute URL string.
 * @returns {{ host: string; port: number }} Object with `host` and numeric `port`.
 */
export function hostPort(url: string): { host: string; port: number } {
  const u = new URL(url);
  const defaultPort = u.protocol === "https:" ? 443 : 80;
  return {
    host: u.hostname,
    port: u.port ? parseInt(u.port, 10) : defaultPort,
  };
}

/**
 * Extract the request path (pathname + search) from a URL.
 *
 * @param {string} url - Absolute URL string.
 * @returns {string} Path string suitable for an HTTP request line.
 */
export function requestPath(url: string): string {
  const u = new URL(url);
  return u.pathname + u.search;
}
