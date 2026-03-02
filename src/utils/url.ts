
/**
 * Resolves `relative` against `base`. When `base` is `undefined` or the
 * resolution fails, `relative` is returned as-is.
 *
 * @param {string | undefined} base     - Base URL string.
 * @param {string}             relative - Relative or absolute URL to resolve.
 * @returns {string} The resolved absolute URL, or `relative` if resolution fails.
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
 * Appends `params` as query-string parameters to `url`. Existing parameters in
 * the URL are preserved. `undefined` and `null` values are omitted.
 *
 * @param {string}                                        url    - Base URL.
 * @param {Record<string, string | number | boolean>}     [params] - Key-value pairs to append.
 * @returns {string} URL with appended query parameters.
 */
export function appendParams(
  url: string,
  params?: Record<string, string | number | boolean>
): string {
  if (!params || Object.keys(params).length === 0) return url;

  const parsed = new URL(url);
  for (const [key, value] of Object.entries(params)) {
    if (value === undefined || value === null) continue;
    parsed.searchParams.append(key, String(value));
  }
  return parsed.toString();
}

/**
 * Parses `raw` into a `URL` object.
 *
 * @param {string} raw - Absolute URL string to parse.
 * @returns {URL} Parsed URL.
 * @throws {TypeError} If `raw` is not a valid absolute URL.
 */
export function parseURL(raw: string): URL {
  return new URL(raw);
}

/**
 * Returns the origin of `url` in `scheme://hostname:port` form. The port is
 * always included explicitly, defaulting to `443` for `https:` and `80` for
 * `http:`.
 *
 * @param {string} url - Absolute URL string.
 * @returns {string} Origin string (e.g. `"https://example.com:443"`).
 */
export function originOf(url: string): string {
  const u = new URL(url);
  const port = u.port || (u.protocol === 'https:' ? '443' : '80');
  return `${u.protocol}//${u.hostname}:${port}`;
}

/**
 * Extracts the hostname from `url` for use as the TLS SNI server-name value.
 *
 * @param {string} url - Absolute URL string.
 * @returns {string} Hostname without port (e.g. `"example.com"`).
 */
export function sniHost(url: string): string {
  return new URL(url).hostname;
}

/**
 * Extracts the host and port from `url`. The port defaults to `443` for
 * `https:` and `80` for `http:` when not explicitly specified in the URL.
 *
 * @param {string} url - Absolute URL string.
 * @returns {{ host: string; port: number }} Hostname and numeric port.
 */
export function hostPort(url: string): { host: string; port: number } {
  const u = new URL(url);
  const defaultPort = u.protocol === 'https:' ? 443 : 80;
  return {
    host: u.hostname,
    port: u.port ? parseInt(u.port, 10) : defaultPort,
  };
}

/**
 * Returns the path and query string of `url` suitable for use as the
 * request-target in an HTTP/1.1 request line.
 *
 * @param {string} url - Absolute URL string.
 * @returns {string} Path + query string (e.g. `"/search?q=hello"`).
 */
export function requestPath(url: string): string {
  const u = new URL(url);
  return u.pathname + u.search;
}
