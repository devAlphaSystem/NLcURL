/**
 * URL utilities -- parsing, query string encoding, base URL joining.
 * Zero dependencies; uses the built-in WHATWG URL API.
 */

export function resolveURL(base: string | undefined, relative: string): string {
  if (!base) return relative;
  try {
    return new URL(relative, base).toString();
  } catch {
    return relative;
  }
}

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

export function parseURL(raw: string): URL {
  return new URL(raw);
}

/**
 * Extract the origin key used for connection pooling:
 * `protocol://host:port`
 */
export function originOf(url: string): string {
  const u = new URL(url);
  const port = u.port || (u.protocol === 'https:' ? '443' : '80');
  return `${u.protocol}//${u.hostname}:${port}`;
}

/** Return the hostname suitable for the TLS SNI extension. */
export function sniHost(url: string): string {
  return new URL(url).hostname;
}

/** Return the host:port string for TCP connection. */
export function hostPort(url: string): { host: string; port: number } {
  const u = new URL(url);
  const defaultPort = u.protocol === 'https:' ? 443 : 80;
  return {
    host: u.hostname,
    port: u.port ? parseInt(u.port, 10) : defaultPort,
  };
}

/** Return the request path including query string. */
export function requestPath(url: string): string {
  const u = new URL(url);
  return u.pathname + u.search;
}
