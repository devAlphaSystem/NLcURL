/**
 * Resolves proxy configuration from standard environment variables
 * (`HTTP_PROXY`, `HTTPS_PROXY`, `NO_PROXY` and their lowercase variants).
 * Follows the same conventions as curl, got, axios, and undici.
 */

/**
 * Checks whether the given hostname should bypass the proxy according to the
 * `NO_PROXY` / `no_proxy` environment variable.
 *
 * @param {string} hostname - The target hostname to check.
 * @param {string} noProxy  - Comma-separated list of hosts/domains/CIDRs to bypass.
 * @returns {boolean} `true` if the hostname matches a bypass pattern.
 */
function matchesNoProxy(hostname: string, noProxy: string): boolean {
  if (noProxy === "*") return true;

  const host = hostname.toLowerCase();
  const entries = noProxy
    .split(",")
    .map((e) => e.trim().toLowerCase())
    .filter(Boolean);

  for (const entry of entries) {
    if (entry === host) return true;
    if (entry.startsWith(".") && (host.endsWith(entry) || host === entry.slice(1))) return true;
    if (host === entry || host.endsWith("." + entry)) return true;
  }

  return false;
}

/**
 * Resolves a proxy URL from environment variables for the given request URL.
 * Returns `undefined` if no proxy should be used (either not configured or
 * the host is in the `NO_PROXY` bypass list).
 *
 * Precedence (same as curl):
 * 1. `no_proxy` / `NO_PROXY` to skip proxy for matching hosts.
 * 2. `https_proxy` / `HTTPS_PROXY` for HTTPS URLs.
 * 3. `http_proxy` / `HTTP_PROXY` for HTTP URLs.
 * 4. `all_proxy` / `ALL_PROXY` as a fallback for either protocol.
 *
 * @param {string} url - The target request URL.
 * @returns {string | undefined} Proxy URL, or `undefined` if no proxy applies.
 */
export function resolveEnvProxy(url: string): string | undefined {
  let parsed: URL;
  try {
    parsed = new URL(url);
  } catch {
    return undefined;
  }

  const noProxy = process.env["no_proxy"] ?? process.env["NO_PROXY"] ?? "";
  if (noProxy && matchesNoProxy(parsed.hostname, noProxy)) {
    return undefined;
  }

  const isHttps = parsed.protocol === "https:" || parsed.protocol === "wss:";

  if (isHttps) {
    const proxy = process.env["https_proxy"] ?? process.env["HTTPS_PROXY"];
    if (proxy) return proxy;
  } else {
    const proxy = process.env["http_proxy"] ?? process.env["HTTP_PROXY"];
    if (proxy) return proxy;
  }

  const allProxy = process.env["all_proxy"] ?? process.env["ALL_PROXY"];
  if (allProxy) return allProxy;

  return undefined;
}
