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
 * Resolve a proxy URL from standard environment variables.
 *
 * Checks `NO_PROXY` / `no_proxy` first, then selects `HTTPS_PROXY` or
 * `HTTP_PROXY` (and their lowercase variants) based on the URL scheme.
 *
 * @param {string} url - Absolute URL to resolve a proxy for.
 * @returns {string|undefined} Proxy URL string, or `undefined` if none applies.
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
