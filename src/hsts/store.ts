import type { HSTSConfig, HSTSEntry, HSTSPreloadEntry } from "./types.js";

/**
 * In-memory HSTS policy store implementing RFC 6797.
 *
 * Parses `Strict-Transport-Security` response headers, stores per-host policies,
 * and upgrades `http://` URLs to `https://` when an active policy matches.
 */
export class HSTSStore {
  private readonly policies = new Map<string, HSTSEntry>();

  constructor(config?: HSTSConfig) {
    if (config?.preload) {
      for (const entry of config.preload) {
        this.addPreload(entry);
      }
    }
  }

  /**
   * Seeds a preload entry with a very long max-age (20 years).
   */
  private addPreload(entry: HSTSPreloadEntry): void {
    const host = canonicalizeHost(entry.host);
    if (!host) return;
    this.policies.set(host, {
      host,
      expires: Date.now() + 20 * 365 * 24 * 60 * 60 * 1000,
      includeSubDomains: entry.includeSubDomains ?? false,
    });
  }

  /**
   * Parses a `Strict-Transport-Security` header value and stores the policy.
   * Only processes headers received over a secure (HTTPS) connection, as
   * required by RFC 6797 §8.1.
   *
   * @param host     - The hostname from the request URL.
   * @param value    - The raw STS header value (e.g. `"max-age=31536000; includeSubDomains"`).
   * @param isSecure - Whether the response was received over HTTPS.
   */
  parseHeader(host: string, value: string, isSecure: boolean): void {
    if (!isSecure) return;

    const canonical = canonicalizeHost(host);
    if (!canonical) return;

    if (isIPAddress(canonical)) return;

    const directives = parseDirectives(value);
    const maxAgeStr = directives.get("max-age");
    if (maxAgeStr === undefined) return;

    const maxAge = parseInt(maxAgeStr, 10);
    if (!Number.isFinite(maxAge) || maxAge < 0) return;

    if (maxAge === 0) {
      this.policies.delete(canonical);
      return;
    }

    this.policies.set(canonical, {
      host: canonical,
      expires: Date.now() + maxAge * 1000,
      includeSubDomains: directives.has("includesubdomains"),
    });
  }

  /**
   * Checks whether the given host has an active HSTS policy, either via
   * congruent match or superdomain match with `includeSubDomains`.
   */
  isSecure(host: string): boolean {
    const canonical = canonicalizeHost(host);
    if (!canonical) return false;
    if (isIPAddress(canonical)) return false;

    const exact = this.policies.get(canonical);
    if (exact) {
      if (Date.now() < exact.expires) return true;
      this.policies.delete(canonical);
    }

    const parts = canonical.split(".");
    for (let i = 1; i < parts.length; i++) {
      const parent = parts.slice(i).join(".");
      const entry = this.policies.get(parent);
      if (entry && entry.includeSubDomains) {
        if (Date.now() < entry.expires) return true;
        this.policies.delete(parent);
      }
    }

    return false;
  }

  /**
   * If there is an active HSTS policy for the host in the given URL,
   * upgrades the scheme from `http:` to `https:`. Returns the original
   * URL string if no upgrade is needed.
   */
  upgradeURL(urlString: string): string {
    let parsed: URL;
    try {
      parsed = new URL(urlString);
    } catch {
      return urlString;
    }

    if (parsed.protocol !== "http:") return urlString;

    if (this.isSecure(parsed.hostname)) {
      parsed.protocol = "https:";
      return parsed.toString();
    }

    return urlString;
  }

  /** Returns the number of active policies stored. */
  get size(): number {
    return this.policies.size;
  }

  /** Clears all stored policies. */
  clear(): void {
    this.policies.clear();
  }
}

/** Lowercases the host and strips a trailing dot. */
function canonicalizeHost(host: string): string {
  let h = host.toLowerCase().trim();
  if (h.endsWith(".")) h = h.slice(0, -1);
  return h;
}

/** Returns `true` if the string looks like an IPv4 or IPv6 address. */
function isIPAddress(host: string): boolean {
  if (host.startsWith("[")) return true;
  const parts = host.split(".");
  if (
    parts.length === 4 &&
    parts.every((p) => {
      if (!/^\d{1,3}$/.test(p)) return false;
      const n = parseInt(p, 10);
      return n >= 0 && n <= 255;
    })
  )
    return true;
  if (host.includes(":")) return true;
  return false;
}

/**
 * Parses the STS header value into a case-insensitive directive map.
 * Directive names are lowercased; quoted string values are unquoted.
 */
function parseDirectives(value: string): Map<string, string> {
  const directives = new Map<string, string>();
  const parts = value.split(";");
  for (const part of parts) {
    const trimmed = part.trim();
    if (!trimmed) continue;
    const eqIdx = trimmed.indexOf("=");
    if (eqIdx === -1) {
      directives.set(trimmed.toLowerCase(), "");
    } else {
      const name = trimmed.slice(0, eqIdx).trim().toLowerCase();
      let val = trimmed.slice(eqIdx + 1).trim();
      if (val.startsWith('"') && val.endsWith('"')) {
        val = val.slice(1, -1);
      }
      directives.set(name, val);
    }
  }
  return directives;
}
