import type { HSTSConfig, HSTSEntry, HSTSPreloadEntry } from "./types.js";

/** Store for HTTP Strict Transport Security policies. */
export class HSTSStore {
  private readonly policies = new Map<string, HSTSEntry>();

  /**
   * Create a new HSTS store.
   *
   * @param {HSTSConfig} [config] - Optional HSTS configuration with preload entries.
   */
  constructor(config?: HSTSConfig) {
    if (config?.preload) {
      for (const entry of config.preload) {
        this.addPreload(entry);
      }
    }
  }

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
   * Parse a Strict-Transport-Security response header and store the policy.
   *
   * @param {string} host - Origin hostname.
   * @param {string} value - Raw Strict-Transport-Security header value.
   * @param {boolean} isSecure - Whether the response was delivered over a secure transport.
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
   * Check whether a host has an active HSTS policy.
   *
   * @param {string} host - Hostname to check.
   * @returns {boolean} `true` if the host or a parent domain has an active includeSubDomains policy.
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
   * Upgrade an HTTP URL to HTTPS if an HSTS policy applies.
   *
   * @param {string} urlString - URL to potentially upgrade.
   * @returns {string} The original URL or an HTTPS-upgraded version.
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

  /** Number of active HSTS policies in the store. */
  get size(): number {
    return this.policies.size;
  }

  /** Remove all HSTS policies from the store. */
  clear(): void {
    this.policies.clear();
  }
}

function canonicalizeHost(host: string): string {
  let h = host.toLowerCase().trim();
  if (h.endsWith(".")) h = h.slice(0, -1);
  return h;
}

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
