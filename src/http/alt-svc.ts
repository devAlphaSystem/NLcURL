/**
 * Alt-Svc (Alternative Services) implementation per RFC 7838.
 *
 * Parses `Alt-Svc` response headers and maintains a store of alternative
 * service entries. This is the primary mechanism for HTTP/3 discovery:
 * servers advertise `h3=":443"` in Alt-Svc to indicate QUIC availability.
 *
 * @see https://datatracker.ietf.org/doc/html/rfc7838
 */

/**
 * A single alternative service entry parsed from an Alt-Svc header.
 */
export interface AltSvcEntry {
  /** ALPN protocol identifier (e.g. "h3", "h3-29", "h2"). */
  alpn: string;
  /** Authority — host:port of the alternative service. */
  host: string;
  port: number;
  /** Maximum age in seconds before this entry expires. */
  maxAge: number;
  /** Whether the entry has been confirmed via a successful connection. */
  persist: boolean;
  /** Timestamp (ms) when this entry was stored. */
  storedAt: number;
}

/**
 * Configuration for the Alt-Svc store.
 */
export interface AltSvcConfig {
  /** Maximum number of entries across all origins. @default 1000 */
  maxEntries?: number;
  /** Whether to enable Alt-Svc processing. @default true */
  enabled?: boolean;
}

const DEFAULT_MAX_AGE = 86400;
const DEFAULT_MAX_ENTRIES = 1000;

/**
 * In-memory store for Alt-Svc (Alternative Services) per RFC 7838.
 *
 * Tracks alternative service advertisements from HTTP response headers
 * and provides lookup for the best alternative to use for a given origin.
 *
 * Primary use case: HTTP/3 discovery via `h3=":443"` advertisements.
 */
export class AltSvcStore {
  private readonly entries = new Map<string, AltSvcEntry[]>();
  private readonly maxEntries: number;
  private totalEntries = 0;

  constructor(config?: AltSvcConfig) {
    this.maxEntries = config?.maxEntries ?? DEFAULT_MAX_ENTRIES;
  }

  /**
   * Parses an `Alt-Svc` response header value and stores the entries
   * associated with the given origin.
   *
   * @param origin   Origin of the response (e.g. "https://example.com:443").
   * @param headerValue  Raw `Alt-Svc` header value.
   *
   * @example
   * store.parseHeader("https://example.com:443", 'h3=":443"; ma=86400, h2=":443"');
   */
  parseHeader(origin: string, headerValue: string): void {
    const trimmed = headerValue.trim();

    if (trimmed === "clear") {
      this.clear(origin);
      return;
    }

    const now = Date.now();
    const parsed = parseAltSvcHeader(trimmed, origin, now);
    if (parsed.length === 0) return;

    const existing = this.entries.get(origin);
    if (existing) {
      this.totalEntries -= existing.length;
    }

    while (this.totalEntries + parsed.length > this.maxEntries) {
      this.evictOldest();
    }

    this.entries.set(origin, parsed);
    this.totalEntries += parsed.length;
  }

  /**
   * Looks up the best available alternative service for a given origin.
   * Prefers h3 over h2. Expired entries are pruned during lookup.
   *
   * @param origin Origin to look up alternatives for.
   * @returns The best Alt-Svc entry, or undefined if no valid alternative exists.
   */
  lookup(origin: string): AltSvcEntry | undefined {
    const entries = this.entries.get(origin);
    if (!entries) return undefined;

    const now = Date.now();

    const valid = entries.filter((e) => now - e.storedAt < e.maxAge * 1000);
    if (valid.length === 0) {
      this.entries.delete(origin);
      this.totalEntries -= entries.length;
      return undefined;
    }

    if (valid.length !== entries.length) {
      this.totalEntries -= entries.length - valid.length;
      this.entries.set(origin, valid);
    }

    const h3 = valid.find((e) => e.alpn === "h3");
    if (h3) return h3;

    const h3Draft = valid.find((e) => e.alpn.startsWith("h3-"));
    if (h3Draft) return h3Draft;

    return valid[0];
  }

  /**
   * Checks if there's an h3 alternative available for an origin.
   */
  hasH3(origin: string): boolean {
    const entry = this.lookup(origin);
    return entry !== undefined && (entry.alpn === "h3" || entry.alpn.startsWith("h3-"));
  }

  /**
   * Removes all alternative service entries for a specific origin.
   */
  clear(origin: string): void {
    const entries = this.entries.get(origin);
    if (entries) {
      this.totalEntries -= entries.length;
      this.entries.delete(origin);
    }
  }

  /**
   * Removes all entries from the store.
   */
  clearAll(): void {
    this.entries.clear();
    this.totalEntries = 0;
  }

  /**
   * Returns the total number of stored entries.
   */
  get size(): number {
    return this.totalEntries;
  }

  private evictOldest(): void {
    let oldestOrigin: string | undefined;
    let oldestTime = Infinity;

    for (const [origin, entries] of this.entries) {
      for (const entry of entries) {
        if (entry.storedAt < oldestTime) {
          oldestTime = entry.storedAt;
          oldestOrigin = origin;
        }
      }
    }

    if (oldestOrigin) {
      this.clear(oldestOrigin);
    }
  }
}

/**
 * Parses an Alt-Svc header value into structured entries.
 *
 * Format: `protocol="host:port"; ma=86400; persist=1, ...`
 *
 * Per RFC 7838 §3:
 * - `protocol` is the ALPN protocol identifier
 * - The quoted value is the authority `host:port`
 * - `ma` is max-age in seconds (default 24h)
 * - `persist` indicates whether to retain across network changes
 */
function parseAltSvcHeader(value: string, origin: string, now: number): AltSvcEntry[] {
  const entries: AltSvcEntry[] = [];
  const originUrl = new URL(origin);
  const defaultHost = originUrl.hostname;
  const defaultPort = parseInt(originUrl.port) || (originUrl.protocol === "https:" ? 443 : 80);

  const alternatives = splitAltSvc(value);

  for (const alt of alternatives) {
    const entry = parseSingleAltSvc(alt.trim(), defaultHost, defaultPort, now);
    if (entry) entries.push(entry);
  }

  return entries;
}

/**
 * Splits Alt-Svc header by commas, respecting quoted strings.
 */
function splitAltSvc(value: string): string[] {
  const parts: string[] = [];
  let current = "";
  let inQuotes = false;

  for (const ch of value) {
    if (ch === '"') {
      inQuotes = !inQuotes;
      current += ch;
    } else if (ch === "," && !inQuotes) {
      parts.push(current);
      current = "";
    } else {
      current += ch;
    }
  }
  if (current) parts.push(current);
  return parts;
}

/**
 * Parses a single Alt-Svc alternative entry.
 *
 * Format: `h3=":443"; ma=86400; persist=1`
 */
function parseSingleAltSvc(alt: string, defaultHost: string, defaultPort: number, now: number): AltSvcEntry | null {
  const match = alt.match(/^([a-zA-Z0-9-]+)="([^"]*)"/);
  if (!match) return null;

  const alpn = match[1]!;
  const authority = match[2]!;

  let host = defaultHost;
  let port = defaultPort;

  if (authority) {
    const colonIdx = authority.lastIndexOf(":");
    if (colonIdx >= 0) {
      const hostPart = authority.substring(0, colonIdx);
      const portPart = authority.substring(colonIdx + 1);
      if (hostPart) host = hostPart;
      const parsedPort = parseInt(portPart, 10);
      if (!isNaN(parsedPort) && parsedPort > 0 && parsedPort <= 65535) {
        port = parsedPort;
      }
    }
  }

  let maxAge = DEFAULT_MAX_AGE;
  let persist = false;

  const params = alt.substring(match[0].length);
  const maMatch = params.match(/;\s*ma=(\d+)/);
  if (maMatch) {
    maxAge = parseInt(maMatch[1]!, 10);
  }

  const persistMatch = params.match(/;\s*persist=1/);
  if (persistMatch) {
    persist = true;
  }

  return { alpn, host, port, maxAge, persist, storedAt: now };
}
