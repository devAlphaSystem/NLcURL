/** Parsed Alt-Svc header entry. */
export interface AltSvcEntry {
  /** ALPN protocol identifier (e.g. "h2"). */
  alpn: string;
  /** Alternative authority hostname. */
  host: string;
  /** Alternative authority port. */
  port: number;
  /** Maximum age of the entry in seconds. */
  maxAge: number;
  /** Whether the entry persists across network changes. */
  persist: boolean;
  /** Timestamp when the entry was stored. */
  storedAt: number;
}

/** Configuration for {@link AltSvcStore}. */
export interface AltSvcConfig {
  /** Maximum number of entries across all origins. */
  maxEntries?: number;
  /** Whether Alt-Svc processing is enabled. */
  enabled?: boolean;
}

const DEFAULT_MAX_AGE = 86400;
const DEFAULT_MAX_ENTRIES = 1000;

/** Store for Alt-Svc (Alternative Services) header entries. */
export class AltSvcStore {
  private readonly entries = new Map<string, AltSvcEntry[]>();
  private readonly maxEntries: number;
  private totalEntries = 0;

  /**
   * Create a new Alt-Svc store.
   *
   * @param {AltSvcConfig} [config] - Store configuration.
   */
  constructor(config?: AltSvcConfig) {
    this.maxEntries = config?.maxEntries ?? DEFAULT_MAX_ENTRIES;
  }

  /**
   * Parse an Alt-Svc response header and store the entries.
   *
   * @param {string} origin - Request origin (scheme + host + port).
   * @param {string} headerValue - Raw Alt-Svc header value.
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
   * Look up the best alternative service for an origin.
   *
   * @param {string} origin - Request origin to look up.
   * @returns {AltSvcEntry|undefined} Best matching entry, or `undefined` if none.
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

    return valid[0];
  }

  /**
   * Remove all Alt-Svc entries for an origin.
   *
   * @param {string} origin - Origin to clear.
   */
  clear(origin: string): void {
    const entries = this.entries.get(origin);
    if (entries) {
      this.totalEntries -= entries.length;
      this.entries.delete(origin);
    }
  }

  /** Remove all Alt-Svc entries from the store. */
  clearAll(): void {
    this.entries.clear();
    this.totalEntries = 0;
  }

  /** Total number of entries across all origins. */
  get size(): number {
    return this.totalEntries;
  }

  /**
   * Serialize all Alt-Svc entries to a JSON string for disk persistence.
   *
   * @returns {string} JSON representation of all entries.
   */
  toJSON(): string {
    const data: Record<string, AltSvcEntry[]> = {};
    const now = Date.now();
    for (const [origin, entries] of this.entries) {
      const valid = entries.filter((e) => now - e.storedAt < e.maxAge * 1000);
      if (valid.length > 0) {
        data[origin] = valid;
      }
    }
    return JSON.stringify(data);
  }

  /**
   * Load Alt-Svc entries from a previously serialized JSON string.
   *
   * @param {string} json - JSON string from {@link toJSON}.
   */
  loadJSON(json: string): void {
    const data = JSON.parse(json) as Record<string, AltSvcEntry[]>;
    const now = Date.now();
    for (const [origin, entries] of Object.entries(data)) {
      if (!Array.isArray(entries)) continue;
      const valid = entries.filter((e) => typeof e.alpn === "string" && typeof e.storedAt === "number" && now - e.storedAt < (e.maxAge ?? 86400) * 1000);
      if (valid.length > 0) {
        this.entries.set(origin, valid);
        this.totalEntries += valid.length;
      }
    }
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
