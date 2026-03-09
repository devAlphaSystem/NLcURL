import type { DNSRecord } from "./types.js";

/** Stored DNS cache entry with TTL and access tracking. */
export interface DNSCacheEntry {
  /** Cached DNS records. */
  records: DNSRecord[];
  /** Timestamp when the entry was stored. */
  storedAt: number;
  /** Effective time-to-live in seconds. */
  ttl: number;
  /** Monotonic counter value of the last access (for LRU eviction). */
  lastAccessedAt: number;
  /** Pinned IP addresses from the first resolution (for rebinding protection). */
  pinnedAddresses?: Set<string>;
}

const DEFAULT_MAX_ENTRIES = 500;
const DEFAULT_MIN_TTL = 30;
const DEFAULT_MAX_TTL = 86400;

/** Configuration options for {@link DNSCache}. */
export interface DNSCacheConfig {
  /** Maximum number of entries before LRU eviction. */
  maxEntries?: number;
  /** Minimum TTL in seconds applied to any cached record. */
  minTTL?: number;
  /** Maximum TTL in seconds applied to any cached record. */
  maxTTL?: number;
  /** Enable DNS rebinding protection by pinning IPs on first resolution. */
  pinning?: boolean;
}

/** LRU cache for DNS records with configurable TTL bounds and optional rebinding protection. */
export class DNSCache {
  private readonly entries = new Map<string, DNSCacheEntry>();
  private readonly maxEntries: number;
  private readonly minTTL: number;
  private readonly maxTTL: number;
  private readonly pinning: boolean;
  private accessCounter = 0;

  /**
   * Create a new DNS cache.
   *
   * @param {DNSCacheConfig} [config] - Cache configuration options.
   */
  constructor(config?: DNSCacheConfig) {
    this.maxEntries = config?.maxEntries ?? DEFAULT_MAX_ENTRIES;
    this.minTTL = config?.minTTL ?? DEFAULT_MIN_TTL;
    this.maxTTL = config?.maxTTL ?? DEFAULT_MAX_TTL;
    this.pinning = config?.pinning ?? true;
  }

  private cacheKey(name: string, type: string): string {
    return `${type}:${name.toLowerCase()}`;
  }

  /**
   * Retrieve cached records for a name and type.
   *
   * @param {string} name - Domain name to look up.
   * @param {string} type - Record type string.
   * @returns {DNSRecord[]|undefined} Cached records, or `undefined` if absent or expired.
   */
  get(name: string, type: string): DNSRecord[] | undefined {
    const key = this.cacheKey(name, type);
    const entry = this.entries.get(key);
    if (!entry) return undefined;

    const age = (Date.now() - entry.storedAt) / 1000;
    if (age >= entry.ttl) {
      this.entries.delete(key);
      return undefined;
    }

    entry.lastAccessedAt = ++this.accessCounter;
    return entry.records;
  }

  /**
   * Store DNS records in the cache, with optional IP pinning for rebinding protection.
   *
   * @param {string} name - Domain name.
   * @param {string} type - Record type string.
   * @param {DNSRecord[]} records - DNS records to cache.
   * @throws {Error} If pinning is enabled and new addresses don't match pinned set.
   */
  set(name: string, type: string, records: DNSRecord[]): void {
    if (records.length === 0) return;

    const ttl = this.computeTTL(records);
    const key = this.cacheKey(name, type);

    const existing = this.entries.get(key);
    let pinnedAddresses: Set<string> | undefined;

    if (this.pinning && (type === "A" || type === "AAAA")) {
      const newAddresses = new Set(records.map((r) => String(r.data)));

      if (existing?.pinnedAddresses) {
        for (const addr of newAddresses) {
          if (!existing.pinnedAddresses.has(addr)) {
            throw new Error(`DNS rebinding detected for ${name}: address ${addr} not in pinned set`);
          }
        }
        pinnedAddresses = existing.pinnedAddresses;
      } else {
        pinnedAddresses = newAddresses;
      }
    }

    if (this.entries.size >= this.maxEntries && !this.entries.has(key)) {
      this.evictLRU();
    }

    this.entries.set(key, {
      records,
      storedAt: Date.now(),
      ttl,
      lastAccessedAt: ++this.accessCounter,
      pinnedAddresses,
    });
  }

  private computeTTL(records: DNSRecord[]): number {
    let minRecordTTL = Infinity;
    for (const record of records) {
      if (record.ttl < minRecordTTL) {
        minRecordTTL = record.ttl;
      }
    }
    if (minRecordTTL === Infinity) minRecordTTL = this.minTTL;
    return Math.max(this.minTTL, Math.min(this.maxTTL, minRecordTTL));
  }

  private evictLRU(): void {
    let oldestKey: string | undefined;
    let oldestAccess = Infinity;
    for (const [key, entry] of this.entries) {
      if (entry.lastAccessedAt < oldestAccess) {
        oldestAccess = entry.lastAccessedAt;
        oldestKey = key;
      }
    }
    if (oldestKey) {
      this.entries.delete(oldestKey);
    }
  }

  /** Remove all entries from the cache. */
  clear(): void {
    this.entries.clear();
  }

  /** Number of entries currently in the cache. */
  get size(): number {
    return this.entries.size;
  }
}
