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
}

/** LRU cache for DNS records with configurable TTL bounds. */
export class DNSCache {
  private readonly entries = new Map<string, DNSCacheEntry>();
  private readonly maxEntries: number;
  private readonly minTTL: number;
  private readonly maxTTL: number;
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
   * Store DNS records in the cache.
   *
   * @param {string} name - Domain name.
   * @param {string} type - Record type string.
   * @param {DNSRecord[]} records - DNS records to cache.
   */
  set(name: string, type: string, records: DNSRecord[]): void {
    if (records.length === 0) return;

    const ttl = this.computeTTL(records);
    const key = this.cacheKey(name, type);

    if (this.entries.size >= this.maxEntries && !this.entries.has(key)) {
      this.evictLRU();
    }

    this.entries.set(key, {
      records,
      storedAt: Date.now(),
      ttl,
      lastAccessedAt: ++this.accessCounter,
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
