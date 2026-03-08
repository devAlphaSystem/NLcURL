/** Cached TLS session ticket with expiry and ALPN metadata. */
export interface SessionTicketEntry {
  /** Serialized session ticket bytes. */
  ticket: Buffer;
  /** Timestamp (ms since epoch) when this entry expires. */
  expiresAt: number;
  /** ALPN protocol negotiated during the original handshake. */
  alpn?: string;
}

const DEFAULT_MAX_ENTRIES = 256;
const DEFAULT_LIFETIME_MS = 7200_000;

/** Configuration for the TLS session ticket cache. */
export interface SessionCacheOptions {
  /** Maximum number of cached entries. */
  maxEntries?: number;
  /** Default ticket lifetime in milliseconds. */
  defaultLifetimeMs?: number;
}

/** LRU cache for TLS session tickets enabling session resumption. */
export class TLSSessionCache {
  private readonly maxEntries: number;
  private readonly defaultLifetimeMs: number;
  private readonly entries = new Map<string, SessionTicketEntry>();

  /**
   * Create a new session cache.
   *
   * @param {SessionCacheOptions} [options] - Cache size and lifetime configuration.
   */
  constructor(options: SessionCacheOptions = {}) {
    this.maxEntries = options.maxEntries ?? DEFAULT_MAX_ENTRIES;
    this.defaultLifetimeMs = options.defaultLifetimeMs ?? DEFAULT_LIFETIME_MS;
  }

  /**
   * Store a session ticket for the given origin.
   *
   * @param {string} origin - Origin key (e.g. `"example.com:443"`).
   * @param {Buffer} ticket - Serialized session ticket.
   * @param {number} [lifetimeMs] - Optional custom lifetime in milliseconds.
   * @param {string} [alpn] - Negotiated ALPN protocol.
   */
  set(origin: string, ticket: Buffer, lifetimeMs?: number, alpn?: string): void {
    if (this.entries.size >= this.maxEntries) {
      const oldest = this.entries.keys().next().value;
      if (oldest !== undefined) this.entries.delete(oldest);
    }

    this.entries.delete(origin);
    this.entries.set(origin, {
      ticket,
      expiresAt: Date.now() + (lifetimeMs ?? this.defaultLifetimeMs),
      alpn,
    });
  }

  /**
   * Retrieve a cached session ticket.
   *
   * Expired entries are evicted automatically.
   *
   * @param {string} origin - Origin key.
   * @returns {SessionTicketEntry|undefined} Cached entry, or `undefined` if not found or expired.
   */
  get(origin: string): SessionTicketEntry | undefined {
    const entry = this.entries.get(origin);
    if (!entry) return undefined;

    if (Date.now() >= entry.expiresAt) {
      this.entries.delete(origin);
      return undefined;
    }

    this.entries.delete(origin);
    this.entries.set(origin, entry);
    return entry;
  }

  /**
   * Remove a cached entry by origin.
   *
   * @param {string} origin - Origin key.
   * @returns {boolean} `true` if an entry was removed.
   */
  delete(origin: string): boolean {
    return this.entries.delete(origin);
  }

  /** Remove all cached session tickets. */
  clear(): void {
    this.entries.clear();
  }

  /** Number of entries currently in the cache. */
  get size(): number {
    return this.entries.size;
  }
}
