/**
 * TLS session ticket cache for session resumption (RFC 5077 / RFC 8446 §4.6.1).
 * Stores session tickets keyed by origin (`host:port`) and evicts expired
 * entries automatically. Used by both {@link NodeTLSEngine} and
 * {@link StealthTLSEngine} to enable 0-RTT and abbreviated handshakes.
 */

/**
 * A cached TLS session ticket with its expiration metadata.
 *
 * @typedef  {Object} SessionTicketEntry
 * @property {Buffer} ticket    - Opaque session ticket bytes.
 * @property {number} expiresAt - Unix timestamp (ms) at which the ticket is no longer valid.
 * @property {string} [alpn]    - ALPN protocol negotiated during the original handshake.
 */
export interface SessionTicketEntry {
  ticket: Buffer;
  expiresAt: number;
  alpn?: string;
}

const DEFAULT_MAX_ENTRIES = 256;
const DEFAULT_LIFETIME_MS = 7200_000;

/**
 * Options for constructing a {@link TLSSessionCache}.
 *
 * @typedef  {Object} SessionCacheOptions
 * @property {number} [maxEntries=256]      - Maximum number of tickets to store.
 * @property {number} [defaultLifetimeMs=7200000] - Default ticket lifetime in ms when server doesn't specify.
 */
export interface SessionCacheOptions {
  maxEntries?: number;
  defaultLifetimeMs?: number;
}

/**
 * In-memory LRU cache for TLS session tickets. Thread-safe for single-threaded
 * Node.js usage. Keys are `host:port` origin strings. Only valid (non-expired)
 * tickets are returned on lookup.
 */
export class TLSSessionCache {
  private readonly maxEntries: number;
  private readonly defaultLifetimeMs: number;
  private readonly entries = new Map<string, SessionTicketEntry>();

  constructor(options: SessionCacheOptions = {}) {
    this.maxEntries = options.maxEntries ?? DEFAULT_MAX_ENTRIES;
    this.defaultLifetimeMs = options.defaultLifetimeMs ?? DEFAULT_LIFETIME_MS;
  }

  /**
   * Stores a session ticket for the given origin.
   *
   * @param {string} origin   - Origin key in `host:port` form.
   * @param {Buffer} ticket   - Opaque session ticket bytes.
   * @param {number} [lifetimeMs] - Ticket lifetime in ms; uses default if omitted.
   * @param {string} [alpn]   - ALPN protocol from the original handshake.
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
   * Retrieves a valid, non-expired session ticket for the given origin.
   * Returns `undefined` if no ticket exists or the ticket has expired.
   *
   * @param {string} origin - Origin key in `host:port` form.
   * @returns {SessionTicketEntry | undefined}
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
   * Removes a specific ticket from the cache.
   *
   * @param {string} origin - Origin key.
   * @returns {boolean} Whether an entry was removed.
   */
  delete(origin: string): boolean {
    return this.entries.delete(origin);
  }

  /** Removes all entries from the cache. */
  clear(): void {
    this.entries.clear();
  }

  /** Returns the number of entries currently cached. */
  get size(): number {
    return this.entries.size;
  }
}
