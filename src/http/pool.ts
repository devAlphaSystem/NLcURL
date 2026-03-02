
import type { Duplex } from 'node:stream';
import type { TLSSocket, TLSConnectionInfo } from '../tls/types.js';
import { H2Client } from './h2/client.js';
import type { H2Profile } from '../fingerprints/types.js';

/**
 * Represents a single pooled connection entry, holding the TLS socket,
 * protocol version, and lifecycle timestamps.
 *
 * @typedef  {Object}       PoolEntry
 * @property {string}       origin    - Origin key in `protocol://hostname:port` form.
 * @property {TLSSocket}    socket    - The underlying TLS (or TCP) socket.
 * @property {'h1'|'h2'}   protocol  - Negotiated HTTP protocol version.
 * @property {H2Client}     [h2Client] - HTTP/2 client instance when `protocol === 'h2'`.
 * @property {number}       createdAt - Unix timestamp (ms) when the connection was established.
 * @property {number}       lastUsed  - Unix timestamp (ms) when the connection was last checked out.
 * @property {boolean}      busy      - `true` while an HTTP/1.1 request is in flight.
 */
export interface PoolEntry {
  origin: string;
  socket: TLSSocket;
  protocol: 'h1' | 'h2';
  h2Client?: H2Client;
  createdAt: number;
  lastUsed: number;
  busy: boolean;
}

/**
 * Configuration options for the {@link ConnectionPool}.
 *
 * @typedef  {Object}  PoolOptions
 * @property {number}  [maxConnectionsPerOrigin=6]  - Maximum simultaneous connections to a single origin.
 * @property {number}  [maxTotalConnections=64]     - Maximum total connections across all origins.
 * @property {number}  [idleTimeout=60000]          - Milliseconds of inactivity before a connection is evicted.
 * @property {number}  [maxAge=300000]              - Maximum lifetime of a connection in milliseconds.
 */
export interface PoolOptions {
  maxConnectionsPerOrigin?: number;
  maxTotalConnections?: number;
  idleTimeout?: number;
  maxAge?: number;
}

const DEFAULT_POOL_OPTIONS: Required<PoolOptions> = {
  maxConnectionsPerOrigin: 6,
  maxTotalConnections: 64,
  idleTimeout: 60_000,
  maxAge: 300_000,
};

/**
 * Maintains a pool of reusable TLS connections, keyed by origin, supporting
 * both HTTP/1.1 (exclusive per-request access) and HTTP/2 (multiplexed)
 * connections. Idle and expired connections are evicted automatically on a
 * 30-second timer.
 */
export class ConnectionPool {
  private readonly options: Required<PoolOptions>;
  private readonly connections = new Map<string, PoolEntry[]>();
  private totalConnections = 0;
  private cleanupTimer: ReturnType<typeof setInterval> | undefined;

  /**
   * Creates a new ConnectionPool.
   *
   * @param {PoolOptions} [options={}] - Pool configuration; unset fields use their defaults.
   */
  constructor(options: PoolOptions = {}) {
    this.options = { ...DEFAULT_POOL_OPTIONS, ...options };
    this.cleanupTimer = setInterval(() => this.evictIdle(), 30_000);
    if (this.cleanupTimer.unref) {
      this.cleanupTimer.unref();
    }
  }

  /**
   * Checks out a usable connection for the given origin. For HTTP/2 returns
   * any live connection (multiplexing); for HTTP/1.1 returns a non-busy,
   * non-expired connection and marks it busy.
   *
   * @param {string} origin - Origin key in `protocol://hostname:port` form.
   * @returns {PoolEntry|undefined} A ready connection entry, or `undefined` if none is available.
   */
  get(origin: string): PoolEntry | undefined {
    const entries = this.connections.get(origin);
    if (!entries) return undefined;

    const now = Date.now();

    for (const entry of entries) {
      if (entry.protocol === 'h2' && !this.isExpired(entry, now)) {
        if (entry.h2Client?.isClosed) {
          continue;
        }
        entry.lastUsed = now;
        return entry;
      }

      if (entry.protocol === 'h1' && !entry.busy && !this.isExpired(entry, now)) {
        entry.busy = true;
        entry.lastUsed = now;
        return entry;
      }
    }

    return undefined;
  }

  /**
   * Registers a new connection in the pool. If adding the entry would exceed
   * the per-origin limit, the oldest entry for that origin is evicted. If the
   * total connection limit has been reached, the globally least-recently-used
   * idle connection is evicted first.
   *
   * @param {string}               origin         - Origin key.
   * @param {TLSSocket}            socket         - Connected socket to pool.
   * @param {'h1'|'h2'}           protocol       - Negotiated HTTP protocol.
   * @param {H2Profile}            [h2Profile]    - H2 profile used to configure the H2Client.
   * @param {Array<[string,string]>} [defaultHeaders] - Default headers applied to every H2 request.
   * @returns {PoolEntry} The newly created pool entry.
   */
  put(
    origin: string,
    socket: TLSSocket,
    protocol: 'h1' | 'h2',
    h2Profile?: H2Profile,
    defaultHeaders?: Array<[string, string]>,
  ): PoolEntry {
    if (this.totalConnections >= this.options.maxTotalConnections) {
      this.evictOldest();
    }

    const entry: PoolEntry = {
      origin,
      socket,
      protocol,
      createdAt: Date.now(),
      lastUsed: Date.now(),
      busy: protocol === 'h1',
    };

    if (protocol === 'h2') {
      entry.h2Client = new H2Client(socket as unknown as Duplex, h2Profile, defaultHeaders);
    }

    let entries = this.connections.get(origin);
    if (!entries) {
      entries = [];
      this.connections.set(origin, entries);
    }

    while (entries.length >= this.options.maxConnectionsPerOrigin) {
      const evicted = entries.shift();
      if (evicted) {
        evicted.socket.destroyTLS();
        this.totalConnections--;
      }
    }

    entries.push(entry);
    this.totalConnections++;

    return entry;
  }

  /**
   * Marks an HTTP/1.1 pool entry as available for reuse once a request has
   * completed. Updates the `lastUsed` timestamp.
   *
   * @param {PoolEntry} entry - The connection entry to release.
   */
  release(entry: PoolEntry): void {
    entry.busy = false;
    entry.lastUsed = Date.now();
  }

  /**
   * Removes a connection entry from the pool and destroys its socket.
   * Typically called when a connection error has occurred or the server
   * sent a `Connection: close` header.
   *
   * @param {PoolEntry} entry - The connection entry to remove and destroy.
   */
  remove(entry: PoolEntry): void {
    const entries = this.connections.get(entry.origin);
    if (entries) {
      const idx = entries.indexOf(entry);
      if (idx >= 0) {
        entries.splice(idx, 1);
        this.totalConnections--;
      }
      if (entries.length === 0) {
        this.connections.delete(entry.origin);
      }
    }
    entry.socket.destroyTLS();
  }

  /**
   * Destroys all pooled connections and stops the idle-eviction timer.
   * The pool must not be used after this call.
   */
  close(): void {
    if (this.cleanupTimer) {
      clearInterval(this.cleanupTimer);
      this.cleanupTimer = undefined;
    }

    for (const [, entries] of this.connections) {
      for (const entry of entries) {
        if (entry.h2Client) entry.h2Client.destroy();
        entry.socket.destroyTLS();
      }
    }
    this.connections.clear();
    this.totalConnections = 0;
  }

  /**
   * Returns the total number of connections (both idle and busy) currently held
   * in the pool across all origins.
   *
   * @returns {number} Total pooled connection count.
   */
  get size(): number {
    return this.totalConnections;
  }

  private isExpired(entry: PoolEntry, now: number): boolean {
    if (now - entry.createdAt > this.options.maxAge) return true;
    if (now - entry.lastUsed > this.options.idleTimeout) return true;
    return false;
  }

  private evictIdle(): void {
    const now = Date.now();
    for (const [origin, entries] of this.connections) {
      for (let i = entries.length - 1; i >= 0; i--) {
        const entry = entries[i]!;
        if (this.isExpired(entry, now) && !entry.busy) {
          entries.splice(i, 1);
          this.totalConnections--;
          if (entry.h2Client) entry.h2Client.destroy();
          entry.socket.destroyTLS();
        }
      }
      if (entries.length === 0) {
        this.connections.delete(origin);
      }
    }
  }

  private evictOldest(): void {
    let oldest: { entry: PoolEntry; origin: string } | undefined;

    for (const [origin, entries] of this.connections) {
      for (const entry of entries) {
        if (!entry.busy) {
          if (!oldest || entry.lastUsed < oldest.entry.lastUsed) {
            oldest = { entry, origin };
          }
        }
      }
    }

    if (oldest) {
      this.remove(oldest.entry);
    }
  }
}
