import type { Duplex } from "node:stream";
import type { TLSSocket } from "../tls/types.js";
import { H2Client } from "./h2/client.js";
import type { H2Profile } from "../fingerprints/types.js";

/** A pooled connection entry. */
export interface PoolEntry {
  /** Origin key (scheme + host + port). */
  origin: string;
  /** Underlying TLS socket. */
  socket: TLSSocket;
  /** Negotiated HTTP protocol version. */
  protocol: "h1" | "h2";
  /** HTTP/2 multiplexing client, if this is an h2 connection. */
  h2Client?: H2Client;
  /** Timestamp when the connection was created. */
  createdAt: number;
  /** Timestamp when the connection was last used. */
  lastUsed: number;
  /** Whether the connection is currently in use. */
  busy: boolean;
}

/** Connection pool configuration. */
export interface PoolOptions {
  /** Maximum connections per origin. */
  maxConnectionsPerOrigin?: number;
  /** Maximum total connections across all origins. */
  maxTotalConnections?: number;
  /** Idle timeout in milliseconds before connections are closed. */
  idleTimeout?: number;
  /** Maximum connection age in milliseconds. */
  maxAge?: number;
}

const DEFAULT_POOL_OPTIONS: Required<PoolOptions> = {
  maxConnectionsPerOrigin: 6,
  maxTotalConnections: 64,
  idleTimeout: 60_000,
  maxAge: 300_000,
};

/** HTTP connection pool with idle eviction and per-origin limits. */
export class ConnectionPool {
  private readonly options: Required<PoolOptions>;
  private readonly connections = new Map<string, PoolEntry[]>();
  private totalConnections = 0;
  private cleanupTimer: ReturnType<typeof setInterval> | undefined;

  /**
   * Create a new connection pool.
   *
   * @param {PoolOptions} [options] - Pool configuration.
   */
  constructor(options: PoolOptions = {}) {
    this.options = { ...DEFAULT_POOL_OPTIONS, ...options };
    this.cleanupTimer = setInterval(() => {
      this.evictIdle();
    }, 30_000);
    if (this.cleanupTimer.unref) {
      this.cleanupTimer.unref();
    }
  }

  /**
   * Get an available connection for the given origin.
   *
   * @param {string} origin - Origin to look up.
   * @returns {PoolEntry|undefined} A pool entry, or `undefined` if none is available.
   */
  get(origin: string): PoolEntry | undefined {
    const entries = this.connections.get(origin);
    if (!entries) return undefined;

    const now = Date.now();

    for (const entry of entries) {
      if (entry.protocol === "h2" && !this.isExpired(entry, now)) {
        if (entry.h2Client?.isClosed) {
          continue;
        }
        entry.lastUsed = now;
        return entry;
      }

      if (entry.protocol === "h1" && !entry.busy && !this.isExpired(entry, now)) {
        entry.busy = true;
        entry.lastUsed = now;
        return entry;
      }
    }

    return undefined;
  }

  /**
   * Add a new connection to the pool.
   *
   * @param {string} origin - Origin key.
   * @param {TLSSocket} socket - TLS socket.
   * @param {"h1"|"h2"} protocol - Negotiated protocol.
   * @param {H2Profile} [h2Profile] - Optional HTTP/2 profile for h2 connections.
   * @param {Array<[string, string]>} [defaultHeaders] - Default headers for h2 connections.
   * @returns {PoolEntry} The created pool entry.
   */
  put(origin: string, socket: TLSSocket, protocol: "h1" | "h2", h2Profile?: H2Profile, defaultHeaders?: Array<[string, string]>): PoolEntry {
    if (this.totalConnections >= this.options.maxTotalConnections) {
      this.evictOldest();
    }

    const entry: PoolEntry = {
      origin,
      socket,
      protocol,
      createdAt: Date.now(),
      lastUsed: Date.now(),
      busy: protocol === "h1",
    };

    if (protocol === "h2") {
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
   * Mark a connection as idle and available for reuse.
   *
   * @param {PoolEntry} entry - Pool entry to release.
   */
  release(entry: PoolEntry): void {
    entry.busy = false;
    entry.lastUsed = Date.now();
  }

  /**
   * Remove a connection from the pool and destroy its socket.
   *
   * @param {PoolEntry} entry - Pool entry to remove.
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

  /** Close all pooled connections and stop the cleanup timer. */
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

  /** Total number of connections across all origins. */
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
