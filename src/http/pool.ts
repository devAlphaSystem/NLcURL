/**
 * Connection pool.
 *
 * Manages TLS connections keyed by origin, supporting both HTTP/1.1
 * keep-alive and HTTP/2 multiplexing.  Handles connection reuse,
 * eviction, and idle timeout.
 */

import type { Duplex } from 'node:stream';
import type { TLSSocket, TLSConnectionInfo } from '../tls/types.js';
import { H2Client } from './h2/client.js';
import type { H2Profile } from '../fingerprints/types.js';

export interface PoolEntry {
  origin: string;
  socket: TLSSocket;
  protocol: 'h1' | 'h2';
  h2Client?: H2Client;
  createdAt: number;
  lastUsed: number;
  busy: boolean;
}

export interface PoolOptions {
  /** Maximum connections per origin. */
  maxConnectionsPerOrigin?: number;
  /** Maximum total connections across all origins. */
  maxTotalConnections?: number;
  /** Connection idle timeout in milliseconds. */
  idleTimeout?: number;
  /** Connection max age in milliseconds. */
  maxAge?: number;
}

const DEFAULT_POOL_OPTIONS: Required<PoolOptions> = {
  maxConnectionsPerOrigin: 6,
  maxTotalConnections: 64,
  idleTimeout: 60_000,
  maxAge: 300_000,
};

export class ConnectionPool {
  private readonly options: Required<PoolOptions>;
  private readonly connections = new Map<string, PoolEntry[]>();
  private totalConnections = 0;
  private cleanupTimer: ReturnType<typeof setInterval> | undefined;

  constructor(options: PoolOptions = {}) {
    this.options = { ...DEFAULT_POOL_OPTIONS, ...options };
    // Periodic cleanup
    this.cleanupTimer = setInterval(() => this.evictIdle(), 30_000);
    if (this.cleanupTimer.unref) {
      this.cleanupTimer.unref();
    }
  }

  /**
   * Get an existing idle connection for the given origin.
   *
   * Returns undefined if no reusable connection is available.
   */
  get(origin: string): PoolEntry | undefined {
    const entries = this.connections.get(origin);
    if (!entries) return undefined;

    const now = Date.now();

    for (const entry of entries) {
      // H2 connections can be multiplexed (always reusable)
      if (entry.protocol === 'h2' && !this.isExpired(entry, now)) {
        entry.lastUsed = now;
        return entry;
      }

      // H1 connections must be idle
      if (entry.protocol === 'h1' && !entry.busy && !this.isExpired(entry, now)) {
        entry.busy = true;
        entry.lastUsed = now;
        return entry;
      }
    }

    return undefined;
  }

  /**
   * Add a new connection to the pool.
   */
  put(
    origin: string,
    socket: TLSSocket,
    protocol: 'h1' | 'h2',
    h2Profile?: H2Profile,
    defaultHeaders?: Array<[string, string]>,
  ): PoolEntry {
    // Evict if at capacity
    if (this.totalConnections >= this.options.maxTotalConnections) {
      this.evictOldest();
      // If eviction failed (all busy), allow temporary over-capacity
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

    // Check per-origin limit
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
   * Release an H1 connection back to the pool.
   */
  release(entry: PoolEntry): void {
    entry.busy = false;
    entry.lastUsed = Date.now();
  }

  /**
   * Remove a specific connection from the pool.
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
   * Close all connections and stop the cleanup timer.
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

  get size(): number {
    return this.totalConnections;
  }

  // ---- Internal ----

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
