/**
 * Tests for the connection pool.
 */

import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { ConnectionPool, type PoolEntry } from '../../src/http/pool.js';
import type { TLSSocket, TLSConnectionInfo } from '../../src/tls/types.js';
import { EventEmitter } from 'node:events';

/** Create a minimal mock TLS socket for testing. */
function mockSocket(): TLSSocket {
  const emitter = new EventEmitter();
  return Object.assign(emitter, {
    connectionInfo: {
      version: 'TLSv1.3',
      alpnProtocol: 'h2',
      cipher: 'TLS_AES_128_GCM_SHA256',
    } as TLSConnectionInfo,
    destroyTLS() {
      // no-op
    },
    write(_data: Buffer, cb?: (err?: Error) => void) { cb?.(); },
    end() {},
    destroy() {},
    on: emitter.on.bind(emitter),
    once: emitter.once.bind(emitter),
    removeListener: emitter.removeListener.bind(emitter),
  }) as unknown as TLSSocket;
}

describe('ConnectionPool', () => {
  it('stores and retrieves connections by origin', () => {
    const pool = new ConnectionPool({ maxConnectionsPerOrigin: 2, maxTotalConnections: 10, idleTimeout: 60000, maxAge: 300000 });
    const sock = mockSocket();
    const entry = pool.put('https://example.com:443', sock, 'h1');
    // H1 connections start busy on put(); release before get()
    pool.release(entry);

    const retrieved = pool.get('https://example.com:443');
    assert.ok(retrieved, 'should retrieve the connection');
    assert.equal(retrieved.origin, 'https://example.com:443');
    pool.close();
  });

  it('returns undefined for unknown origin', () => {
    const pool = new ConnectionPool();
    const result = pool.get('https://unknown.com:443');
    assert.equal(result, undefined);
    pool.close();
  });

  it('marks H1 connections as busy on get', () => {
    const pool = new ConnectionPool();
    const sock = mockSocket();
    const putEntry = pool.put('https://example.com:443', sock, 'h1');
    pool.release(putEntry); // make idle so get() finds it

    const entry = pool.get('https://example.com:443');
    assert.ok(entry);
    assert.equal(entry.busy, true);

    // Second get should return undefined (busy)
    const second = pool.get('https://example.com:443');
    assert.equal(second, undefined);
    pool.close();
  });

  it('releases H1 connections back to pool', () => {
    const pool = new ConnectionPool();
    const sock = mockSocket();
    const putEntry = pool.put('https://example.com:443', sock, 'h1');
    // put() marks H1 busy, release first to simulate idle
    pool.release(putEntry);

    const entry = pool.get('https://example.com:443')!;
    assert.ok(entry.busy);

    pool.release(entry);
    assert.equal(entry.busy, false);

    // Now should be gettable again
    const second = pool.get('https://example.com:443');
    assert.ok(second);
    pool.close();
  });

  it('removes connections correctly', () => {
    const pool = new ConnectionPool();
    const sock = mockSocket();
    const entry = pool.put('https://example.com:443', sock, 'h1');

    assert.equal(pool.size, 1);

    pool.remove(entry);

    assert.equal(pool.size, 0);
    assert.equal(pool.get('https://example.com:443'), undefined);
    pool.close();
  });

  it('respects maxConnectionsPerOrigin limit', () => {
    const pool = new ConnectionPool({ maxConnectionsPerOrigin: 2, maxTotalConnections: 100 });
    const s1 = mockSocket();
    const s2 = mockSocket();
    const s3 = mockSocket();

    pool.put('https://example.com:443', s1, 'h1');
    pool.put('https://example.com:443', s2, 'h1');
    pool.put('https://example.com:443', s3, 'h1'); // Should evict oldest

    assert.equal(pool.size, 2);
    pool.close();
  });

  it('close() clears all connections', () => {
    const pool = new ConnectionPool();
    pool.put('https://a.com:443', mockSocket(), 'h1');
    pool.put('https://b.com:443', mockSocket(), 'h1');

    assert.equal(pool.size, 2);
    pool.close();
    assert.equal(pool.size, 0);
  });
});
