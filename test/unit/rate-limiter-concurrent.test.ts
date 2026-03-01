/**
 * Tests for RateLimiter concurrency safety and queue behavior.
 */

import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { RateLimiter } from '../../src/middleware/rate-limiter.js';

describe('RateLimiter concurrency', () => {
  it('never allows more than maxRequests in a window', async () => {
    const limiter = new RateLimiter({ maxRequests: 2, windowMs: 200 });

    // Launch 5 concurrent acquire calls
    let completed = 0;
    const timestamps: number[] = [];
    const start = Date.now();

    const promises = Array.from({ length: 5 }, () =>
      limiter.acquire().then(() => {
        completed++;
        timestamps.push(Date.now() - start);
      }),
    );

    await Promise.all(promises);

    assert.equal(completed, 5, 'all 5 should complete');
    // First 2 should be near-instant (< 50ms)
    assert.ok(timestamps[0]! < 50, `First should be fast, was ${timestamps[0]}ms`);
    assert.ok(timestamps[1]! < 50, `Second should be fast, was ${timestamps[1]}ms`);
    // Remaining should be delayed by at least one window
    assert.ok(timestamps[2]! >= 100, `Third should wait, was ${timestamps[2]}ms`);
  });

  it('processes queued requests in FIFO order', async () => {
    const limiter = new RateLimiter({ maxRequests: 1, windowMs: 100 });

    const order: number[] = [];

    await limiter.acquire();
    order.push(1);

    // These will queue
    const p2 = limiter.acquire().then(() => order.push(2));
    const p3 = limiter.acquire().then(() => order.push(3));

    await Promise.all([p2, p3]);

    assert.equal(order[0], 1);
    assert.equal(order[1], 2);
    assert.equal(order[2], 3);
  });

  it('handles single-request limit without going negative', async () => {
    const limiter = new RateLimiter({ maxRequests: 1, windowMs: 100 });

    // Exhaust the token
    await limiter.acquire();

    // Two concurrent requests for one slot
    const start = Date.now();
    const p1 = limiter.acquire();
    const p2 = limiter.acquire();

    await Promise.all([p1, p2]);
    const elapsed = Date.now() - start;

    // Both should complete (at least one needs to wait for 2 windows)
    assert.ok(elapsed >= 100, `Should have waited, elapsed=${elapsed}ms`);
  });
});
