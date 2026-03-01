/**
 * Unit tests for the rate limiter.
 */

import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { RateLimiter } from '../../src/middleware/rate-limiter.js';

describe('RateLimiter', () => {
  it('allows requests up to the limit', async () => {
    const limiter = new RateLimiter({ maxRequests: 3, windowMs: 1000 });

    // Should not block for 3 requests
    const start = Date.now();
    await limiter.acquire();
    await limiter.acquire();
    await limiter.acquire();
    const elapsed = Date.now() - start;

    assert.ok(elapsed < 100, `Should be fast, took ${elapsed}ms`);
  });

  it('blocks when limit is exceeded', async () => {
    const limiter = new RateLimiter({ maxRequests: 1, windowMs: 200 });

    await limiter.acquire(); // First should be instant

    const start = Date.now();
    await limiter.acquire(); // Second should wait ~200ms
    const elapsed = Date.now() - start;

    assert.ok(elapsed >= 100, `Should have waited, elapsed=${elapsed}ms`);
  });

  it('refills after window expires', async () => {
    const limiter = new RateLimiter({ maxRequests: 1, windowMs: 100 });

    await limiter.acquire();

    // Wait for window to expire
    await new Promise<void>((r) => setTimeout(r, 150));

    const start = Date.now();
    await limiter.acquire(); // Should be instant after refill
    const elapsed = Date.now() - start;

    assert.ok(elapsed < 50, `Should be instant after refill, took ${elapsed}ms`);
  });
});
