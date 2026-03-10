/**
 * Unit tests for src/middleware/rate-limiter.ts
 * Token-bucket rate limiter.
 */
import { describe, it } from "node:test";
import { strict as assert } from "node:assert";
import { RateLimiter } from "../../src/middleware/rate-limiter.js";

describe("RateLimiter", () => {
  it("allows immediate acquire up to maxRequests", async () => {
    const limiter = new RateLimiter({ maxRequests: 3, windowMs: 10000 });
    await limiter.acquire();
    await limiter.acquire();
    await limiter.acquire();
  });

  it("starts with full tokens", async () => {
    const limiter = new RateLimiter({ maxRequests: 5, windowMs: 60000 });
    for (let i = 0; i < 5; i++) {
      await limiter.acquire();
    }
  });

  it("queues when tokens are exhausted and resolves after refill", async () => {
    const limiter = new RateLimiter({ maxRequests: 1, windowMs: 50 });
    await limiter.acquire();

    const start = Date.now();
    await limiter.acquire();
    const elapsed = Date.now() - start;
    assert.ok(elapsed >= 30, `Expected delay >= 30ms, got ${elapsed}ms`);
  });

  it("refills tokens after window expires", async () => {
    const limiter = new RateLimiter({ maxRequests: 2, windowMs: 50 });
    await limiter.acquire();
    await limiter.acquire();

    await new Promise((r) => setTimeout(r, 60));

    const start = Date.now();
    await limiter.acquire();
    const elapsed = Date.now() - start;
    assert.ok(elapsed < 40, `Expected near-immediate acquire, got ${elapsed}ms`);
  });
});
