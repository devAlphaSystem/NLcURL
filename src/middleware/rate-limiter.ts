import { validateRateLimitConfig } from "../core/validation.js";

/**
 * Configuration options for a token-bucket rate limiter.
 *
 * @typedef  {Object} RateLimitConfig
 * @property {number} maxRequests - Maximum number of requests allowed per `windowMs` interval.
 * @property {number} windowMs    - Duration of the rate-limiting window in milliseconds.
 */
export interface RateLimitConfig {
  maxRequests: number;
  windowMs: number;
}

/**
 * Token-bucket rate limiter. Callers must call {@link RateLimiter.acquire} and
 * await the returned promise before sending each request. Requests that would
 * exceed the configured rate are queued and granted once the window refills.
 */
export class RateLimiter {
  private readonly maxRequests: number;
  private readonly windowMs: number;
  private tokens: number;
  private lastRefill: number;
  private waitQueue: Array<() => void> = [];

  /**
   * Creates a new RateLimiter.
   *
   * @param {RateLimitConfig} config - Rate-limit parameters.
   */
  constructor(config: RateLimitConfig) {
    validateRateLimitConfig(config as unknown as Record<string, unknown>);
    this.maxRequests = config.maxRequests;
    this.windowMs = config.windowMs;
    this.tokens = config.maxRequests;
    this.lastRefill = Date.now();
  }

  /**
   * Acquires a rate-limit token. Resolves immediately when a token is
   * available, or waits until the current window refills.
   *
   * @returns {Promise<void>} Resolves once a token has been granted to the caller.
   */
  async acquire(): Promise<void> {
    this.refill();

    if (this.tokens > 0) {
      this.tokens--;
      return;
    }

    await new Promise<void>((resolve) => {
      this.waitQueue.push(resolve);
      const elapsed = Date.now() - this.lastRefill;
      const waitMs = Math.max(1, this.windowMs - elapsed);
      setTimeout(() => this.drain(), waitMs);
    });
  }

  private drain(): void {
    this.refill();
    while (this.tokens > 0 && this.waitQueue.length > 0) {
      this.tokens--;
      const next = this.waitQueue.shift()!;
      next();
    }

    if (this.waitQueue.length > 0) {
      const elapsed = Date.now() - this.lastRefill;
      const waitMs = Math.max(1, this.windowMs - elapsed);
      setTimeout(() => this.drain(), waitMs);
    }
  }

  private refill(): void {
    const now = Date.now();
    const elapsed = now - this.lastRefill;
    if (elapsed < 0) {
      this.lastRefill = now;
      return;
    }
    if (elapsed >= this.windowMs) {
      this.tokens = this.maxRequests;
      this.lastRefill = now;
    }
  }
}
