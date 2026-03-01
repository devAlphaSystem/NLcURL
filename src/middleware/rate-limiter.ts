/**
 * Rate limiter middleware.
 *
 * Token-bucket rate limiter for controlling request frequency.
 */

export interface RateLimitConfig {
  /** Maximum requests per window. */
  maxRequests: number;
  /** Window duration in milliseconds. */
  windowMs: number;
}

export class RateLimiter {
  private readonly maxRequests: number;
  private readonly windowMs: number;
  private tokens: number;
  private lastRefill: number;
  private waitQueue: Array<() => void> = [];

  constructor(config: RateLimitConfig) {
    this.maxRequests = config.maxRequests;
    this.windowMs = config.windowMs;
    this.tokens = config.maxRequests;
    this.lastRefill = Date.now();
  }

  /**
   * Wait until a request token is available.
   */
  async acquire(): Promise<void> {
    this.refill();

    if (this.tokens > 0) {
      this.tokens--;
      return;
    }

    // Enqueue and wait for a token to become available
    await new Promise<void>((resolve) => {
      this.waitQueue.push(resolve);
      // Schedule a refill check after the current window expires
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

    // If there are still waiters, schedule another drain
    if (this.waitQueue.length > 0) {
      const elapsed = Date.now() - this.lastRefill;
      const waitMs = Math.max(1, this.windowMs - elapsed);
      setTimeout(() => this.drain(), waitMs);
    }
  }

  private refill(): void {
    const now = Date.now();
    const elapsed = now - this.lastRefill;
    if (elapsed >= this.windowMs) {
      this.tokens = this.maxRequests;
      this.lastRefill = now;
    }
  }
}
