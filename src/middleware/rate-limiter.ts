import { validateRateLimitConfig } from "../core/validation.js";

/** Configuration for the token-bucket rate limiter. */
export interface RateLimitConfig {
  /** Maximum number of requests allowed per window. */
  maxRequests: number;
  /** Window duration in milliseconds. */
  windowMs: number;
}

/** Token-bucket rate limiter for outgoing requests. */
export class RateLimiter {
  private readonly maxRequests: number;
  private readonly windowMs: number;
  private tokens: number;
  private lastRefill: number;
  private waitQueue: Array<() => void> = [];
  private drainTimer: ReturnType<typeof setTimeout> | null = null;

  /**
   * Create a new rate limiter.
   *
   * @param {RateLimitConfig} config - Rate limit configuration.
   */
  constructor(config: RateLimitConfig) {
    validateRateLimitConfig(config as unknown as Record<string, unknown>);
    this.maxRequests = config.maxRequests;
    this.windowMs = config.windowMs;
    this.tokens = config.maxRequests;
    this.lastRefill = Date.now();
  }

  /**
   * Acquire a token, waiting if the rate limit has been reached.
   *
   * @returns {Promise<void>} Promise that resolves when a token is available.
   */
  async acquire(): Promise<void> {
    this.refill();

    if (this.tokens > 0) {
      this.tokens--;
      return;
    }

    await new Promise<void>((resolve) => {
      this.waitQueue.push(resolve);
      this.scheduleDrain();
    });
  }

  private scheduleDrain(): void {
    if (this.drainTimer) return;
    const elapsed = Date.now() - this.lastRefill;
    const waitMs = Math.max(1, this.windowMs - elapsed);
    this.drainTimer = setTimeout(() => {
      this.drainTimer = null;
      this.drain();
    }, waitMs);
  }

  private drain(): void {
    this.refill();
    while (this.tokens > 0 && this.waitQueue.length > 0) {
      this.tokens--;
      const next = this.waitQueue.shift()!;
      next();
    }

    if (this.waitQueue.length > 0) {
      this.scheduleDrain();
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
