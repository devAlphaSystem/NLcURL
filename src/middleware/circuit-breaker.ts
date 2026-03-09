import { NLcURLError } from "../core/errors.js";

/** Circuit breaker states. */
export const enum CircuitState {
  CLOSED = 0,
  OPEN = 1,
  HALF_OPEN = 2,
}

/** Configuration for the circuit breaker. */
export interface CircuitBreakerConfig {
  /** Number of consecutive failures before opening the circuit. */
  failureThreshold: number;
  /** Time in ms the circuit stays open before allowing a probe request. */
  resetTimeoutMs: number;
  /** Number of successful probe requests to close the circuit (default: 1). */
  successThreshold?: number;
  /** Optional predicate to determine if a status code is a failure. */
  isFailure?: (statusCode: number) => boolean;
}

/** Per-origin circuit breaker for preventing cascading failures. */
export class CircuitBreaker {
  private readonly failureThreshold: number;
  private readonly resetTimeoutMs: number;
  private readonly successThreshold: number;
  private readonly isFailure: (statusCode: number) => boolean;
  private readonly circuits = new Map<string, CircuitEntry>();

  constructor(config: CircuitBreakerConfig) {
    this.failureThreshold = config.failureThreshold;
    this.resetTimeoutMs = config.resetTimeoutMs;
    this.successThreshold = config.successThreshold ?? 1;
    this.isFailure = config.isFailure ?? ((s) => s >= 500);
  }

  /**
   * Check if a request to the given origin should be allowed.
   * Throws if the circuit is open and not yet ready for a probe.
   */
  allowRequest(origin: string): void {
    const entry = this.circuits.get(origin);
    if (!entry) return;

    if (entry.state === CircuitState.OPEN) {
      if (Date.now() >= entry.openedAt + this.resetTimeoutMs) {
        entry.state = CircuitState.HALF_OPEN;
        entry.halfOpenSuccesses = 0;
      } else {
        throw new NLcURLError(`Circuit breaker open for ${origin} — failing fast`, "ERR_CIRCUIT_OPEN");
      }
    }
  }

  /** Record a successful request to the origin. */
  recordSuccess(origin: string): void {
    const entry = this.circuits.get(origin);
    if (!entry) return;

    if (entry.state === CircuitState.HALF_OPEN) {
      entry.halfOpenSuccesses++;
      if (entry.halfOpenSuccesses >= this.successThreshold) {
        entry.state = CircuitState.CLOSED;
        entry.consecutiveFailures = 0;
      }
    } else if (entry.state === CircuitState.CLOSED) {
      entry.consecutiveFailures = 0;
    }
  }

  /** Record a failed request or a failure status code. */
  recordFailure(origin: string): void {
    let entry = this.circuits.get(origin);
    if (!entry) {
      entry = { state: CircuitState.CLOSED, consecutiveFailures: 0, openedAt: 0, halfOpenSuccesses: 0 };
      this.circuits.set(origin, entry);
    }

    if (entry.state === CircuitState.HALF_OPEN) {
      entry.state = CircuitState.OPEN;
      entry.openedAt = Date.now();
      return;
    }

    entry.consecutiveFailures++;
    if (entry.consecutiveFailures >= this.failureThreshold) {
      entry.state = CircuitState.OPEN;
      entry.openedAt = Date.now();
    }
  }

  /** Record a response and automatically classify as success/failure. */
  recordResponse(origin: string, statusCode: number): void {
    if (this.isFailure(statusCode)) {
      this.recordFailure(origin);
    } else {
      this.recordSuccess(origin);
    }
  }

  /** Get the current state of the circuit for an origin. */
  getState(origin: string): CircuitState {
    return this.circuits.get(origin)?.state ?? CircuitState.CLOSED;
  }

  /** Reset a specific origin's circuit. */
  reset(origin: string): void {
    this.circuits.delete(origin);
  }

  /** Reset all circuits. */
  resetAll(): void {
    this.circuits.clear();
  }
}

interface CircuitEntry {
  state: CircuitState;
  consecutiveFailures: number;
  openedAt: number;
  halfOpenSuccesses: number;
}
