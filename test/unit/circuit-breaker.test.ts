/**
 * Unit tests for src/middleware/circuit-breaker.ts
 * Circuit breaker state machine: CLOSED → OPEN → HALF_OPEN → CLOSED.
 */
import { describe, it } from "node:test";
import { strict as assert } from "node:assert";
import { CircuitBreaker, CircuitState } from "../../src/middleware/circuit-breaker.js";
import { NLcURLError } from "../../src/core/errors.js";

describe("CircuitBreaker", () => {
  const config = {
    failureThreshold: 3,
    resetTimeoutMs: 1000,
    successThreshold: 1,
  };

  describe("initial state", () => {
    it("starts in CLOSED state for any origin", () => {
      const cb = new CircuitBreaker(config);
      assert.equal(cb.getState("https://api.example.com"), CircuitState.CLOSED);
    });

    it("allows requests in CLOSED state", () => {
      const cb = new CircuitBreaker(config);
      assert.doesNotThrow(() => cb.allowRequest("https://api.example.com"));
    });
  });

  describe("CLOSED → OPEN transition", () => {
    it("opens after consecutive failures reach threshold", () => {
      const cb = new CircuitBreaker(config);
      const origin = "https://api.example.com";
      cb.recordFailure(origin);
      cb.recordFailure(origin);
      assert.equal(cb.getState(origin), CircuitState.CLOSED);
      cb.recordFailure(origin);
      assert.equal(cb.getState(origin), CircuitState.OPEN);
    });

    it("rejects requests when circuit is OPEN", () => {
      const cb = new CircuitBreaker(config);
      const origin = "https://api.example.com";
      for (let i = 0; i < 3; i++) cb.recordFailure(origin);
      assert.throws(() => cb.allowRequest(origin), NLcURLError);
    });

    it("resets failure count on success", () => {
      const cb = new CircuitBreaker(config);
      const origin = "https://api.example.com";
      cb.recordFailure(origin);
      cb.recordFailure(origin);
      cb.recordSuccess(origin);
      cb.recordFailure(origin);
      assert.equal(cb.getState(origin), CircuitState.CLOSED);
    });
  });

  describe("OPEN → HALF_OPEN transition", () => {
    it("transitions to HALF_OPEN after resetTimeout", () => {
      const cb = new CircuitBreaker({ ...config, resetTimeoutMs: 0 });
      const origin = "https://api.example.com";
      for (let i = 0; i < 3; i++) cb.recordFailure(origin);
      assert.doesNotThrow(() => cb.allowRequest(origin));
      assert.equal(cb.getState(origin), CircuitState.HALF_OPEN);
    });
  });

  describe("HALF_OPEN → CLOSED transition", () => {
    it("closes after successThreshold successes in HALF_OPEN", () => {
      const cb = new CircuitBreaker({ ...config, resetTimeoutMs: 0, successThreshold: 2 });
      const origin = "https://api.example.com";
      for (let i = 0; i < 3; i++) cb.recordFailure(origin);
      cb.allowRequest(origin);
      cb.recordSuccess(origin);
      assert.equal(cb.getState(origin), CircuitState.HALF_OPEN);
      cb.recordSuccess(origin);
      assert.equal(cb.getState(origin), CircuitState.CLOSED);
    });
  });

  describe("HALF_OPEN → OPEN transition", () => {
    it("re-opens on failure during HALF_OPEN", () => {
      const cb = new CircuitBreaker({ ...config, resetTimeoutMs: 0 });
      const origin = "https://api.example.com";
      for (let i = 0; i < 3; i++) cb.recordFailure(origin);
      cb.allowRequest(origin);
      cb.recordFailure(origin);
      assert.equal(cb.getState(origin), CircuitState.OPEN);
    });
  });

  describe("recordResponse", () => {
    it("classifies status >= 500 as failure by default", () => {
      const cb = new CircuitBreaker(config);
      const origin = "https://api.example.com";
      cb.recordResponse(origin, 500);
      cb.recordResponse(origin, 503);
      cb.recordResponse(origin, 502);
      assert.equal(cb.getState(origin), CircuitState.OPEN);
    });

    it("classifies status < 500 as success by default", () => {
      const cb = new CircuitBreaker(config);
      const origin = "https://api.example.com";
      cb.recordResponse(origin, 200);
      cb.recordResponse(origin, 404);
      assert.equal(cb.getState(origin), CircuitState.CLOSED);
    });

    it("uses custom isFailure predicate", () => {
      const cb = new CircuitBreaker({
        ...config,
        isFailure: (s) => s === 429,
      });
      const origin = "https://api.example.com";
      cb.recordResponse(origin, 429);
      cb.recordResponse(origin, 429);
      cb.recordResponse(origin, 429);
      assert.equal(cb.getState(origin), CircuitState.OPEN);
    });
  });

  describe("per-origin isolation", () => {
    it("maintains separate circuits per origin", () => {
      const cb = new CircuitBreaker(config);
      for (let i = 0; i < 3; i++) cb.recordFailure("https://a.com");
      assert.equal(cb.getState("https://a.com"), CircuitState.OPEN);
      assert.equal(cb.getState("https://b.com"), CircuitState.CLOSED);
    });
  });

  describe("reset", () => {
    it("reset removes circuit for specific origin", () => {
      const cb = new CircuitBreaker(config);
      for (let i = 0; i < 3; i++) cb.recordFailure("https://a.com");
      cb.reset("https://a.com");
      assert.equal(cb.getState("https://a.com"), CircuitState.CLOSED);
    });

    it("resetAll removes all circuits", () => {
      const cb = new CircuitBreaker(config);
      for (let i = 0; i < 3; i++) cb.recordFailure("https://a.com");
      for (let i = 0; i < 3; i++) cb.recordFailure("https://b.com");
      cb.resetAll();
      assert.equal(cb.getState("https://a.com"), CircuitState.CLOSED);
      assert.equal(cb.getState("https://b.com"), CircuitState.CLOSED);
    });
  });
});
