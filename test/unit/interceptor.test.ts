/**
 * Unit tests for src/middleware/interceptor.ts
 * InterceptorChain: ordered request/response interceptor pipeline.
 */
import { describe, it } from "node:test";
import { strict as assert } from "node:assert";
import { InterceptorChain } from "../../src/middleware/interceptor.js";

describe("InterceptorChain", () => {
  describe("addRequestInterceptor", () => {
    it("returns this for chaining", () => {
      const chain = new InterceptorChain();
      const result = chain.addRequestInterceptor((r) => r);
      assert.equal(result, chain);
    });
  });

  describe("addResponseInterceptor", () => {
    it("returns this for chaining", () => {
      const chain = new InterceptorChain();
      const result = chain.addResponseInterceptor((r) => r);
      assert.equal(result, chain);
    });
  });

  describe("processRequest", () => {
    it("returns the original request when no interceptors are added", async () => {
      const chain = new InterceptorChain();
      const req = { url: "https://example.com", method: "GET" as const, headers: {} };
      const result = await chain.processRequest(req);
      assert.equal(result, req);
    });

    it("applies interceptors in order", async () => {
      const chain = new InterceptorChain();
      const log: number[] = [];
      chain.addRequestInterceptor((r) => {
        log.push(1);
        return { ...r, headers: { ...r.headers, "x-first": "1" } };
      });
      chain.addRequestInterceptor((r) => {
        log.push(2);
        return { ...r, headers: { ...r.headers, "x-second": "2" } };
      });
      const req = { url: "https://example.com", method: "GET" as const, headers: {} };
      const result = await chain.processRequest(req);
      assert.deepEqual(log, [1, 2]);
      assert.equal(result.headers!["x-first"], "1");
      assert.equal(result.headers!["x-second"], "2");
    });

    it("supports async interceptors", async () => {
      const chain = new InterceptorChain();
      chain.addRequestInterceptor(async (r) => {
        await new Promise((resolve) => setTimeout(resolve, 1));
        return { ...r, headers: { ...r.headers, "x-async": "true" } };
      });
      const req = { url: "https://example.com", method: "GET" as const, headers: {} };
      const result = await chain.processRequest(req);
      assert.equal(result.headers!["x-async"], "true");
    });
  });

  describe("processResponse", () => {
    it("returns the original response when no interceptors are added", async () => {
      const chain = new InterceptorChain();
      const resp = { status: 200 } as any;
      const result = await chain.processResponse(resp);
      assert.equal(result, resp);
    });

    it("applies response interceptors in order", async () => {
      const chain = new InterceptorChain();
      const log: string[] = [];
      chain.addResponseInterceptor((r) => {
        log.push("first");
        return r;
      });
      chain.addResponseInterceptor((r) => {
        log.push("second");
        return r;
      });
      const resp = { status: 200 } as any;
      await chain.processResponse(resp);
      assert.deepEqual(log, ["first", "second"]);
    });
  });
});
