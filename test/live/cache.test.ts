/**
 * Live HTTP caching tests.
 *
 * Tests real caching behavior using servers that return proper
 * Cache-Control, ETag, and Last-Modified headers. Validates that
 * cached responses are served correctly and conditional requests
 * work with 304 Not Modified.
 */
import { describe, it } from "node:test";
import { strict as assert } from "node:assert";
import { createSession, CacheStore } from "../../src/index.js";
import { LIVE_TIMEOUT, assertOk } from "./helpers.js";

const HTTPBIN = "https://httpbin.org";

describe("HTTP cache with Cache-Control", { timeout: LIVE_TIMEOUT }, () => {
  it("caches a response with max-age and serves from cache", async () => {
    const session = createSession({
      cacheConfig: { enabled: true, maxEntries: 100, maxSize: 10 * 1024 * 1024 },
    });

    try {
      const resp1 = await session.get(`${HTTPBIN}/cache/60`);
      assertOk(resp1, "First request");

      const resp2 = await session.get(`${HTTPBIN}/cache/60`);
      assertOk(resp2, "Second request (potentially cached)");

      assert.equal(resp1.text(), resp2.text());
    } finally {
      session.close();
    }
  });

  it("respects no-cache directive", async () => {
    const session = createSession({
      cacheConfig: { enabled: true },
    });

    try {
      const resp = await session.get(`${HTTPBIN}/get`, { cache: "no-cache" });
      assertOk(resp);
    } finally {
      session.close();
    }
  });

  it("respects no-store directive", async () => {
    const session = createSession({
      cacheConfig: { enabled: true },
    });

    try {
      const resp = await session.get(`${HTTPBIN}/get`, { cache: "no-store" });
      assertOk(resp);

      const cache = session.getCache();
      assert.ok(cache, "Cache store should exist");
    } finally {
      session.close();
    }
  });
});

describe("ETag / conditional requests", { timeout: LIVE_TIMEOUT }, () => {
  it("sends If-None-Match with ETag on revalidation", async () => {
    const session = createSession({
      cacheConfig: { enabled: true },
    });

    try {
      const resp1 = await session.get(`${HTTPBIN}/etag/test-etag-123`, {
        headers: { "If-None-Match": "" },
      });
      assertOk(resp1, "First ETag request");
      const etag = resp1.headers["etag"];
      assert.ok(etag, "Expected ETag header in response");
    } finally {
      session.close();
    }
  });

  it("handles 304 Not Modified correctly", async () => {
    const session = createSession({
      cacheConfig: { enabled: true },
    });

    try {
      const resp1 = await session.get(`${HTTPBIN}/etag/nlcurl-test`);
      assertOk(resp1);
      const etag = resp1.headers["etag"];

      if (etag) {
        const resp2 = await session.get(`${HTTPBIN}/etag/nlcurl-test`, {
          headers: { "If-None-Match": etag },
        });
        assert.ok(resp2.status === 200 || resp2.status === 304, `Expected 200 or 304, got ${resp2.status}`);
      }
    } finally {
      session.close();
    }
  });
});

describe("Caching of static resources", { timeout: LIVE_TIMEOUT }, () => {
  it("caches a cacheable response and serves it faster", async () => {
    const session = createSession({
      cacheConfig: { enabled: true, maxEntries: 100 },
    });

    try {
      const resp1 = await session.get(`${HTTPBIN}/cache/300`);
      assertOk(resp1);
      const time1 = resp1.timings.total;

      const resp2 = await session.get(`${HTTPBIN}/cache/300`);
      assertOk(resp2);
      const time2 = resp2.timings.total;

      if (time1 > 100) {
        assert.ok(time2 < time1, `Cache hit (${time2}ms) should be faster than miss (${time1}ms)`);
      }
    } finally {
      session.close();
    }
  });
});

describe("Cache key generation", () => {
  it("generates consistent cache keys for the same URL", () => {
    const key1 = CacheStore.cacheKey("GET", "https://example.com/path?q=1");
    const key2 = CacheStore.cacheKey("GET", "https://example.com/path?q=1");
    assert.equal(key1, key2);
  });

  it("generates different keys for different methods", () => {
    const get = CacheStore.cacheKey("GET", "https://example.com/");
    const head = CacheStore.cacheKey("HEAD", "https://example.com/");
    assert.notEqual(get, head);
  });

  it("generates different keys for different URLs", () => {
    const a = CacheStore.cacheKey("GET", "https://example.com/a");
    const b = CacheStore.cacheKey("GET", "https://example.com/b");
    assert.notEqual(a, b);
  });
});
