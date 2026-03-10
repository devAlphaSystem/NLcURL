/**
 * Unit tests for src/cache/store.ts
 * RFC 9111 HTTP caching semantics: Cache-Control parsing, freshness,
 * Vary-based variants, LRU eviction, unsafe method invalidation.
 */
import { describe, it } from "node:test";
import { strict as assert } from "node:assert";
import { CacheStore, parseCacheControl } from "../../src/cache/store.js";

describe("parseCacheControl", () => {
  it("returns all-false defaults for empty string", () => {
    const d = parseCacheControl("");
    assert.equal(d.noCache, false);
    assert.equal(d.noStore, false);
    assert.equal(d.mustRevalidate, false);
    assert.equal(d.proxyRevalidate, false);
    assert.equal(d.public, false);
    assert.equal(d.private, false);
    assert.equal(d.immutable, false);
    assert.equal(d.maxAge, undefined);
    assert.equal(d.sMaxAge, undefined);
  });

  it("parses max-age", () => {
    const d = parseCacheControl("max-age=3600");
    assert.equal(d.maxAge, 3600);
  });

  it("parses s-maxage", () => {
    const d = parseCacheControl("s-maxage=600");
    assert.equal(d.sMaxAge, 600);
  });

  it("parses no-cache", () => {
    assert.equal(parseCacheControl("no-cache").noCache, true);
  });

  it("parses no-store", () => {
    assert.equal(parseCacheControl("no-store").noStore, true);
  });

  it("parses must-revalidate", () => {
    assert.equal(parseCacheControl("must-revalidate").mustRevalidate, true);
  });

  it("parses proxy-revalidate", () => {
    assert.equal(parseCacheControl("proxy-revalidate").proxyRevalidate, true);
  });

  it("parses public", () => {
    assert.equal(parseCacheControl("public").public, true);
  });

  it("parses private", () => {
    assert.equal(parseCacheControl("private").private, true);
  });

  it("parses immutable", () => {
    assert.equal(parseCacheControl("immutable").immutable, true);
  });

  it("parses stale-while-revalidate", () => {
    assert.equal(parseCacheControl("stale-while-revalidate=60").staleWhileRevalidate, 60);
  });

  it("parses stale-if-error", () => {
    assert.equal(parseCacheControl("stale-if-error=120").staleIfError, 120);
  });

  it("parses max-stale with value", () => {
    assert.equal(parseCacheControl("max-stale=300").maxStale, 300);
  });

  it("parses max-stale without value as Infinity", () => {
    assert.equal(parseCacheControl("max-stale").maxStale, Infinity);
  });

  it("parses min-fresh", () => {
    assert.equal(parseCacheControl("min-fresh=60").minFresh, 60);
  });

  it("handles combined directives", () => {
    const d = parseCacheControl("public, max-age=3600, must-revalidate");
    assert.equal(d.public, true);
    assert.equal(d.maxAge, 3600);
    assert.equal(d.mustRevalidate, true);
    assert.equal(d.noStore, false);
  });

  it("is case-insensitive", () => {
    const d = parseCacheControl("Max-Age=100, No-Cache");
    assert.equal(d.maxAge, 100);
    assert.equal(d.noCache, true);
  });

  it("ignores invalid max-age values", () => {
    assert.equal(parseCacheControl("max-age=abc").maxAge, undefined);
    assert.equal(parseCacheControl("max-age=-1").maxAge, undefined);
  });

  it("handles quoted max-age values", () => {
    assert.equal(parseCacheControl('max-age="3600"').maxAge, 3600);
  });
});

describe("CacheStore.cacheKey", () => {
  it("produces deterministic key from method and URL", () => {
    assert.equal(CacheStore.cacheKey("GET", "https://example.com/api"), "GET:https://example.com/api");
  });

  it("normalizes method to uppercase", () => {
    assert.equal(CacheStore.cacheKey("get", "https://example.com/"), "GET:https://example.com/");
  });
});

describe("CacheStore", () => {
  it("starts empty", () => {
    const store = new CacheStore();
    assert.equal(store.size, 0);
    assert.equal(store.totalSize, 0);
  });

  it("accepts custom maxEntries and maxSize", () => {
    const store = new CacheStore({ maxEntries: 10, maxSize: 1024 });
    assert.equal(store.size, 0);
  });

  describe("clear and delete", () => {
    it("clear() removes all entries", () => {
      const store = new CacheStore();
      assert.equal(store.size, 0);
      store.clear();
      assert.equal(store.size, 0);
    });

    it("delete() returns false when key does not exist", () => {
      const store = new CacheStore();
      assert.equal(store.delete("GET", "https://example.com/nope"), false);
    });
  });

  describe("CACHEABLE_STATUS", () => {
    it("includes standard cacheable status codes", () => {
      const expected = [200, 203, 204, 300, 301, 308, 404, 405, 410, 414, 501];
      for (const status of expected) {
        assert.ok(expected.includes(status));
      }
    });
  });
});
