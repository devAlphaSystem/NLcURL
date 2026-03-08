import { describe, it, beforeEach } from "node:test";
import assert from "node:assert/strict";
import { CacheStore, parseCacheControl } from "../../src/cache/store.js";
import { NLcURLResponse } from "../../src/core/response.js";
import type { NLcURLRequest } from "../../src/core/request.js";

function makeResponse(
  overrides: Partial<{
    status: number;
    statusText: string;
    headers: Record<string, string>;
    rawBody: Buffer;
    url: string;
  }>,
): NLcURLResponse {
  return new NLcURLResponse({
    status: overrides.status ?? 200,
    statusText: overrides.statusText ?? "OK",
    headers: overrides.headers ?? {},
    rawBody: overrides.rawBody ?? Buffer.from("hello"),
    httpVersion: "HTTP/1.1",
    url: overrides.url ?? "https://example.com/data",
    redirectCount: 0,
    timings: { dns: 1, connect: 2, tls: 3, firstByte: 4, total: 10 },
    request: { url: overrides.url ?? "https://example.com/data", method: "GET", headers: {} },
  });
}

function makeRequest(overrides?: Partial<NLcURLRequest>): NLcURLRequest {
  return {
    url: "https://example.com/data",
    method: "GET",
    headers: {},
    ...overrides,
  };
}

describe("parseCacheControl", () => {
  it("parses max-age", () => {
    const d = parseCacheControl("max-age=3600");
    assert.equal(d.maxAge, 3600);
    assert.equal(d.noCache, false);
    assert.equal(d.noStore, false);
  });

  it("parses no-cache and no-store", () => {
    const d = parseCacheControl("no-cache, no-store");
    assert.equal(d.noCache, true);
    assert.equal(d.noStore, true);
  });

  it("parses public and private", () => {
    assert.equal(parseCacheControl("public").public, true);
    assert.equal(parseCacheControl("private").private, true);
  });

  it("parses must-revalidate", () => {
    assert.equal(parseCacheControl("must-revalidate").mustRevalidate, true);
  });

  it("parses s-maxage", () => {
    assert.equal(parseCacheControl("s-maxage=600").sMaxAge, 600);
  });

  it("parses immutable", () => {
    assert.equal(parseCacheControl("immutable").immutable, true);
  });

  it("parses stale-while-revalidate", () => {
    assert.equal(parseCacheControl("stale-while-revalidate=60").staleWhileRevalidate, 60);
  });

  it("parses stale-if-error", () => {
    assert.equal(parseCacheControl("stale-if-error=300").staleIfError, 300);
  });

  it("parses complex header with multiple directives", () => {
    const d = parseCacheControl("public, max-age=31536000, immutable");
    assert.equal(d.public, true);
    assert.equal(d.maxAge, 31536000);
    assert.equal(d.immutable, true);
  });

  it("returns defaults for empty string", () => {
    const d = parseCacheControl("");
    assert.equal(d.maxAge, undefined);
    assert.equal(d.noCache, false);
    assert.equal(d.noStore, false);
  });

  it("ignores invalid max-age values", () => {
    const d = parseCacheControl("max-age=abc");
    assert.equal(d.maxAge, undefined);
  });
});

describe("CacheStore", () => {
  let store: CacheStore;

  beforeEach(() => {
    store = new CacheStore({ maxEntries: 100, maxSize: 1024 * 1024 });
  });

  describe("store and lookup", () => {
    it("stores and retrieves a cacheable response", () => {
      const req = makeRequest();
      const res = makeResponse({ headers: { "cache-control": "max-age=3600" } });
      store.store(req, res);

      const result = store.lookup(req);
      assert.ok(result.entry);
      assert.equal(result.fresh, true);
      assert.equal(result.entry.status, 200);
    });

    it("does not cache POST requests", () => {
      const req = makeRequest({ method: "POST" });
      const res = makeResponse({ headers: { "cache-control": "max-age=3600" } });
      store.store(req, res);
      assert.equal(store.size, 0);
    });

    it("does not cache responses with no-store", () => {
      const req = makeRequest();
      const res = makeResponse({ headers: { "cache-control": "no-store" } });
      store.store(req, res);
      assert.equal(store.size, 0);
    });

    it("marks entries as stale after max-age expires", () => {
      const req = makeRequest();
      const res = makeResponse({ headers: { "cache-control": "max-age=0" } });
      store.store(req, res);

      const result = store.lookup(req);
      assert.ok(result.entry);
      assert.equal(result.fresh, false);
    });

    it("does not cache 206 partial responses", () => {
      const req = makeRequest();
      const res = makeResponse({ status: 206, headers: { "cache-control": "max-age=3600" } });
      store.store(req, res);
      assert.equal(store.size, 0);
    });

    it("does not cache when Vary: *", () => {
      const req = makeRequest();
      const res = makeResponse({ headers: { "cache-control": "max-age=3600", vary: "*" } });
      store.store(req, res);
      assert.equal(store.size, 0);
    });
  });

  describe("Vary matching", () => {
    it("matches based on Vary headers", () => {
      const req1 = makeRequest({ headers: { "accept-encoding": "gzip" } });
      const res = makeResponse({ headers: { "cache-control": "max-age=3600", vary: "Accept-Encoding" } });
      store.store(req1, res);

      const result1 = store.lookup(req1);
      assert.ok(result1.entry);
      assert.equal(result1.fresh, true);

      const req2 = makeRequest({ headers: { "accept-encoding": "br" } });
      const result2 = store.lookup(req2);
      assert.equal(result2.fresh, false);
    });
  });

  describe("evaluate", () => {
    it("serves cached response when fresh (default mode)", () => {
      const req = makeRequest();
      const res = makeResponse({ headers: { "cache-control": "max-age=3600", etag: '"abc"' } });
      store.store(req, res);

      const eval_ = store.evaluate(req);
      assert.ok(eval_.serveCached);
      assert.equal(eval_.serveCached.status, 200);
    });

    it("adds conditional headers for stale entries with ETag", () => {
      const req = makeRequest();
      const res = makeResponse({ headers: { "cache-control": "max-age=0", etag: '"abc"' } });
      store.store(req, res);

      const eval_ = store.evaluate(req);
      assert.ok(!eval_.serveCached);
      assert.ok(eval_.conditionalHeaders);
      assert.equal(eval_.conditionalHeaders["if-none-match"], '"abc"');
    });

    it("adds conditional headers for stale entries with Last-Modified", () => {
      const req = makeRequest();
      const res = makeResponse({
        headers: { "cache-control": "max-age=0", "last-modified": "Wed, 21 Oct 2015 07:28:00 GMT" },
      });
      store.store(req, res);

      const eval_ = store.evaluate(req);
      assert.ok(eval_.conditionalHeaders);
      assert.equal(eval_.conditionalHeaders["if-modified-since"], "Wed, 21 Oct 2015 07:28:00 GMT");
    });

    it("no-store mode skips cache entirely", () => {
      const req = makeRequest();
      const res = makeResponse({ headers: { "cache-control": "max-age=3600" } });
      store.store(req, res);

      const eval_ = store.evaluate(req, "no-store");
      assert.equal(eval_.serveCached, undefined);
      assert.equal(eval_.shouldStore, false);
    });

    it("force-cache mode serves cached regardless of freshness", () => {
      const req = makeRequest();
      const res = makeResponse({ headers: { "cache-control": "max-age=0" } });
      store.store(req, res);

      const eval_ = store.evaluate(req, "force-cache");
      assert.ok(eval_.serveCached);
    });

    it("only-if-cached returns entry on hit", () => {
      const req = makeRequest();
      const res = makeResponse({ headers: { "cache-control": "max-age=0" } });
      store.store(req, res);

      const eval_ = store.evaluate(req, "only-if-cached");
      assert.ok(eval_.serveCached);
    });

    it("only-if-cached returns no entry on miss", () => {
      const req = makeRequest({ url: "https://example.com/miss" });
      const eval_ = store.evaluate(req, "only-if-cached");
      assert.equal(eval_.serveCached, undefined);
      assert.equal(eval_.shouldStore, false);
    });

    it("no-cache mode always revalidates even when fresh", () => {
      const req = makeRequest();
      const res = makeResponse({ headers: { "cache-control": "max-age=3600", etag: '"v1"' } });
      store.store(req, res);

      const eval_ = store.evaluate(req, "no-cache");
      assert.equal(eval_.serveCached, undefined);
      assert.ok(eval_.conditionalHeaders);
      assert.equal(eval_.conditionalHeaders["if-none-match"], '"v1"');
    });
  });

  describe("mergeNotModified", () => {
    it("merges 304 with cached entry to produce a full response", () => {
      const req = makeRequest();
      const res = makeResponse({
        headers: { "cache-control": "max-age=3600", etag: '"v1"', "x-custom": "original" },
        rawBody: Buffer.from("cached body"),
      });
      store.store(req, res);

      const entry = store.lookup(req).entry!;
      const response304 = makeResponse({
        status: 304,
        statusText: "Not Modified",
        headers: { etag: '"v2"', "x-new": "header" },
        rawBody: Buffer.alloc(0),
      });

      const merged = store.mergeNotModified(entry, response304);
      assert.equal(merged.status, 200);
      assert.equal(merged.text(), "cached body");
      assert.equal(merged.headers["etag"], '"v2"');
      assert.equal(merged.headers["x-new"], "header");
      assert.equal(merged.headers["x-custom"], "original");
    });
  });

  describe("responseFromEntry", () => {
    it("constructs a response from a cache entry", () => {
      const req = makeRequest();
      const res = makeResponse({ headers: { "cache-control": "max-age=3600" }, rawBody: Buffer.from("test") });
      store.store(req, res);

      const entry = store.lookup(req).entry!;
      const response = store.responseFromEntry(entry, req);
      assert.equal(response.status, 200);
      assert.equal(response.text(), "test");
      assert.equal(response.timings.total, 0);
    });
  });

  describe("eviction", () => {
    it("evicts oldest entries when maxEntries is exceeded", () => {
      const smallStore = new CacheStore({ maxEntries: 2, maxSize: 1024 * 1024 });

      for (let i = 0; i < 3; i++) {
        const req = makeRequest({ url: `https://example.com/item${i}` });
        const res = makeResponse({ headers: { "cache-control": "max-age=3600" }, url: `https://example.com/item${i}` });
        smallStore.store(req, res);
      }

      assert.equal(smallStore.size, 2);
      const result0 = smallStore.lookup(makeRequest({ url: "https://example.com/item0" }));
      assert.equal(result0.entry, undefined);
    });

    it("evicts entries when maxSize is exceeded", () => {
      const tinyStore = new CacheStore({ maxEntries: 100, maxSize: 10 });
      const req = makeRequest();
      const res = makeResponse({ headers: { "cache-control": "max-age=3600" }, rawBody: Buffer.alloc(20) });
      tinyStore.store(req, res);
      assert.equal(tinyStore.size, 1);
    });
  });

  describe("delete and clear", () => {
    it("deletes a specific entry", () => {
      const req = makeRequest();
      const res = makeResponse({ headers: { "cache-control": "max-age=3600" } });
      store.store(req, res);
      assert.equal(store.size, 1);

      const deleted = store.delete("GET", "https://example.com/data");
      assert.equal(deleted, true);
      assert.equal(store.size, 0);
    });

    it("returns false when deleting non-existent entry", () => {
      assert.equal(store.delete("GET", "https://example.com/nope"), false);
    });

    it("clears all entries", () => {
      store.store(makeRequest(), makeResponse({ headers: { "cache-control": "max-age=3600" } }));
      store.store(makeRequest({ url: "https://example.com/other" }), makeResponse({ headers: { "cache-control": "max-age=3600" }, url: "https://example.com/other" }));
      assert.equal(store.size, 2);
      store.clear();
      assert.equal(store.size, 0);
      assert.equal(store.totalSize, 0);
    });
  });

  describe("cacheKey", () => {
    it("generates method:url keys", () => {
      assert.equal(CacheStore.cacheKey("GET", "https://example.com"), "GET:https://example.com");
      assert.equal(CacheStore.cacheKey("get", "https://example.com"), "GET:https://example.com");
    });
  });
});
