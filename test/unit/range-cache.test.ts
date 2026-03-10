/**
 * Unit tests for src/cache/range.ts
 * Content-Range / Range header parsing (RFC 7233) and RangeCache segment storage.
 */
import { describe, it } from "node:test";
import { strict as assert } from "node:assert";
import { parseContentRange, parseRangeHeader, RangeCache } from "../../src/cache/range.js";

describe("parseContentRange", () => {
  it("parses standard Content-Range header", () => {
    const r = parseContentRange("bytes 0-499/1234");
    assert.notEqual(r, null);
    assert.equal(r!.unit, "bytes");
    assert.equal(r!.start, 0);
    assert.equal(r!.end, 499);
    assert.equal(r!.total, 1234);
  });

  it("parses Content-Range with unknown total (*)", () => {
    const r = parseContentRange("bytes 100-199/*");
    assert.notEqual(r, null);
    assert.equal(r!.total, -1);
  });

  it("returns null for start > end", () => {
    assert.equal(parseContentRange("bytes 500-100/1000"), null);
  });

  it("returns null for end >= total", () => {
    assert.equal(parseContentRange("bytes 0-1000/1000"), null);
  });

  it("returns null for malformed header", () => {
    assert.equal(parseContentRange("invalid"), null);
    assert.equal(parseContentRange(""), null);
  });
});

describe("parseRangeHeader", () => {
  it("parses single range", () => {
    const ranges = parseRangeHeader("bytes=0-499");
    assert.notEqual(ranges, null);
    assert.equal(ranges!.length, 1);
    assert.deepEqual(ranges![0], [0, 499]);
  });

  it("parses multiple ranges", () => {
    const ranges = parseRangeHeader("bytes=0-499,1000-1499");
    assert.notEqual(ranges, null);
    assert.equal(ranges!.length, 2);
    assert.deepEqual(ranges![0], [0, 499]);
    assert.deepEqual(ranges![1], [1000, 1499]);
  });

  it("parses open-ended range (bytes=500-)", () => {
    const ranges = parseRangeHeader("bytes=500-");
    assert.notEqual(ranges, null);
    assert.deepEqual(ranges![0], [500, undefined]);
  });

  it("parses suffix range (bytes=-500)", () => {
    const ranges = parseRangeHeader("bytes=-500");
    assert.notEqual(ranges, null);
    assert.deepEqual(ranges![0], [-500, 500]);
  });

  it("returns null for non-bytes unit", () => {
    assert.equal(parseRangeHeader("items=0-10"), null);
  });

  it("returns null for malformed range", () => {
    assert.equal(parseRangeHeader("bytes="), null);
    assert.equal(parseRangeHeader(""), null);
  });

  it("returns null for range without dash", () => {
    assert.equal(parseRangeHeader("bytes=100"), null);
  });

  it("returns null for empty start and end", () => {
    assert.equal(parseRangeHeader("bytes=-"), null);
  });
});

describe("RangeCache", () => {
  it("starts empty", () => {
    const cache = new RangeCache();
    assert.equal(cache.lookup("https://example.com/file", 0, 100), null);
  });

  it("stores and retrieves a range segment", () => {
    const cache = new RangeCache();
    const data = Buffer.from("Hello, World!");
    const range = { unit: "bytes", start: 0, end: 12, total: 100 };
    cache.store("https://example.com/file", range, data);

    const result = cache.lookup("https://example.com/file", 0, 12);
    assert.notEqual(result, null);
    assert.deepEqual(result, data);
  });

  it("retrieves a sub-range of a cached segment", () => {
    const cache = new RangeCache();
    const data = Buffer.from("ABCDEFGHIJ");
    cache.store("https://example.com/file", { unit: "bytes", start: 0, end: 9, total: 100 }, data);

    const result = cache.lookup("https://example.com/file", 2, 5);
    assert.notEqual(result, null);
    assert.deepEqual(result, Buffer.from("CDEF"));
  });

  it("returns null for uncached ranges", () => {
    const cache = new RangeCache();
    const data = Buffer.from("AB");
    cache.store("https://example.com/file", { unit: "bytes", start: 0, end: 1, total: 100 }, data);

    assert.equal(cache.lookup("https://example.com/file", 50, 60), null);
  });

  it("invalidates segments when etag changes", () => {
    const cache = new RangeCache();
    cache.store("https://example.com/file", { unit: "bytes", start: 0, end: 9, total: 100 }, Buffer.alloc(10), { etag: '"v1"' });
    cache.store("https://example.com/file", { unit: "bytes", start: 10, end: 19, total: 100 }, Buffer.alloc(10), { etag: '"v2"' });
    assert.equal(cache.lookup("https://example.com/file", 0, 9), null);
    assert.notEqual(cache.lookup("https://example.com/file", 10, 19), null);
  });

  it("evicts oldest entry when maxEntries is exceeded", () => {
    const cache = new RangeCache({ maxEntries: 2 });
    cache.store("https://a.com/1", { unit: "bytes", start: 0, end: 0, total: 1 }, Buffer.from("A"));
    cache.store("https://b.com/2", { unit: "bytes", start: 0, end: 0, total: 1 }, Buffer.from("B"));
    cache.store("https://c.com/3", { unit: "bytes", start: 0, end: 0, total: 1 }, Buffer.from("C"));
    assert.equal(cache.lookup("https://a.com/1", 0, 0), null);
    assert.notEqual(cache.lookup("https://c.com/3", 0, 0), null);
  });

  it("isComplete returns true when all bytes are cached", () => {
    const cache = new RangeCache();
    cache.store("https://example.com/file", { unit: "bytes", start: 0, end: 9, total: 10 }, Buffer.alloc(10));
    assert.equal(cache.isComplete("https://example.com/file"), true);
  });

  it("isComplete returns false for partial cache", () => {
    const cache = new RangeCache();
    cache.store("https://example.com/file", { unit: "bytes", start: 0, end: 4, total: 10 }, Buffer.alloc(5));
    assert.equal(cache.isComplete("https://example.com/file"), false);
  });

  it("isComplete returns false for unknown URL", () => {
    const cache = new RangeCache();
    assert.equal(cache.isComplete("https://example.com/nope"), false);
  });

  it("replaces overlapping segments", () => {
    const cache = new RangeCache();
    cache.store("https://example.com/f", { unit: "bytes", start: 0, end: 9, total: 20 }, Buffer.alloc(10, 0x41));
    cache.store("https://example.com/f", { unit: "bytes", start: 5, end: 14, total: 20 }, Buffer.alloc(10, 0x42));
    assert.equal(cache.lookup("https://example.com/f", 0, 4), null);
    assert.notEqual(cache.lookup("https://example.com/f", 5, 14), null);
  });
});
