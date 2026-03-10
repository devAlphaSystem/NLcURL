/**
 * Unit tests for src/dns/cache.ts
 * DNSCache: LRU eviction, TTL bounds (30–86400s), rebinding protection.
 */
import { describe, it } from "node:test";
import { strict as assert } from "node:assert";
import { DNSCache } from "../../src/dns/cache.js";
import type { DNSRecord } from "../../src/dns/types.js";

function makeRecord(ttl: number): DNSRecord {
  return { name: "example.com", type: 1, ttl, data: Buffer.from([93, 184, 216, 34]) };
}

describe("DNSCache", () => {
  it("starts empty", () => {
    const cache = new DNSCache();
    assert.equal(cache.size, 0);
  });

  it("stores and retrieves records", () => {
    const cache = new DNSCache();
    const records = [makeRecord(300)];
    cache.set("example.com", "A", records);
    assert.equal(cache.size, 1);
    const result = cache.get("example.com", "A");
    assert.notEqual(result, undefined);
    assert.equal(result!.length, 1);
  });

  it("returns undefined for non-existent entry", () => {
    const cache = new DNSCache();
    assert.equal(cache.get("nope.com", "A"), undefined);
  });

  it("is case-insensitive for lookup names", () => {
    const cache = new DNSCache();
    cache.set("Example.COM", "A", [makeRecord(300)]);
    assert.notEqual(cache.get("example.com", "A"), undefined);
  });

  it("does not store empty record arrays", () => {
    const cache = new DNSCache();
    cache.set("example.com", "A", []);
    assert.equal(cache.size, 0);
  });

  describe("TTL bounds", () => {
    it("enforces minimum TTL of 30 seconds (DEFAULT_MIN_TTL)", () => {
      const cache = new DNSCache({ minTTL: 30, maxTTL: 86400 });
      cache.set("example.com", "A", [makeRecord(1)]);
      assert.notEqual(cache.get("example.com", "A"), undefined);
    });

    it("enforces maximum TTL of 86400 seconds (DEFAULT_MAX_TTL)", () => {
      const cache = new DNSCache({ minTTL: 30, maxTTL: 86400 });
      cache.set("example.com", "A", [makeRecord(1000000)]);
      assert.notEqual(cache.get("example.com", "A"), undefined);
    });

    it("respects custom TTL bounds", () => {
      const cache = new DNSCache({ minTTL: 60, maxTTL: 600 });
      cache.set("example.com", "A", [makeRecord(10)]);
      assert.notEqual(cache.get("example.com", "A"), undefined);
    });
  });

  describe("LRU eviction", () => {
    it("evicts least-recently-used when maxEntries is exceeded", () => {
      const cache = new DNSCache({ maxEntries: 2 });
      cache.set("a.com", "A", [makeRecord(300)]);
      cache.set("b.com", "A", [makeRecord(300)]);
      cache.set("c.com", "A", [makeRecord(300)]);
      assert.equal(cache.size, 2);
      assert.equal(cache.get("a.com", "A"), undefined);
      assert.notEqual(cache.get("b.com", "A"), undefined);
      assert.notEqual(cache.get("c.com", "A"), undefined);
    });

    it("LRU access updates prevent eviction", () => {
      const cache = new DNSCache({ maxEntries: 2 });
      cache.set("a.com", "A", [makeRecord(3600)]);
      cache.set("b.com", "A", [makeRecord(3600)]);
      cache.get("a.com", "A");
      cache.set("c.com", "A", [makeRecord(3600)]);
      assert.notEqual(cache.get("a.com", "A"), undefined);
      assert.equal(cache.get("b.com", "A"), undefined);
    });
  });

  describe("rebinding protection", () => {
    it("pins IP addresses on first resolution by default", () => {
      const cache = new DNSCache({ pinning: true });
      cache.set("example.com", "A", [makeRecord(300)]);
      cache.set("example.com", "A", [makeRecord(300)]);
      assert.notEqual(cache.get("example.com", "A"), undefined);
    });

    it("throws when new address doesn't match pinned set", () => {
      const cache = new DNSCache({ pinning: true });
      const original = [{ name: "example.com", type: 1, ttl: 300, data: Buffer.from([1, 2, 3, 4]) }];
      cache.set("example.com", "A", original);

      const rogue = [{ name: "example.com", type: 1, ttl: 300, data: Buffer.from([127, 0, 0, 1]) }];
      assert.throws(() => cache.set("example.com", "A", rogue), /rebinding/i);
    });

    it("does not throw when pinning is disabled", () => {
      const cache = new DNSCache({ pinning: false });
      const original = [{ name: "example.com", type: 1, ttl: 300, data: Buffer.from([1, 2, 3, 4]) }];
      cache.set("example.com", "A", original);

      const different = [{ name: "example.com", type: 1, ttl: 300, data: Buffer.from([5, 6, 7, 8]) }];
      assert.doesNotThrow(() => cache.set("example.com", "A", different));
    });
  });

  describe("clear", () => {
    it("removes all entries", () => {
      const cache = new DNSCache();
      cache.set("a.com", "A", [makeRecord(300)]);
      cache.set("b.com", "A", [makeRecord(300)]);
      cache.clear();
      assert.equal(cache.size, 0);
    });
  });
});
