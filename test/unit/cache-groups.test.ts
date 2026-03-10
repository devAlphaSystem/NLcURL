/**
 * Unit tests for src/cache/groups.ts
 * CacheGroupStore: named group management and batch invalidation.
 */
import { describe, it } from "node:test";
import { strict as assert } from "node:assert";
import { parseCacheGroups, CacheGroupStore } from "../../src/cache/groups.js";

describe("parseCacheGroups", () => {
  it("returns empty array for empty string", () => {
    assert.deepEqual(parseCacheGroups(""), []);
  });

  it("parses single group name", () => {
    assert.deepEqual(parseCacheGroups("products"), ["products"]);
  });

  it("parses comma-separated group names", () => {
    assert.deepEqual(parseCacheGroups("products, users, orders"), ["products", "users", "orders"]);
  });

  it("strips quotes from group names", () => {
    assert.deepEqual(parseCacheGroups('"products", "users"'), ["products", "users"]);
  });

  it("filters out empty segments", () => {
    assert.deepEqual(parseCacheGroups("a,,b, ,c"), ["a", "b", "c"]);
  });
});

describe("CacheGroupStore", () => {
  it("starts empty", () => {
    const store = new CacheGroupStore();
    assert.equal(store.size, 0);
  });

  describe("addToGroups / getGroupKeys", () => {
    it("adds cache key to specified groups", () => {
      const store = new CacheGroupStore();
      store.addToGroups("GET:https://api/items", ["items", "all"]);
      assert.ok(store.getGroupKeys("items").has("GET:https://api/items"));
      assert.ok(store.getGroupKeys("all").has("GET:https://api/items"));
    });

    it("returns empty set for unknown group", () => {
      const store = new CacheGroupStore();
      assert.equal(store.getGroupKeys("nope").size, 0);
    });

    it("creates groups on demand", () => {
      const store = new CacheGroupStore();
      store.addToGroups("key1", ["group1"]);
      assert.equal(store.size, 1);
    });
  });

  describe("removeFromAll", () => {
    it("removes a cache key from all groups", () => {
      const store = new CacheGroupStore();
      store.addToGroups("key1", ["g1", "g2"]);
      store.removeFromAll("key1");
      assert.equal(store.getGroupKeys("g1").size, 0);
      assert.equal(store.getGroupKeys("g2").size, 0);
    });
  });

  describe("invalidate", () => {
    it("returns the keys in the group and clears it", () => {
      const store = new CacheGroupStore();
      store.addToGroups("k1", ["grp"]);
      store.addToGroups("k2", ["grp"]);
      const keys = store.invalidate("grp");
      assert.ok(keys.includes("k1"));
      assert.ok(keys.includes("k2"));
      assert.equal(store.getGroupKeys("grp").size, 0);
    });

    it("returns empty array for unknown group", () => {
      const store = new CacheGroupStore();
      assert.deepEqual(store.invalidate("nope"), []);
    });
  });

  describe("invalidateAll", () => {
    it("returns all unique keys across all groups", () => {
      const store = new CacheGroupStore();
      store.addToGroups("k1", ["g1"]);
      store.addToGroups("k2", ["g2"]);
      store.addToGroups("k1", ["g2"]);
      const keys = store.invalidateAll();
      assert.equal(keys.length, 2);
      assert.ok(keys.includes("k1"));
      assert.ok(keys.includes("k2"));
    });

    it("clears all group keys", () => {
      const store = new CacheGroupStore();
      store.addToGroups("k1", ["g1"]);
      store.invalidateAll();
      assert.equal(store.getGroupKeys("g1").size, 0);
    });
  });

  describe("isInvalidatedSince", () => {
    it("returns false when no invalidation has occurred", () => {
      const store = new CacheGroupStore();
      store.addToGroups("k1", ["grp"]);
      assert.equal(store.isInvalidatedSince("k1", Date.now() - 1000), false);
    });

    it("returns true when group was invalidated after storedAt", () => {
      const store = new CacheGroupStore();
      store.addToGroups("k1", ["grp"]);
      const storedAt = Date.now() - 1000;
      store.invalidate("grp");
      store.addToGroups("k1", ["grp"]);
      assert.equal(store.isInvalidatedSince("k1", storedAt), true);
    });
  });

  describe("clear", () => {
    it("removes all groups", () => {
      const store = new CacheGroupStore();
      store.addToGroups("k1", ["g1", "g2"]);
      store.clear();
      assert.equal(store.size, 0);
    });
  });
});
