import { describe, it, beforeEach } from "node:test";
import { strict as assert } from "node:assert";
import { HSTSStore } from "../../src/hsts/store.js";

describe("HSTSStore", () => {
  let store: HSTSStore;

  beforeEach(() => {
    store = new HSTSStore();
  });

  describe("parseHeader", () => {
    it("stores a basic max-age policy", () => {
      store.parseHeader("example.com", "max-age=31536000", true);
      assert.equal(store.isSecure("example.com"), true);
      assert.equal(store.size, 1);
    });

    it("parses includeSubDomains directive", () => {
      store.parseHeader("example.com", "max-age=31536000; includeSubDomains", true);
      assert.equal(store.isSecure("example.com"), true);
      assert.equal(store.isSecure("sub.example.com"), true);
      assert.equal(store.isSecure("deep.sub.example.com"), true);
    });

    it("ignores non-secure responses per RFC 6797 §8.1", () => {
      store.parseHeader("example.com", "max-age=31536000", false);
      assert.equal(store.isSecure("example.com"), false);
      assert.equal(store.size, 0);
    });

    it("ignores IP address hosts per RFC 6797 §8.3.3", () => {
      store.parseHeader("192.168.1.1", "max-age=31536000", true);
      assert.equal(store.size, 0);
    });

    it("ignores IPv6 addresses in brackets", () => {
      store.parseHeader("[::1]", "max-age=31536000", true);
      assert.equal(store.size, 0);
    });

    it("ignores header without max-age directive", () => {
      store.parseHeader("example.com", "includeSubDomains", true);
      assert.equal(store.size, 0);
    });

    it("deletes policy when max-age=0 per RFC 6797 §6.1.1", () => {
      store.parseHeader("example.com", "max-age=31536000", true);
      assert.equal(store.size, 1);
      store.parseHeader("example.com", "max-age=0", true);
      assert.equal(store.size, 0);
      assert.equal(store.isSecure("example.com"), false);
    });

    it("ignores negative max-age", () => {
      store.parseHeader("example.com", "max-age=-1", true);
      assert.equal(store.size, 0);
    });

    it("ignores non-numeric max-age", () => {
      store.parseHeader("example.com", "max-age=abc", true);
      assert.equal(store.size, 0);
    });

    it("handles quoted max-age values", () => {
      store.parseHeader("example.com", 'max-age="31536000"', true);
      assert.equal(store.isSecure("example.com"), true);
    });

    it("canonicalizes host to lowercase", () => {
      store.parseHeader("EXAMPLE.COM", "max-age=31536000", true);
      assert.equal(store.isSecure("example.com"), true);
    });

    it("strips trailing dot from host", () => {
      store.parseHeader("example.com.", "max-age=31536000", true);
      assert.equal(store.isSecure("example.com"), true);
    });

    it("updates existing policy on re-parse", () => {
      store.parseHeader("example.com", "max-age=100", true);
      store.parseHeader("example.com", "max-age=31536000; includeSubDomains", true);
      assert.equal(store.isSecure("sub.example.com"), true);
      assert.equal(store.size, 1);
    });
  });

  describe("isSecure", () => {
    it("returns false for unknown hosts", () => {
      assert.equal(store.isSecure("unknown.example.com"), false);
    });

    it("returns false for IP addresses", () => {
      assert.equal(store.isSecure("127.0.0.1"), false);
    });

    it("returns false for IPv6 addresses", () => {
      assert.equal(store.isSecure("[::1]"), false);
    });

    it("matches exact host", () => {
      store.parseHeader("example.com", "max-age=31536000", true);
      assert.equal(store.isSecure("example.com"), true);
      assert.equal(store.isSecure("other.com"), false);
    });

    it("does not match subdomains without includeSubDomains", () => {
      store.parseHeader("example.com", "max-age=31536000", true);
      assert.equal(store.isSecure("sub.example.com"), false);
    });

    it("walks parent domains for includeSubDomains", () => {
      store.parseHeader("example.com", "max-age=31536000; includeSubDomains", true);
      assert.equal(store.isSecure("a.b.c.example.com"), true);
    });

    it("evicts expired policies on lookup", () => {
      store.parseHeader("example.com", "max-age=1", true);
      assert.equal(store.isSecure("example.com"), true);
    });

    it("is case-insensitive", () => {
      store.parseHeader("Example.COM", "max-age=31536000", true);
      assert.equal(store.isSecure("EXAMPLE.com"), true);
    });
  });

  describe("upgradeURL", () => {
    it("upgrades http to https when HSTS applies", () => {
      store.parseHeader("example.com", "max-age=31536000", true);
      const result = store.upgradeURL("http://example.com/path?q=1");
      assert.ok(result.startsWith("https://"));
      const parsed = new URL(result);
      assert.equal(parsed.protocol, "https:");
      assert.equal(parsed.hostname, "example.com");
      assert.equal(parsed.pathname, "/path");
    });

    it("does not upgrade already-https URLs", () => {
      store.parseHeader("example.com", "max-age=31536000", true);
      const url = "https://example.com/path";
      assert.equal(store.upgradeURL(url), url);
    });

    it("does not upgrade when no HSTS policy exists", () => {
      const url = "http://example.com/path";
      assert.equal(store.upgradeURL(url), url);
    });

    it("returns invalid URLs unchanged", () => {
      assert.equal(store.upgradeURL("not-a-url"), "not-a-url");
    });

    it("upgrades subdomain URLs with includeSubDomains", () => {
      store.parseHeader("example.com", "max-age=31536000; includeSubDomains", true);
      const result = store.upgradeURL("http://sub.example.com/page");
      assert.ok(result.startsWith("https://"));
    });
  });

  describe("preload", () => {
    it("loads preloaded entries on construction", () => {
      const preloaded = new HSTSStore({
        preload: [{ host: "preloaded.com", includeSubDomains: true }, { host: "another.com" }],
      });
      assert.equal(preloaded.isSecure("preloaded.com"), true);
      assert.equal(preloaded.isSecure("sub.preloaded.com"), true);
      assert.equal(preloaded.isSecure("another.com"), true);
      assert.equal(preloaded.isSecure("sub.another.com"), false);
      assert.equal(preloaded.size, 2);
    });

    it("ignores preload entries with empty host", () => {
      const preloaded = new HSTSStore({
        preload: [{ host: "" }],
      });
      assert.equal(preloaded.size, 0);
    });
  });

  describe("toJSON / loadJSON", () => {
    it("round-trips policies through JSON", () => {
      store.parseHeader("example.com", "max-age=31536000; includeSubDomains", true);
      store.parseHeader("other.org", "max-age=86400", true);
      const json = store.toJSON();
      const parsed = JSON.parse(json);
      assert.equal(Array.isArray(parsed), true);
      assert.equal(parsed.length, 2);

      const restored = new HSTSStore();
      restored.loadJSON(json);
      assert.equal(restored.isSecure("example.com"), true);
      assert.equal(restored.isSecure("sub.example.com"), true);
      assert.equal(restored.isSecure("other.org"), true);
      assert.equal(restored.size, 2);
    });

    it("excludes expired entries during serialization", () => {
      store.parseHeader("example.com", "max-age=31536000", true);
      const json = store.toJSON();
      const entries = JSON.parse(json);
      assert.equal(entries.length, 1);
      assert.ok(entries[0].expires > Date.now());
    });

    it("skips invalid entries during load", () => {
      const json = JSON.stringify([
        { host: 123, expires: Date.now() + 10000, includeSubDomains: false },
        { host: "valid.com", expires: "not-a-number", includeSubDomains: false },
        { host: "good.com", expires: Date.now() + 60000, includeSubDomains: true },
      ]);
      store.loadJSON(json);
      assert.equal(store.size, 1);
      assert.equal(store.isSecure("good.com"), true);
    });

    it("skips already-expired entries during load", () => {
      const json = JSON.stringify([{ host: "expired.com", expires: Date.now() - 1000, includeSubDomains: false }]);
      store.loadJSON(json);
      assert.equal(store.size, 0);
    });
  });

  describe("clear", () => {
    it("removes all policies", () => {
      store.parseHeader("a.com", "max-age=1000", true);
      store.parseHeader("b.com", "max-age=1000", true);
      assert.equal(store.size, 2);
      store.clear();
      assert.equal(store.size, 0);
      assert.equal(store.isSecure("a.com"), false);
    });
  });
});
