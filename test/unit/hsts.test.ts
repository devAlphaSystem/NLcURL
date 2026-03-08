import { describe, it } from "node:test";
import assert from "node:assert/strict";
import { HSTSStore } from "../../src/hsts/store.js";

describe("HSTSStore", () => {
  describe("parseHeader", () => {
    it("stores a policy from a valid STS header over HTTPS", () => {
      const store = new HSTSStore();
      store.parseHeader("example.com", "max-age=31536000", true);
      assert.equal(store.isSecure("example.com"), true);
    });

    it("ignores STS headers received over HTTP (RFC 6797 §8.1)", () => {
      const store = new HSTSStore();
      store.parseHeader("example.com", "max-age=31536000", false);
      assert.equal(store.isSecure("example.com"), false);
    });

    it("ignores STS headers for IP addresses (RFC 6797 §8.3.2)", () => {
      const store = new HSTSStore();
      store.parseHeader("192.168.1.1", "max-age=31536000", true);
      assert.equal(store.isSecure("192.168.1.1"), false);
    });

    it("ignores IPv6 addresses", () => {
      const store = new HSTSStore();
      store.parseHeader("[::1]", "max-age=31536000", true);
      assert.equal(store.isSecure("[::1]"), false);
    });

    it("requires the max-age directive", () => {
      const store = new HSTSStore();
      store.parseHeader("example.com", "includeSubDomains", true);
      assert.equal(store.isSecure("example.com"), false);
    });

    it("removes policy when max-age=0 (RFC 6797 §6.1.1)", () => {
      const store = new HSTSStore();
      store.parseHeader("example.com", "max-age=31536000", true);
      assert.equal(store.isSecure("example.com"), true);
      store.parseHeader("example.com", "max-age=0", true);
      assert.equal(store.isSecure("example.com"), false);
    });

    it("parses includeSubDomains directive", () => {
      const store = new HSTSStore();
      store.parseHeader("example.com", "max-age=31536000; includeSubDomains", true);
      assert.equal(store.isSecure("example.com"), true);
      assert.equal(store.isSecure("sub.example.com"), true);
      assert.equal(store.isSecure("deep.sub.example.com"), true);
    });

    it("does not match subdomains without includeSubDomains", () => {
      const store = new HSTSStore();
      store.parseHeader("example.com", "max-age=31536000", true);
      assert.equal(store.isSecure("sub.example.com"), false);
    });

    it("handles quoted max-age values", () => {
      const store = new HSTSStore();
      store.parseHeader("example.com", 'max-age="31536000"', true);
      assert.equal(store.isSecure("example.com"), true);
    });

    it("is case-insensitive for host matching", () => {
      const store = new HSTSStore();
      store.parseHeader("Example.COM", "max-age=31536000", true);
      assert.equal(store.isSecure("example.com"), true);
      assert.equal(store.isSecure("EXAMPLE.COM"), true);
    });

    it("strips trailing dots from hostnames", () => {
      const store = new HSTSStore();
      store.parseHeader("example.com.", "max-age=31536000", true);
      assert.equal(store.isSecure("example.com"), true);
    });

    it("ignores invalid max-age values", () => {
      const store = new HSTSStore();
      store.parseHeader("example.com", "max-age=abc", true);
      assert.equal(store.isSecure("example.com"), false);
    });

    it("ignores negative max-age values", () => {
      const store = new HSTSStore();
      store.parseHeader("example.com", "max-age=-1", true);
      assert.equal(store.isSecure("example.com"), false);
    });
  });

  describe("upgradeURL", () => {
    it("upgrades http:// to https:// when policy exists", () => {
      const store = new HSTSStore();
      store.parseHeader("example.com", "max-age=31536000", true);
      assert.equal(store.upgradeURL("http://example.com/path"), "https://example.com/path");
    });

    it("does not modify https:// URLs", () => {
      const store = new HSTSStore();
      store.parseHeader("example.com", "max-age=31536000", true);
      assert.equal(store.upgradeURL("https://example.com/path"), "https://example.com/path");
    });

    it("does not modify URLs without a matching policy", () => {
      const store = new HSTSStore();
      assert.equal(store.upgradeURL("http://example.com/path"), "http://example.com/path");
    });

    it("upgrades subdomain URLs when includeSubDomains is set", () => {
      const store = new HSTSStore();
      store.parseHeader("example.com", "max-age=31536000; includeSubDomains", true);
      const upgraded = store.upgradeURL("http://api.example.com/v1");
      assert.equal(upgraded, "https://api.example.com/v1");
    });

    it("preserves query strings and fragments", () => {
      const store = new HSTSStore();
      store.parseHeader("example.com", "max-age=31536000", true);
      const result = store.upgradeURL("http://example.com/path?q=1");
      assert.ok(result.startsWith("https://example.com/path"));
      assert.ok(result.includes("q=1"));
    });

    it("returns invalid URLs unchanged", () => {
      const store = new HSTSStore();
      assert.equal(store.upgradeURL("not-a-url"), "not-a-url");
    });
  });

  describe("preload", () => {
    it("seeds the store with preload entries", () => {
      const store = new HSTSStore({
        preload: [{ host: "preloaded.com", includeSubDomains: true }],
      });
      assert.equal(store.isSecure("preloaded.com"), true);
      assert.equal(store.isSecure("sub.preloaded.com"), true);
    });

    it("preload entries can be overridden by headers", () => {
      const store = new HSTSStore({
        preload: [{ host: "example.com" }],
      });
      assert.equal(store.isSecure("example.com"), true);
      store.parseHeader("example.com", "max-age=0", true);
      assert.equal(store.isSecure("example.com"), false);
    });
  });

  describe("size and clear", () => {
    it("reports the number of stored policies", () => {
      const store = new HSTSStore();
      assert.equal(store.size, 0);
      store.parseHeader("a.com", "max-age=100", true);
      store.parseHeader("b.com", "max-age=100", true);
      assert.equal(store.size, 2);
    });

    it("clears all stored policies", () => {
      const store = new HSTSStore();
      store.parseHeader("a.com", "max-age=100", true);
      store.clear();
      assert.equal(store.size, 0);
      assert.equal(store.isSecure("a.com"), false);
    });
  });
});
