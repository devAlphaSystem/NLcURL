import { describe, it } from "node:test";
import assert from "node:assert/strict";
import { AltSvcStore } from "../../src/http/alt-svc.js";

describe("AltSvcStore", () => {
  describe("parseHeader", () => {
    it("parses a simple h2 Alt-Svc header", () => {
      const store = new AltSvcStore();
      store.parseHeader("https://example.com", 'h2=":443"; ma=86400');

      const entry = store.lookup("https://example.com");
      assert.ok(entry, "entry should exist");
      assert.equal(entry!.alpn, "h2");
      assert.equal(entry!.port, 443);
      assert.equal(entry!.maxAge, 86400);
    });

    it("parses multiple alternatives, returns first", () => {
      const store = new AltSvcStore();
      store.parseHeader("https://example.com", 'h2=":443"; ma=3600, h2=":8443"; ma=86400');

      const entry = store.lookup("https://example.com");
      assert.ok(entry);
      assert.equal(entry!.alpn, "h2");
    });

    it("parses Alt-Svc with custom host and port", () => {
      const store = new AltSvcStore();
      store.parseHeader("https://example.com", 'h2="alt.example.com:8443"; ma=600');

      const entry = store.lookup("https://example.com");
      assert.ok(entry);
      assert.equal(entry!.host, "alt.example.com");
      assert.equal(entry!.port, 8443);
    });

    it('handles "clear" directive', () => {
      const store = new AltSvcStore();
      store.parseHeader("https://example.com", 'h2=":443"; ma=86400');
      assert.ok(store.lookup("https://example.com"));

      store.parseHeader("https://example.com", "clear");
      assert.equal(store.lookup("https://example.com"), undefined);
    });

    it("ignores empty header", () => {
      const store = new AltSvcStore();
      store.parseHeader("https://example.com", "");
      assert.equal(store.lookup("https://example.com"), undefined);
    });

    it("parses persist=1 flag", () => {
      const store = new AltSvcStore();
      store.parseHeader("https://example.com", 'h2=":443"; ma=86400; persist=1');

      const entry = store.lookup("https://example.com");
      assert.ok(entry);
      assert.equal(entry!.persist, true);
    });
  });

  describe("lookup", () => {
    it("returns undefined for unknown origin", () => {
      const store = new AltSvcStore();
      assert.equal(store.lookup("https://unknown.com"), undefined);
    });

    it("evicts entries after maxAge expires", () => {
      const store = new AltSvcStore();
      store.parseHeader("https://example.com", 'h2=":443"; ma=0');

      const entry = store.lookup("https://example.com");
      assert.equal(entry, undefined, "entry with ma=0 should be expired");
    });
  });

  describe("clear / clearAll", () => {
    it("clears entries for a specific origin", () => {
      const store = new AltSvcStore();
      store.parseHeader("https://a.com", 'h2=":443"; ma=86400');
      store.parseHeader("https://b.com", 'h2=":443"; ma=86400');

      store.clear("https://a.com");
      assert.equal(store.lookup("https://a.com"), undefined);
      assert.ok(store.lookup("https://b.com"));
    });

    it("clears all entries", () => {
      const store = new AltSvcStore();
      store.parseHeader("https://a.com", 'h2=":443"; ma=86400');
      store.parseHeader("https://b.com", 'h2=":443"; ma=86400');

      store.clearAll();
      assert.equal(store.lookup("https://a.com"), undefined);
      assert.equal(store.lookup("https://b.com"), undefined);
    });
  });

  describe("LRU eviction", () => {
    it("evicts oldest entries when maxEntries is exceeded", () => {
      const store = new AltSvcStore({ maxEntries: 3 });

      store.parseHeader("https://a.com", 'h2=":443"; ma=86400');
      store.parseHeader("https://b.com", 'h2=":443"; ma=86400');
      store.parseHeader("https://c.com", 'h2=":443"; ma=86400');

      store.parseHeader("https://d.com", 'h2=":443"; ma=86400');

      assert.equal(store.lookup("https://a.com"), undefined, "oldest entry should be evicted");
      assert.ok(store.lookup("https://d.com"), "newest entry should exist");
    });
  });
});
