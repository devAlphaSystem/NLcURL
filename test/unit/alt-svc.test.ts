/**
 * Unit tests for src/http/alt-svc.ts
 * Alt-Svc header parsing and store per RFC 7838.
 */
import { describe, it } from "node:test";
import { strict as assert } from "node:assert";
import { AltSvcStore } from "../../src/http/alt-svc.js";

describe("AltSvcStore", () => {
  it("starts empty", () => {
    const store = new AltSvcStore();
    assert.equal(store.size, 0);
  });

  describe("parseHeader", () => {
    it("parses basic h2 Alt-Svc header", () => {
      const store = new AltSvcStore();
      store.parseHeader("https://example.com", 'h2=":443"');
      assert.equal(store.size, 1);
      const entry = store.lookup("https://example.com");
      assert.notEqual(entry, undefined);
      assert.equal(entry!.alpn, "h2");
      assert.equal(entry!.port, 443);
    });

    it("parses Alt-Svc with ma parameter", () => {
      const store = new AltSvcStore();
      store.parseHeader("https://example.com", 'h2=":443"; ma=3600');
      const entry = store.lookup("https://example.com");
      assert.notEqual(entry, undefined);
      assert.equal(entry!.maxAge, 3600);
    });

    it("parses Alt-Svc with persist parameter", () => {
      const store = new AltSvcStore();
      store.parseHeader("https://example.com", 'h2=":443"; persist=1');
      const entry = store.lookup("https://example.com");
      assert.notEqual(entry, undefined);
      assert.equal(entry!.persist, true);
    });

    it("parses Alt-Svc with custom host", () => {
      const store = new AltSvcStore();
      store.parseHeader("https://example.com", 'h2="alt.example.com:8443"');
      const entry = store.lookup("https://example.com");
      assert.notEqual(entry, undefined);
      assert.equal(entry!.host, "alt.example.com");
      assert.equal(entry!.port, 8443);
    });

    it("parses multiple alternatives", () => {
      const store = new AltSvcStore();
      store.parseHeader("https://example.com", 'h2=":443", h3=":443"');
      assert.equal(store.size, 2);
      const entry = store.lookup("https://example.com");
      assert.notEqual(entry, undefined);
    });

    it("handles 'clear' directive", () => {
      const store = new AltSvcStore();
      store.parseHeader("https://example.com", 'h2=":443"');
      assert.equal(store.size, 1);
      store.parseHeader("https://example.com", "clear");
      assert.equal(store.size, 0);
    });

    it("defaults to 86400 max-age when ma is absent", () => {
      const store = new AltSvcStore();
      store.parseHeader("https://example.com", 'h2=":443"');
      const entry = store.lookup("https://example.com");
      assert.equal(entry!.maxAge, 86400);
    });
  });

  describe("lookup", () => {
    it("returns undefined for unknown origin", () => {
      const store = new AltSvcStore();
      assert.equal(store.lookup("https://nope.com"), undefined);
    });

    it("returns undefined when all entries have expired", () => {
      const store = new AltSvcStore();
      store.parseHeader("https://example.com", 'h2=":443"; ma=0');
      assert.equal(store.lookup("https://example.com"), undefined);
    });
  });

  describe("clear and clearAll", () => {
    it("clear removes entries for specific origin", () => {
      const store = new AltSvcStore();
      store.parseHeader("https://a.com", 'h2=":443"');
      store.parseHeader("https://b.com", 'h2=":443"');
      store.clear("https://a.com");
      assert.equal(store.lookup("https://a.com"), undefined);
      assert.notEqual(store.lookup("https://b.com"), undefined);
    });

    it("clearAll removes all entries", () => {
      const store = new AltSvcStore();
      store.parseHeader("https://a.com", 'h2=":443"');
      store.parseHeader("https://b.com", 'h2=":443"');
      store.clearAll();
      assert.equal(store.size, 0);
    });
  });

  describe("JSON serialization round-trip", () => {
    it("toJSON and loadJSON preserve entries", () => {
      const store = new AltSvcStore();
      store.parseHeader("https://example.com", 'h2=":443"; ma=3600');
      store.parseHeader("https://other.com", 'h3=":443"');

      const json = store.toJSON();
      const store2 = new AltSvcStore();
      store2.loadJSON(json);

      assert.notEqual(store2.lookup("https://example.com"), undefined);
      assert.notEqual(store2.lookup("https://other.com"), undefined);
    });
  });

  describe("eviction", () => {
    it("evicts oldest entries when maxEntries exceeded", () => {
      const store = new AltSvcStore({ maxEntries: 2 });
      store.parseHeader("https://a.com", 'h2=":443"');
      store.parseHeader("https://b.com", 'h2=":443"');
      store.parseHeader("https://c.com", 'h2=":443"');
      assert.ok(store.size <= 2);
    });
  });
});
