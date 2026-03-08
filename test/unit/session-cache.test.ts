import { describe, it } from "node:test";
import assert from "node:assert/strict";
import { TLSSessionCache } from "../../src/tls/session-cache.js";

describe("TLSSessionCache", () => {
  it("stores and retrieves a session ticket", () => {
    const cache = new TLSSessionCache();
    const ticket = Buffer.from("ticket-data");
    cache.set("example.com:443", ticket, 60_000, "h2");

    const entry = cache.get("example.com:443");
    assert.ok(entry);
    assert.deepEqual(entry.ticket, ticket);
    assert.equal(entry.alpn, "h2");
  });

  it("returns undefined for missing origin", () => {
    const cache = new TLSSessionCache();
    assert.equal(cache.get("unknown:443"), undefined);
  });

  it("evicts expired tickets", () => {
    const cache = new TLSSessionCache();
    cache.set("example.com:443", Buffer.from("old"), 1);

    const start = Date.now();
    while (Date.now() - start < 5) {}

    assert.equal(cache.get("example.com:443"), undefined);
  });

  it("evicts oldest entry when max size is reached", () => {
    const cache = new TLSSessionCache({ maxEntries: 2 });
    cache.set("a:443", Buffer.from("a"));
    cache.set("b:443", Buffer.from("b"));
    cache.set("c:443", Buffer.from("c"));

    assert.equal(cache.get("a:443"), undefined);
    assert.ok(cache.get("b:443"));
    assert.ok(cache.get("c:443"));
  });

  it("delete removes an entry", () => {
    const cache = new TLSSessionCache();
    cache.set("host:443", Buffer.from("t"));
    assert.equal(cache.delete("host:443"), true);
    assert.equal(cache.get("host:443"), undefined);
  });

  it("clear removes all entries", () => {
    const cache = new TLSSessionCache();
    cache.set("a:443", Buffer.from("a"));
    cache.set("b:443", Buffer.from("b"));
    cache.clear();
    assert.equal(cache.size, 0);
  });

  it("reports correct size", () => {
    const cache = new TLSSessionCache();
    assert.equal(cache.size, 0);
    cache.set("a:443", Buffer.from("a"));
    assert.equal(cache.size, 1);
    cache.set("b:443", Buffer.from("b"));
    assert.equal(cache.size, 2);
  });
});
