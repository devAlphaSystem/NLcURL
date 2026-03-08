import { describe, it } from "node:test";
import assert from "node:assert/strict";
import { DoHResolver } from "../../src/dns/doh-resolver.js";

describe("DoHResolver", () => {
  it("constructs with valid config", () => {
    const resolver = new DoHResolver({
      server: "https://1.1.1.1/dns-query",
    });
    assert.ok(resolver, "resolver should be created");
  });

  it("constructs with GET method", () => {
    const resolver = new DoHResolver({
      server: "https://dns.google/dns-query",
      method: "GET",
      timeout: 3000,
    });
    assert.ok(resolver);
  });

  it("constructs with POST method", () => {
    const resolver = new DoHResolver({
      server: "https://1.1.1.1/dns-query",
      method: "POST",
      timeout: 10000,
      bootstrap: false,
    });
    assert.ok(resolver);
  });
});
