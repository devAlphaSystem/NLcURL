import { describe, it } from "node:test";
import assert from "node:assert/strict";
import { HTTPSRRResolver } from "../../src/dns/https-rr.js";

describe("HTTPSRRResolver", () => {
  it("constructs without DoH config (system DNS)", () => {
    const resolver = new HTTPSRRResolver();
    assert.ok(resolver, "should construct with system DNS backend");
  });

  it("constructs with DoH config", () => {
    const resolver = new HTTPSRRResolver({
      server: "https://1.1.1.1/dns-query",
    });
    assert.ok(resolver, "should construct with DoH backend");
  });
});
