/**
 * Unit tests for src/middleware/retry-after.ts
 * Retry-After header parsing per RFC 7231 §7.1.3.
 */
import { describe, it } from "node:test";
import { strict as assert } from "node:assert";
import { parseRetryAfter, getRetryAfterMs } from "../../src/middleware/retry-after.js";

describe("parseRetryAfter", () => {
  it("parses integer delay-seconds", () => {
    assert.equal(parseRetryAfter("120"), 120000);
  });

  it("parses 0 seconds", () => {
    assert.equal(parseRetryAfter("0"), 0);
  });

  it("parses a future HTTP-date", () => {
    const future = new Date(Date.now() + 60000);
    const result = parseRetryAfter(future.toUTCString());
    assert.notEqual(result, undefined);
    assert.ok(result! > 0, "Expected positive delay for future date");
    assert.ok(result! <= 60000 + 2000, "Expected delay close to 60s");
  });

  it("returns 0 for a past HTTP-date", () => {
    const past = new Date(Date.now() - 10000);
    const result = parseRetryAfter(past.toUTCString());
    assert.equal(result, 0);
  });

  it("returns undefined for empty string", () => {
    assert.equal(parseRetryAfter(""), undefined);
  });

  it("returns undefined for unparseable value", () => {
    assert.equal(parseRetryAfter("not-a-date-or-number"), undefined);
  });

  it("handles whitespace-padded values", () => {
    assert.equal(parseRetryAfter("  60  "), 60000);
  });
});

describe("getRetryAfterMs", () => {
  it("extracts Retry-After from headers object", () => {
    const headers = { "retry-after": "30" };
    assert.equal(getRetryAfterMs(headers), 30000);
  });

  it("returns undefined when header is absent", () => {
    assert.equal(getRetryAfterMs({}), undefined);
    assert.equal(getRetryAfterMs({ "content-type": "text/html" }), undefined);
  });
});
