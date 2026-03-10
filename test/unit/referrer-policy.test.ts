/**
 * Unit tests for src/http/referrer-policy.ts
 * W3C Referrer Policy: https://www.w3.org/TR/referrer-policy/
 * All 8 policy types tested.
 */
import { describe, it } from "node:test";
import { strict as assert } from "node:assert";
import { parseReferrerPolicy, computeReferrer } from "../../src/http/referrer-policy.js";

describe("parseReferrerPolicy", () => {
  it("parses each valid policy value", () => {
    const policies = ["no-referrer", "no-referrer-when-downgrade", "origin", "origin-when-cross-origin", "same-origin", "strict-origin", "strict-origin-when-cross-origin", "unsafe-url"] as const;

    for (const p of policies) {
      assert.equal(parseReferrerPolicy(p), p);
    }
  });

  it("returns undefined for empty string", () => {
    assert.equal(parseReferrerPolicy(""), undefined);
  });

  it("returns undefined for unrecognized value", () => {
    assert.equal(parseReferrerPolicy("invalid-policy"), undefined);
  });

  it("uses the last recognized value when multiple are present (per spec)", () => {
    assert.equal(parseReferrerPolicy("no-referrer, origin"), "origin");
    assert.equal(parseReferrerPolicy("invalid, strict-origin"), "strict-origin");
  });

  it("is case-insensitive", () => {
    assert.equal(parseReferrerPolicy("No-Referrer"), "no-referrer");
    assert.equal(parseReferrerPolicy("ORIGIN"), "origin");
  });

  it("handles whitespace", () => {
    assert.equal(parseReferrerPolicy("  origin  "), "origin");
  });
});

describe("computeReferrer", () => {
  const from = new URL("https://example.com/page?q=test#hash");
  const sameOriginDest = new URL("https://example.com/other");
  const crossOriginDest = new URL("https://other.com/page");
  const httpDest = new URL("http://example.com/page");

  describe("no-referrer", () => {
    it("always returns empty string", () => {
      assert.equal(computeReferrer(from, sameOriginDest, "no-referrer"), "");
      assert.equal(computeReferrer(from, crossOriginDest, "no-referrer"), "");
    });
  });

  describe("origin", () => {
    it("sends only origin regardless of destination", () => {
      assert.equal(computeReferrer(from, sameOriginDest, "origin"), "https://example.com/");
      assert.equal(computeReferrer(from, crossOriginDest, "origin"), "https://example.com/");
      assert.equal(computeReferrer(from, httpDest, "origin"), "https://example.com/");
    });
  });

  describe("unsafe-url", () => {
    it("sends full URL without fragment", () => {
      assert.equal(computeReferrer(from, crossOriginDest, "unsafe-url"), "https://example.com/page?q=test");
    });

    it("strips fragment from referrer", () => {
      const result = computeReferrer(from, crossOriginDest, "unsafe-url");
      assert.ok(!result.includes("#hash"));
    });
  });

  describe("same-origin", () => {
    it("sends full URL for same-origin requests", () => {
      assert.equal(computeReferrer(from, sameOriginDest, "same-origin"), "https://example.com/page?q=test");
    });

    it("sends empty string for cross-origin requests", () => {
      assert.equal(computeReferrer(from, crossOriginDest, "same-origin"), "");
    });
  });

  describe("strict-origin", () => {
    it("sends origin for same-protocol cross-origin", () => {
      assert.equal(computeReferrer(from, crossOriginDest, "strict-origin"), "https://example.com/");
    });

    it("sends empty string on downgrade (HTTPS → HTTP)", () => {
      assert.equal(computeReferrer(from, httpDest, "strict-origin"), "");
    });
  });

  describe("no-referrer-when-downgrade", () => {
    it("sends full URL for non-downgrade requests", () => {
      assert.equal(computeReferrer(from, crossOriginDest, "no-referrer-when-downgrade"), "https://example.com/page?q=test");
    });

    it("sends empty string on downgrade", () => {
      assert.equal(computeReferrer(from, httpDest, "no-referrer-when-downgrade"), "");
    });
  });

  describe("origin-when-cross-origin", () => {
    it("sends full URL for same-origin", () => {
      assert.equal(computeReferrer(from, sameOriginDest, "origin-when-cross-origin"), "https://example.com/page?q=test");
    });

    it("sends only origin for cross-origin", () => {
      assert.equal(computeReferrer(from, crossOriginDest, "origin-when-cross-origin"), "https://example.com/");
    });
  });

  describe("strict-origin-when-cross-origin", () => {
    it("sends full URL for same-origin", () => {
      assert.equal(computeReferrer(from, sameOriginDest, "strict-origin-when-cross-origin"), "https://example.com/page?q=test");
    });

    it("sends origin for cross-origin (no downgrade)", () => {
      assert.equal(computeReferrer(from, crossOriginDest, "strict-origin-when-cross-origin"), "https://example.com/");
    });

    it("sends empty string on downgrade", () => {
      assert.equal(computeReferrer(from, httpDest, "strict-origin-when-cross-origin"), "");
    });
  });
});
