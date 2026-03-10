/**
 * Unit tests for src/cache/no-vary-search.ts
 * No-Vary-Search header parsing and URL-matching logic.
 */
import { describe, it } from "node:test";
import { strict as assert } from "node:assert";
import { parseNoVarySearch, urlsMatchWithNoVarySearch, normalizeUrlForCache } from "../../src/cache/no-vary-search.js";

describe("parseNoVarySearch", () => {
  it("returns null for empty string", () => {
    assert.equal(parseNoVarySearch(""), null);
  });

  it("parses 'params' as boolean true", () => {
    const d = parseNoVarySearch("params");
    assert.notEqual(d, null);
    assert.equal(d!.params, true);
  });

  it("parses 'key-order'", () => {
    const d = parseNoVarySearch("key-order");
    assert.notEqual(d, null);
    assert.equal(d!.keyOrder, true);
  });

  it("parses 'params' combined with 'key-order'", () => {
    const d = parseNoVarySearch("params, key-order");
    assert.notEqual(d, null);
    assert.equal(d!.params, true);
    assert.equal(d!.keyOrder, true);
  });

  it('parses params=("a" "b") as specific param list', () => {
    const d = parseNoVarySearch('params=("a" "b")');
    assert.notEqual(d, null);
    assert.ok(Array.isArray(d!.params));
    assert.deepEqual(d!.params, ["a", "b"]);
  });

  it('parses except=("c") with params=true', () => {
    const d = parseNoVarySearch('params, except=("c")');
    assert.notEqual(d, null);
    assert.equal(d!.params, true);
    assert.deepEqual(d!.except, ["c"]);
  });
});

describe("urlsMatchWithNoVarySearch", () => {
  it("matches when all params are ignored", () => {
    const directive = { params: true as const, except: [], keyOrder: false };
    assert.ok(urlsMatchWithNoVarySearch("https://example.com/page?a=1&b=2", "https://example.com/page?c=3", directive));
  });

  it("does not match when origins differ", () => {
    const directive = { params: true as const, except: [], keyOrder: false };
    assert.equal(urlsMatchWithNoVarySearch("https://example.com/page", "https://other.com/page", directive), false);
  });

  it("does not match when pathnames differ", () => {
    const directive = { params: true as const, except: [], keyOrder: false };
    assert.equal(urlsMatchWithNoVarySearch("https://example.com/a", "https://example.com/b", directive), false);
  });

  it("matches with key-order when params are in different order", () => {
    const directive = { params: false, except: [], keyOrder: true };
    assert.ok(urlsMatchWithNoVarySearch("https://example.com/page?b=2&a=1", "https://example.com/page?a=1&b=2", directive));
  });

  it("does not match with different order when key-order is false", () => {
    const directive = { params: false, except: [], keyOrder: false };
    assert.equal(urlsMatchWithNoVarySearch("https://example.com/page?b=2&a=1", "https://example.com/page?a=1&b=2", directive), false);
  });

  it("ignores specific params in the list", () => {
    const directive = { params: ["tracking"] as string[], except: [], keyOrder: false };
    assert.ok(urlsMatchWithNoVarySearch("https://example.com/page?q=test&tracking=abc", "https://example.com/page?q=test&tracking=xyz", directive));
  });

  it("keeps 'except' params when params=true", () => {
    const directive = { params: true as const, except: ["session"], keyOrder: false };
    assert.equal(urlsMatchWithNoVarySearch("https://example.com/page?session=a&other=1", "https://example.com/page?session=b&other=2", directive), false);
  });

  it("matches when except params are the same", () => {
    const directive = { params: true as const, except: ["session"], keyOrder: false };
    assert.ok(urlsMatchWithNoVarySearch("https://example.com/page?session=x&other=1", "https://example.com/page?session=x&other=2", directive));
  });

  it("returns false for invalid URLs", () => {
    const directive = { params: true as const, except: [], keyOrder: false };
    assert.equal(urlsMatchWithNoVarySearch("not-a-url", "also-not-a-url", directive), false);
  });
});

describe("normalizeUrlForCache", () => {
  it("removes all params when params=true", () => {
    const directive = { params: true as const, except: [], keyOrder: false };
    const result = normalizeUrlForCache("https://example.com/page?a=1&b=2", directive);
    assert.equal(result, "https://example.com/page");
  });

  it("keeps except params when params=true", () => {
    const directive = { params: true as const, except: ["id"], keyOrder: false };
    const result = normalizeUrlForCache("https://example.com/page?id=42&tracking=abc", directive);
    assert.ok(result.includes("id=42"));
    assert.ok(!result.includes("tracking"));
  });

  it("removes specific params from the list", () => {
    const directive = { params: ["utm_source", "utm_medium"] as string[], except: [], keyOrder: false };
    const result = normalizeUrlForCache("https://example.com/page?q=test&utm_source=google&utm_medium=cpc", directive);
    assert.ok(result.includes("q=test"));
    assert.ok(!result.includes("utm_source"));
    assert.ok(!result.includes("utm_medium"));
  });

  it("sorts params when key-order is true", () => {
    const directive = { params: false, except: [], keyOrder: true };
    const result = normalizeUrlForCache("https://example.com/page?z=3&a=1&m=2", directive);
    const u = new URL(result);
    const keys = [...u.searchParams.keys()];
    assert.deepEqual(keys, ["a", "m", "z"]);
  });

  it("returns original string for invalid URLs", () => {
    const directive = { params: true as const, except: [], keyOrder: false };
    assert.equal(normalizeUrlForCache("not-a-url", directive), "not-a-url");
  });
});
