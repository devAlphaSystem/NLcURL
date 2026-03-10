/**
 * Unit tests for src/utils/url.ts
 * Expected values derived from RFC 3986 (URI syntax) and WHATWG URL Standard.
 */
import { describe, it } from "node:test";
import { strict as assert } from "node:assert";
import { resolveURL, appendParams, parseURL, originOf, sniHost, hostPort, requestPath } from "../../src/utils/url.js";

describe("resolveURL", () => {
  it("resolves a relative path against a base URL", () => {
    assert.equal(resolveURL("https://example.com/a/b", "/c"), "https://example.com/c");
  });

  it("resolves a relative path with base path component", () => {
    assert.equal(resolveURL("https://example.com/a/b/", "c"), "https://example.com/a/b/c");
  });

  it("returns relative URL unchanged when no base is provided", () => {
    assert.equal(resolveURL(undefined, "https://example.com/test"), "https://example.com/test");
  });

  it("returns absolute URL unchanged even with a base", () => {
    assert.equal(resolveURL("https://other.com", "https://example.com/test"), "https://example.com/test");
  });

  it("returns relative URL on invalid base (graceful fallback)", () => {
    assert.equal(resolveURL("not-a-url", "/path"), "/path");
  });

  it("resolves .. parent traversal per RFC 3986 §5.4", () => {
    assert.equal(resolveURL("https://example.com/a/b/c", "../d"), "https://example.com/a/d");
  });
});

describe("appendParams", () => {
  it("appends query parameters to a URL", () => {
    const result = appendParams("https://example.com/api", { page: 1, sort: "name" });
    const parsed = new URL(result);
    assert.equal(parsed.searchParams.get("page"), "1");
    assert.equal(parsed.searchParams.get("sort"), "name");
    assert.equal(parsed.pathname, "/api");
  });

  it("returns URL unchanged when params is undefined", () => {
    assert.equal(appendParams("https://example.com/api", undefined), "https://example.com/api");
  });

  it("returns URL unchanged when params is empty object", () => {
    assert.equal(appendParams("https://example.com/api", {}), "https://example.com/api");
  });

  it("appends boolean parameter as string", () => {
    const result = appendParams("https://example.com", { active: true });
    const parsed = new URL(result);
    assert.equal(parsed.searchParams.get("active"), "true");
  });

  it("preserves existing query parameters", () => {
    const result = appendParams("https://example.com?existing=1", { added: "2" });
    const parsed = new URL(result);
    assert.equal(parsed.searchParams.get("existing"), "1");
    assert.equal(parsed.searchParams.get("added"), "2");
  });
});

describe("parseURL", () => {
  it("parses a valid HTTPS URL", () => {
    const url = parseURL("https://example.com:8443/path?q=1#frag");
    assert.equal(url.protocol, "https:");
    assert.equal(url.hostname, "example.com");
    assert.equal(url.port, "8443");
    assert.equal(url.pathname, "/path");
    assert.equal(url.search, "?q=1");
    assert.equal(url.hash, "#frag");
  });

  it("throws TypeError for invalid URL", () => {
    assert.throws(() => parseURL("not a url"), TypeError);
  });

  it("parses IPv6 URL per RFC 3986 §3.2.2", () => {
    const url = parseURL("https://[::1]:8080/path");
    assert.equal(url.hostname, "[::1]");
    assert.equal(url.port, "8080");
  });
});

describe("originOf", () => {
  it("returns origin with default HTTPS port 443", () => {
    assert.equal(originOf("https://example.com/path"), "https://example.com:443");
  });

  it("returns origin with default HTTP port 80", () => {
    assert.equal(originOf("http://example.com/path"), "http://example.com:80");
  });

  it("returns origin with explicit port", () => {
    assert.equal(originOf("https://example.com:8443/path"), "https://example.com:8443");
  });
});

describe("sniHost", () => {
  it("extracts hostname for TLS SNI", () => {
    assert.equal(sniHost("https://example.com:443/path"), "example.com");
  });

  it("extracts hostname from IPv6 URL", () => {
    assert.equal(sniHost("https://[::1]:443/path"), "[::1]");
  });
});

describe("hostPort", () => {
  it("returns host and default HTTPS port 443", () => {
    const result = hostPort("https://example.com/path");
    assert.deepStrictEqual(result, { host: "example.com", port: 443 });
  });

  it("returns host and default HTTP port 80", () => {
    const result = hostPort("http://example.com/path");
    assert.deepStrictEqual(result, { host: "example.com", port: 80 });
  });

  it("returns host and explicit port", () => {
    const result = hostPort("https://example.com:9090/path");
    assert.deepStrictEqual(result, { host: "example.com", port: 9090 });
  });
});

describe("requestPath", () => {
  it("returns pathname + search for request line", () => {
    assert.equal(requestPath("https://example.com/api/users?page=1"), "/api/users?page=1");
  });

  it("returns just pathname when no query string", () => {
    assert.equal(requestPath("https://example.com/api/users"), "/api/users");
  });

  it("returns / for root URL", () => {
    assert.equal(requestPath("https://example.com"), "/");
  });

  it("preserves encoded characters in path", () => {
    assert.equal(requestPath("https://example.com/path%20with%20spaces"), "/path%20with%20spaces");
  });
});
