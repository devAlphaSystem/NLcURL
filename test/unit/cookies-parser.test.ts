/**
 * Unit tests for src/cookies/parser.ts
 * Per RFC 6265 §5.2 Set-Cookie parsing rules, RFC 6265bis §4.1 cookie prefixes,
 * and Chromium's 400-day max-age cap.
 */
import { describe, it } from "node:test";
import { strict as assert } from "node:assert";
import { parseSetCookie, serializeCookies } from "../../src/cookies/parser.js";

const url = (s: string) => new URL(s);

describe("parseSetCookie", () => {
  describe("basic name=value parsing", () => {
    it("parses a simple name=value pair", () => {
      const c = parseSetCookie("session=abc123", url("https://example.com/app"));
      assert.notEqual(c, null);
      assert.equal(c!.name, "session");
      assert.equal(c!.value, "abc123");
    });

    it("handles empty value", () => {
      const c = parseSetCookie("token=", url("https://example.com/"));
      assert.notEqual(c, null);
      assert.equal(c!.name, "token");
      assert.equal(c!.value, "");
    });

    it("handles value with equals sign", () => {
      const c = parseSetCookie("token=abc=def", url("https://example.com/"));
      assert.notEqual(c, null);
      assert.equal(c!.value, "abc=def");
    });

    it("returns null for header with no =", () => {
      assert.equal(parseSetCookie("invalidcookie", url("https://example.com/")), null);
    });

    it("returns null for empty name", () => {
      assert.equal(parseSetCookie("=value", url("https://example.com/")), null);
    });

    it("rejects name with invalid characters (RFC 7230 token)", () => {
      assert.equal(parseSetCookie("bad name=value", url("https://example.com/")), null);
    });

    it("rejects value with control characters", () => {
      assert.equal(parseSetCookie("name=val\x01ue", url("https://example.com/")), null);
    });

    it("rejects cookies exceeding MAX_COOKIE_SIZE (4096)", () => {
      const longValue = "x".repeat(4097);
      assert.equal(parseSetCookie(`a=${longValue}`, url("https://example.com/")), null);
    });
  });

  describe("domain attribute", () => {
    it("uses request hostname as default domain", () => {
      const c = parseSetCookie("k=v", url("https://www.example.com/path"));
      assert.notEqual(c, null);
      assert.equal(c!.domain, "www.example.com");
    });

    it("strips leading dot from domain attribute", () => {
      const c = parseSetCookie("k=v; Domain=.example.com", url("https://sub.example.com/"));
      assert.notEqual(c, null);
      assert.equal(c!.domain, "example.com");
    });

    it("accepts domain matching the request hostname", () => {
      const c = parseSetCookie("k=v; Domain=example.com", url("https://example.com/"));
      assert.notEqual(c, null);
      assert.equal(c!.domain, "example.com");
    });

    it("accepts domain that is a parent of request hostname", () => {
      const c = parseSetCookie("k=v; Domain=example.com", url("https://sub.example.com/"));
      assert.notEqual(c, null);
      assert.equal(c!.domain, "example.com");
    });

    it("rejects domain not matching request hostname", () => {
      assert.equal(parseSetCookie("k=v; Domain=other.com", url("https://example.com/")), null);
    });

    it("rejects setting cookies for public suffixes", () => {
      assert.equal(parseSetCookie("k=v; Domain=com", url("https://example.com/")), null);
    });

    it("rejects cross-domain for IP addresses", () => {
      assert.equal(parseSetCookie("k=v; Domain=10.0.0.2", url("http://10.0.0.1/")), null);
    });

    it("allows exact IP match for Domain", () => {
      const c = parseSetCookie("k=v; Domain=10.0.0.1", url("http://10.0.0.1/"));
      assert.notEqual(c, null);
      assert.equal(c!.domain, "10.0.0.1");
    });
  });

  describe("path attribute", () => {
    it("defaults path from the request URI per RFC 6265 §5.1.4", () => {
      const c = parseSetCookie("k=v", url("https://example.com/a/b/c"));
      assert.notEqual(c, null);
      assert.equal(c!.path, "/a/b");
    });

    it("defaults to / when request path is /", () => {
      const c = parseSetCookie("k=v", url("https://example.com/"));
      assert.notEqual(c, null);
      assert.equal(c!.path, "/");
    });

    it("defaults to / when request path has no subdirectory", () => {
      const c = parseSetCookie("k=v", url("https://example.com/page"));
      assert.notEqual(c, null);
      assert.equal(c!.path, "/");
    });

    it("uses explicit Path attribute", () => {
      const c = parseSetCookie("k=v; Path=/api", url("https://example.com/other"));
      assert.notEqual(c, null);
      assert.equal(c!.path, "/api");
    });
  });

  describe("expires and max-age", () => {
    it("parses Expires attribute", () => {
      const c = parseSetCookie("k=v; Expires=Sun, 01 Dec 2030 00:00:00 GMT", url("https://example.com/"));
      assert.notEqual(c, null);
      assert.ok(c!.expires instanceof Date);
      assert.equal(c!.expires!.toUTCString(), "Sun, 01 Dec 2030 00:00:00 GMT");
    });

    it("ignores invalid Expires value", () => {
      const c = parseSetCookie("k=v; Expires=not-a-date", url("https://example.com/"));
      assert.notEqual(c, null);
      assert.equal(c!.expires, undefined);
    });

    it("parses Max-Age attribute", () => {
      const c = parseSetCookie("k=v; Max-Age=3600", url("https://example.com/"));
      assert.notEqual(c, null);
      assert.equal(c!.maxAge, 3600);
    });

    it("caps Max-Age at 400 days (34560000 seconds)", () => {
      const tooLong = 500 * 24 * 60 * 60;
      const maxAllowed = 400 * 24 * 60 * 60;
      const c = parseSetCookie(`k=v; Max-Age=${tooLong}`, url("https://example.com/"));
      assert.notEqual(c, null);
      assert.equal(c!.maxAge, maxAllowed);
    });
  });

  describe("secure and httponly flags", () => {
    it("defaults secure to false", () => {
      const c = parseSetCookie("k=v", url("https://example.com/"));
      assert.notEqual(c, null);
      assert.equal(c!.secure, false);
    });

    it("parses Secure flag", () => {
      const c = parseSetCookie("k=v; Secure", url("https://example.com/"));
      assert.notEqual(c, null);
      assert.equal(c!.secure, true);
    });

    it("defaults httpOnly to false", () => {
      const c = parseSetCookie("k=v", url("https://example.com/"));
      assert.notEqual(c, null);
      assert.equal(c!.httpOnly, false);
    });

    it("parses HttpOnly flag", () => {
      const c = parseSetCookie("k=v; HttpOnly", url("https://example.com/"));
      assert.notEqual(c, null);
      assert.equal(c!.httpOnly, true);
    });
  });

  describe("SameSite attribute", () => {
    it("defaults to Lax when SameSite is omitted", () => {
      const c = parseSetCookie("k=v", url("https://example.com/"));
      assert.notEqual(c, null);
      assert.equal(c!.sameSite, "lax");
    });

    it("parses SameSite=Strict", () => {
      const c = parseSetCookie("k=v; SameSite=Strict", url("https://example.com/"));
      assert.notEqual(c, null);
      assert.equal(c!.sameSite, "strict");
    });

    it("parses SameSite=Lax", () => {
      const c = parseSetCookie("k=v; SameSite=Lax", url("https://example.com/"));
      assert.notEqual(c, null);
      assert.equal(c!.sameSite, "lax");
    });

    it("parses SameSite=None with Secure flag", () => {
      const c = parseSetCookie("k=v; SameSite=None; Secure", url("https://example.com/"));
      assert.notEqual(c, null);
      assert.equal(c!.sameSite, "none");
    });

    it("rejects SameSite=None without Secure", () => {
      assert.equal(parseSetCookie("k=v; SameSite=None", url("https://example.com/")), null);
    });
  });

  describe("Partitioned attribute", () => {
    it("parses Partitioned flag with Secure", () => {
      const c = parseSetCookie("k=v; Partitioned; Secure; SameSite=None", url("https://example.com/"));
      assert.notEqual(c, null);
      assert.equal(c!.partitioned, true);
    });

    it("rejects Partitioned without Secure", () => {
      assert.equal(parseSetCookie("k=v; Partitioned; SameSite=Lax", url("https://example.com/")), null);
    });
  });

  describe("__Host- prefix (RFC 6265bis §4.1.3.1)", () => {
    it("accepts valid __Host- cookie", () => {
      const c = parseSetCookie("__Host-id=abc; Secure; Path=/", url("https://example.com/"));
      assert.notEqual(c, null);
      assert.equal(c!.name, "__Host-id");
    });

    it("rejects __Host- without Secure", () => {
      assert.equal(parseSetCookie("__Host-id=abc; Path=/", url("https://example.com/")), null);
    });

    it("rejects __Host- with non-/ path", () => {
      assert.equal(parseSetCookie("__Host-id=abc; Secure; Path=/foo", url("https://example.com/")), null);
    });

    it("rejects __Host- with Domain attribute different from request host", () => {
      assert.equal(parseSetCookie("__Host-id=abc; Secure; Path=/; Domain=example.com", url("https://sub.example.com/")), null);
    });
  });

  describe("__Secure- prefix (RFC 6265bis §4.1.3.2)", () => {
    it("accepts valid __Secure- cookie", () => {
      const c = parseSetCookie("__Secure-token=xyz; Secure", url("https://example.com/"));
      assert.notEqual(c, null);
      assert.equal(c!.name, "__Secure-token");
    });

    it("rejects __Secure- without Secure", () => {
      assert.equal(parseSetCookie("__Secure-token=xyz", url("https://example.com/")), null);
    });
  });
});

describe("serializeCookies", () => {
  it("returns empty string for empty array", () => {
    assert.equal(serializeCookies([]), "");
  });

  it("serializes single cookie", () => {
    const cookies = [{ name: "a", value: "1" }] as any;
    assert.equal(serializeCookies(cookies), "a=1");
  });

  it("serializes multiple cookies with '; ' separator", () => {
    const cookies = [
      { name: "a", value: "1" },
      { name: "b", value: "2" },
      { name: "c", value: "3" },
    ] as any;
    assert.equal(serializeCookies(cookies), "a=1; b=2; c=3");
  });
});
