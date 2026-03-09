import { get, createSession, NLcURLError, validateUrlSafety, CookieJar } from "../../../../src/index.js";
import { parseSetCookie } from "../../../../src/cookies/parser.js";
import { HPACKEncoder, HPACKDecoder } from "../../../../src/http/h2/hpack.js";
import { DNSCache } from "../../../../src/dns/cache.js";
import { RTYPE } from "../../../../src/dns/types.js";
import { encodeRequest } from "../../../../src/http/h1/encoder.js";
import { HttpResponseParser } from "../../../../src/http/h1/parser.js";
import { assertPlainObject } from "../../../../src/core/validation.js";
import { test, assertEqual, assert, assertIncludes, getBaseURL } from "../runner.js";

export default async function () {
  const BASE = getBaseURL();

  await test("blocks request to dangerous port (FTP 21)", async () => {
    try {
      validateUrlSafety("https://example.com:21/resource");
      assert(false, "should have thrown");
    } catch (err: any) {
      assertIncludes(err.message, "dangerous port", "error message");
    }
  });

  await test("blocks request to dangerous port (SMTP 25)", async () => {
    try {
      validateUrlSafety("https://example.com:25/mail");
      assert(false, "should have thrown");
    } catch (err: any) {
      assertIncludes(err.message, "dangerous port", "error message");
    }
  });

  await test("allows request to standard ports", async () => {
    validateUrlSafety("https://example.com:443/ok");
    validateUrlSafety("http://example.com:80/ok");
    validateUrlSafety("https://example.com:8080/ok");
  });

  await test("blocks request to private IPv4 (127.0.0.1)", async () => {
    try {
      validateUrlSafety("http://127.0.0.1:8080/internal");
      assert(false, "should have thrown");
    } catch (err: any) {
      assertIncludes(err.message, "private", "error message");
    }
  });

  await test("blocks request to private IPv4 (10.x.x.x)", async () => {
    try {
      validateUrlSafety("http://10.0.0.1/secret");
      assert(false, "should have thrown");
    } catch (err: any) {
      assertIncludes(err.message, "private", "error message");
    }
  });

  await test("blocks request to private IPv4 (192.168.x.x)", async () => {
    try {
      validateUrlSafety("http://192.168.1.1/admin");
      assert(false, "should have thrown");
    } catch (err: any) {
      assertIncludes(err.message, "private", "error message");
    }
  });

  await test("blocks request to IPv6 loopback (::1)", async () => {
    try {
      validateUrlSafety("http://[::1]:3000/api");
      assert(false, "should have thrown");
    } catch (err: any) {
      assertIncludes(err.message, "private", "error message");
    }
  });

  await test("allowPrivateIPs option bypasses check", async () => {
    validateUrlSafety("http://127.0.0.1:8080/ok", { allowPrivateIPs: true });
    validateUrlSafety("http://10.0.0.1/ok", { allowPrivateIPs: true });
  });

  await test("allowDangerousPorts option bypasses check", async () => {
    validateUrlSafety("https://example.com:21/ok", { allowDangerousPorts: true });
  });

  await test("rejects excessively long URLs", async () => {
    const longUrl = "https://example.com/" + "a".repeat(70000);
    try {
      validateUrlSafety(longUrl);
      assert(false, "should have thrown");
    } catch (err: any) {
      assertIncludes(err.message, "maximum length", "error message");
    }
  });

  await test("detects redirect loop (A → B → A)", async () => {
    try {
      await get(`${BASE}/redirect/loop-a`, { insecure: true });
      assert(false, "should have thrown on redirect loop");
    } catch (err: any) {
      assertIncludes(err.message, "loop", "error should mention loop");
    }
  });

  await test("detects self-referencing redirect", async () => {
    try {
      await get(`${BASE}/redirect/self`, { insecure: true });
      assert(false, "should have thrown on self redirect");
    } catch (err: any) {
      assertIncludes(err.message, "loop", "error should mention loop");
    }
  });

  await test("caps Max-Age at 400 days", async () => {
    const url = new URL(`${BASE}/cookies/maxage`);
    const cookie = parseSetCookie("huge=capped; Path=/; Max-Age=999999999", url);
    assert(cookie !== null, "cookie should be parsed");
    const maxAllowed = 400 * 24 * 60 * 60;
    assert(cookie!.maxAge! <= maxAllowed, `maxAge ${cookie!.maxAge} should be <= ${maxAllowed}`);
  });

  await test("limits Set-Cookie headers per response to 50", async () => {
    const session = createSession({ insecure: true });
    try {
      await session.get(`${BASE}/cookies/many`);
      const jar = session.getCookies()!;
      assert(jar.size <= 50, `should have at most 50 cookies, got ${jar.size}`);
    } finally {
      session.close();
    }
  });

  await test("HPACK decoder rejects oversized header list", async () => {
    const encoder = new HPACKEncoder(4096);
    const headers: Array<[string, string]> = [];
    for (let i = 0; i < 400; i++) {
      headers.push([`x-large-${String(i).padStart(4, "0")}`, "a".repeat(620)]);
    }
    const encoded = encoder.encode(headers);

    const decoder = new HPACKDecoder(4096);
    try {
      decoder.decode(encoded);
      assert(false, "should have thrown on oversized header list");
    } catch (err: any) {
      assertIncludes(err.message, "exceeds limit", "error message");
    }
  });

  await test("HPACK decoder rejects excessive header count", async () => {
    const encoder = new HPACKEncoder(4096);
    const headers: Array<[string, string]> = [];
    for (let i = 0; i < 600; i++) {
      headers.push([`x-h-${i}`, "v"]);
    }
    const encoded = encoder.encode(headers);

    const decoder = new HPACKDecoder(4096, 10 * 1024 * 1024);
    try {
      decoder.decode(encoded);
      assert(false, "should have thrown on too many headers");
    } catch (err: any) {
      assertIncludes(err.message, "too many headers", "error message");
    }
  });

  await test("rejects mismatched Content-Length on request", async () => {
    try {
      encodeRequest(
        {
          url: "https://example.com/test",
          method: "POST",
          body: "hello",
          headers: { "content-length": "999" },
        },
        [],
      );
      assert(false, "should have thrown on CL mismatch");
    } catch (err: any) {
      assertIncludes(err.message, "Content-Length mismatch", "error message");
    }
  });

  await test("accepts matching Content-Length on request", async () => {
    const buf = encodeRequest(
      {
        url: "https://example.com/test",
        method: "POST",
        body: "hello",
        headers: { "content-length": "5" },
      },
      [],
    );
    assert(buf.length > 0, "should produce encoded request");
  });

  await test("H1 parser rejects excessive header count", async () => {
    const parser = new HttpResponseParser("GET");
    let response = "HTTP/1.1 200 OK\r\n";
    for (let i = 0; i < 510; i++) {
      response += `x-header-${i}: value\r\n`;
    }
    response += "\r\n";

    try {
      parser.feed(Buffer.from(response, "latin1"));
      assert(false, "should have thrown on too many headers");
    } catch (err: any) {
      assertIncludes(err.message, "Too many", "error message");
    }
  });

  await test("DNS cache detects rebinding attack", async () => {
    const cache = new DNSCache({ pinning: true });
    cache.set("example.com", "A", [{ name: "example.com", type: RTYPE.A, ttl: 300, data: Buffer.from("93.184.216.34") }]);

    try {
      cache.set("example.com", "A", [{ name: "example.com", type: RTYPE.A, ttl: 300, data: Buffer.from("127.0.0.1") }]);
      assert(false, "should have thrown on DNS rebinding");
    } catch (err: any) {
      assertIncludes(err.message, "rebinding", "error message");
    }
  });

  await test("DNS cache allows same addresses on re-resolution", async () => {
    const cache = new DNSCache({ pinning: true });
    cache.set("stable.com", "A", [{ name: "stable.com", type: RTYPE.A, ttl: 300, data: Buffer.from("1.2.3.4") }]);

    cache.set("stable.com", "A", [{ name: "stable.com", type: RTYPE.A, ttl: 300, data: Buffer.from("1.2.3.4") }]);
  });

  await test("rejects objects with __proto__ key", async () => {
    const malicious = JSON.parse('{"__proto__": {"admin": true}, "name": "test"}');
    try {
      assertPlainObject(malicious, "config");
      assert(false, "should have thrown on __proto__");
    } catch (err: any) {
      assertIncludes(err.message, "prototype pollution", "error message");
    }
  });

  await test("session blocks requests to dangerous ports", async () => {
    const session = createSession({ insecure: true, blockDangerousPorts: true });
    try {
      await session.get("https://example.com:21/ftp-attempt");
      assert(false, "should have thrown");
    } catch (err: any) {
      assertIncludes(err.message, "dangerous port", "error message");
    } finally {
      session.close();
    }
  });

  await test("session blocks private IPs when configured", async () => {
    const session = createSession({ insecure: true, blockPrivateIPs: true });
    try {
      await session.get("http://127.0.0.1:8080/internal");
      assert(false, "should have thrown");
    } catch (err: any) {
      assertIncludes(err.message, "private", "error message");
    } finally {
      session.close();
    }
  });

  await test("session allows private IPs by default", async () => {
    const session = createSession({ insecure: true });
    try {
      const res = await session.get(`${BASE}/json`);
      assertEqual(res.status, 200, "should succeed");
    } finally {
      session.close();
    }
  });
}
