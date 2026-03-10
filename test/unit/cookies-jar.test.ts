/**
 * Unit tests for src/cookies/jar.ts
 * CookieJar: RFC 6265 storage, SameSite enforcement, domain/path matching,
 * LRU eviction, Netscape format serialization / deserialization.
 */
import { describe, it } from "node:test";
import { strict as assert } from "node:assert";
import { CookieJar } from "../../src/cookies/jar.js";

const u = (s: string) => new URL(s);

function makeHeaders(setCookies: string[]): [Record<string, string>, Array<[string, string]>] {
  const raw: Array<[string, string]> = setCookies.map((v) => ["set-cookie", v]);
  return [{}, raw];
}

describe("CookieJar", () => {
  describe("constructor", () => {
    it("creates empty jar with default limits", () => {
      const jar = new CookieJar();
      assert.equal(jar.size, 0);
    });

    it("accepts custom limits", () => {
      const jar = new CookieJar({ maxCookies: 100, maxCookiesPerDomain: 10 });
      assert.equal(jar.size, 0);
    });
  });

  describe("setCookies and getCookieHeader", () => {
    it("stores cookies from Set-Cookie headers and returns them", () => {
      const jar = new CookieJar();
      const [h, rh] = makeHeaders(["session=abc; Path=/"]);
      jar.setCookies(h, u("https://example.com/"), rh);
      assert.equal(jar.size, 1);
      const header = jar.getCookieHeader(u("https://example.com/api"));
      assert.equal(header, "session=abc");
    });

    it("stores multiple cookies from the same response", () => {
      const jar = new CookieJar();
      const [h, rh] = makeHeaders(["a=1; Path=/", "b=2; Path=/"]);
      jar.setCookies(h, u("https://example.com/"), rh);
      assert.equal(jar.size, 2);
    });

    it("replaces existing cookie with same name/domain/path", () => {
      const jar = new CookieJar();
      const [h1, rh1] = makeHeaders(["token=old; Path=/"]);
      jar.setCookies(h1, u("https://example.com/"), rh1);
      const [h2, rh2] = makeHeaders(["token=new; Path=/"]);
      jar.setCookies(h2, u("https://example.com/"), rh2);
      assert.equal(jar.size, 1);
      assert.equal(jar.getCookieHeader(u("https://example.com/")), "token=new");
    });

    it("limits Set-Cookie processing to 50 per response", () => {
      const jar = new CookieJar();
      const cookies: string[] = [];
      for (let i = 0; i < 60; i++) cookies.push(`c${i}=v; Path=/`);
      const [h, rh] = makeHeaders(cookies);
      jar.setCookies(h, u("https://example.com/"), rh);
      assert.equal(jar.size, 50);
    });

    it("deletes cookie when Max-Age=0", () => {
      const jar = new CookieJar();
      const [h1, rh1] = makeHeaders(["sess=val; Path=/"]);
      jar.setCookies(h1, u("https://example.com/"), rh1);
      assert.equal(jar.size, 1);
      const [h2, rh2] = makeHeaders(["sess=val; Path=/; Max-Age=0"]);
      jar.setCookies(h2, u("https://example.com/"), rh2);
      assert.equal(jar.size, 0);
    });
  });

  describe("domain matching", () => {
    it("matches exact domain", () => {
      const jar = new CookieJar();
      const [h, rh] = makeHeaders(["k=v; Path=/"]);
      jar.setCookies(h, u("https://example.com/"), rh);
      assert.ok(jar.getCookieHeader(u("https://example.com/")).includes("k=v"));
    });

    it("matches subdomains when domain is parent", () => {
      const jar = new CookieJar();
      const [h, rh] = makeHeaders(["k=v; Domain=example.com; Path=/"]);
      jar.setCookies(h, u("https://sub.example.com/"), rh);
      assert.ok(jar.getCookieHeader(u("https://sub.example.com/")).includes("k=v"));
      assert.ok(jar.getCookieHeader(u("https://other.example.com/")).includes("k=v"));
    });

    it("does not match unrelated domains", () => {
      const jar = new CookieJar();
      const [h, rh] = makeHeaders(["k=v; Path=/"]);
      jar.setCookies(h, u("https://example.com/"), rh);
      assert.equal(jar.getCookieHeader(u("https://other.com/")), "");
    });
  });

  describe("path matching", () => {
    it("matches when request path starts with cookie path", () => {
      const jar = new CookieJar();
      const [h, rh] = makeHeaders(["k=v; Path=/api"]);
      jar.setCookies(h, u("https://example.com/"), rh);
      assert.ok(jar.getCookieHeader(u("https://example.com/api/users")).includes("k=v"));
    });

    it("does not match when path does not match", () => {
      const jar = new CookieJar();
      const [h, rh] = makeHeaders(["k=v; Path=/api"]);
      jar.setCookies(h, u("https://example.com/"), rh);
      assert.equal(jar.getCookieHeader(u("https://example.com/other")), "");
    });

    it("sorts by longest path first", () => {
      const jar = new CookieJar();
      const [h, rh] = makeHeaders(["a=1; Path=/", "b=2; Path=/api"]);
      jar.setCookies(h, u("https://example.com/"), rh);
      const header = jar.getCookieHeader(u("https://example.com/api"));
      assert.ok(header.startsWith("b=2"));
    });
  });

  describe("Secure flag enforcement", () => {
    it("excludes Secure cookies from HTTP requests", () => {
      const jar = new CookieJar();
      const [h, rh] = makeHeaders(["k=v; Secure; Path=/; SameSite=Lax"]);
      jar.setCookies(h, u("https://example.com/"), rh);
      assert.equal(jar.getCookieHeader(u("http://example.com/")), "");
    });

    it("includes Secure cookies for HTTPS requests", () => {
      const jar = new CookieJar();
      const [h, rh] = makeHeaders(["k=v; Secure; Path=/; SameSite=Lax"]);
      jar.setCookies(h, u("https://example.com/"), rh);
      assert.ok(jar.getCookieHeader(u("https://example.com/")).includes("k=v"));
    });
  });

  describe("SameSite enforcement", () => {
    it("excludes Strict cookies in cross-site context", () => {
      const jar = new CookieJar();
      const [h, rh] = makeHeaders(["k=v; SameSite=Strict; Path=/"]);
      jar.setCookies(h, u("https://example.com/"), rh);
      assert.equal(jar.getCookieHeader(u("https://example.com/"), { isSameSite: false }), "");
    });

    it("excludes Lax cookies in cross-site subresource requests", () => {
      const jar = new CookieJar();
      const [h, rh] = makeHeaders(["k=v; SameSite=Lax; Path=/"]);
      jar.setCookies(h, u("https://example.com/"), rh);
      assert.equal(
        jar.getCookieHeader(u("https://example.com/"), {
          isSameSite: false,
          type: "subresource",
        }),
        "",
      );
    });

    it("includes Lax cookies for cross-site safe top-level navigation (GET)", () => {
      const jar = new CookieJar();
      const [h, rh] = makeHeaders(["k=v; SameSite=Lax; Path=/"]);
      jar.setCookies(h, u("https://example.com/"), rh);
      const header = jar.getCookieHeader(u("https://example.com/"), {
        isSameSite: false,
        type: "navigate",
        method: "GET",
      });
      assert.ok(header.includes("k=v"));
    });

    it("excludes Lax cookies for cross-site POST navigation", () => {
      const jar = new CookieJar();
      const [h, rh] = makeHeaders(["k=v; SameSite=Lax; Path=/"]);
      jar.setCookies(h, u("https://example.com/"), rh);
      assert.equal(
        jar.getCookieHeader(u("https://example.com/"), {
          isSameSite: false,
          type: "navigate",
          method: "POST",
        }),
        "",
      );
    });

    it("includes SameSite=None cookies in cross-site context", () => {
      const jar = new CookieJar();
      const [h, rh] = makeHeaders(["k=v; SameSite=None; Secure; Path=/"]);
      jar.setCookies(h, u("https://example.com/"), rh);
      const header = jar.getCookieHeader(u("https://example.com/"), { isSameSite: false });
      assert.ok(header.includes("k=v"));
    });
  });

  describe("expired cookie exclusion", () => {
    it("excludes cookies past their Max-Age", () => {
      const jar = new CookieJar();
      const [h, rh] = makeHeaders(["k=v; Max-Age=-1; Path=/"]);
      jar.setCookies(h, u("https://example.com/"), rh);
      assert.equal(jar.size, 0);
    });

    it("excludes cookies past their Expires date", () => {
      const jar = new CookieJar();
      const [h, rh] = makeHeaders(["k=v; Expires=Thu, 01 Jan 1970 00:00:00 GMT; Path=/"]);
      jar.setCookies(h, u("https://example.com/"), rh);
      const header = jar.getCookieHeader(u("https://example.com/"));
      assert.equal(header, "");
    });
  });

  describe("LRU eviction", () => {
    it("evicts least-recently-used when per-domain limit is exceeded", () => {
      const jar = new CookieJar({ maxCookiesPerDomain: 3 });
      for (let i = 0; i < 4; i++) {
        const [h, rh] = makeHeaders([`c${i}=v; Path=/p${i}`]);
        jar.setCookies(h, u("https://example.com/"), rh);
      }
      assert.equal(jar.size, 3);
    });

    it("evicts from the domain with the most cookies on global limit", () => {
      const jar = new CookieJar({ maxCookies: 5, maxCookiesPerDomain: 10 });
      for (let i = 0; i < 4; i++) {
        const [h, rh] = makeHeaders([`c${i}=v; Path=/p${i}`]);
        jar.setCookies(h, u("https://a.com/"), rh);
      }
      const [h2, rh2] = makeHeaders(["x=y; Path=/", "y=z; Path=/y"]);
      jar.setCookies(h2, u("https://b.com/"), rh2);
      assert.ok(jar.size <= 5);
    });
  });

  describe("clear and clearDomain", () => {
    it("clear() removes all cookies", () => {
      const jar = new CookieJar();
      const [h, rh] = makeHeaders(["a=1; Path=/", "b=2; Path=/"]);
      jar.setCookies(h, u("https://example.com/"), rh);
      jar.clear();
      assert.equal(jar.size, 0);
    });

    it("clearDomain() only removes cookies for that domain", () => {
      const jar = new CookieJar();
      const [h1, rh1] = makeHeaders(["a=1; Path=/"]);
      jar.setCookies(h1, u("https://a.com/"), rh1);
      const [h2, rh2] = makeHeaders(["b=2; Path=/"]);
      jar.setCookies(h2, u("https://b.com/"), rh2);
      jar.clearDomain("a.com");
      assert.equal(jar.size, 1);
      assert.equal(jar.getCookieHeader(u("https://b.com/")), "b=2");
    });
  });

  describe("all()", () => {
    it("excludes httpOnly cookies by default", () => {
      const jar = new CookieJar();
      const [h, rh] = makeHeaders(["pub=1; Path=/", "priv=2; HttpOnly; Path=/"]);
      jar.setCookies(h, u("https://example.com/"), rh);
      const all = jar.all();
      assert.equal(all.length, 1);
      assert.equal(all[0]!.name, "pub");
    });

    it("includes httpOnly cookies when includeHttpOnly=true", () => {
      const jar = new CookieJar();
      const [h, rh] = makeHeaders(["pub=1; Path=/", "priv=2; HttpOnly; Path=/"]);
      jar.setCookies(h, u("https://example.com/"), rh);
      const all = jar.all({ includeHttpOnly: true });
      assert.equal(all.length, 2);
    });
  });

  describe("Netscape format round-trip", () => {
    it("serializes and loads cookies in Netscape format", () => {
      const jar = new CookieJar();
      const [h, rh] = makeHeaders(["session=abc; Secure; Path=/; SameSite=None", "lang=en; Path=/"]);
      jar.setCookies(h, u("https://example.com/"), rh);
      const netscape = jar.toNetscapeString();

      assert.ok(netscape.startsWith("# Netscape HTTP Cookie File"));
      assert.ok(netscape.includes("session"));
      assert.ok(netscape.includes("lang"));

      const jar2 = new CookieJar();
      jar2.loadNetscapeString(netscape);
      assert.ok(jar2.size >= 1);
    });

    it("loadNetscapeString skips comment and blank lines", () => {
      const jar = new CookieJar();
      jar.loadNetscapeString("# comment\n\n");
      assert.equal(jar.size, 0);
    });

    it("loadNetscapeString validates __Host- prefix rules", () => {
      const jar = new CookieJar();
      jar.loadNetscapeString(".example.com\tTRUE\t/\tTRUE\t0\t__Host-id\tabc\tFALSE");
      assert.equal(jar.size, 0);
    });

    it("loadNetscapeString validates __Secure- prefix rules", () => {
      const jar = new CookieJar();
      jar.loadNetscapeString(".example.com\tTRUE\t/\tFALSE\t0\t__Secure-tok\txyz\tFALSE");
      assert.equal(jar.size, 0);
    });

    it("loadNetscapeString skips expired cookies", () => {
      const jar = new CookieJar();
      jar.loadNetscapeString(".example.com\tTRUE\t/\tFALSE\t1\texpired\tval\tFALSE");
      assert.equal(jar.size, 0);
    });
  });

  describe("Cookie header length limit", () => {
    it("truncates Cookie header to fit within 8190 bytes", () => {
      const jar = new CookieJar();
      const cookies: string[] = [];
      for (let i = 0; i < 100; i++) {
        cookies.push(`cookie${i}=${"x".repeat(80)}; Path=/`);
      }
      const [h, rh] = makeHeaders(cookies);
      jar.setCookies(h, u("https://example.com/"), rh);
      const header = jar.getCookieHeader(u("https://example.com/"));
      assert.ok(Buffer.byteLength(header, "utf-8") <= 8190);
    });
  });

  describe("MAX_COOKIES_PER_REQUEST (150)", () => {
    it("caps the number of cookies per request at 150", () => {
      const jar = new CookieJar({ maxCookies: 5000, maxCookiesPerDomain: 5000 });
      const cookies: string[] = [];
      for (let i = 0; i < 200; i++) {
        cookies.push(`c${i}=v; Path=/p${i}`);
      }
      for (let batch = 0; batch < 4; batch++) {
        const batch50 = cookies.slice(batch * 50, (batch + 1) * 50);
        const [h, rh] = makeHeaders(batch50);
        jar.setCookies(h, u("https://example.com/"), rh);
      }
      jar.clear();
      for (let i = 0; i < 200; i++) {
        const [h, rh] = makeHeaders([`c${i}=v; Path=/`]);
        jar.setCookies(h, u("https://example.com/"), rh);
      }
      const header = jar.getCookieHeader(u("https://example.com/page"));
      const count = header.split("; ").length;
      assert.ok(count <= 150, `Expected <= 150 cookies in header, got ${count}`);
    });
  });
});
