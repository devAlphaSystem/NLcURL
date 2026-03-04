import { describe, it } from "node:test";
import assert from "node:assert/strict";
import { CookieJar } from "../../src/cookies/jar.js";

describe("CookieJar with rawHeaders", () => {
  it("stores multiple cookies from rawHeaders", () => {
    const jar = new CookieJar();
    const url = new URL("https://example.com");

    jar.setCookies({ "set-cookie": "a=1, b=2" }, url, [
      ["set-cookie", "a=1; Path=/"],
      ["set-cookie", "b=2; Path=/"],
      ["content-type", "text/html"],
    ]);

    const header = jar.getCookieHeader(new URL("https://example.com/"));
    assert.ok(header.includes("a=1"), "should contain cookie a");
    assert.ok(header.includes("b=2"), "should contain cookie b");
    assert.equal(jar.size, 2);
  });

  it("handles three Set-Cookie headers", () => {
    const jar = new CookieJar();
    const url = new URL("https://example.com");

    jar.setCookies({}, url, [
      ["set-cookie", "session=abc; Path=/; HttpOnly"],
      ["set-cookie", "csrf=xyz; Path=/"],
      ["set-cookie", "prefs=dark; Path=/; Max-Age=86400"],
    ]);

    assert.equal(jar.size, 3);
    const header = jar.getCookieHeader(new URL("https://example.com/"));
    assert.ok(header.includes("session=abc"), "should include session");
    assert.ok(header.includes("csrf=xyz"), "should include csrf");
    assert.ok(header.includes("prefs=dark"), "should include prefs");
  });

  it("falls back to Record when rawHeaders not provided", () => {
    const jar = new CookieJar();
    const url = new URL("https://example.com");

    jar.setCookies({ "set-cookie": "token=abc; Path=/" }, url);

    assert.equal(jar.size, 1);
    const header = jar.getCookieHeader(new URL("https://example.com/"));
    assert.ok(header.includes("token=abc"));
  });

  it("handles Set-Cookie with expires containing comma", () => {
    const jar = new CookieJar();
    const url = new URL("https://example.com");

    jar.setCookies({}, url, [["set-cookie", "id=42; Expires=Thu, 01 Jan 2099 00:00:00 GMT; Path=/"]]);

    assert.equal(jar.size, 1);
    const cookies = jar.all();
    assert.equal(cookies[0]!.name, "id");
    assert.ok(cookies[0]!.expires instanceof Date);
  });

  it("ignores non-set-cookie rawHeaders", () => {
    const jar = new CookieJar();
    const url = new URL("https://example.com");

    jar.setCookies({}, url, [
      ["content-type", "text/html"],
      ["set-cookie", "x=1; Path=/"],
      ["cache-control", "no-cache"],
    ]);

    assert.equal(jar.size, 1);
  });

  it("handles case-insensitive rawHeader names", () => {
    const jar = new CookieJar();
    const url = new URL("https://example.com");

    jar.setCookies({}, url, [
      ["Set-Cookie", "a=1; Path=/"],
      ["SET-COOKIE", "b=2; Path=/"],
      ["set-cookie", "c=3; Path=/"],
    ]);

    assert.equal(jar.size, 3);
  });
});
