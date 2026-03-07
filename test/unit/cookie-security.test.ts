import { describe, it } from "node:test";
import assert from "node:assert/strict";
import { parseSetCookie } from "../../src/cookies/parser.js";

describe("Cookie PSL enforcement", () => {
  const baseUrl = new URL("https://example.com/path");

  it("rejects cookie with domain=.com (public suffix)", () => {
    const cookie = parseSetCookie("x=1; Domain=.com", baseUrl);
    assert.equal(cookie, null);
  });

  it("rejects cookie with domain=co.uk (ccSLD)", () => {
    const ukUrl = new URL("https://example.co.uk/path");
    const cookie = parseSetCookie("x=1; Domain=.co.uk", ukUrl);
    assert.equal(cookie, null);
  });

  it("rejects cookie with domain=github.io (hosting suffix)", () => {
    const ghUrl = new URL("https://myapp.github.io/path");
    const cookie = parseSetCookie("x=1; Domain=.github.io", ghUrl);
    assert.equal(cookie, null);
  });

  it("accepts cookie with valid registrable domain", () => {
    const cookie = parseSetCookie("x=1; Domain=example.com", baseUrl);
    assert.ok(cookie);
    assert.equal(cookie.domain, "example.com");
  });

  it("accepts cookie with no Domain attribute", () => {
    const cookie = parseSetCookie("session=abc", baseUrl);
    assert.ok(cookie);
    assert.equal(cookie.domain, "example.com");
  });
});

describe("SameSite default", () => {
  const baseUrl = new URL("https://example.com/");

  it("defaults SameSite to lax when not specified", () => {
    const cookie = parseSetCookie("id=42; Secure", baseUrl);
    assert.ok(cookie);
    assert.equal(cookie.sameSite, "lax");
  });

  it("preserves explicit SameSite=none", () => {
    const cookie = parseSetCookie("id=42; Secure; SameSite=None", baseUrl);
    assert.ok(cookie);
    assert.equal(cookie.sameSite, "none");
  });

  it("preserves explicit SameSite=strict", () => {
    const cookie = parseSetCookie("id=42; SameSite=Strict", baseUrl);
    assert.ok(cookie);
    assert.equal(cookie.sameSite, "strict");
  });

  it("preserves explicit SameSite=lax", () => {
    const cookie = parseSetCookie("id=42; SameSite=Lax", baseUrl);
    assert.ok(cookie);
    assert.equal(cookie.sameSite, "lax");
  });
});

describe("Cookie prefix validation (__Host- and __Secure-)", () => {
  it("accepts valid __Host- cookie", () => {
    const url = new URL("https://example.com/");
    const cookie = parseSetCookie("__Host-id=1; Secure; Path=/", url);
    assert.ok(cookie);
    assert.equal(cookie.name, "__Host-id");
    assert.equal(cookie.secure, true);
    assert.equal(cookie.path, "/");
  });

  it("rejects __Host- cookie without Secure", () => {
    const url = new URL("https://example.com/");
    const cookie = parseSetCookie("__Host-id=1; Path=/", url);
    assert.equal(cookie, null);
  });

  it("rejects __Host- cookie with Domain attribute", () => {
    const url = new URL("https://sub.example.com/");
    const cookie = parseSetCookie("__Host-id=1; Secure; Path=/; Domain=example.com", url);
    assert.equal(cookie, null);
  });

  it("rejects __Host- cookie with path != /", () => {
    const url = new URL("https://example.com/api");
    const cookie = parseSetCookie("__Host-id=1; Secure; Path=/api", url);
    assert.equal(cookie, null);
  });

  it("accepts valid __Secure- cookie", () => {
    const url = new URL("https://example.com/");
    const cookie = parseSetCookie("__Secure-token=abc; Secure", url);
    assert.ok(cookie);
    assert.equal(cookie.name, "__Secure-token");
  });

  it("rejects __Secure- cookie without Secure", () => {
    const url = new URL("https://example.com/");
    const cookie = parseSetCookie("__Secure-token=abc", url);
    assert.equal(cookie, null);
  });
});
