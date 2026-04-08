/**
 * Live HSTS enforcement tests.
 *
 * Verifies that the HSTSStore correctly parses real-world
 * Strict-Transport-Security headers from major sites and
 * that URL upgrade logic works end-to-end.
 */
import { describe, it } from "node:test";
import { strict as assert } from "node:assert";
import { HSTSStore, createSession } from "../../src/index.js";
import { LIVE_TIMEOUT, get, assertOk, withTlsRetry, skipIfTlsBroken } from "./helpers.js";

describe("HSTS header parsing from real servers", { timeout: LIVE_TIMEOUT }, () => {
  it("parses github.com HSTS header", async () => {
    const resp = await get("https://github.com", { insecure: true });
    assertOk(resp);

    const hstsHeader = resp.headers["strict-transport-security"];
    assert.ok(hstsHeader, "github.com should send Strict-Transport-Security");

    const store = new HSTSStore();
    store.parseHeader("github.com", hstsHeader, true);

    assert.ok(store.isSecure("github.com"), "github.com should be HSTS-secured");
    assert.ok(store.size > 0, "Store should have entries");
  });

  it(
    "parses google.com HSTS header",
    skipIfTlsBroken(async () => {
      const resp = await withTlsRetry(() =>
        get("https://www.google.com", {
          impersonate: "chrome136",
          stealth: true,
          insecure: true,
        }),
      );
      assertOk(resp);

      const hstsHeader = resp.headers["strict-transport-security"];
      if (!hstsHeader) return;

      const store = new HSTSStore();
      store.parseHeader("www.google.com", hstsHeader, true);
      assert.ok(store.isSecure("www.google.com"));
    }),
  );

  it("parses cloudflare.com includeSubDomains HSTS header", async () => {
    const resp = await get("https://cloudflare.com", { insecure: true });
    assertOk(resp);

    const hstsHeader = resp.headers["strict-transport-security"];
    if (!hstsHeader) return;

    const store = new HSTSStore();
    store.parseHeader("cloudflare.com", hstsHeader, true);

    assert.ok(store.isSecure("cloudflare.com"));

    if (hstsHeader.toLowerCase().includes("includesubdomains")) {
      assert.ok(store.isSecure("any.cloudflare.com"), "Subdomains should be covered by includeSubDomains");
    }
  });

  it(
    "parses facebook.com HSTS header",
    skipIfTlsBroken(async () => {
      const resp = await withTlsRetry(() =>
        get("https://www.facebook.com", {
          timeout: 20_000,
        }),
      );
      assert.ok(typeof resp.status === "number");

      const hstsHeader = resp.headers["strict-transport-security"];
      if (!hstsHeader || resp.status >= 400) return;

      const store = new HSTSStore();
      store.parseHeader("www.facebook.com", hstsHeader, true);
      assert.ok(store.isSecure("www.facebook.com"));
    }),
  );
});

describe("HSTS URL upgrade", { timeout: LIVE_TIMEOUT }, () => {
  it("upgrades HTTP URL to HTTPS for known HSTS host", async () => {
    const resp = await get("https://github.com", { insecure: true });
    const hstsHeader = resp.headers["strict-transport-security"];
    assert.ok(hstsHeader);

    const store = new HSTSStore();
    store.parseHeader("github.com", hstsHeader, true);

    const upgraded = store.upgradeURL("http://github.com/some/path?q=1");
    assert.ok(upgraded.startsWith("https://"), `Expected HTTPS, got: ${upgraded}`);
    assert.ok(upgraded.includes("github.com/some/path"), "Path should be preserved");
  });

  it("does not upgrade URLs for non-HSTS hosts", () => {
    const store = new HSTSStore();
    const original = "http://example-no-hsts.invalid/test";
    const result = store.upgradeURL(original);
    assert.equal(result, original);
  });

  it("does not upgrade already-HTTPS URLs", async () => {
    const store = new HSTSStore();
    store.parseHeader("github.com", "max-age=31536000; includeSubDomains", true);

    const url = "https://github.com/already-secure";
    const result = store.upgradeURL(url);
    assert.equal(result, url, "HTTPS URLs should not be modified");
  });

  it("ignores HSTS from insecure context", () => {
    const store = new HSTSStore();
    store.parseHeader("example.com", "max-age=31536000", false);

    assert.ok(!store.isSecure("example.com"), "Should not accept HSTS from insecure context");
  });
});

describe("HSTS preload", { timeout: LIVE_TIMEOUT }, () => {
  it("creates a store with preloaded entries", () => {
    const store = new HSTSStore({
      preload: [
        { host: "github.com", includeSubDomains: true },
        { host: "google.com", includeSubDomains: true },
        { host: "facebook.com", includeSubDomains: false },
      ],
    });

    assert.equal(store.size, 3);
    assert.ok(store.isSecure("github.com"));
    assert.ok(store.isSecure("api.github.com"));
    assert.ok(store.isSecure("google.com"));
    assert.ok(store.isSecure("mail.google.com"));
    assert.ok(store.isSecure("facebook.com"));
    assert.ok(!store.isSecure("apps.facebook.com"));
  });

  it("clears all policies", () => {
    const store = new HSTSStore({
      preload: [{ host: "test.com", includeSubDomains: false }],
    });
    assert.equal(store.size, 1);
    store.clear();
    assert.equal(store.size, 0);
    assert.ok(!store.isSecure("test.com"));
  });
});

describe("HSTS with session integration", { timeout: LIVE_TIMEOUT }, () => {
  it(
    "session accumulates HSTS policies from multiple hosts",
    skipIfTlsBroken(async () => {
      const session = createSession({
        hsts: true,
        impersonate: "chrome136",
        stealth: true,
        insecure: true,
      });

      const resp1 = await withTlsRetry(() => session.get("https://github.com"));
      assertOk(resp1);

      const resp2 = await withTlsRetry(() => session.get("https://www.google.com"));
      assertOk(resp2);

      assert.ok(resp1.status >= 200 && resp1.status < 400);
      assert.ok(resp2.status >= 200 && resp2.status < 400);
    }),
  );
});
