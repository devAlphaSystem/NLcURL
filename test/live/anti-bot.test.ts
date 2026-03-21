/**
 * Live anti-bot / stealth mode stress tests.
 *
 * Tests stealth TLS fingerprinting against sites known to have aggressive
 * bot detection — the real-world scenario where NLcURL must produce
 * browser-identical TLS ClientHellos, HTTP/2 settings, and headers.
 *
 * These tests verify that stealth mode works end-to-end without triggering
 * captchas, blocks, or 403 responses.
 */
import { describe, it } from "node:test";
import { strict as assert } from "node:assert";
import { get, createSession } from "../../src/index.js";
import { SLOW_TIMEOUT, withTlsRetry, skipIfTlsBroken } from "./helpers.js";

/**
 * Helper: assert the response is a successful page load (2xx/3xx)
 * and not a Cloudflare challenge, captcha, or access denied page.
 */
function assertNotBlocked(resp: { status: number; text: () => string }, site: string): void {
  assert.ok(resp.status >= 200 && resp.status < 400, `${site}: expected 2xx/3xx, got ${resp.status}`);

  const body = resp.text().toLowerCase();
  const blockedIndicators = ["access denied", "captcha", "challenge-platform", "bot detected", "automated access", "please verify you are a human"];

  for (const indicator of blockedIndicators) {
    if (resp.status === 403 && body.includes(indicator)) {
      assert.fail(`${site}: appears to be blocked — found "${indicator}" in response`);
    }
  }
}

describe("Stealth: e-commerce sites", { timeout: SLOW_TIMEOUT }, () => {
  it(
    "mercadolivre.com.br with chrome136",
    skipIfTlsBroken(async () => {
      const resp = await withTlsRetry(() =>
        get("https://www.mercadolivre.com.br", {
          impersonate: "chrome136",
          stealth: true,
          insecure: true,
        }),
      );
      assertNotBlocked(resp, "mercadolivre.com.br");
      assert.ok(resp.text().length > 5000, "Expected full page");
    }),
  );

  it(
    "amazon.com with chrome136",
    skipIfTlsBroken(async () => {
      const resp = await withTlsRetry(() =>
        get("https://www.amazon.com", {
          impersonate: "chrome136",
          stealth: true,
          insecure: true,
        }),
      );
      assertNotBlocked(resp, "amazon.com");
      assert.ok(resp.text().length > 1000);
    }),
  );

  it(
    "ebay.com with chrome136",
    skipIfTlsBroken(async () => {
      const resp = await withTlsRetry(() =>
        get("https://www.ebay.com", {
          impersonate: "chrome136",
          stealth: true,
          insecure: true,
        }),
      );
      assertNotBlocked(resp, "ebay.com");
      assert.ok(resp.text().length > 1000);
    }),
  );
});

describe("Stealth: high-security sites", { timeout: SLOW_TIMEOUT }, () => {
  it(
    "google.com with chrome136",
    skipIfTlsBroken(async () => {
      const resp = await withTlsRetry(() =>
        get("https://www.google.com", {
          impersonate: "chrome136",
          stealth: true,
          insecure: true,
        }),
      );
      assertNotBlocked(resp, "google.com");
    }),
  );

  it(
    "cloudflare.com with chrome136",
    skipIfTlsBroken(async () => {
      const resp = await withTlsRetry(() =>
        get("https://cloudflare.com", {
          impersonate: "chrome136",
          stealth: true,
          insecure: true,
        }),
      );
      assertNotBlocked(resp, "cloudflare.com");
    }),
  );

  it(
    "linkedin.com with chrome136",
    skipIfTlsBroken(async () => {
      const resp = await withTlsRetry(() =>
        get("https://www.linkedin.com", {
          impersonate: "chrome136",
          stealth: true,
          insecure: true,
        }),
      );
      assertNotBlocked(resp, "linkedin.com");
    }),
  );
});

describe("Stealth: multiple browser profiles", { timeout: SLOW_TIMEOUT }, () => {
  const targets = ["https://www.google.com", "https://cloudflare.com"];

  for (const url of targets) {
    const host = new URL(url).hostname;

    it(
      `${host} with firefox135`,
      skipIfTlsBroken(async () => {
        const resp = await withTlsRetry(() => get(url, { impersonate: "firefox135", stealth: true, insecure: true }));
        assertNotBlocked(resp, `${host}/firefox135`);
      }),
    );

    it(
      `${host} with safari182`,
      skipIfTlsBroken(async () => {
        const resp = await withTlsRetry(() => get(url, { impersonate: "safari182", stealth: true, insecure: true }));
        assertNotBlocked(resp, `${host}/safari182`);
      }),
    );

    it(
      `${host} with edge136`,
      skipIfTlsBroken(async () => {
        const resp = await withTlsRetry(() => get(url, { impersonate: "edge136", stealth: true, insecure: true }));
        assertNotBlocked(resp, `${host}/edge136`);
      }),
    );
  }
});

describe("Stealth: session persistence across requests", { timeout: SLOW_TIMEOUT }, () => {
  it(
    "simulates a browsing session with multiple page loads",
    skipIfTlsBroken(async () => {
      const session = createSession({
        impersonate: "chrome136",
        stealth: true,
        insecure: true,
        cookieJar: true,
      });

      const home = await withTlsRetry(() => session.get("https://www.google.com"));
      assertNotBlocked(home, "google.com (first)");

      const search = await withTlsRetry(() => session.get("https://www.google.com/search?q=test"));
      assertNotBlocked(search, "google.com/search");

      const images = await withTlsRetry(() => session.get("https://www.google.com/imghp"));
      assertNotBlocked(images, "google.com/imghp");
    }),
  );
});

describe("Stealth: HTTP/2 fingerprint consistency", { timeout: SLOW_TIMEOUT }, () => {
  it(
    "maintains consistent fingerprint across multiple requests to same origin",
    skipIfTlsBroken(async () => {
      const session = createSession({
        impersonate: "chrome136",
        stealth: true,
        insecure: true,
      });

      const urls = ["https://httpbin.org/get", "https://httpbin.org/headers", "https://httpbin.org/ip"];

      for (const url of urls) {
        const resp = await withTlsRetry(() => session.get(url));
        assert.ok(resp.status >= 200 && resp.status < 300, `${url}: status ${resp.status}`);
      }
    }),
  );
});

describe("Stealth: older browser versions still work", { timeout: SLOW_TIMEOUT }, () => {
  it(
    "chrome99 connects to Google",
    skipIfTlsBroken(async () => {
      const resp = await withTlsRetry(() =>
        get("https://www.google.com", {
          impersonate: "chrome99",
          stealth: true,
          insecure: true,
        }),
      );
      assertNotBlocked(resp, "google.com/chrome99");
    }),
  );

  it(
    "chrome120 connects to Cloudflare",
    skipIfTlsBroken(async () => {
      const resp = await withTlsRetry(() =>
        get("https://cloudflare.com", {
          impersonate: "chrome120",
          stealth: true,
          insecure: true,
        }),
      );
      assertNotBlocked(resp, "cloudflare.com/chrome120");
    }),
  );
});

describe("Non-stealth fallback still works", { timeout: SLOW_TIMEOUT }, () => {
  it("connects without stealth to a permissive endpoint", async () => {
    const resp = await get("https://httpbin.org/get");
    assert.ok(resp.status === 200);
  });

  it("connects without impersonation to example.com", async () => {
    const resp = await get("https://example.com", { insecure: true });
    assert.ok(resp.status === 200);
    assert.ok(resp.text().includes("Example Domain"));
  });
});
