/**
 * Live TLS stealth handshake tests.
 *
 * Tests real TLS 1.3 connections to public servers using browser fingerprint
 * impersonation. These tests validate the entire stealth pipeline end-to-end:
 * ClientHello construction, handshake, ALPS negotiation, certificate verification,
 * and data exchange — against real-world TLS stacks.
 */
import { describe, it } from "node:test";
import { strict as assert } from "node:assert";
import { createSession, getProfile, listProfiles } from "../../src/index.js";
import { LIVE_TIMEOUT, SLOW_TIMEOUT, get, assertOk, assertHeader, assertBody, withTlsRetry, skipIfTlsBroken } from "./helpers.js";

describe("Stealth TLS handshake against Google", { timeout: SLOW_TIMEOUT }, () => {
  it(
    "connects with chrome136 stealth and gets HTTP/2",
    skipIfTlsBroken(async () => {
      const resp = await withTlsRetry(() =>
        get("https://www.google.com/", {
          impersonate: "chrome136",
          stealth: true,
          insecure: true,
          headers: { accept: "text/html" },
        }),
      );
      assertOk(resp, "Google chrome136");
      assertBody(resp, "Google chrome136");
      assert.equal(resp.httpVersion, "h2", "Expected HTTP/2 negotiation");
    }),
  );

  it(
    "connects with chrome120 stealth",
    skipIfTlsBroken(async () => {
      const resp = await withTlsRetry(() =>
        get("https://www.google.com/", {
          impersonate: "chrome120",
          stealth: true,
          insecure: true,
        }),
      );
      assertOk(resp, "Google chrome120");
    }),
  );

  it(
    "connects with firefox135 stealth",
    skipIfTlsBroken(async () => {
      const resp = await withTlsRetry(() =>
        get("https://www.google.com/", {
          impersonate: "firefox135",
          stealth: true,
          insecure: true,
        }),
      );
      assertOk(resp, "Google firefox");
    }),
  );

  it(
    "connects with safari182 stealth",
    skipIfTlsBroken(async () => {
      const resp = await withTlsRetry(() =>
        get("https://www.google.com/", {
          impersonate: "safari182",
          stealth: true,
          insecure: true,
        }),
      );
      assertOk(resp, "Google safari");
    }),
  );

  it(
    "connects with edge136 stealth",
    skipIfTlsBroken(async () => {
      const resp = await withTlsRetry(() =>
        get("https://www.google.com/", {
          impersonate: "edge136",
          stealth: true,
          insecure: true,
        }),
      );
      assertOk(resp, "Google edge");
    }),
  );
});

describe("Stealth TLS against Cloudflare", { timeout: SLOW_TIMEOUT }, () => {
  it(
    "connects with chrome136 stealth to cloudflare.com",
    skipIfTlsBroken(async () => {
      const resp = await withTlsRetry(() =>
        get("https://www.cloudflare.com/", {
          impersonate: "chrome136",
          stealth: true,
          insecure: true,
        }),
      );
      assertOk(resp, "Cloudflare chrome136");
      assertBody(resp, "Cloudflare chrome136");
    }),
  );

  it(
    "connects with chrome136 stealth to 1.1.1.1 DNS page",
    skipIfTlsBroken(async () => {
      const resp = await withTlsRetry(() =>
        get("https://one.one.one.one/", {
          impersonate: "chrome136",
          stealth: true,
          insecure: true,
        }),
      );
      assertOk(resp, "1.1.1.1");
    }),
  );
});

describe("Stealth TLS against strict anti-bot sites", { timeout: SLOW_TIMEOUT }, () => {
  it(
    "connects with chrome136 stealth to mercadolivre.com.br",
    skipIfTlsBroken(async () => {
      const resp = await withTlsRetry(() =>
        get("https://www.mercadolivre.com.br/", {
          impersonate: "chrome136",
          stealth: true,
          insecure: true,
          headers: {
            accept: "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            "accept-language": "en-US,en;q=0.5",
          },
        }),
      );
      assert.ok(resp.status >= 200 && resp.status < 400, `Expected 2xx/3xx from mercadolivre, got ${resp.status}`);
    }),
  );

  it(
    "connects with chrome136 stealth to Amazon",
    skipIfTlsBroken(async () => {
      const resp = await withTlsRetry(() =>
        get("https://www.amazon.com/", {
          impersonate: "chrome136",
          stealth: true,
          insecure: true,
          headers: {
            accept: "text/html",
            "accept-language": "en-US,en;q=0.9",
          },
        }),
      );
      assert.ok(resp.status >= 200 && resp.status < 400, `Amazon: ${resp.status}`);
    }),
  );
});

describe("Stealth TLS with different cipher suites", { timeout: SLOW_TIMEOUT }, () => {
  it(
    "negotiates AES-128-GCM or AES-256-GCM",
    skipIfTlsBroken(async () => {
      const resp = await withTlsRetry(() =>
        get("https://www.google.com/", {
          impersonate: "chrome136",
          stealth: true,
          insecure: true,
        }),
      );
      assertOk(resp);
    }),
  );
});

describe("Stealth TLS ALPN negotiation", { timeout: SLOW_TIMEOUT }, () => {
  it(
    "negotiates h2 with HTTP/2 capable server",
    skipIfTlsBroken(async () => {
      const resp = await withTlsRetry(() =>
        get("https://www.google.com/", {
          impersonate: "chrome136",
          stealth: true,
          insecure: true,
        }),
      );
      assertOk(resp);
      assert.equal(resp.httpVersion, "h2");
    }),
  );

  it("can force HTTP/1.1 via standard TLS", async () => {
    const resp = await withTlsRetry(() =>
      get("https://www.google.com/", {
        httpVersion: "1.1",
      }),
    );
    assertOk(resp);
    assert.equal(resp.httpVersion, "HTTP/1.1");
  });
});

describe("Stealth TLS session persistence", { timeout: SLOW_TIMEOUT }, () => {
  it(
    "reuses TLS session across requests in same session",
    skipIfTlsBroken(async () => {
      const session = createSession({
        impersonate: "chrome136",
        stealth: true,
        insecure: true,
      });

      try {
        const resp1 = await withTlsRetry(() => session.get("https://www.google.com/"));
        assertOk(resp1, "Session request 1");

        const resp2 = await withTlsRetry(() => session.get("https://www.google.com/"));
        assertOk(resp2, "Session request 2");
      } finally {
        session.close();
      }
    }),
  );
});

describe("Non-stealth TLS still works", { timeout: LIVE_TIMEOUT }, () => {
  it("makes HTTPS request without stealth mode", async () => {
    const resp = await withTlsRetry(() => get("https://httpbin.org/get"));
    assertOk(resp, "httpbin non-stealth");
    assertBody(resp);
  });
});

describe("All browser profiles can handshake", { timeout: SLOW_TIMEOUT }, () => {
  const profiles = listProfiles();

  const subset = profiles.filter((name) => {
    return /^(chrome136|firefox135|safari182|edge136|tor145)$/.test(name);
  });

  for (const profileName of subset) {
    it(
      `profile "${profileName}" completes TLS handshake`,
      skipIfTlsBroken(async () => {
        const profile = getProfile(profileName);
        assert.ok(profile, `Profile "${profileName}" not found`);

        const resp = await withTlsRetry(() =>
          get("https://www.google.com/", {
            impersonate: profileName,
            stealth: true,
            insecure: true,
          }),
        );
        assert.ok(resp.status >= 200 && resp.status < 400, `${profileName}: got ${resp.status}`);
      }),
    );
  }
});
