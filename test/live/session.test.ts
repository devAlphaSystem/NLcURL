/**
 * Live session and connection reuse tests.
 *
 * Validates session state management, connection pooling,
 * concurrent requests, and request/response interceptors
 * against real servers.
 */
import { describe, it } from "node:test";
import { strict as assert } from "node:assert";
import { createSession } from "../../src/index.js";
import { LIVE_TIMEOUT, SLOW_TIMEOUT, get, assertOk, withTlsRetry, skipIfTlsBroken } from "./helpers.js";

describe("Session state persistence", { timeout: LIVE_TIMEOUT }, () => {
  it("shares cookies across requests in a session", async () => {
    const session = createSession({ cookieJar: true });

    try {
      await session.get("https://httpbin.org/cookies/set?session_test=hello123");

      const resp = await session.get("https://httpbin.org/cookies");
      assertOk(resp);
      const json = resp.json() as { cookies: Record<string, string> };
      assert.equal(json.cookies.session_test, "hello123");
    } finally {
      session.close();
    }
  });

  it("maintains separate state per session", async () => {
    const session1 = createSession({ cookieJar: true });
    const session2 = createSession({ cookieJar: true });

    try {
      await session1.get("https://httpbin.org/cookies/set?s1key=s1val");
      await session2.get("https://httpbin.org/cookies/set?s2key=s2val");

      const resp1 = await session1.get("https://httpbin.org/cookies");
      assertOk(resp1, "Session 1 cookies read");
      const resp2 = await session2.get("https://httpbin.org/cookies");
      assertOk(resp2, "Session 2 cookies read");

      const cookies1 = (resp1.json() as { cookies: Record<string, string> }).cookies;
      const cookies2 = (resp2.json() as { cookies: Record<string, string> }).cookies;

      assert.equal(cookies1.s1key, "s1val");
      assert.ok(!cookies1.s2key, "Session 1 should not have session 2 cookies");

      assert.equal(cookies2.s2key, "s2val");
      assert.ok(!cookies2.s1key, "Session 2 should not have session 1 cookies");
    } finally {
      session1.close();
      session2.close();
    }
  });
});

describe("Session with default headers", { timeout: LIVE_TIMEOUT }, () => {
  it("sends default headers on every request", async () => {
    const session = createSession({
      headers: {
        "x-session-id": "test-session-001",
        "x-api-version": "2",
      },
    });

    const resp = await session.get("https://httpbin.org/headers");
    assertOk(resp);

    const json = resp.json() as { headers: Record<string, string> };
    assert.equal(json.headers["X-Session-Id"], "test-session-001");
    assert.equal(json.headers["X-Api-Version"], "2");
  });

  it("allows per-request header override", async () => {
    const session = createSession({
      headers: { "x-default": "original" },
    });

    const resp = await session.get("https://httpbin.org/headers", {
      headers: { "x-default": "overridden" },
    });
    assertOk(resp);

    const json = resp.json() as { headers: Record<string, string> };
    assert.equal(json.headers["X-Default"], "overridden");
  });
});

describe("Session baseURL", { timeout: LIVE_TIMEOUT }, () => {
  it("prepends baseURL to relative paths", async () => {
    const session = createSession({
      baseURL: "https://httpbin.org",
    });

    const resp = await session.get("/get");
    assertOk(resp);
    const json = resp.json() as { url: string };
    assert.ok(json.url.includes("httpbin.org/get"));
  });

  it("baseURL works with various HTTP methods", async () => {
    const session = createSession({
      baseURL: "https://httpbin.org",
    });

    const getResp = await session.get("/get");
    assertOk(getResp);

    const postResp = await session.post("/post", { key: "val" });
    assertOk(postResp);

    const putResp = await session.put("/put", { key: "val" });
    assertOk(putResp);

    const delResp = await session.delete("/delete");
    assertOk(delResp);
  });
});

describe("Concurrent requests", { timeout: SLOW_TIMEOUT }, () => {
  it(
    "handles multiple parallel requests",
    skipIfTlsBroken(async () => {
      const session = createSession({
        impersonate: "chrome136",
        stealth: true,
        insecure: true,
      });

      const urls = ["https://httpbin.org/get", "https://httpbin.org/headers", "https://httpbin.org/ip", "https://httpbin.org/user-agent"];

      const results = await Promise.all(urls.map((url) => withTlsRetry(() => session.get(url))));

      for (const resp of results) {
        assertOk(resp);
      }

      const bodies = results.map((r) => r.text());
      const unique = new Set(bodies);
      assert.ok(unique.size >= 3, "Expected mostly distinct responses from different endpoints");
    }),
  );

  it(
    "handles concurrent requests to different hosts",
    skipIfTlsBroken(async () => {
      const results = await Promise.all([withTlsRetry(() => get("https://httpbin.org/get", { impersonate: "chrome136", stealth: true, insecure: true })), withTlsRetry(() => get("https://example.com", { impersonate: "chrome136", stealth: true, insecure: true })), withTlsRetry(() => get("https://cloudflare.com", { impersonate: "chrome136", stealth: true, insecure: true }))]);

      for (const resp of results) {
        assertOk(resp);
      }
    }),
  );
});

describe("Session impersonation", { timeout: SLOW_TIMEOUT }, () => {
  it(
    "session applies impersonation to all requests",
    skipIfTlsBroken(async () => {
      const session = createSession({
        impersonate: "chrome136",
        stealth: true,
        insecure: true,
      });

      const resp = await withTlsRetry(() => session.get("https://httpbin.org/headers"));
      assertOk(resp);

      const json = resp.json() as { headers: Record<string, string> };
      const userAgent = json.headers["User-Agent"] || "";
      assert.ok(userAgent.includes("Chrome"), `Expected Chrome user-agent, got: ${userAgent}`);
    }),
  );

  it(
    "different impersonation profiles send different user-agents",
    skipIfTlsBroken(async () => {
      const chromeSession = createSession({ impersonate: "chrome136", stealth: true, insecure: true });
      const firefoxSession = createSession({ impersonate: "firefox135", stealth: true, insecure: true });

      const [chromeResp, firefoxResp] = await Promise.all([withTlsRetry(() => chromeSession.get("https://httpbin.org/user-agent")), withTlsRetry(() => firefoxSession.get("https://httpbin.org/user-agent"))]);

      assertOk(chromeResp);
      assertOk(firefoxResp);

      const chromeUA = (chromeResp.json() as { "user-agent": string })["user-agent"];
      const firefoxUA = (firefoxResp.json() as { "user-agent": string })["user-agent"];

      assert.ok(chromeUA.includes("Chrome"), `Chrome UA: ${chromeUA}`);
      assert.ok(firefoxUA.includes("Firefox"), `Firefox UA: ${firefoxUA}`);
      assert.notEqual(chromeUA, firefoxUA);
    }),
  );
});

describe("Session with stealth against anti-bot sites", { timeout: SLOW_TIMEOUT }, () => {
  it(
    "mercadolivre.com.br with stealth session",
    skipIfTlsBroken(async () => {
      const session = createSession({
        impersonate: "chrome136",
        stealth: true,
        insecure: true,
      });

      const resp = await withTlsRetry(() => session.get("https://www.mercadolivre.com.br"));
      assert.ok(resp.status >= 200 && resp.status < 400, `Expected success with stealth, got: ${resp.status}`);
      assert.ok(resp.text().length > 1000, "Expected a full page response");
    }),
  );

  it(
    "amazon.com with stealth session",
    skipIfTlsBroken(async () => {
      const session = createSession({
        impersonate: "chrome136",
        stealth: true,
        insecure: true,
      });

      const resp = await withTlsRetry(() => session.get("https://www.amazon.com"));
      assert.ok(resp.status >= 200 && resp.status < 400, `Expected success, got: ${resp.status}`);
      assert.ok(resp.text().length > 1000);
    }),
  );
});

describe("Request methods on session", { timeout: LIVE_TIMEOUT }, () => {
  it("all HTTP methods work through session", async () => {
    const session = createSession({
      baseURL: "https://httpbin.org",
    });

    const getResp = await withTlsRetry(() => session.get("/get"));
    assert.equal(getResp.status, 200);

    const postResp = await withTlsRetry(() => session.post("/post", { test: 1 }));
    assert.equal(postResp.status, 200);

    const putResp = await withTlsRetry(() => session.put("/put", "data"));
    assert.equal(putResp.status, 200);

    const delResp = await withTlsRetry(() => session.delete("/delete"));
    assert.equal(delResp.status, 200);

    const headResp = await withTlsRetry(() => session.head("/get"));
    assert.equal(headResp.status, 200);
    assert.equal(headResp.rawBody.length, 0);
  });
});
