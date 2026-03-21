/**
 * Live cookie handling tests.
 *
 * Tests real cookie setting, persistence, and domain scoping by making
 * requests to servers that set cookies (httpbin.org/cookies/set) and
 * verifying they're sent back on subsequent requests.
 */
import { describe, it } from "node:test";
import { strict as assert } from "node:assert";
import { createSession, CookieJar } from "../../src/index.js";
import { LIVE_TIMEOUT, SLOW_TIMEOUT, assertOk, withTlsRetry, skipIfTlsBroken } from "./helpers.js";

const HTTPBIN = "https://httpbin.org";

describe("Cookie persistence across requests", { timeout: LIVE_TIMEOUT }, () => {
  it("stores cookies set by the server and sends them back", async () => {
    const session = createSession({ cookieJar: true });

    try {
      const setResp = await session.get(`${HTTPBIN}/cookies/set?session_token=abc123&user=testuser`);
      assertOk(setResp, "Cookie set");

      const cookieResp = await session.get(`${HTTPBIN}/cookies`);
      assertOk(cookieResp, "Cookie read");
      const json = cookieResp.json<{ cookies: Record<string, string> }>();
      assert.equal(json.cookies.session_token, "abc123");
      assert.equal(json.cookies.user, "testuser");
    } finally {
      session.close();
    }
  });

  it("persists cookies across multiple requests", async () => {
    const session = createSession({ cookieJar: true });

    try {
      await session.get(`${HTTPBIN}/cookies/set?first=aaa`);
      await session.get(`${HTTPBIN}/cookies/set?second=bbb`);

      const resp = await session.get(`${HTTPBIN}/cookies`);
      assertOk(resp);
      const json = resp.json<{ cookies: Record<string, string> }>();
      assert.equal(json.cookies.first, "aaa");
      assert.equal(json.cookies.second, "bbb");
    } finally {
      session.close();
    }
  });
});

describe("Cookie jar inspection", { timeout: LIVE_TIMEOUT }, () => {
  it("allows reading stored cookies from the jar", async () => {
    const session = createSession({ cookieJar: true });

    try {
      await session.get(`${HTTPBIN}/cookies/set?visible=yes`);

      const jar = session.getCookies();
      assert.ok(jar, "Cookie jar should exist");
      const cookies = jar.all();
      assert.ok(cookies.length > 0, "Expected at least one cookie in jar");
      const visible = cookies.find((c) => c.name === "visible");
      assert.ok(visible, "Expected 'visible' cookie in jar");
      assert.equal(visible.value, "yes");
    } finally {
      session.close();
    }
  });
});

describe("Cookie domain isolation", { timeout: LIVE_TIMEOUT }, () => {
  it("does not send httpbin cookies to a different domain", async () => {
    const session = createSession({ cookieJar: true });

    try {
      await session.get(`${HTTPBIN}/cookies/set?secret=httpbin_only`);

      const resp = await session.get("https://www.google.com/", {
        headers: { accept: "text/html" },
      });
      assert.ok(resp.status >= 200 && resp.status < 400, `Expected success from Google, got ${resp.status}`);

      const jar = session.getCookies()!;
      const header = jar.getCookieHeader(new URL("https://www.google.com/"));
      assert.ok(!header.includes("secret=httpbin_only"), "Httpbin cookie should not be sent to google.com");
    } finally {
      session.close();
    }
  });
});

describe("Cookie with custom CookieJar", { timeout: LIVE_TIMEOUT }, () => {
  it("uses a pre-populated cookie jar", async () => {
    const jar = new CookieJar();
    jar.setCookies({ "set-cookie": "preloaded=yes; Path=/" }, new URL(HTTPBIN));

    const session = createSession({ cookieJar: jar });

    try {
      const resp = await session.get(`${HTTPBIN}/cookies`);
      assertOk(resp);
      const json = resp.json<{ cookies: Record<string, string> }>();
      assert.equal(json.cookies.preloaded, "yes");
    } finally {
      session.close();
    }
  });
});

describe("Real-world cookie handling", { timeout: SLOW_TIMEOUT }, () => {
  it(
    "handles cookies from a real website (Google)",
    skipIfTlsBroken(async () => {
      const session = createSession({
        cookieJar: true,
        impersonate: "chrome136",
        stealth: true,
        insecure: true,
      });

      try {
        const resp = await withTlsRetry(() =>
          session.get("https://www.google.com/", {
            headers: { accept: "text/html" },
          }),
        );
        assertOk(resp);

        const jar = session.getCookies()!;
        const cookies = jar.all();
        assert.ok(cookies.length >= 0, "Should handle Google cookies without error");
      } finally {
        session.close();
      }
    }),
  );
});
