/**
 * Live HTTP client tests.
 *
 * Tests real HTTP/HTTPS requests using the full NLcURL API against
 * public services like httpbin.org — validates GET, POST, headers,
 * redirects, compression, JSON parsing, timeouts, and errors.
 */
import { describe, it } from "node:test";
import { strict as assert } from "node:assert";
import { createSession } from "../../src/index.js";
import { NLcURLError, TimeoutError, HTTPError } from "../../src/index.js";
import { LIVE_TIMEOUT, SLOW_TIMEOUT, get, post, put, del, head, assertOk, assertHeader, assertBody, withTlsRetry, skipIfTlsBroken } from "./helpers.js";

const HTTPBIN = "https://httpbin.org";

describe("HTTP GET requests", { timeout: LIVE_TIMEOUT }, () => {
  it("GETs JSON from httpbin", async () => {
    const resp = await get(`${HTTPBIN}/get`);
    assertOk(resp, "httpbin GET");
    const json = resp.json<{ url: string; headers: Record<string, string> }>();
    assert.ok(json.url.includes("/get"), "Response URL should contain /get");
    assert.ok(json.headers, "Response should include headers echo");
  });

  it("sends custom headers", async () => {
    const resp = await get(`${HTTPBIN}/headers`, {
      headers: {
        "X-Custom-Test": "nlcurl-live-test",
        Accept: "application/json",
      },
    });
    assertOk(resp);
    const json = resp.json<{ headers: Record<string, string> }>();
    assert.equal(json.headers["X-Custom-Test"] || json.headers["x-custom-test"], "nlcurl-live-test");
  });

  it("sends query parameters", async () => {
    const resp = await get(`${HTTPBIN}/get`, {
      params: { foo: "bar", count: 42 },
    });
    assertOk(resp);
    const json = resp.json<{ args: Record<string, string> }>();
    assert.equal(json.args.foo, "bar");
    assert.equal(json.args.count, "42");
  });

  it("receives gzip-compressed response", async () => {
    const resp = await get(`${HTTPBIN}/gzip`);
    assertOk(resp);
    const json = resp.json<{ gzipped: boolean }>();
    assert.equal(json.gzipped, true);
  });

  it("receives brotli-compressed response", async () => {
    const resp = await get(`${HTTPBIN}/brotli`);
    assertOk(resp);
    const json = resp.json<{ brotli: boolean }>();
    assert.equal(json.brotli, true);
  });

  it("receives deflate-compressed response", async () => {
    const resp = await get(`${HTTPBIN}/deflate`);
    assertOk(resp);
    const json = resp.json<{ deflated: boolean }>();
    assert.equal(json.deflated, true);
  });
});

describe("HTTP POST requests", { timeout: LIVE_TIMEOUT }, () => {
  it("POSTs JSON body", async () => {
    const body = { message: "hello", number: 123 };
    const resp = await post(`${HTTPBIN}/post`, body, {
      headers: { "Content-Type": "application/json" },
    });
    assertOk(resp, "httpbin POST JSON");
    const json = resp.json<{ json: typeof body }>();
    assert.deepStrictEqual(json.json, body);
  });

  it("POSTs form-urlencoded body", async () => {
    const params = new URLSearchParams({ username: "test", password: "secret" });
    const resp = await post(`${HTTPBIN}/post`, params.toString(), {
      headers: { "Content-Type": "application/x-www-form-urlencoded" },
    });
    assertOk(resp, "httpbin POST form");
    const json = resp.json<{ form: Record<string, string> }>();
    assert.equal(json.form.username, "test");
    assert.equal(json.form.password, "secret");
  });

  it("POSTs string body", async () => {
    const resp = await post(`${HTTPBIN}/post`, "raw text body", {
      headers: { "Content-Type": "text/plain" },
    });
    assertOk(resp);
    const json = resp.json<{ data: string }>();
    assert.equal(json.data, "raw text body");
  });

  it("POSTs Buffer body", async () => {
    const buf = Buffer.from([0x01, 0x02, 0x03, 0x04]);
    const resp = await post(`${HTTPBIN}/post`, buf, {
      headers: { "Content-Type": "application/octet-stream" },
    });
    assertOk(resp);
  });
});

describe("HTTP PUT/DELETE/HEAD", { timeout: LIVE_TIMEOUT }, () => {
  it("PUTs JSON body", async () => {
    const resp = await put(
      `${HTTPBIN}/put`,
      { key: "value" },
      {
        headers: { "Content-Type": "application/json" },
      },
    );
    assertOk(resp, "httpbin PUT");
    const json = resp.json<{ json: { key: string } }>();
    assert.equal(json.json.key, "value");
  });

  it("DELETEs a resource", async () => {
    const resp = await del(`${HTTPBIN}/delete`);
    assertOk(resp, "httpbin DELETE");
  });

  it("HEAD returns no body", async () => {
    const resp = await head(`${HTTPBIN}/get`);
    assertOk(resp, "httpbin HEAD");
    assert.equal(resp.rawBody.length, 0, "HEAD response should have empty body");
  });
});

describe("HTTP status codes", { timeout: LIVE_TIMEOUT }, () => {
  it("returns 404 for non-existent path", async () => {
    const resp = await get(`${HTTPBIN}/status/404`);
    assert.equal(resp.status, 404);
    assert.ok(!resp.ok);
  });

  it("returns 500 for server error", async () => {
    const resp = await get(`${HTTPBIN}/status/500`);
    assert.equal(resp.status, 500);
    assert.ok(!resp.ok);
  });

  it("throws HTTPError when throwOnError=true", async () => {
    await assert.rejects(
      () => get(`${HTTPBIN}/status/403`, { throwOnError: true }),
      (err: Error) => {
        assert.ok(err.message.includes("403") || err.message.includes("Forbidden"), `Expected 403 error, got: ${err.message}`);
        return true;
      },
    );
  });
});

describe("HTTP redirects", { timeout: LIVE_TIMEOUT }, () => {
  it("follows 302 redirect", async () => {
    const resp = await get(`${HTTPBIN}/redirect-to?url=${encodeURIComponent(`${HTTPBIN}/get`)}&status_code=302`);
    assertOk(resp, "302 redirect");
    assert.ok(resp.redirectCount >= 1, "Should have followed at least 1 redirect");
  });

  it("follows multiple redirects", async () => {
    const resp = await get(`${HTTPBIN}/redirect/3`);
    assertOk(resp, "multiple redirects");
    assert.ok(resp.redirectCount >= 2, `Expected ≥2 redirects, got ${resp.redirectCount}`);
  });

  it("respects followRedirects=false", async () => {
    const resp = await get(`${HTTPBIN}/redirect/1`, {
      followRedirects: false,
    });
    assert.equal(resp.status, 302, "Should get 302 without following");
    assert.equal(resp.redirectCount, 0);
  });
});

describe("HTTP timeouts", { timeout: LIVE_TIMEOUT }, () => {
  it("times out on slow response", async () => {
    await assert.rejects(
      () => get(`${HTTPBIN}/delay/10`, { timeout: 2000 }),
      (err: Error) => {
        assert.ok(err.message.toLowerCase().includes("timeout") || err.name.includes("Timeout"), `Expected timeout error, got: ${err.name}: ${err.message}`);
        return true;
      },
    );
  });
});

describe("HTTP response parsing", { timeout: LIVE_TIMEOUT }, () => {
  it("parses text response", async () => {
    const resp = await withTlsRetry(() => get(`${HTTPBIN}/html`));
    assertOk(resp);
    const text = resp.text();
    assert.ok(text.includes("<html") || text.includes("<h1"), "Expected HTML content");
  });

  it("parses JSON response", async () => {
    const resp = await get(`${HTTPBIN}/json`);
    assertOk(resp);
    const json = resp.json();
    assert.ok(typeof json === "object" && json !== null);
  });

  it("captures response headers", async () => {
    const resp = await get(`${HTTPBIN}/response-headers?X-Test=hello`);
    assertOk(resp);
    assert.equal(resp.headers["x-test"], "hello");
  });
});

describe("HTTP User-Agent impersonation", { timeout: LIVE_TIMEOUT }, () => {
  it("sends Chrome User-Agent when impersonating", async () => {
    const resp = await get(`${HTTPBIN}/user-agent`, {
      impersonate: "chrome136",
    });
    assertOk(resp);
    const json = resp.json<{ "user-agent": string }>();
    assert.ok(json["user-agent"]?.includes("Chrome"), `Expected Chrome UA, got: ${json["user-agent"]}`);
  });

  it("sends Firefox User-Agent when impersonating", async () => {
    const resp = await get(`${HTTPBIN}/user-agent`, {
      impersonate: "firefox135",
    });
    assertOk(resp);
    const json = resp.json<{ "user-agent": string }>();
    assert.ok(json["user-agent"]?.includes("Firefox"), `Expected Firefox UA, got: ${json["user-agent"]}`);
  });
});

describe("HTTP session with multiple requests", { timeout: SLOW_TIMEOUT }, () => {
  it(
    "makes multiple requests reusing the same session",
    skipIfTlsBroken(async () => {
      const session = createSession({
        impersonate: "chrome136",
        stealth: true,
        insecure: true,
      });

      try {
        const r1 = await withTlsRetry(() => session.get(`${HTTPBIN}/get`));
        assertOk(r1, "Session GET 1");

        const r2 = await withTlsRetry(() =>
          session.post(
            `${HTTPBIN}/post`,
            { seq: 2 },
            {
              headers: { "Content-Type": "application/json" },
            },
          ),
        );
        assertOk(r2, "Session POST");

        const r3 = await withTlsRetry(() => session.get(`${HTTPBIN}/get`));
        assertOk(r3, "Session GET 2");
      } finally {
        session.close();
      }
    }),
  );

  it("session with baseURL resolves relative paths", async () => {
    const session = createSession({ baseURL: HTTPBIN });
    try {
      const resp = await session.get("/get");
      assertOk(resp, "baseURL relative");
      assert.ok(resp.url.includes("/get"));
    } finally {
      session.close();
    }
  });

  it("session with default headers applies them to every request", async () => {
    const session = createSession({
      headers: { "X-Session-Header": "persistent" },
    });
    try {
      const resp = await session.get(`${HTTPBIN}/headers`);
      assertOk(resp);
      const json = resp.json<{ headers: Record<string, string> }>();
      assert.equal(json.headers["X-Session-Header"] || json.headers["x-session-header"], "persistent");
    } finally {
      session.close();
    }
  });
});

describe("HTTP request timing", { timeout: LIVE_TIMEOUT }, () => {
  it("captures timing data for a request", async () => {
    const resp = await get(`${HTTPBIN}/get`);
    assertOk(resp);
    assert.ok(resp.timings.total > 0, "Expected total timing > 0");
    assert.ok(resp.timings.dns >= 0, "Expected DNS timing >= 0");
    assert.ok(resp.timings.connect >= 0, "Expected connect timing >= 0");
  });
});

describe("HTTPS to various servers", { timeout: SLOW_TIMEOUT }, () => {
  const targets = ["https://www.google.com/", "https://www.cloudflare.com/", "https://github.com/", "https://httpbin.org/get", "https://example.com/"];

  for (const url of targets) {
    it(
      `successfully GETs ${new URL(url).hostname}`,
      skipIfTlsBroken(async () => {
        const resp = await withTlsRetry(() =>
          get(url, {
            impersonate: "chrome136",
            stealth: true,
            insecure: true,
          }),
        );
        assert.ok(resp.status >= 200 && resp.status < 400, `${url}: ${resp.status}`);
      }),
    );
  }
});
