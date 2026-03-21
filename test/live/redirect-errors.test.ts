/**
 * Live redirect and error handling tests.
 *
 * Validates correct behavior for HTTP redirects (301, 302, 307, 308),
 * error codes, timeouts, and edge cases against real servers.
 */
import { describe, it } from "node:test";
import { strict as assert } from "node:assert";
import { get, post, createSession } from "../../src/index.js";
import { LIVE_TIMEOUT, SLOW_TIMEOUT, assertOk, withTlsRetry, skipIfTlsBroken } from "./helpers.js";

describe("HTTP redirects", { timeout: LIVE_TIMEOUT }, () => {
  it("follows 302 redirect to final destination", async () => {
    const resp = await get("https://httpbin.org/redirect/1");
    assertOk(resp);
    const json = resp.json() as { url: string };
    assert.ok(json.url.includes("httpbin.org/get"), `Final URL should be /get, got: ${json.url}`);
  });

  it("follows multiple chained redirects", async () => {
    const resp = await get("https://httpbin.org/redirect/3");
    assertOk(resp);
    const json = resp.json() as { url: string };
    assert.ok(json.url.includes("httpbin.org/get"));
  });

  it(
    "follows absolute URL redirect",
    skipIfTlsBroken(async () => {
      const resp = await withTlsRetry(() =>
        get("https://httpbin.org/absolute-redirect/2", {
          impersonate: "chrome136",
          stealth: true,
          insecure: true,
        }),
      );
      assertOk(resp);
      const json = resp.json() as { url: string };
      assert.ok(json.url.includes("httpbin.org/get"));
    }),
  );

  it("follows relative redirect", async () => {
    const resp = await get("https://httpbin.org/relative-redirect/2");
    assertOk(resp);
    const json = resp.json() as { url: string };
    assert.ok(json.url.includes("httpbin.org/get"));
  });

  it("stops following redirects when followRedirects is false", async () => {
    const resp = await get("https://httpbin.org/redirect/1", {
      followRedirects: false,
    });
    assert.equal(resp.status, 302, `Expected 302, got ${resp.status}`);
  });

  it("handles 301 permanent redirect", async () => {
    const resp = await get("https://httpbin.org/redirect-to?url=https%3A%2F%2Fhttpbin.org%2Fget&status_code=301");
    assertOk(resp);
    const json = resp.json() as { url: string };
    assert.ok(json.url.includes("httpbin.org/get"));
  });

  it("handles 307 temporary redirect preserving method", async () => {
    const resp = await post("https://httpbin.org/redirect-to?url=https%3A%2F%2Fhttpbin.org%2Fpost&status_code=307", { test: true });
    assertOk(resp);
  });

  it("handles 308 permanent redirect preserving method", async () => {
    const resp = await post("https://httpbin.org/redirect-to?url=https%3A%2F%2Fhttpbin.org%2Fpost&status_code=308", { data: "preserved" });
    assertOk(resp);
  });
});

describe("HTTP error status codes", { timeout: LIVE_TIMEOUT }, () => {
  it("returns 404 without throwing by default", async () => {
    const resp = await get("https://httpbin.org/status/404");
    assert.equal(resp.status, 404);
  });

  it("returns 500 without throwing by default", async () => {
    const resp = await get("https://httpbin.org/status/500");
    assert.equal(resp.status, 500);
  });

  it("throws on 4xx/5xx when throwOnError is set", async () => {
    await assert.rejects(
      () => get("https://httpbin.org/status/404", { throwOnError: true }),
      (err: Error) => {
        assert.ok(err.message.length > 0);
        return true;
      },
    );
  });

  it("returns 418 I'm a Teapot", async () => {
    const resp = await get("https://httpbin.org/status/418");
    assert.equal(resp.status, 418);
  });

  it("returns various status codes", async () => {
    for (const code of [200, 201, 204, 400, 401, 403, 404, 500, 502, 503]) {
      const resp = await get(`https://httpbin.org/status/${code}`);
      assert.equal(resp.status, code, `Expected ${code}`);
    }
  });
});

describe("Timeout behavior", { timeout: SLOW_TIMEOUT }, () => {
  it("times out on a slow endpoint", async () => {
    await assert.rejects(
      () => get("https://httpbin.org/delay/10", { timeout: 2_000 }),
      (err: Error) => {
        assert.ok(err.message.toLowerCase().includes("timeout") || err.constructor.name.includes("Timeout") || err.constructor.name.includes("Abort"), `Expected timeout error, got: ${err.constructor.name}: ${err.message}`);
        return true;
      },
    );
  });

  it("succeeds if timeout is generous enough", async () => {
    const resp = await get("https://httpbin.org/delay/1", { timeout: 10_000 });
    assertOk(resp);
  });
});

describe("Connection to non-existent hosts", { timeout: SLOW_TIMEOUT }, () => {
  it("throws on DNS resolution failure", async () => {
    await assert.rejects(
      () => get("https://this-domain-definitely-does-not-exist-nlcurl-test.invalid"),
      (err: Error) => {
        assert.ok(err.message.length > 0, "Error should have a message");
        return true;
      },
    );
  });

  it("throws on connection refused", async () => {
    await assert.rejects(
      () => get("https://localhost:1", { timeout: 5_000 }),
      (err: Error) => {
        assert.ok(err.message.length > 0);
        return true;
      },
    );
  });
});

describe("Response headers and metadata", { timeout: LIVE_TIMEOUT }, () => {
  it("returns correct response headers from httpbin", async () => {
    const resp = await get("https://httpbin.org/response-headers?X-Custom-Header=test-value&X-Another=42");
    assertOk(resp);

    const custom = resp.headers["x-custom-header"];
    assert.equal(custom, "test-value");
    const another = resp.headers["x-another"];
    assert.equal(another, "42");
  });

  it("returns timing/performance data", async () => {
    const resp = await get("https://httpbin.org/get");
    assertOk(resp);

    if (resp.timing) {
      assert.ok(typeof resp.timing === "object");
    }
  });

  it("returns correct HTTP version", async () => {
    const resp = await get("https://httpbin.org/get");
    assertOk(resp);
    if (resp.httpVersion) {
      assert.ok(["1.1", "2", "2.0", "h2"].includes(resp.httpVersion), `Unexpected HTTP version: ${resp.httpVersion}`);
    }
  });
});

describe("Real-world redirect chains", { timeout: SLOW_TIMEOUT }, () => {
  it(
    "follows HTTP to HTTPS redirect on google.com",
    skipIfTlsBroken(async () => {
      const resp = await withTlsRetry(() =>
        get("http://google.com", {
          impersonate: "chrome136",
          stealth: true,
          insecure: true,
          timeout: 15_000,
        }),
      );
      assert.ok(resp.status >= 200 && resp.status < 400, `Status: ${resp.status}`);
      assert.ok(resp.text().length > 100);
    }),
  );

  it("follows www redirect on github.com", async () => {
    const resp = await get("https://github.com");
    assertOk(resp);
    assert.ok(resp.text().includes("GitHub"));
  });
});
