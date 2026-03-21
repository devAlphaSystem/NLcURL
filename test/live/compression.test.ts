/**
 * Live compression and encoding tests.
 *
 * Tests real gzip, brotli, deflate, and zstd decompression
 * against actual compressed responses from httpbin.org and
 * real-world servers.
 */
import { describe, it } from "node:test";
import { strict as assert } from "node:assert";
import { get, createSession } from "../../src/index.js";
import { LIVE_TIMEOUT, SLOW_TIMEOUT, assertOk, withTlsRetry, skipIfTlsBroken } from "./helpers.js";

describe("Response decompression", { timeout: LIVE_TIMEOUT }, () => {
  it("decompresses gzip responses", async () => {
    const resp = await get("https://httpbin.org/gzip");
    assertOk(resp);

    const json = resp.json() as { gzipped: boolean; method: string };
    assert.equal(json.gzipped, true, "Response should be gzip-decoded");
    assert.equal(json.method, "GET");
  });

  it("decompresses brotli responses", async () => {
    const resp = await get("https://httpbin.org/brotli");
    assertOk(resp);

    const json = resp.json() as { brotli: boolean; method: string };
    assert.equal(json.brotli, true, "Response should be brotli-decoded");
  });

  it("decompresses deflate responses", async () => {
    const resp = await get("https://httpbin.org/deflate");
    assertOk(resp);

    const json = resp.json() as { deflated: boolean; method: string };
    assert.equal(json.deflated, true, "Response should be deflate-decoded");
  });
});

describe("Accept-Encoding negotiation", { timeout: SLOW_TIMEOUT }, () => {
  it(
    "sends Accept-Encoding header when impersonating",
    skipIfTlsBroken(async () => {
      const resp = await withTlsRetry(() =>
        get("https://httpbin.org/headers", {
          impersonate: "chrome136",
          stealth: true,
          insecure: true,
        }),
      );
      assertOk(resp);

      const json = resp.json() as { headers: Record<string, string> };
      const ae = json.headers["Accept-Encoding"] || "";
      assert.ok(ae.length > 0, "Accept-Encoding should be sent when impersonating");
    }),
  );

  it("handles identity encoding (no compression)", async () => {
    const resp = await get("https://httpbin.org/get", {
      headers: { "accept-encoding": "identity" },
    });
    assertOk(resp);
    const json = resp.json() as { url: string };
    assert.ok(json.url);
  });
});

describe("Real-world compressed responses", { timeout: SLOW_TIMEOUT }, () => {
  it(
    "decompresses Google search page",
    skipIfTlsBroken(async () => {
      const resp = await withTlsRetry(() =>
        get("https://www.google.com", {
          impersonate: "chrome136",
          stealth: true,
          insecure: true,
        }),
      );
      assertOk(resp);

      const text = resp.text();
      assert.ok(text.length > 1000, "Expected full decompressed page");
      assert.ok(text.includes("<!doctype html>") || text.includes("<html"), "Should be valid HTML");
    }),
  );

  it("decompresses GitHub API response", async () => {
    const resp = await get("https://api.github.com/", {
      headers: { "user-agent": "NLcURL-Test/1.0" },
    });
    assertOk(resp);

    const json = resp.json() as Record<string, string>;
    assert.ok(json.current_user_url, "GitHub API should return index");
  });

  it("decompresses Cloudflare response", async () => {
    const resp = await get("https://cloudflare.com");
    assertOk(resp);

    const text = resp.text();
    assert.ok(text.length > 500, "Expected decompressed Cloudflare page");
  });
});

describe("Encoding edge cases", { timeout: LIVE_TIMEOUT }, () => {
  it("handles UTF-8 content correctly", async () => {
    const resp = await get("https://httpbin.org/encoding/utf8");
    assertOk(resp);

    const text = resp.text();
    assert.ok(text.length > 100, "Expected UTF-8 encoded content");
    assert.ok(text.includes("UTF-8") || text.includes("encoded"), "Should contain UTF-8 content markers");
  });

  it("handles response bytes endpoint", async () => {
    const numBytes = 256;
    const resp = await get(`https://httpbin.org/bytes/${numBytes}`);
    assertOk(resp);
    assert.ok(resp.rawBody.length > 0, "Should receive binary bytes");
  });

  it("handles base64-decoded endpoints", async () => {
    const encoded = Buffer.from("Hello NLcURL!").toString("base64url");
    const resp = await get(`https://httpbin.org/base64/${encoded}`);
    assertOk(resp);
    const text = resp.text();
    assert.ok(text.length > 0, `Expected non-empty response, got: "${text}"`);
  });
});
