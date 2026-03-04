import { describe, it } from "node:test";
import assert from "node:assert/strict";
import { withRetry } from "../../src/middleware/retry.js";
import { NLcURLResponse } from "../../src/core/response.js";
import { ProtocolError, ConnectionError, TimeoutError, AbortError } from "../../src/core/errors.js";

const emptyTimings = { dns: 0, connect: 0, tls: 0, firstByte: 0, total: 0 };

function makeOkResponse(): NLcURLResponse {
  return new NLcURLResponse({
    status: 200,
    statusText: "OK",
    headers: {},
    rawBody: Buffer.alloc(0),
    httpVersion: "1.1",
    url: "https://example.com",
    redirectCount: 0,
    timings: emptyTimings,
    request: { method: "GET", headers: {}, url: "https://example.com" },
  });
}

const noRetry = { count: 2, delay: 0, backoff: "linear" as const, jitter: 0 };

describe("withRetry — H2 ProtocolError retry", () => {
  it("retries on error code 1 (PROTOCOL_ERROR)", async () => {
    let attempts = 0;
    const res = await withRetry(noRetry, async () => {
      if (++attempts === 1) throw new ProtocolError("stream reset: error code 1", 1);
      return makeOkResponse();
    });
    assert.equal(attempts, 2);
    assert.equal(res.status, 200);
  });

  it("retries on error code 2 (INTERNAL_ERROR)", async () => {
    let attempts = 0;
    await withRetry(noRetry, async () => {
      if (++attempts === 1) throw new ProtocolError("stream reset: error code 2", 2);
      return makeOkResponse();
    });
    assert.equal(attempts, 2);
  });

  it("retries on error code 7 (REFUSED_STREAM)", async () => {
    let attempts = 0;
    await withRetry(noRetry, async () => {
      if (++attempts === 1) throw new ProtocolError("stream reset: error code 7", 7);
      return makeOkResponse();
    });
    assert.equal(attempts, 2);
  });

  it("retries on error code 11 (ENHANCE_YOUR_CALM)", async () => {
    let attempts = 0;
    await withRetry(noRetry, async () => {
      if (++attempts === 1) throw new ProtocolError("stream reset: error code 11", 11);
      return makeOkResponse();
    });
    assert.equal(attempts, 2);
  });

  it("does NOT retry on error code 0 (NO_ERROR)", async () => {
    let attempts = 0;
    await assert.rejects(
      withRetry(noRetry, async () => {
        attempts++;
        throw new ProtocolError("stream reset: error code 0", 0);
      }),
      ProtocolError,
    );
    assert.equal(attempts, 1);
  });

  it("does NOT retry ProtocolError without an error code", async () => {
    let attempts = 0;
    await assert.rejects(
      withRetry(noRetry, async () => {
        attempts++;
        throw new ProtocolError("generic H2 error");
      }),
      ProtocolError,
    );
    assert.equal(attempts, 1);
  });
});

describe("withRetry — existing retry behaviour", () => {
  it("retries ConnectionError", async () => {
    let attempts = 0;
    await withRetry(noRetry, async () => {
      if (++attempts === 1) throw new ConnectionError("ECONNRESET");
      return makeOkResponse();
    });
    assert.equal(attempts, 2);
  });

  it("retries TimeoutError", async () => {
    let attempts = 0;
    await withRetry(noRetry, async () => {
      if (++attempts === 1) throw new TimeoutError("timed out", "response");
      return makeOkResponse();
    });
    assert.equal(attempts, 2);
  });

  it("retries on HTTP 429", async () => {
    let attempts = 0;
    const res = await withRetry(noRetry, async () => {
      if (++attempts === 1) {
        return new NLcURLResponse({
          status: 429,
          statusText: "Too Many Requests",
          headers: {},
          rawBody: Buffer.alloc(0),
          httpVersion: "1.1",
          url: "https://example.com",
          redirectCount: 0,
          timings: emptyTimings,
          request: { method: "GET", headers: {}, url: "https://example.com" },
        });
      }
      return makeOkResponse();
    });
    assert.equal(attempts, 2);
    assert.equal(res.status, 200);
  });

  it("retries on HTTP 503", async () => {
    let attempts = 0;
    const res = await withRetry(noRetry, async () => {
      if (++attempts === 1) {
        return new NLcURLResponse({
          status: 503,
          statusText: "Service Unavailable",
          headers: {},
          rawBody: Buffer.alloc(0),
          httpVersion: "1.1",
          url: "https://example.com",
          redirectCount: 0,
          timings: emptyTimings,
          request: { method: "GET", headers: {}, url: "https://example.com" },
        });
      }
      return makeOkResponse();
    });
    assert.equal(attempts, 2);
    assert.equal(res.status, 200);
  });

  it("never retries AbortError", async () => {
    let attempts = 0;
    await assert.rejects(
      withRetry(noRetry, async () => {
        attempts++;
        throw new AbortError();
      }),
      AbortError,
    );
    assert.equal(attempts, 1);
  });

  it("respects retry count", async () => {
    let attempts = 0;
    await assert.rejects(
      withRetry({ count: 3, delay: 0, backoff: "linear", jitter: 0 }, async () => {
        attempts++;
        throw new ConnectionError("ECONNREFUSED");
      }),
      ConnectionError,
    );
    assert.equal(attempts, 4);
  });

  it("custom retryOn predicate overrides defaults", async () => {
    let attempts = 0;
    await withRetry({ ...noRetry, retryOn: (_err, status) => status === 404 }, async () => {
      if (++attempts === 1) {
        return new NLcURLResponse({
          status: 404,
          statusText: "Not Found",
          headers: {},
          rawBody: Buffer.alloc(0),
          httpVersion: "1.1",
          url: "https://example.com",
          redirectCount: 0,
          timings: emptyTimings,
          request: { method: "GET", headers: {}, url: "https://example.com" },
        });
      }
      return makeOkResponse();
    });
    assert.equal(attempts, 2);
  });
});
