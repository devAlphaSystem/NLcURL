/**
 * Unit tests for src/core/errors.ts
 * Tests the NLcURL error hierarchy including serialization and inheritance.
 */
import { describe, it } from "node:test";
import { strict as assert } from "node:assert";
import { NLcURLError, TLSError, HTTPError, TimeoutError, ProxyError, AbortError, ConnectionError, ProtocolError } from "../../src/core/errors.js";

describe("NLcURLError", () => {
  it("sets name, message, and code correctly", () => {
    const err = new NLcURLError("test message", "ERR_TEST");
    assert.equal(err.name, "NLcURLError");
    assert.equal(err.message, "test message");
    assert.equal(err.code, "ERR_TEST");
    assert.ok(err instanceof Error);
    assert.ok(err instanceof NLcURLError);
  });

  it("preserves cause when provided", () => {
    const cause = new Error("root cause");
    const err = new NLcURLError("wrapper", "ERR_WRAP", cause);
    assert.equal(err.cause, cause);
  });

  it("serializes to JSON with name, code, message", () => {
    const err = new NLcURLError("test", "ERR_TEST");
    const json = err.toJSON();
    assert.equal(json["name"], "NLcURLError");
    assert.equal(json["code"], "ERR_TEST");
    assert.equal(json["message"], "test");
    assert.ok("stack" in json);
  });

  it("includes cause in JSON when cause is a NLcURLError", () => {
    const inner = new NLcURLError("inner", "ERR_INNER");
    const outer = new NLcURLError("outer", "ERR_OUTER", inner);
    const json = outer.toJSON();
    const causeJson = json["cause"] as Record<string, unknown>;
    assert.equal(causeJson["code"], "ERR_INNER");
    assert.equal(causeJson["message"], "inner");
  });

  it("includes cause in JSON when cause is a plain Error", () => {
    const inner = new TypeError("type error");
    const outer = new NLcURLError("outer", "ERR_OUTER", inner);
    const json = outer.toJSON();
    const causeJson = json["cause"] as Record<string, unknown>;
    assert.equal(causeJson["name"], "TypeError");
    assert.equal(causeJson["message"], "type error");
  });

  it("has correct prototype chain for instanceof checks", () => {
    const err = new NLcURLError("test", "ERR_TEST");
    assert.ok(err instanceof NLcURLError);
    assert.ok(err instanceof Error);
  });
});

describe("TLSError", () => {
  it("has correct name, code, and alertCode", () => {
    const err = new TLSError("TLS handshake failed", 40);
    assert.equal(err.name, "TLSError");
    assert.equal(err.code, "ERR_TLS");
    assert.equal(err.alertCode, 40);
    assert.ok(err instanceof TLSError);
    assert.ok(err instanceof NLcURLError);
    assert.ok(err instanceof Error);
  });

  it("includes alertCode in JSON", () => {
    const err = new TLSError("cert invalid", 42);
    const json = err.toJSON();
    assert.equal(json["alertCode"], 42);
    assert.equal(json["code"], "ERR_TLS");
  });

  it("omits alertCode from JSON when undefined", () => {
    const err = new TLSError("generic TLS error");
    const json = err.toJSON();
    assert.equal(json["alertCode"], undefined);
  });

  it("preserves cause chain", () => {
    const cause = new Error("socket error");
    const err = new TLSError("handshake failed", 48, cause);
    assert.equal(err.cause, cause);
  });
});

describe("HTTPError", () => {
  it("has correct name, code, and statusCode", () => {
    const err = new HTTPError("Not Found", 404);
    assert.equal(err.name, "HTTPError");
    assert.equal(err.code, "ERR_HTTP");
    assert.equal(err.statusCode, 404);
  });

  it("includes statusCode in JSON", () => {
    const err = new HTTPError("Server Error", 500);
    const json = err.toJSON();
    assert.equal(json["statusCode"], 500);
    assert.equal(json["code"], "ERR_HTTP");
  });

  it("supports various HTTP status codes", () => {
    for (const code of [400, 401, 403, 404, 429, 500, 502, 503]) {
      const err = new HTTPError(`Error ${code}`, code);
      assert.equal(err.statusCode, code);
    }
  });
});

describe("TimeoutError", () => {
  it("has correct phase", () => {
    const phases = ["connect", "tls", "response", "total"] as const;
    for (const phase of phases) {
      const err = new TimeoutError(`${phase} timeout`, phase);
      assert.equal(err.name, "TimeoutError");
      assert.equal(err.code, "ERR_TIMEOUT");
      assert.equal(err.phase, phase);
      assert.ok(err instanceof TimeoutError);
      assert.ok(err instanceof NLcURLError);
    }
  });

  it("includes phase in JSON", () => {
    const err = new TimeoutError("connect timed out", "connect");
    const json = err.toJSON();
    assert.equal(json["phase"], "connect");
  });
});

describe("ProxyError", () => {
  it("has ERR_PROXY code", () => {
    const err = new ProxyError("proxy unreachable");
    assert.equal(err.name, "ProxyError");
    assert.equal(err.code, "ERR_PROXY");
    assert.ok(err instanceof ProxyError);
    assert.ok(err instanceof NLcURLError);
  });
});

describe("AbortError", () => {
  it("defaults to 'Request aborted' message", () => {
    const err = new AbortError();
    assert.equal(err.name, "AbortError");
    assert.equal(err.code, "ERR_ABORTED");
    assert.equal(err.message, "Request aborted");
  });

  it("accepts custom message", () => {
    const err = new AbortError("user cancelled");
    assert.equal(err.message, "user cancelled");
  });
});

describe("ConnectionError", () => {
  it("has ERR_CONNECTION code", () => {
    const err = new ConnectionError("ECONNREFUSED");
    assert.equal(err.name, "ConnectionError");
    assert.equal(err.code, "ERR_CONNECTION");
    assert.ok(err instanceof ConnectionError);
    assert.ok(err instanceof NLcURLError);
  });
});

describe("ProtocolError", () => {
  it("has correct name, code, and errorCode", () => {
    const err = new ProtocolError("stream error", 2);
    assert.equal(err.name, "ProtocolError");
    assert.equal(err.code, "ERR_PROTOCOL");
    assert.equal(err.errorCode, 2);
  });

  it("includes errorCode in JSON", () => {
    const err = new ProtocolError("flow control error", 3);
    const json = err.toJSON();
    assert.equal(json["errorCode"], 3);
  });

  it("omits errorCode from JSON when undefined", () => {
    const err = new ProtocolError("unknown protocol error");
    const json = err.toJSON();
    assert.equal(json["errorCode"], undefined);
  });
});
