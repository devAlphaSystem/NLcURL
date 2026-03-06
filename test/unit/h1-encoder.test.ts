import { describe, it } from "node:test";
import assert from "node:assert/strict";
import { encodeRequest } from "../../src/http/h1/encoder.js";
import type { NLcURLRequest } from "../../src/core/request.js";

describe("encodeRequest", () => {
  it("encodes a simple GET request", () => {
    const req: NLcURLRequest = {
      url: "https://example.com/api/data?q=test",
      method: "GET",
    };

    const buf = encodeRequest(req, []);
    const text = buf.toString("latin1");

    assert.ok(text.startsWith("GET /api/data?q=test HTTP/1.1\r\n"));
    assert.ok(text.includes("host: example.com"));
    assert.ok(text.endsWith("\r\n\r\n"));
  });

  it("includes request headers", () => {
    const req: NLcURLRequest = {
      url: "https://example.com/",
      method: "GET",
      headers: {
        Authorization: "Bearer token123",
        Accept: "application/json",
      },
    };

    const buf = encodeRequest(req, []);
    const text = buf.toString("latin1");

    assert.ok(text.includes("authorization: Bearer token123"));
    assert.ok(text.includes("accept: application/json"));
  });

  it("includes default headers", () => {
    const req: NLcURLRequest = {
      url: "https://example.com/",
      method: "GET",
    };

    const buf = encodeRequest(req, [["user-agent", "NLcURL/1.0"]]);
    const text = buf.toString("latin1");

    assert.ok(text.includes("user-agent: NLcURL/1.0"));
  });

  it("request headers override default headers", () => {
    const req: NLcURLRequest = {
      url: "https://example.com/",
      method: "GET",
      headers: { "User-Agent": "Custom/1.0" },
    };

    const buf = encodeRequest(req, [["user-agent", "Default/1.0"]]);
    const text = buf.toString("latin1");

    assert.ok(text.includes("user-agent: Custom/1.0"));
    assert.ok(!text.includes("Default/1.0"));
  });

  it("encodes POST request with string body", () => {
    const req: NLcURLRequest = {
      url: "https://example.com/api",
      method: "POST",
      body: "key=value",
    };

    const buf = encodeRequest(req, []);
    const text = buf.toString("latin1");

    assert.ok(text.includes("POST /api HTTP/1.1"));
    assert.ok(text.includes("content-length: 9"));
    assert.ok(text.includes("content-type: text/plain; charset=utf-8"));
    assert.ok(text.includes("key=value"));
  });

  it("encodes POST request with JSON body", () => {
    const req: NLcURLRequest = {
      url: "https://example.com/api",
      method: "POST",
      body: { hello: "world" },
      headers: { "Content-Type": "application/json" },
    };

    const buf = encodeRequest(req, []);
    const text = buf.toString();

    assert.ok(text.includes("content-type: application/json"));
    assert.ok(text.includes('{"hello":"world"}'));
  });

  it("encodes POST with Buffer body", () => {
    const req: NLcURLRequest = {
      url: "https://example.com/upload",
      method: "POST",
      body: Buffer.from([0x01, 0x02, 0x03]),
    };

    const buf = encodeRequest(req, []);
    const text = buf.toString("latin1");

    assert.ok(text.includes("content-length: 3"));
  });

  it("includes port in host header when non-default", () => {
    const req: NLcURLRequest = {
      url: "https://example.com:8443/api",
      method: "GET",
    };

    const buf = encodeRequest(req, []);
    const text = buf.toString("latin1");

    assert.ok(text.includes("host: example.com:8443"));
  });
});
