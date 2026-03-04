import { describe, it } from "node:test";
import assert from "node:assert/strict";
import { NLcURLResponse } from "../../src/core/response.js";
import { PassThrough } from "node:stream";

const emptyTimings = { dns: 0, connect: 0, tls: 0, firstByte: 0, total: 0 };

describe("NLcURLResponse", () => {
  function makeResponse(status: number, body: string, headers: Record<string, string> = {}): NLcURLResponse {
    return new NLcURLResponse({
      status,
      statusText: status === 200 ? "OK" : "Error",
      headers,
      rawBody: Buffer.from(body),
      httpVersion: "1.1",
      url: "https://example.com/",
      redirectCount: 0,
      timings: emptyTimings,
      request: { method: "GET", headers: {}, url: "https://example.com/" },
    });
  }

  it("has correct status", () => {
    const res = makeResponse(200, "ok");
    assert.equal(res.status, 200);
  });

  it("ok is true for 2xx", () => {
    assert.equal(makeResponse(200, "").ok, true);
    assert.equal(makeResponse(201, "").ok, true);
    assert.equal(makeResponse(204, "").ok, true);
    assert.equal(makeResponse(299, "").ok, true);
  });

  it("ok is false for non-2xx", () => {
    assert.equal(makeResponse(301, "").ok, false);
    assert.equal(makeResponse(404, "").ok, false);
    assert.equal(makeResponse(500, "").ok, false);
    assert.equal(makeResponse(100, "").ok, false);
  });

  it("text() decodes body as UTF-8", () => {
    const res = makeResponse(200, "hello world");
    assert.equal(res.text(), "hello world");
  });

  it("json() parses JSON body", () => {
    const res = makeResponse(200, '{"key":"value","num":42}');
    const data = res.json();
    assert.deepEqual(data, { key: "value", num: 42 });
  });

  it("json() throws on invalid JSON", () => {
    const res = makeResponse(200, "not json");
    assert.throws(() => res.json());
  });

  it("rawBody is accessible as Buffer", () => {
    const res = makeResponse(200, "data");
    assert.ok(Buffer.isBuffer(res.rawBody));
    assert.equal(res.rawBody.toString(), "data");
  });

  it("preserves headers", () => {
    const res = makeResponse(200, "", {
      "content-type": "text/html",
      "x-custom": "val",
    });
    assert.equal(res.headers["content-type"], "text/html");
    assert.equal(res.headers["x-custom"], "val");
  });

  it("preserves URL", () => {
    const res = new NLcURLResponse({
      status: 200,
      statusText: "OK",
      headers: {},
      rawBody: Buffer.alloc(0),
      httpVersion: "2",
      url: "https://api.example.com/data",
      redirectCount: 0,
      timings: emptyTimings,
      request: { method: "POST", headers: {}, url: "https://api.example.com/data" },
    });
    assert.equal(res.url, "https://api.example.com/data");
    assert.equal(res.request.method, "POST");
  });

  it("contentLength from header", () => {
    const res = makeResponse(200, "hi", { "content-length": "2" });
    assert.equal(res.contentLength, 2);
  });

  it("contentLength falls back to body size", () => {
    const res = makeResponse(200, "hello");
    assert.equal(res.contentLength, 5);
  });

  it("rawHeaders defaults to Object.entries of headers", () => {
    const res = makeResponse(200, "", { "x-foo": "bar", "x-baz": "qux" });
    assert.ok(Array.isArray(res.rawHeaders));
    assert.equal(res.rawHeaders.length, 2);
  });

  it("rawHeaders preserves explicit duplicates", () => {
    const res = new NLcURLResponse({
      status: 200,
      statusText: "OK",
      headers: { "set-cookie": "a=1, b=2" },
      rawHeaders: [
        ["set-cookie", "a=1; Path=/"],
        ["set-cookie", "b=2; Path=/"],
        ["content-type", "text/html"],
      ],
      rawBody: Buffer.alloc(0),
      httpVersion: "1.1",
      url: "https://example.com/",
      redirectCount: 0,
      timings: emptyTimings,
      request: { method: "GET", headers: {}, url: "https://example.com/" },
    });

    assert.equal(res.rawHeaders.length, 3);
    const setCookies = res.rawHeaders.filter(([k]) => k === "set-cookie");
    assert.equal(setCookies.length, 2);
    assert.equal(setCookies[0]![1], "a=1; Path=/");
    assert.equal(setCookies[1]![1], "b=2; Path=/");
  });

  it("body is null when not in streaming mode", () => {
    const res = makeResponse(200, "hello");
    assert.equal(res.body, null);
    assert.equal(res.text(), "hello");
  });

  it("body holds a Readable when provided", () => {
    const bodyStream = new PassThrough();
    const res = new NLcURLResponse({
      status: 200,
      statusText: "OK",
      headers: {},
      rawBody: Buffer.alloc(0),
      body: bodyStream,
      httpVersion: "1.1",
      url: "https://example.com/",
      redirectCount: 0,
      timings: emptyTimings,
      request: { method: "GET", headers: {}, url: "https://example.com/" },
    });
    assert.ok(res.body !== null);
    assert.equal(res.rawBody.length, 0);
  });

  it("text() throws on a streaming response", () => {
    const res = new NLcURLResponse({
      status: 200,
      statusText: "OK",
      headers: {},
      rawBody: Buffer.alloc(0),
      body: new PassThrough(),
      httpVersion: "1.1",
      url: "https://example.com/",
      redirectCount: 0,
      timings: emptyTimings,
      request: { method: "GET", headers: {}, url: "https://example.com/" },
    });
    assert.throws(() => res.text(), /streaming response/);
  });

  it("json() throws on a streaming response", () => {
    const res = new NLcURLResponse({
      status: 200,
      statusText: "OK",
      headers: {},
      rawBody: Buffer.alloc(0),
      body: new PassThrough(),
      httpVersion: "1.1",
      url: "https://example.com/",
      redirectCount: 0,
      timings: emptyTimings,
      request: { method: "GET", headers: {}, url: "https://example.com/" },
    });
    assert.throws(() => res.json(), /streaming response/);
  });

  it("getAll() returns all values for a header from rawHeaders", () => {
    const res = new NLcURLResponse({
      status: 200,
      statusText: "OK",
      headers: { "set-cookie": "a=1; b=2" },
      rawHeaders: [
        ["set-cookie", "a=1; Path=/"],
        ["set-cookie", "b=2; Path=/"],
        ["content-type", "text/html"],
      ],
      rawBody: Buffer.alloc(0),
      httpVersion: "1.1",
      url: "https://example.com/",
      redirectCount: 0,
      timings: emptyTimings,
      request: { method: "GET", headers: {}, url: "https://example.com/" },
    });
    assert.deepEqual(res.getAll("set-cookie"), ["a=1; Path=/", "b=2; Path=/"]);
  });

  it("getAll() returns empty array for a missing header", () => {
    const res = makeResponse(200, "");
    assert.deepEqual(res.getAll("x-missing"), []);
  });

  it("getAll() is case-insensitive", () => {
    const res = new NLcURLResponse({
      status: 200,
      statusText: "OK",
      headers: {},
      rawHeaders: [
        ["Content-Type", "text/html"],
        ["CONTENT-TYPE", "text/plain"],
      ],
      rawBody: Buffer.alloc(0),
      httpVersion: "1.1",
      url: "https://example.com/",
      redirectCount: 0,
      timings: emptyTimings,
      request: { method: "GET", headers: {}, url: "https://example.com/" },
    });
    assert.deepEqual(res.getAll("content-type"), ["text/html", "text/plain"]);
  });
});
