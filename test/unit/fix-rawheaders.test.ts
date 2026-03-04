import { describe, it } from "node:test";
import assert from "node:assert/strict";
import { HttpResponseParser } from "../../src/http/h1/parser.js";

describe("Fix 8 – rawHeaders preserve original header name casing", () => {
  it("parser rawHeaders retain original casing", () => {
    const parser = new HttpResponseParser();
    const raw = Buffer.from("HTTP/1.1 200 OK\r\n" + "Content-Type: text/html\r\n" + "X-Request-ID: abc123\r\n" + "Set-Cookie: session=xyz\r\n" + "Content-Length: 2\r\n" + "\r\n" + "ok", "latin1");

    const done = parser.feed(raw);
    assert.ok(done);

    const result = parser.getResult();
    const rawMap = new Map(result.rawHeaders);

    assert.equal(rawMap.get("Content-Type"), "text/html", "Content-Type name should be mixed case");
    assert.equal(rawMap.get("X-Request-ID"), "abc123", "X-Request-ID name should be mixed case");
    assert.equal(rawMap.get("Set-Cookie"), "session=xyz", "Set-Cookie should be mixed case");
    assert.equal(rawMap.get("Content-Length"), "2");

    assert.ok(!result.rawHeaders.some(([k]) => k === "content-type"), "rawHeaders should NOT have lowercased content-type");
    assert.ok(!result.rawHeaders.some(([k]) => k === "x-request-id"), "rawHeaders should NOT have lowercased x-request-id");
  });

  it("parser rawHeaders preserve ALL-CAPS header names", () => {
    const parser = new HttpResponseParser();
    const raw = Buffer.from("HTTP/1.1 200 OK\r\n" + "SERVER: Apache\r\n" + "X-POWERED-BY: PHP/8.1\r\n" + "content-length: 0\r\n" + "\r\n", "latin1");

    const done = parser.feed(raw);
    assert.ok(done);

    const result = parser.getResult();
    const rawNames = result.rawHeaders.map(([k]) => k);

    assert.ok(rawNames.includes("SERVER"), "ALL-CAPS SERVER should be preserved");
    assert.ok(rawNames.includes("X-POWERED-BY"), "ALL-CAPS X-POWERED-BY should be preserved");
    assert.ok(rawNames.includes("content-length"), "lowercase content-length should be preserved");
  });

  it("lookup headers (headers map) are lowercased while rawHeaders are not", () => {
    const parser = new HttpResponseParser();
    const raw = Buffer.from("HTTP/1.1 200 OK\r\n" + "Content-Type: application/json\r\n" + "Content-Length: 0\r\n" + "\r\n", "latin1");

    const done = parser.feed(raw);
    assert.ok(done);

    const result = parser.getResult();

    assert.equal(result.headers.get("content-type"), "application/json");

    assert.equal(result.rawHeaders[0]![0], "Content-Type");
  });
});
