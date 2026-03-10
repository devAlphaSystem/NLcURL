/**
 * Unit tests for src/http/trailers.ts
 * HTTP trailer fields validation, serialization, parsing per RFC 7230 §4.1.2.
 */
import { describe, it } from "node:test";
import { strict as assert } from "node:assert";
import { isValidTrailerField, serializeTrailers, parseTrailers, buildTrailerHeader } from "../../src/http/trailers.js";

describe("isValidTrailerField", () => {
  const forbiddenFields = ["transfer-encoding", "content-length", "host", "cache-control", "expect", "max-forwards", "pragma", "range", "te", "authorization", "content-encoding", "content-range", "content-type", "trailer", "set-cookie"];

  for (const field of forbiddenFields) {
    it(`rejects forbidden field: ${field}`, () => {
      assert.equal(isValidTrailerField(field), false);
    });
  }

  it("rejects forbidden fields case-insensitively", () => {
    assert.equal(isValidTrailerField("Transfer-Encoding"), false);
    assert.equal(isValidTrailerField("CONTENT-LENGTH"), false);
  });

  it("accepts non-forbidden fields", () => {
    assert.equal(isValidTrailerField("x-checksum"), true);
    assert.equal(isValidTrailerField("server-timing"), true);
    assert.equal(isValidTrailerField("grpc-status"), true);
  });
});

describe("serializeTrailers", () => {
  it("serializes valid trailer fields to CRLF-delimited buffer", () => {
    const buf = serializeTrailers({ "x-checksum": "abc123", "server-timing": "total;dur=50" });
    const str = buf.toString("ascii");
    assert.ok(str.includes("x-checksum: abc123"));
    assert.ok(str.includes("server-timing: total;dur=50"));
    assert.ok(str.endsWith("\r\n"));
  });

  it("skips forbidden trailer fields", () => {
    const buf = serializeTrailers({
      "x-checksum": "abc",
      "content-type": "text/html",
    });
    const str = buf.toString("ascii");
    assert.ok(str.includes("x-checksum"));
    assert.ok(!str.includes("content-type"));
  });

  it("returns buffer with just CRLF when all fields are forbidden", () => {
    const buf = serializeTrailers({ "content-length": "42" });
    assert.equal(buf.toString("ascii"), "\r\n");
  });
});

describe("parseTrailers", () => {
  it("parses CRLF-delimited trailer fields", () => {
    const data = Buffer.from("x-checksum: abc123\r\nserver-timing: total\r\n", "ascii");
    const result = parseTrailers(data);
    assert.equal(result["x-checksum"], "abc123");
    assert.equal(result["server-timing"], "total");
  });

  it("lowercases field names", () => {
    const data = Buffer.from("X-Checksum: ABC\r\n", "ascii");
    const result = parseTrailers(data);
    assert.equal(result["x-checksum"], "ABC");
  });

  it("skips forbidden fields during parsing", () => {
    const data = Buffer.from("content-type: text/html\r\nx-ok: yes\r\n", "ascii");
    const result = parseTrailers(data);
    assert.equal(result["content-type"], undefined);
    assert.equal(result["x-ok"], "yes");
  });

  it("handles empty or malformed lines", () => {
    const data = Buffer.from("nocolon\r\nx-valid: ok\r\n\r\n", "ascii");
    const result = parseTrailers(data);
    assert.equal(result["x-valid"], "ok");
    assert.equal(Object.keys(result).length, 1);
  });
});

describe("buildTrailerHeader", () => {
  it("builds comma-separated header from valid field names", () => {
    const result = buildTrailerHeader(["x-checksum", "server-timing"]);
    assert.equal(result, "x-checksum, server-timing");
  });

  it("filters out forbidden field names", () => {
    const result = buildTrailerHeader(["x-checksum", "content-length", "server-timing"]);
    assert.equal(result, "x-checksum, server-timing");
  });

  it("returns empty string when all fields are forbidden", () => {
    assert.equal(buildTrailerHeader(["content-type", "authorization"]), "");
  });

  it("returns empty string for empty input", () => {
    assert.equal(buildTrailerHeader([]), "");
  });
});
