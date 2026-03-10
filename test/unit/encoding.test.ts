/**
 * Unit tests for src/utils/encoding.ts
 * Expected values derived from zlib specifications and RFC 7230/7231 Content-Encoding rules.
 * Decompression bomb threshold: 100:1 ratio, min size 1024 bytes.
 * Max encoding layers: 5.
 */
import { describe, it } from "node:test";
import { strict as assert } from "node:assert";
import * as zlib from "node:zlib";
import { promisify } from "node:util";
import { decompressBody, createDecompressStream, defaultAcceptEncoding, sanitizeAcceptEncoding, supportsZstd } from "../../src/utils/encoding.js";

const gzipAsync = promisify(zlib.gzip);
const deflateAsync = promisify(zlib.deflate);
const brotliCompressAsync = promisify(zlib.brotliCompress);

describe("decompressBody", () => {
  const original = Buffer.from("Hello, World! ".repeat(20));

  it("decompresses gzip-encoded body", async () => {
    const compressed = (await gzipAsync(original)) as Buffer;
    const result = await decompressBody(compressed, "gzip");
    assert.deepStrictEqual(result, original);
  });

  it("decompresses x-gzip (alias for gzip per RFC 7230 §4.2.3)", async () => {
    const compressed = (await gzipAsync(original)) as Buffer;
    const result = await decompressBody(compressed, "x-gzip");
    assert.deepStrictEqual(result, original);
  });

  it("decompresses deflate-encoded body", async () => {
    const compressed = (await deflateAsync(original)) as Buffer;
    const result = await decompressBody(compressed, "deflate");
    assert.deepStrictEqual(result, original);
  });

  it("decompresses brotli-encoded body", async () => {
    const compressed = (await brotliCompressAsync(original)) as Buffer;
    const result = await decompressBody(compressed, "br");
    assert.deepStrictEqual(result, original);
  });

  it("returns body unchanged when contentEncoding is undefined", async () => {
    const result = await decompressBody(original, undefined);
    assert.deepStrictEqual(result, original);
  });

  it("returns body unchanged when contentEncoding is empty string", async () => {
    const result = await decompressBody(original, "");
    assert.deepStrictEqual(result, original);
  });

  it("returns empty buffer for empty body regardless of encoding", async () => {
    const result = await decompressBody(Buffer.alloc(0), "gzip");
    assert.equal(result.length, 0);
  });

  it("returns body unchanged for identity encoding", async () => {
    const result = await decompressBody(original, "identity");
    assert.deepStrictEqual(result, original);
  });

  it("handles layered encoding: gzip, deflate (applied right-to-left)", async () => {
    const gzipped = (await gzipAsync(original)) as Buffer;
    const gzDeflated = (await deflateAsync(gzipped)) as Buffer;
    const result = await decompressBody(gzDeflated, "gzip, deflate");
    assert.deepStrictEqual(result, original);
  });

  it("throws Error when encoding layers exceed 5", async () => {
    await assert.rejects(
      () => decompressBody(Buffer.from("data"), "gzip, gzip, gzip, gzip, gzip, gzip"),
      (err: Error) => {
        assert.ok(err.message.includes("maximum layer count"));
        return true;
      },
    );
  });

  it("throws Error on decompression bomb (ratio > 100:1 for data >= 1024 bytes)", async () => {
    const bigPayload = Buffer.alloc(200_000, 0x00);
    const compressed = (await gzipAsync(bigPayload)) as Buffer;
    if (compressed.length >= 1024 && bigPayload.length / compressed.length > 100) {
      await assert.rejects(
        () => decompressBody(compressed, "gzip"),
        (err: Error) => {
          assert.ok(err.message.includes("Decompression bomb"));
          return true;
        },
      );
    }
  });
});

describe("createDecompressStream", () => {
  it("returns null when contentEncoding is undefined", () => {
    assert.equal(createDecompressStream(undefined), null);
  });

  it("returns null when contentEncoding is empty string", () => {
    assert.equal(createDecompressStream(""), null);
  });

  it("returns null for identity encoding", () => {
    assert.equal(createDecompressStream("identity"), null);
  });

  it("returns a Transform stream for gzip encoding", () => {
    const stream = createDecompressStream("gzip");
    assert.notEqual(stream, null);
    stream!.destroy();
  });

  it("returns a Transform stream for deflate encoding", () => {
    const stream = createDecompressStream("deflate");
    assert.notEqual(stream, null);
    stream!.destroy();
  });

  it("returns a Transform stream for br encoding", () => {
    const stream = createDecompressStream("br");
    assert.notEqual(stream, null);
    stream!.destroy();
  });
});

describe("defaultAcceptEncoding", () => {
  it("includes gzip, deflate, and br", () => {
    const value = defaultAcceptEncoding();
    assert.ok(value.includes("gzip"));
    assert.ok(value.includes("deflate"));
    assert.ok(value.includes("br"));
  });

  it("includes zstd if runtime supports it", () => {
    const value = defaultAcceptEncoding();
    if (supportsZstd) {
      assert.ok(value.includes("zstd"));
    } else {
      assert.ok(!value.includes("zstd"));
    }
  });
});

describe("sanitizeAcceptEncoding", () => {
  it("passes through standard encodings unchanged when zstd not supported", () => {
    if (!supportsZstd) {
      assert.equal(sanitizeAcceptEncoding("gzip, deflate, br"), "gzip, deflate, br");
    }
  });

  it("strips zstd when runtime does not support it", () => {
    if (!supportsZstd) {
      const result = sanitizeAcceptEncoding("gzip, deflate, br, zstd");
      assert.ok(!result.includes("zstd"));
      assert.ok(result.includes("gzip"));
      assert.ok(result.includes("deflate"));
      assert.ok(result.includes("br"));
    }
  });

  it("keeps all encodings when zstd is supported", () => {
    if (supportsZstd) {
      const result = sanitizeAcceptEncoding("gzip, deflate, br, zstd");
      assert.equal(result, "gzip, deflate, br, zstd");
    }
  });
});
