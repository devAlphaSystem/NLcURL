/**
 * Unit tests for src/utils/compression.ts
 * Expected values derived from zlib specification behavior and the 1024-byte threshold.
 */
import { describe, it } from "node:test";
import { strict as assert } from "node:assert";
import * as zlib from "node:zlib";
import { promisify } from "node:util";
import { compressBody, shouldCompress } from "../../src/utils/compression.js";

const gunzipAsync = promisify(zlib.gunzip);
const inflateAsync = promisify(zlib.inflate);
const brotliDecompressAsync = promisify(zlib.brotliDecompress);

describe("compressBody", () => {
  const testData = Buffer.from("Hello, World! This is test data for compression.");

  it("compresses with gzip and produces valid gzip output", async () => {
    const compressed = await compressBody(testData, "gzip");
    const decompressed = (await gunzipAsync(compressed)) as Buffer;
    assert.deepStrictEqual(decompressed, testData);
    assert.equal(compressed[0], 0x1f);
    assert.equal(compressed[1], 0x8b);
  });

  it("compresses with deflate and produces valid deflate output", async () => {
    const compressed = await compressBody(testData, "deflate");
    const decompressed = (await inflateAsync(compressed)) as Buffer;
    assert.deepStrictEqual(decompressed, testData);
  });

  it("compresses with brotli and produces valid brotli output", async () => {
    const compressed = await compressBody(testData, "br");
    const decompressed = (await brotliDecompressAsync(compressed)) as Buffer;
    assert.deepStrictEqual(decompressed, testData);
  });

  it("handles empty buffer", async () => {
    const compressed = await compressBody(Buffer.alloc(0), "gzip");
    const decompressed = (await gunzipAsync(compressed)) as Buffer;
    assert.equal(decompressed.length, 0);
  });

  it("handles large buffer (10KB)", async () => {
    const large = Buffer.alloc(10240, 0x41);
    const compressed = await compressBody(large, "gzip");
    assert.ok(compressed.length < large.length, `Expected compressed (${compressed.length}) < original (${large.length})`);
    const decompressed = (await gunzipAsync(compressed)) as Buffer;
    assert.deepStrictEqual(decompressed, large);
  });
});

describe("shouldCompress", () => {
  it("returns false for body smaller than 1024 bytes", () => {
    assert.equal(shouldCompress(0), false);
    assert.equal(shouldCompress(1), false);
    assert.equal(shouldCompress(512), false);
    assert.equal(shouldCompress(1023), false);
  });

  it("returns true for body at exactly 1024 bytes", () => {
    assert.equal(shouldCompress(1024), true);
  });

  it("returns true for body larger than 1024 bytes", () => {
    assert.equal(shouldCompress(1025), true);
    assert.equal(shouldCompress(10240), true);
    assert.equal(shouldCompress(1048576), true);
  });
});
