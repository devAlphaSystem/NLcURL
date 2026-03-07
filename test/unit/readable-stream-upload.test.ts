import { describe, it } from "node:test";
import assert from "node:assert/strict";
import { drainReadableStream, drainRequestBody, encodeRequest } from "../../src/http/h1/encoder.js";

describe("drainReadableStream", () => {
  it("drains a ReadableStream into a Buffer", async () => {
    const chunks = [new Uint8Array([1, 2, 3]), new Uint8Array([4, 5, 6])];
    let idx = 0;
    const stream = new ReadableStream<Uint8Array>({
      pull(controller) {
        if (idx < chunks.length) {
          controller.enqueue(chunks[idx]!);
          idx++;
        } else {
          controller.close();
        }
      },
    });

    const result = await drainReadableStream(stream);
    assert.ok(Buffer.isBuffer(result));
    assert.deepEqual([...result], [1, 2, 3, 4, 5, 6]);
  });

  it("returns empty buffer for empty stream", async () => {
    const stream = new ReadableStream<Uint8Array>({
      start(controller) {
        controller.close();
      },
    });

    const result = await drainReadableStream(stream);
    assert.equal(result.length, 0);
  });

  it("handles a large stream", async () => {
    const chunkSize = 1024;
    const numChunks = 100;
    let sent = 0;
    const stream = new ReadableStream<Uint8Array>({
      pull(controller) {
        if (sent < numChunks) {
          controller.enqueue(new Uint8Array(chunkSize).fill(0xab));
          sent++;
        } else {
          controller.close();
        }
      },
    });

    const result = await drainReadableStream(stream);
    assert.equal(result.length, chunkSize * numChunks);
    assert.equal(result[0], 0xab);
    assert.equal(result[result.length - 1], 0xab);
  });
});

describe("drainRequestBody", () => {
  it("buffers ReadableStream body into a Buffer", async () => {
    const stream = new ReadableStream<Uint8Array>({
      start(controller) {
        controller.enqueue(new TextEncoder().encode("hello world"));
        controller.close();
      },
    });

    const req = { url: "https://example.com", method: "POST" as const, body: stream };
    const result = await drainRequestBody(req);

    assert.ok(Buffer.isBuffer(result.body));
    assert.equal((result.body as Buffer).toString("utf-8"), "hello world");
  });

  it("passes through non-ReadableStream bodies unchanged", async () => {
    const body = Buffer.from("test");
    const req = { url: "https://example.com", method: "POST" as const, body };
    const result = await drainRequestBody(req);
    assert.strictEqual(result.body, body);
  });

  it("passes through string bodies unchanged", async () => {
    const req = { url: "https://example.com", method: "POST" as const, body: "hello" };
    const result = await drainRequestBody(req);
    assert.equal(result.body, "hello");
  });

  it("passes through null body unchanged", async () => {
    const req = { url: "https://example.com", method: "GET" as const, body: null };
    const result = await drainRequestBody(req);
    assert.equal(result.body, null);
  });
});

describe("encodeRequest with ReadableStream body", () => {
  it("throws when given a ReadableStream directly (must pre-drain)", () => {
    const stream = new ReadableStream<Uint8Array>({
      start(controller) {
        controller.enqueue(new TextEncoder().encode("data"));
        controller.close();
      },
    });

    const req = { url: "https://example.com/", method: "POST" as const, body: stream };
    assert.throws(() => encodeRequest(req, []), /ReadableStream body must be pre-drained/);
  });

  it("works after drainRequestBody pre-processing", async () => {
    const stream = new ReadableStream<Uint8Array>({
      start(controller) {
        controller.enqueue(new TextEncoder().encode("stream data"));
        controller.close();
      },
    });

    const req = { url: "https://example.com/api", method: "POST" as const, body: stream };
    const drained = await drainRequestBody(req);
    const buf = encodeRequest(drained, []);
    const text = buf.toString("latin1");

    assert.ok(text.includes("POST /api HTTP/1.1"));
    assert.ok(text.includes("content-length: 11"));
    assert.ok(text.includes("stream data"));
  });
});
