import { describe, it } from "node:test";
import assert from "node:assert/strict";
import { PassThrough, Duplex } from "node:stream";
import { H2Client } from "../../src/http/h2/client.js";
import { HPACKEncoder, HPACKDecoder } from "../../src/http/h2/hpack.js";
import type { NLcURLRequest } from "../../src/core/request.js";
import { readFrame, buildSettingsFrame, buildHeadersFrame, buildDataFrame, Flags, FrameType } from "../../src/http/h2/frames.js";

function createMockTransport() {
  const written: Buffer[] = [];
  const transport = new PassThrough();

  transport.write = function (chunk: any): boolean {
    written.push(Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk));
    return true;
  } as any;

  return { transport, written };
}

function buildResponseHeaders(encoder: HPACKEncoder, streamId: number, endStream: boolean, extraHeaders?: Array<[string, string]>): Buffer {
  const headers: Array<[string, string]> = [[":status", "200"], ...(extraHeaders ?? [])];
  const headerBlock = encoder.encode(headers);
  return buildHeadersFrame(streamId, headerBlock, endStream, true);
}

function extractRequestHeaders(written: Buffer[], decoder: HPACKDecoder): Array<[string, string]>[] {
  const result: Array<[string, string]>[] = [];
  for (const buf of written) {
    let offset = 0;
    while (offset < buf.length) {
      const frame = readFrame(buf, offset);
      if (!frame) break;
      offset += frame.bytesRead;
      if (frame.frame.type === FrameType.HEADERS) {
        let payload = frame.frame.payload;
        if (frame.frame.flags & Flags.PADDED) {
          const padLen = payload[0]!;
          payload = payload.subarray(1, payload.length - padLen);
        }
        if (frame.frame.flags & 0x20) {
          payload = payload.subarray(5);
        }
        const headers = decoder.decode(payload);
        result.push(headers);
      }
    }
  }
  return result;
}

describe("Fix 4 – H2 request headers override default headers", () => {
  it("request-level header overrides a default header with same name", async () => {
    const { transport, written } = createMockTransport();
    const enc = new HPACKEncoder();
    const dec = new HPACKDecoder();

    const defaultHeaders: Array<[string, string]> = [
      ["user-agent", "DefaultBrowser/1.0"],
      ["accept", "text/html"],
    ];

    const h2 = new H2Client(transport as unknown as Duplex, undefined, defaultHeaders);

    const req: NLcURLRequest = {
      url: "https://example.com/",
      method: "GET",
      headers: {
        "User-Agent": "CustomAgent/2.0",
      },
    };

    const p = h2.request(req);

    transport.push(buildSettingsFrame([], true));
    transport.push(buildResponseHeaders(enc, 1, true));

    const resp = await p;
    assert.equal(resp.status, 200);

    const allHeaders = extractRequestHeaders(written, dec);
    assert.ok(allHeaders.length >= 1, "Should have at least one HEADERS frame");

    const sentHeaders = allHeaders[0]!;
    const uaHeaders = sentHeaders.filter(([k]) => k === "user-agent");

    assert.equal(uaHeaders.length, 1, "Should have exactly one user-agent header");
    assert.equal(uaHeaders[0]![1], "CustomAgent/2.0", "Request header should override default");
  });

  it("default headers are included when request has no override", async () => {
    const { transport, written } = createMockTransport();
    const enc = new HPACKEncoder();
    const dec = new HPACKDecoder();

    const defaultHeaders: Array<[string, string]> = [
      ["user-agent", "DefaultBrowser/1.0"],
      ["accept-language", "en-US"],
    ];

    const h2 = new H2Client(transport as unknown as Duplex, undefined, defaultHeaders);

    const req: NLcURLRequest = {
      url: "https://example.com/path",
      method: "GET",
      headers: {
        "x-custom": "myvalue",
      },
    };

    const p = h2.request(req);
    transport.push(buildSettingsFrame([], true));
    transport.push(buildResponseHeaders(enc, 1, true));

    await p;

    const allHeaders = extractRequestHeaders(written, dec);
    const sentHeaders = allHeaders[0]!;
    const headerMap = new Map(sentHeaders);

    assert.equal(headerMap.get("user-agent"), "DefaultBrowser/1.0");
    assert.equal(headerMap.get("accept-language"), "en-US");
    assert.equal(headerMap.get("x-custom"), "myvalue");
  });

  it("request adds headers not in defaults", async () => {
    const { transport, written } = createMockTransport();
    const enc = new HPACKEncoder();
    const dec = new HPACKDecoder();

    const defaultHeaders: Array<[string, string]> = [["accept", "text/html"]];

    const h2 = new H2Client(transport as unknown as Duplex, undefined, defaultHeaders);

    const p = h2.request({
      url: "https://example.com/",
      method: "POST",
      headers: {
        "x-request-id": "12345",
        authorization: "Bearer abc",
      },
      body: "{}",
    });

    transport.push(buildSettingsFrame([], true));
    transport.push(buildResponseHeaders(enc, 1, true));

    await p;

    const allHeaders = extractRequestHeaders(written, dec);
    const sentHeaders = allHeaders[0]!;
    const headerMap = new Map(sentHeaders);

    assert.equal(headerMap.get("accept"), "text/html");
    assert.equal(headerMap.get("x-request-id"), "12345");
    assert.equal(headerMap.get("authorization"), "Bearer abc");
  });
});

describe("Fix 6 – H2 streaming response resolves when HEADERS has END_STREAM", () => {
  it("streamRequest resolves even when response body is empty (END_STREAM on HEADERS)", async () => {
    const { transport } = createMockTransport();
    const enc = new HPACKEncoder();

    const h2 = new H2Client(transport as unknown as Duplex);

    const p = h2.streamRequest({
      url: "https://example.com/",
      method: "GET",
      headers: {},
    });

    transport.push(buildSettingsFrame([], true));

    transport.push(buildResponseHeaders(enc, 1, true));

    const resp = await p;
    assert.equal(resp.status, 200);
  });

  it("streamRequest with END_STREAM on HEADERS ends the body stream", async () => {
    const { transport } = createMockTransport();
    const enc = new HPACKEncoder();

    const h2 = new H2Client(transport as unknown as Duplex);

    const p = h2.streamRequest({
      url: "https://example.com/",
      method: "GET",
      headers: {},
    });

    transport.push(buildSettingsFrame([], true));
    transport.push(buildResponseHeaders(enc, 1, true));

    const resp = await p;
    assert.equal(resp.status, 200);

    const chunks: Buffer[] = [];
    if (resp.body && typeof resp.body === "object" && "on" in resp.body) {
      const stream = resp.body as NodeJS.ReadableStream;
      await new Promise<void>((resolve) => {
        stream.on("data", (chunk: Buffer) => chunks.push(chunk));
        stream.on("end", resolve);
      });
    }
    assert.equal(chunks.length, 0, "Empty body response should have no data chunks");
  });

  it("streamRequest with data frames after HEADERS works normally", async () => {
    const { transport } = createMockTransport();
    const enc = new HPACKEncoder();

    const h2 = new H2Client(transport as unknown as Duplex);

    const p = h2.streamRequest({
      url: "https://example.com/",
      method: "GET",
      headers: {},
    });

    transport.push(buildSettingsFrame([], true));
    transport.push(buildResponseHeaders(enc, 1, false));
    transport.push(buildDataFrame(1, Buffer.from("hello world"), true));

    const resp = await p;
    assert.equal(resp.status, 200);

    const chunks: Buffer[] = [];
    if (resp.body && typeof resp.body === "object" && "on" in resp.body) {
      const stream = resp.body as NodeJS.ReadableStream;
      await new Promise<void>((resolve) => {
        stream.on("data", (chunk: Buffer) => chunks.push(chunk));
        stream.on("end", resolve);
      });
    }
    const body = Buffer.concat(chunks).toString();
    assert.equal(body, "hello world");
  });
});
