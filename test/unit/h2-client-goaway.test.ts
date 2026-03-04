import { describe, it } from "node:test";
import assert from "node:assert/strict";
import { PassThrough, Duplex } from "node:stream";
import { H2Client } from "../../src/http/h2/client.js";
import { ProtocolError } from "../../src/core/errors.js";
import { HPACKEncoder } from "../../src/http/h2/hpack.js";
import { buildGoawayFrame, buildSettingsFrame, buildHeadersFrame, buildDataFrame, Flags, FrameType } from "../../src/http/h2/frames.js";

function createMockTransport() {
  const written: Buffer[] = [];
  const transport = new PassThrough();

  transport.write = function (chunk: any, ...args: any[]): boolean {
    written.push(Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk));
    return true;
  } as any;

  return { transport, written };
}

function sendSettingsAckThenGoaway(transport: PassThrough, lastStreamId: number, errorCode: number): void {
  transport.push(buildSettingsFrame([], true));
  transport.push(buildGoawayFrame(lastStreamId, errorCode));
}

function buildResponseHeaders(encoder: HPACKEncoder, streamId: number, endStream: boolean): Buffer {
  const headerBlock = encoder.encode([[":status", "200"]]);
  return buildHeadersFrame(streamId, headerBlock, endStream, true);
}

describe("H2Client — GOAWAY lastStreamId=0 (rejects all streams)", () => {
  it("rejects with ProtocolError(errorCode=0) on graceful GOAWAY", async () => {
    const { transport } = createMockTransport();
    const h2 = new H2Client(transport as unknown as Duplex);

    const p = h2.request({ url: "https://example.com/", method: "GET", headers: {} });
    sendSettingsAckThenGoaway(transport, 0, 0);

    await assert.rejects(p, (err: Error) => {
      assert.ok(err instanceof ProtocolError);
      assert.equal((err as ProtocolError).errorCode, 0);
      assert.match(err.message, /graceful shutdown/i);
      return true;
    });
    assert.equal(h2.isClosed, true);
  });

  it("rejects with error code on non-graceful GOAWAY", async () => {
    const { transport } = createMockTransport();
    const h2 = new H2Client(transport as unknown as Duplex);

    const p = h2.request({ url: "https://example.com/", method: "GET", headers: {} });
    sendSettingsAckThenGoaway(transport, 0, 11);

    await assert.rejects(p, (err: Error) => {
      assert.ok(err instanceof ProtocolError);
      assert.equal((err as ProtocolError).errorCode, 11);
      assert.match(err.message, /error code 11/);
      return true;
    });
  });

  it("rejects ALL pending streams when lastStreamId=0", async () => {
    const { transport } = createMockTransport();
    const h2 = new H2Client(transport as unknown as Duplex);

    const r1 = h2.request({ url: "https://example.com/1", method: "GET", headers: {} });
    const r2 = h2.request({ url: "https://example.com/2", method: "GET", headers: {} });
    const r3 = h2.request({ url: "https://example.com/3", method: "GET", headers: {} });

    sendSettingsAckThenGoaway(transport, 0, 0);

    const results = await Promise.allSettled([r1, r2, r3]);
    for (const r of results) {
      assert.equal(r.status, "rejected");
      assert.ok(r.reason instanceof ProtocolError);
      assert.equal((r.reason as ProtocolError).errorCode, 0);
    }
  });

  it("invokes onClose immediately when no streams remain", async () => {
    const { transport } = createMockTransport();
    const h2 = new H2Client(transport as unknown as Duplex);

    let closeCalled = false;
    h2.onClose = () => {
      closeCalled = true;
    };

    const p = h2.request({ url: "https://example.com/", method: "GET", headers: {} });
    sendSettingsAckThenGoaway(transport, 0, 0);

    await assert.rejects(p, ProtocolError);
    assert.equal(closeCalled, true);
  });

  it("marks connection closed so subsequent requests fail", async () => {
    const { transport } = createMockTransport();
    const h2 = new H2Client(transport as unknown as Duplex);

    const p = h2.request({ url: "https://example.com/", method: "GET", headers: {} });
    sendSettingsAckThenGoaway(transport, 0, 0);
    await assert.rejects(p, ProtocolError);

    await assert.rejects(h2.request({ url: "https://example.com/", method: "GET", headers: {} }), (err: Error) => {
      assert.ok(err instanceof ProtocolError);
      assert.match(err.message, /closed/i);
      return true;
    });
  });

  it('graceful message says "graceful", error message includes code', async () => {
    const { transport: t1 } = createMockTransport();
    const h2a = new H2Client(t1 as unknown as Duplex);
    const p1 = h2a.request({ url: "https://example.com/", method: "GET", headers: {} });
    sendSettingsAckThenGoaway(t1, 0, 0);
    await assert.rejects(p1, (err: Error) => {
      assert.match(err.message, /graceful/i);
      return true;
    });

    const { transport: t2 } = createMockTransport();
    const h2b = new H2Client(t2 as unknown as Duplex);
    const p2 = h2b.request({ url: "https://example.com/", method: "GET", headers: {} });
    sendSettingsAckThenGoaway(t2, 0, 1);
    await assert.rejects(p2, (err: Error) => {
      assert.doesNotMatch(err.message, /graceful/i);
      assert.match(err.message, /error code 1/);
      return true;
    });
  });
});

describe("H2Client — GOAWAY respects lastStreamId (RFC 9113 §6.8)", () => {
  it("allows stream to complete when lastStreamId covers it", async () => {
    const { transport } = createMockTransport();
    const h2 = new H2Client(transport as unknown as Duplex);
    const enc = new HPACKEncoder();

    const p = h2.request({ url: "https://example.com/", method: "GET", headers: {} });

    transport.push(buildSettingsFrame([], true));
    transport.push(buildGoawayFrame(1, 0));
    transport.push(buildResponseHeaders(enc, 1, false));
    transport.push(buildDataFrame(1, Buffer.from('{"ok":true}'), true));

    const resp = await p;
    assert.equal(resp.status, 200);
    assert.equal(resp.text(), '{"ok":true}');
    assert.equal(h2.isClosed, true);
  });

  it("rejects only streams with id > lastStreamId", async () => {
    const { transport } = createMockTransport();
    const h2 = new H2Client(transport as unknown as Duplex);
    const enc = new HPACKEncoder();

    const p1 = h2.request({ url: "https://example.com/1", method: "GET", headers: {} });
    const p3 = h2.request({ url: "https://example.com/3", method: "GET", headers: {} });

    transport.push(buildSettingsFrame([], true));
    transport.push(buildGoawayFrame(1, 0));

    await assert.rejects(p3, (err: Error) => {
      assert.ok(err instanceof ProtocolError);
      assert.equal((err as ProtocolError).errorCode, 0);
      return true;
    });

    transport.push(buildResponseHeaders(enc, 1, false));
    transport.push(buildDataFrame(1, Buffer.from("ok"), true));

    const resp1 = await p1;
    assert.equal(resp1.status, 200);
    assert.equal(resp1.text(), "ok");
  });

  it("prevents new requests after GOAWAY even when lastStreamId covers existing streams", async () => {
    const { transport } = createMockTransport();
    const h2 = new H2Client(transport as unknown as Duplex);
    const enc = new HPACKEncoder();

    const p = h2.request({ url: "https://example.com/", method: "GET", headers: {} });

    transport.push(buildSettingsFrame([], true));
    transport.push(buildGoawayFrame(1, 0));
    transport.push(buildResponseHeaders(enc, 1, false));
    transport.push(buildDataFrame(1, Buffer.from("done"), true));

    await p;

    await assert.rejects(h2.request({ url: "https://example.com/", method: "GET", headers: {} }), (err: Error) => {
      assert.ok(err instanceof ProtocolError);
      assert.match(err.message, /closed/i);
      return true;
    });
  });

  it("defers onClose until the last covered stream completes", async () => {
    const { transport } = createMockTransport();
    const h2 = new H2Client(transport as unknown as Duplex);
    const enc = new HPACKEncoder();

    const closeEvents: string[] = [];
    h2.onClose = () => {
      closeEvents.push("closed");
    };

    const p = h2.request({ url: "https://example.com/", method: "GET", headers: {} });

    transport.push(buildSettingsFrame([], true));
    transport.push(buildGoawayFrame(1, 0));

    assert.equal(closeEvents.length, 0);

    transport.push(buildResponseHeaders(enc, 1, false));
    transport.push(buildDataFrame(1, Buffer.from("x"), true));

    await p;

    assert.equal(closeEvents.length, 1);
  });
});
