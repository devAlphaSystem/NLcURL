import { describe, it } from "node:test";
import assert from "node:assert/strict";
import { readFrame, writeFrame, buildSettingsFrame, buildWindowUpdateFrame, buildHeadersFrame, buildDataFrame, buildPingFrame, buildGoawayFrame, buildRstStreamFrame, H2_PREFACE, FrameType, Flags } from "../../src/http/h2/frames.js";

describe("H2 frame readFrame / writeFrame roundtrip", () => {
  it("roundtrips a simple frame", () => {
    const frame = {
      type: FrameType.DATA,
      flags: Flags.END_STREAM,
      streamId: 1,
      payload: Buffer.from("hello"),
    };

    const encoded = writeFrame(frame);
    const result = readFrame(encoded, 0);

    assert.ok(result);
    assert.equal(result.frame.type, FrameType.DATA);
    assert.equal(result.frame.flags, Flags.END_STREAM);
    assert.equal(result.frame.streamId, 1);
    assert.equal(result.frame.payload.toString(), "hello");
    assert.equal(result.bytesRead, encoded.length);
  });

  it("returns null for incomplete data", () => {
    assert.equal(readFrame(Buffer.alloc(5), 0), null);
    const frame = writeFrame({
      type: FrameType.DATA,
      flags: 0,
      streamId: 1,
      payload: Buffer.alloc(10),
    });
    assert.equal(readFrame(frame.subarray(0, 12), 0), null);
  });

  it("handles empty payload", () => {
    const frame = writeFrame({
      type: FrameType.SETTINGS,
      flags: Flags.ACK,
      streamId: 0,
      payload: Buffer.alloc(0),
    });

    const result = readFrame(frame, 0);
    assert.ok(result);
    assert.equal(result.frame.type, FrameType.SETTINGS);
    assert.equal(result.frame.flags, Flags.ACK);
    assert.equal(result.frame.payload.length, 0);
  });

  it("reads frame at non-zero offset", () => {
    const padding = Buffer.alloc(10);
    const frame = writeFrame({
      type: FrameType.PING,
      flags: 0,
      streamId: 0,
      payload: Buffer.alloc(8, 0x42),
    });

    const combined = Buffer.concat([padding, frame]);
    const result = readFrame(combined, 10);
    assert.ok(result);
    assert.equal(result.frame.type, FrameType.PING);
  });
});

describe("H2 frame builders", () => {
  it("buildSettingsFrame creates valid SETTINGS", () => {
    const settings = [
      { id: 1, value: 65536 },
      { id: 4, value: 6291456 },
    ];
    const buf = buildSettingsFrame(settings);
    const result = readFrame(buf, 0);
    assert.ok(result);
    assert.equal(result.frame.type, FrameType.SETTINGS);
    assert.equal(result.frame.streamId, 0);
    assert.equal(result.frame.payload.length, 12);
  });

  it("buildSettingsFrame ACK has empty payload", () => {
    const buf = buildSettingsFrame([], true);
    const result = readFrame(buf, 0);
    assert.ok(result);
    assert.equal(result.frame.type, FrameType.SETTINGS);
    assert.equal(result.frame.flags & Flags.ACK, Flags.ACK);
    assert.equal(result.frame.payload.length, 0);
  });

  it("buildWindowUpdateFrame creates valid frame", () => {
    const buf = buildWindowUpdateFrame(0, 15663105);
    const result = readFrame(buf, 0);
    assert.ok(result);
    assert.equal(result.frame.type, FrameType.WINDOW_UPDATE);
    assert.equal(result.frame.payload.readUInt32BE(0), 15663105);
  });

  it("buildHeadersFrame sets correct flags", () => {
    const headerBlock = Buffer.from([0x82, 0x86]);
    const buf = buildHeadersFrame(1, headerBlock, true, true);
    const result = readFrame(buf, 0);
    assert.ok(result);
    assert.equal(result.frame.type, FrameType.HEADERS);
    assert.equal(result.frame.streamId, 1);
    assert.ok(result.frame.flags & Flags.END_STREAM);
    assert.ok(result.frame.flags & Flags.END_HEADERS);
  });

  it("buildDataFrame with END_STREAM", () => {
    const buf = buildDataFrame(3, Buffer.from("body"), true);
    const result = readFrame(buf, 0);
    assert.ok(result);
    assert.equal(result.frame.type, FrameType.DATA);
    assert.equal(result.frame.streamId, 3);
    assert.ok(result.frame.flags & Flags.END_STREAM);
    assert.equal(result.frame.payload.toString(), "body");
  });

  it("buildPingFrame roundtrips data", () => {
    const data = Buffer.from([1, 2, 3, 4, 5, 6, 7, 8]);
    const buf = buildPingFrame(data, false);
    const result = readFrame(buf, 0);
    assert.ok(result);
    assert.equal(result.frame.type, FrameType.PING);
    assert.deepEqual(result.frame.payload, data);
    assert.equal(result.frame.flags & Flags.ACK, 0);
  });

  it("buildPingFrame ACK", () => {
    const data = Buffer.alloc(8, 0xff);
    const buf = buildPingFrame(data, true);
    const result = readFrame(buf, 0);
    assert.ok(result);
    assert.ok(result.frame.flags & Flags.ACK);
  });

  it("buildGoawayFrame", () => {
    const buf = buildGoawayFrame(5, 0);
    const result = readFrame(buf, 0);
    assert.ok(result);
    assert.equal(result.frame.type, FrameType.GOAWAY);
    assert.equal(result.frame.payload.readUInt32BE(0), 5);
    assert.equal(result.frame.payload.readUInt32BE(4), 0);
  });

  it("buildRstStreamFrame", () => {
    const buf = buildRstStreamFrame(1, 8);
    const result = readFrame(buf, 0);
    assert.ok(result);
    assert.equal(result.frame.type, FrameType.RST_STREAM);
    assert.equal(result.frame.streamId, 1);
    assert.equal(result.frame.payload.readUInt32BE(0), 8);
  });
});

describe("H2_PREFACE", () => {
  it("has correct magic bytes", () => {
    assert.equal(H2_PREFACE.toString("ascii"), "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n");
    assert.equal(H2_PREFACE.length, 24);
  });
});

describe("H2 PADDED frames", () => {
  it("can construct and read a PADDED DATA frame", () => {
    const payload = Buffer.from("hello");
    const padLength = 3;
    const paddedPayload = Buffer.concat([Buffer.from([padLength]), payload, Buffer.alloc(padLength)]);

    const frame = writeFrame({
      type: FrameType.DATA,
      flags: 0x08,
      streamId: 1,
      payload: paddedPayload,
    });

    const result = readFrame(frame, 0);
    assert.ok(result);
    assert.equal(result.frame.type, FrameType.DATA);
    assert.equal(result.frame.flags & 0x08, 0x08);
    assert.equal(result.frame.payload[0], padLength);
  });

  it("CONTINUATION frame type is recognized", () => {
    const headerBlock = Buffer.from([0x82, 0x86]);
    const frame = writeFrame({
      type: FrameType.CONTINUATION,
      flags: Flags.END_HEADERS,
      streamId: 1,
      payload: headerBlock,
    });

    const result = readFrame(frame, 0);
    assert.ok(result);
    assert.equal(result.frame.type, FrameType.CONTINUATION);
    assert.ok(result.frame.flags & Flags.END_HEADERS);
  });

  it("WINDOW_UPDATE frame carries 4 bytes increment", () => {
    const buf = buildWindowUpdateFrame(1, 32768);
    const result = readFrame(buf, 0);
    assert.ok(result);
    assert.equal(result.frame.type, FrameType.WINDOW_UPDATE);
    assert.equal(result.frame.streamId, 1);
    assert.equal(result.frame.payload.readUInt32BE(0), 32768);
  });
});
