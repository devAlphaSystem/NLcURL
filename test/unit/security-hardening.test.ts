import { describe, it } from "node:test";
import assert from "node:assert/strict";
import { HPACKEncoder, HPACKDecoder } from "../../src/http/h2/hpack.js";
import { readFrame, writeFrame } from "../../src/http/h2/frames.js";
import { BufferWriter } from "../../src/utils/buffer-writer.js";

describe("Security: HPACK decodeInteger bounds check", () => {
  it("throws on truncated continuation-byte sequence", () => {
    const decoder = new HPACKDecoder();
    const malicious = Buffer.from([0xff, 0x80, 0x80, 0x80, 0x80]);
    assert.throws(() => decoder.decode(malicious), /unexpected end of integer encoding/);
  });

  it("throws on integer overflow from excessive continuation bytes", () => {
    const decoder = new HPACKDecoder();
    const bytes = [0xff, 0x80, 0x80, 0x80, 0x80, 0x80, 0x01];
    const malicious = Buffer.from(bytes);
    assert.throws(() => decoder.decode(malicious), /integer overflow/);
  });

  it("decodes valid multi-byte integers correctly", () => {
    const encoder = new HPACKEncoder();
    const decoder = new HPACKDecoder();
    const headers: Array<[string, string]> = [
      [":method", "GET"],
      [":path", "/"],
      [":scheme", "https"],
    ];
    const encoded = encoder.encode(headers);
    const decoded = decoder.decode(encoded);
    assert.deepEqual(decoded, headers);
  });
});

describe("Security: H2 readFrame max frame size", () => {
  it("rejects frames exceeding default max frame size", () => {
    const length = 16385;
    const header = Buffer.alloc(9 + length);
    header[0] = (length >> 16) & 0xff;
    header[1] = (length >> 8) & 0xff;
    header[2] = length & 0xff;
    header[3] = 0x0;
    header[4] = 0x0;
    header[8] = 1;

    assert.throws(() => readFrame(header, 0, 16384), /FRAME_SIZE_ERROR/);
  });

  it("accepts frames within the specified max frame size", () => {
    const payload = Buffer.alloc(100, 0x41);
    const frame = writeFrame({
      type: 0x0,
      flags: 0x0,
      streamId: 1,
      payload,
    });
    const result = readFrame(frame, 0, 16384);
    assert.ok(result);
    assert.equal(result.frame.payload.length, 100);
  });

  it("accepts frames at exact max frame size boundary", () => {
    const payload = Buffer.alloc(16384, 0x42);
    const frame = writeFrame({
      type: 0x0,
      flags: 0x0,
      streamId: 1,
      payload,
    });
    const result = readFrame(frame, 0, 16384);
    assert.ok(result);
    assert.equal(result.frame.payload.length, 16384);
  });

  it("uses protocol max when no limit specified", () => {
    const payload = Buffer.alloc(100, 0x43);
    const frame = writeFrame({
      type: 0x0,
      flags: 0x0,
      streamId: 1,
      payload,
    });
    const result = readFrame(frame, 0);
    assert.ok(result);
    assert.equal(result.frame.payload.length, 100);
  });
});

describe("Security: BufferWriter max capacity", () => {
  it("throws when requested capacity exceeds 256 MiB limit", () => {
    const writer = new BufferWriter(1024);
    const hugeSize = 256 * 1024 * 1024 + 1;
    assert.throws(() => writer.writeBytes(Buffer.alloc(hugeSize)), /exceeds.*limit/);
  });

  it("allows writes within capacity limits", () => {
    const writer = new BufferWriter(64);
    writer.writeBytes(Buffer.alloc(128, 0x41));
    const buf = writer.toBuffer();
    assert.equal(buf.length, 128);
  });
});
