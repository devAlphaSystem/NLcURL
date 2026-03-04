import { describe, it } from "node:test";
import assert from "node:assert/strict";
import { BufferWriter } from "../../src/utils/buffer-writer.js";
import { BufferReader } from "../../src/utils/buffer-reader.js";

describe("BufferWriter", () => {
  it("writes and reads UInt8", () => {
    const w = new BufferWriter();
    w.writeUInt8(0xff);
    w.writeUInt8(0x00);
    w.writeUInt8(0x42);
    const buf = w.toBuffer();
    assert.equal(buf.length, 3);
    assert.equal(buf[0], 0xff);
    assert.equal(buf[1], 0x00);
    assert.equal(buf[2], 0x42);
  });

  it("writes UInt16 in big-endian", () => {
    const w = new BufferWriter();
    w.writeUInt16(0x0301);
    const buf = w.toBuffer();
    assert.equal(buf.length, 2);
    assert.equal(buf.readUInt16BE(0), 0x0301);
  });

  it("writes UInt24", () => {
    const w = new BufferWriter();
    w.writeUInt24(0x010203);
    const buf = w.toBuffer();
    assert.equal(buf.length, 3);
    assert.equal(buf[0], 0x01);
    assert.equal(buf[1], 0x02);
    assert.equal(buf[2], 0x03);
  });

  it("writes UInt32", () => {
    const w = new BufferWriter();
    w.writeUInt32(0xdeadbeef);
    const buf = w.toBuffer();
    assert.equal(buf.length, 4);
    assert.equal(buf.readUInt32BE(0), 0xdeadbeef);
  });

  it("writes bytes", () => {
    const w = new BufferWriter();
    w.writeBytes(Buffer.from([1, 2, 3]));
    w.writeBytes(Buffer.from([4, 5]));
    const buf = w.toBuffer();
    assert.equal(buf.length, 5);
    assert.deepEqual([...buf], [1, 2, 3, 4, 5]);
  });

  it("grows buffer when capacity exceeded", () => {
    const w = new BufferWriter(4);
    for (let i = 0; i < 100; i++) {
      w.writeUInt8(i & 0xff);
    }
    const buf = w.toBuffer();
    assert.equal(buf.length, 100);
    assert.equal(buf[0], 0);
    assert.equal(buf[99], 99);
  });

  it("tracks position correctly", () => {
    const w = new BufferWriter();
    assert.equal(w.position, 0);
    w.writeUInt8(1);
    assert.equal(w.position, 1);
    w.writeUInt16(2);
    assert.equal(w.position, 3);
    w.writeUInt24(3);
    assert.equal(w.position, 6);
    w.writeUInt32(4);
    assert.equal(w.position, 10);
  });

  it("writes length-prefixed vectors", () => {
    const w = new BufferWriter();
    const data = Buffer.from([0xaa, 0xbb, 0xcc]);
    w.writeVector8(data);
    const buf = w.toBuffer();
    assert.equal(buf[0], 3);
    assert.deepEqual([...buf.subarray(1)], [0xaa, 0xbb, 0xcc]);
  });

  it("writes vector16 with 2-byte length prefix", () => {
    const w = new BufferWriter();
    const data = Buffer.from([0x01, 0x02]);
    w.writeVector16(data);
    const buf = w.toBuffer();
    assert.equal(buf.readUInt16BE(0), 2);
    assert.deepEqual([...buf.subarray(2)], [0x01, 0x02]);
  });

  it("reserve and patchUInt16", () => {
    const w = new BufferWriter();
    const offset = w.reserve(2);
    w.writeUInt8(0xaa);
    w.writeUInt8(0xbb);
    w.patchUInt16(offset, 2);
    const buf = w.toBuffer();
    assert.equal(buf.readUInt16BE(0), 2);
    assert.equal(buf[2], 0xaa);
    assert.equal(buf[3], 0xbb);
  });

  it("toBuffer returns independent copy", () => {
    const w = new BufferWriter();
    w.writeUInt8(1);
    const buf1 = w.toBuffer();
    w.writeUInt8(2);
    const buf2 = w.toBuffer();
    assert.equal(buf1.length, 1);
    assert.equal(buf2.length, 2);
  });
});

describe("BufferReader", () => {
  it("reads UInt8", () => {
    const r = new BufferReader(Buffer.from([0xff, 0x42]));
    assert.equal(r.readUInt8(), 0xff);
    assert.equal(r.readUInt8(), 0x42);
  });

  it("reads UInt16", () => {
    const buf = Buffer.alloc(2);
    buf.writeUInt16BE(0x0303, 0);
    const r = new BufferReader(buf);
    assert.equal(r.readUInt16(), 0x0303);
  });

  it("reads UInt24", () => {
    const r = new BufferReader(Buffer.from([0x01, 0x02, 0x03]));
    assert.equal(r.readUInt24(), 0x010203);
  });

  it("reads UInt32", () => {
    const buf = Buffer.alloc(4);
    buf.writeUInt32BE(0xdeadbeef, 0);
    const r = new BufferReader(buf);
    assert.equal(r.readUInt32(), 0xdeadbeef);
  });

  it("reads bytes", () => {
    const r = new BufferReader(Buffer.from([1, 2, 3, 4, 5]));
    const chunk = r.readBytes(3);
    assert.deepEqual([...chunk], [1, 2, 3]);
    assert.equal(r.remaining, 2);
  });

  it("tracks position and remaining", () => {
    const r = new BufferReader(Buffer.from([1, 2, 3, 4]));
    assert.equal(r.position, 0);
    assert.equal(r.remaining, 4);
    r.readUInt8();
    assert.equal(r.position, 1);
    assert.equal(r.remaining, 3);
  });

  it("peeks without advancing position", () => {
    const r = new BufferReader(Buffer.from([0xaa, 0xbb, 0xcc]));
    const peeked = r.peek(2);
    assert.equal(r.position, 0);
    assert.deepEqual([...peeked], [0xaa, 0xbb]);
  });

  it("throws on underflow", () => {
    const r = new BufferReader(Buffer.from([1]));
    r.readUInt8();
    assert.throws(() => r.readUInt8());
  });

  it("roundtrips writer -> reader", () => {
    const w = new BufferWriter();
    w.writeUInt8(0x16);
    w.writeUInt16(0x0303);
    w.writeUInt24(0x000045);
    w.writeUInt32(0xcafebabe);
    w.writeBytes(Buffer.from("hello"));

    const r = new BufferReader(w.toBuffer());
    assert.equal(r.readUInt8(), 0x16);
    assert.equal(r.readUInt16(), 0x0303);
    assert.equal(r.readUInt24(), 0x000045);
    assert.equal(r.readUInt32(), 0xcafebabe);
    assert.equal(r.readBytes(5).toString(), "hello");
    assert.equal(r.remaining, 0);
  });
});
