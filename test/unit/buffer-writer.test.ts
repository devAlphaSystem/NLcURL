/**
 * Unit tests for src/utils/buffer-writer.ts
 * Tests auto-growing big-endian buffer builder.
 * Expected values derived from big-endian encoding rules.
 */
import { describe, it } from "node:test";
import { strict as assert } from "node:assert";
import { BufferWriter } from "../../src/utils/buffer-writer.js";

describe("BufferWriter", () => {
  describe("constructor and properties", () => {
    it("initializes with position 0 and length 0", () => {
      const writer = new BufferWriter();
      assert.equal(writer.position, 0);
      assert.equal(writer.length, 0);
    });

    it("accepts custom initial capacity", () => {
      const writer = new BufferWriter(64);
      assert.equal(writer.position, 0);
      assert.equal(writer.length, 0);
    });

    it("toBuffer returns empty buffer when nothing written", () => {
      const writer = new BufferWriter();
      const buf = writer.toBuffer();
      assert.equal(buf.length, 0);
    });
  });

  describe("writeUInt8", () => {
    it("writes a single byte in big-endian", () => {
      const writer = new BufferWriter();
      writer.writeUInt8(0xff);
      const buf = writer.toBuffer();
      assert.equal(buf.length, 1);
      assert.equal(buf[0], 0xff);
      assert.equal(writer.position, 1);
    });

    it("writes 0x00", () => {
      const writer = new BufferWriter();
      writer.writeUInt8(0x00);
      assert.deepStrictEqual(writer.toBuffer(), Buffer.from([0x00]));
    });

    it("masks to lower 8 bits", () => {
      const writer = new BufferWriter();
      writer.writeUInt8(0x1ff);
      assert.equal(writer.toBuffer()[0], 0xff);
    });

    it("returns this for chaining", () => {
      const writer = new BufferWriter();
      const result = writer.writeUInt8(0x01);
      assert.equal(result, writer);
    });
  });

  describe("writeUInt16", () => {
    it("writes big-endian 16-bit integer", () => {
      const writer = new BufferWriter();
      writer.writeUInt16(258);
      assert.deepStrictEqual(writer.toBuffer(), Buffer.from([0x01, 0x02]));
      assert.equal(writer.position, 2);
    });

    it("writes 0xFFFF (65535)", () => {
      const writer = new BufferWriter();
      writer.writeUInt16(0xffff);
      assert.deepStrictEqual(writer.toBuffer(), Buffer.from([0xff, 0xff]));
    });

    it("writes 0x0000", () => {
      const writer = new BufferWriter();
      writer.writeUInt16(0);
      assert.deepStrictEqual(writer.toBuffer(), Buffer.from([0x00, 0x00]));
    });
  });

  describe("writeUInt24", () => {
    it("writes big-endian 24-bit integer", () => {
      const writer = new BufferWriter();
      writer.writeUInt24(66051);
      assert.deepStrictEqual(writer.toBuffer(), Buffer.from([0x01, 0x02, 0x03]));
      assert.equal(writer.position, 3);
    });

    it("writes 0xFFFFFF (16777215)", () => {
      const writer = new BufferWriter();
      writer.writeUInt24(0xffffff);
      assert.deepStrictEqual(writer.toBuffer(), Buffer.from([0xff, 0xff, 0xff]));
    });

    it("writes 0x000000", () => {
      const writer = new BufferWriter();
      writer.writeUInt24(0);
      assert.deepStrictEqual(writer.toBuffer(), Buffer.from([0x00, 0x00, 0x00]));
    });
  });

  describe("writeUInt32", () => {
    it("writes big-endian 32-bit integer", () => {
      const writer = new BufferWriter();
      writer.writeUInt32(16909060);
      assert.deepStrictEqual(writer.toBuffer(), Buffer.from([0x01, 0x02, 0x03, 0x04]));
      assert.equal(writer.position, 4);
    });

    it("writes 0xFFFFFFFF (4294967295)", () => {
      const writer = new BufferWriter();
      writer.writeUInt32(0xffffffff);
      assert.deepStrictEqual(writer.toBuffer(), Buffer.from([0xff, 0xff, 0xff, 0xff]));
    });

    it("writes 0x00000000", () => {
      const writer = new BufferWriter();
      writer.writeUInt32(0);
      assert.deepStrictEqual(writer.toBuffer(), Buffer.from([0x00, 0x00, 0x00, 0x00]));
    });
  });

  describe("writeBytes", () => {
    it("writes raw bytes from a Buffer", () => {
      const writer = new BufferWriter();
      writer.writeBytes(Buffer.from([0xde, 0xad, 0xbe, 0xef]));
      assert.deepStrictEqual(writer.toBuffer(), Buffer.from([0xde, 0xad, 0xbe, 0xef]));
      assert.equal(writer.position, 4);
    });

    it("writes raw bytes from a Uint8Array", () => {
      const writer = new BufferWriter();
      writer.writeBytes(new Uint8Array([0xca, 0xfe]));
      assert.deepStrictEqual(writer.toBuffer(), Buffer.from([0xca, 0xfe]));
    });

    it("writes empty bytes without advancing", () => {
      const writer = new BufferWriter();
      writer.writeBytes(Buffer.alloc(0));
      assert.equal(writer.position, 0);
      assert.equal(writer.toBuffer().length, 0);
    });
  });

  describe("writeVector8 / writeVector16 / writeVector24", () => {
    it("writes 1-byte length-prefixed vector", () => {
      const writer = new BufferWriter();
      writer.writeVector8(Buffer.from([0xaa, 0xbb]));
      assert.deepStrictEqual(writer.toBuffer(), Buffer.from([0x02, 0xaa, 0xbb]));
    });

    it("throws RangeError for vector8 data > 255 bytes", () => {
      const writer = new BufferWriter();
      assert.throws(() => writer.writeVector8(Buffer.alloc(256)), RangeError);
    });

    it("writes 2-byte length-prefixed vector", () => {
      const writer = new BufferWriter();
      writer.writeVector16(Buffer.from([0xde, 0xad]));
      assert.deepStrictEqual(writer.toBuffer(), Buffer.from([0x00, 0x02, 0xde, 0xad]));
    });

    it("throws RangeError for vector16 data > 65535 bytes", () => {
      const writer = new BufferWriter();
      assert.throws(() => writer.writeVector16(Buffer.alloc(65536)), RangeError);
    });

    it("writes 3-byte length-prefixed vector", () => {
      const writer = new BufferWriter();
      writer.writeVector24(Buffer.from([0xff]));
      assert.deepStrictEqual(writer.toBuffer(), Buffer.from([0x00, 0x00, 0x01, 0xff]));
    });

    it("writes zero-length vector", () => {
      const writer = new BufferWriter();
      writer.writeVector8(Buffer.alloc(0));
      assert.deepStrictEqual(writer.toBuffer(), Buffer.from([0x00]));
    });
  });

  describe("reserve and patch", () => {
    it("reserves space and patches UInt16 later", () => {
      const writer = new BufferWriter();
      writer.writeUInt8(0x17);
      const offset = writer.reserve(2);
      writer.writeBytes(Buffer.from("Hello"));
      writer.patchUInt16(offset, 5);
      const buf = writer.toBuffer();
      assert.equal(buf[0], 0x17);
      assert.equal(buf.readUInt16BE(1), 5);
      assert.deepStrictEqual(buf.subarray(3), Buffer.from("Hello"));
    });

    it("patches UInt24 value", () => {
      const writer = new BufferWriter();
      const offset = writer.reserve(3);
      writer.writeBytes(Buffer.from([0xaa, 0xbb]));
      writer.patchUInt24(offset, 2);
      const buf = writer.toBuffer();
      assert.equal(buf[0], 0x00);
      assert.equal(buf[1], 0x00);
      assert.equal(buf[2], 0x02);
    });
  });

  describe("auto-growth", () => {
    it("grows buffer when writing beyond initial capacity", () => {
      const writer = new BufferWriter(4);
      writer.writeBytes(Buffer.alloc(10, 0xab));
      const buf = writer.toBuffer();
      assert.equal(buf.length, 10);
      assert.equal(buf[0], 0xab);
      assert.equal(buf[9], 0xab);
    });

    it("throws Error when exceeding 256MB max capacity", () => {
      const writer = new BufferWriter(1);
      writer.writeBytes(Buffer.alloc(2048));
      assert.equal(writer.length, 2048);
    });
  });

  describe("round-trip with BufferReader", async () => {
    const { BufferReader } = await import("../../src/utils/buffer-reader.js");

    it("data written by BufferWriter can be read by BufferReader", () => {
      const writer = new BufferWriter();
      writer.writeUInt8(0x17);
      writer.writeUInt16(0x0303);
      writer.writeUInt32(0xdeadbeef);
      writer.writeVector16(Buffer.from("Hello"));

      const reader = new BufferReader(writer.toBuffer());
      assert.equal(reader.readUInt8(), 0x17);
      assert.equal(reader.readUInt16(), 0x0303);
      assert.equal(reader.readUInt32(), 0xdeadbeef);
      const vec = reader.readVector16();
      assert.deepStrictEqual(vec, Buffer.from("Hello"));
      assert.equal(reader.remaining, 0);
    });
  });

  describe("toBuffer returns a copy", () => {
    it("modifying returned buffer does not affect writer state", () => {
      const writer = new BufferWriter();
      writer.writeUInt8(0xaa);
      const buf1 = writer.toBuffer();
      buf1[0] = 0x00;
      const buf2 = writer.toBuffer();
      assert.equal(buf2[0], 0xaa);
    });
  });
});
