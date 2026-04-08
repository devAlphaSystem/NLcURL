/**
 * Unit tests for src/utils/buffer-reader.ts
 * Tests sequential big-endian reading over a fixed Buffer.
 * Expected values derived from big-endian encoding rules (network byte order).
 */
import { describe, it } from "node:test";
import { strict as assert } from "node:assert";
import { BufferReader } from "../../src/utils/buffer-reader.js";

describe("BufferReader", () => {
  describe("constructor and properties", () => {
    it("initializes with position 0 by default", () => {
      const reader = new BufferReader(Buffer.from([0x01, 0x02, 0x03]));
      assert.equal(reader.position, 0);
      assert.equal(reader.remaining, 3);
      assert.equal(reader.length, 3);
    });

    it("initializes with a custom offset", () => {
      const reader = new BufferReader(Buffer.from([0x01, 0x02, 0x03, 0x04]), 2);
      assert.equal(reader.position, 2);
      assert.equal(reader.remaining, 2);
      assert.equal(reader.length, 4);
    });

    it("exposes the underlying buffer", () => {
      const buf = Buffer.from([0xaa, 0xbb]);
      const reader = new BufferReader(buf);
      assert.equal(reader.buffer, buf);
    });

    it("reports remaining=0 for empty buffer", () => {
      const reader = new BufferReader(Buffer.alloc(0));
      assert.equal(reader.position, 0);
      assert.equal(reader.remaining, 0);
      assert.equal(reader.length, 0);
    });
  });

  describe("readUInt8", () => {
    it("reads a single byte and advances position by 1", () => {
      const reader = new BufferReader(Buffer.from([0xff, 0x00, 0x7f]));
      assert.equal(reader.readUInt8(), 255);
      assert.equal(reader.position, 1);
      assert.equal(reader.readUInt8(), 0);
      assert.equal(reader.position, 2);
      assert.equal(reader.readUInt8(), 127);
      assert.equal(reader.position, 3);
    });

    it("throws RangeError when buffer is exhausted", () => {
      const reader = new BufferReader(Buffer.from([0x01]));
      reader.readUInt8();
      assert.throws(() => reader.readUInt8(), RangeError);
    });

    it("throws RangeError on empty buffer", () => {
      const reader = new BufferReader(Buffer.alloc(0));
      assert.throws(() => reader.readUInt8(), RangeError);
    });
  });

  describe("readUInt16", () => {
    it("reads big-endian 16-bit integer", () => {
      const reader = new BufferReader(Buffer.from([0x01, 0x02]));
      assert.equal(reader.readUInt16(), 258);
      assert.equal(reader.position, 2);
    });

    it("reads 0xFFFF as 65535", () => {
      const reader = new BufferReader(Buffer.from([0xff, 0xff]));
      assert.equal(reader.readUInt16(), 65535);
    });

    it("reads 0x0000 as 0", () => {
      const reader = new BufferReader(Buffer.from([0x00, 0x00]));
      assert.equal(reader.readUInt16(), 0);
    });

    it("throws RangeError when only 1 byte remains", () => {
      const reader = new BufferReader(Buffer.from([0x01]));
      assert.throws(() => reader.readUInt16(), RangeError);
    });
  });

  describe("readUInt24", () => {
    it("reads big-endian 24-bit integer", () => {
      const reader = new BufferReader(Buffer.from([0x01, 0x02, 0x03]));
      assert.equal(reader.readUInt24(), 66051);
      assert.equal(reader.position, 3);
    });

    it("reads 0xFFFFFF as 16777215", () => {
      const reader = new BufferReader(Buffer.from([0xff, 0xff, 0xff]));
      assert.equal(reader.readUInt24(), 16777215);
    });

    it("reads 0x000000 as 0", () => {
      const reader = new BufferReader(Buffer.from([0x00, 0x00, 0x00]));
      assert.equal(reader.readUInt24(), 0);
    });

    it("throws RangeError when only 2 bytes remain", () => {
      const reader = new BufferReader(Buffer.from([0x01, 0x02]));
      assert.throws(() => reader.readUInt24(), RangeError);
    });
  });

  describe("readUInt32", () => {
    it("reads big-endian 32-bit integer", () => {
      const reader = new BufferReader(Buffer.from([0x01, 0x02, 0x03, 0x04]));
      assert.equal(reader.readUInt32(), 16909060);
      assert.equal(reader.position, 4);
    });

    it("reads 0xFFFFFFFF as 4294967295", () => {
      const reader = new BufferReader(Buffer.from([0xff, 0xff, 0xff, 0xff]));
      assert.equal(reader.readUInt32(), 4294967295);
    });

    it("reads 0x00000000 as 0", () => {
      const reader = new BufferReader(Buffer.from([0x00, 0x00, 0x00, 0x00]));
      assert.equal(reader.readUInt32(), 0);
    });

    it("throws RangeError when only 3 bytes remain", () => {
      const reader = new BufferReader(Buffer.from([0x01, 0x02, 0x03]));
      assert.throws(() => reader.readUInt32(), RangeError);
    });
  });

  describe("readBytes", () => {
    it("reads exact number of bytes and returns a copy", () => {
      const reader = new BufferReader(Buffer.from([0x0a, 0x0b, 0x0c, 0x0d]));
      const result = reader.readBytes(2);
      assert.deepStrictEqual(result, Buffer.from([0x0a, 0x0b]));
      assert.equal(reader.position, 2);
      result[0] = 0xff;
      assert.equal(reader.buffer[0], 0x0a);
    });

    it("reads 0 bytes without advancing", () => {
      const reader = new BufferReader(Buffer.from([0x01]));
      const result = reader.readBytes(0);
      assert.equal(result.length, 0);
      assert.equal(reader.position, 0);
    });

    it("throws RangeError for excessive length", () => {
      const reader = new BufferReader(Buffer.from([0x01, 0x02]));
      assert.throws(() => reader.readBytes(3), RangeError);
    });
  });

  describe("readVector8 / readVector16 / readVector24", () => {
    it("reads a 1-byte length-prefixed vector", () => {
      const reader = new BufferReader(Buffer.from([0x03, 0xaa, 0xbb, 0xcc]));
      const result = reader.readVector8();
      assert.deepStrictEqual(result, Buffer.from([0xaa, 0xbb, 0xcc]));
      assert.equal(reader.position, 4);
    });

    it("reads a 2-byte length-prefixed vector", () => {
      const reader = new BufferReader(Buffer.from([0x00, 0x02, 0xde, 0xad]));
      const result = reader.readVector16();
      assert.deepStrictEqual(result, Buffer.from([0xde, 0xad]));
      assert.equal(reader.position, 4);
    });

    it("reads a 3-byte length-prefixed vector", () => {
      const reader = new BufferReader(Buffer.from([0x00, 0x00, 0x01, 0xff]));
      const result = reader.readVector24();
      assert.deepStrictEqual(result, Buffer.from([0xff]));
      assert.equal(reader.position, 4);
    });

    it("reads zero-length vector8", () => {
      const reader = new BufferReader(Buffer.from([0x00]));
      const result = reader.readVector8();
      assert.equal(result.length, 0);
      assert.equal(reader.position, 1);
    });
  });

  describe("peek", () => {
    it("returns bytes without advancing position", () => {
      const reader = new BufferReader(Buffer.from([0x01, 0x02, 0x03]));
      const peeked = reader.peek(2);
      assert.deepStrictEqual(peeked, Buffer.from([0x01, 0x02]));
      assert.equal(reader.position, 0);
    });

    it("throws RangeError when peeking beyond remaining", () => {
      const reader = new BufferReader(Buffer.from([0x01]));
      assert.throws(() => reader.peek(2), RangeError);
    });
  });

  describe("skip", () => {
    it("advances position without returning data", () => {
      const reader = new BufferReader(Buffer.from([0x01, 0x02, 0x03, 0x04]));
      reader.skip(2);
      assert.equal(reader.position, 2);
      assert.equal(reader.readUInt8(), 0x03);
    });

    it("throws RangeError when skipping beyond remaining", () => {
      const reader = new BufferReader(Buffer.from([0x01]));
      assert.throws(() => reader.skip(2), RangeError);
    });
  });

  describe("seek", () => {
    it("sets position to absolute offset", () => {
      const reader = new BufferReader(Buffer.from([0x01, 0x02, 0x03, 0x04]));
      reader.seek(3);
      assert.equal(reader.position, 3);
      assert.equal(reader.readUInt8(), 0x04);
    });

    it("allows seeking to position 0", () => {
      const reader = new BufferReader(Buffer.from([0x01, 0x02]));
      reader.readUInt8();
      reader.seek(0);
      assert.equal(reader.position, 0);
    });

    it("allows seeking to end of buffer", () => {
      const reader = new BufferReader(Buffer.from([0x01, 0x02]));
      reader.seek(2);
      assert.equal(reader.position, 2);
      assert.equal(reader.remaining, 0);
    });

    it("throws RangeError for negative position", () => {
      const reader = new BufferReader(Buffer.from([0x01]));
      assert.throws(() => reader.seek(-1), RangeError);
    });

    it("throws RangeError for position beyond buffer length", () => {
      const reader = new BufferReader(Buffer.from([0x01]));
      assert.throws(() => reader.seek(2), RangeError);
    });
  });

  describe("subReader", () => {
    it("creates a sub-reader over specified bytes and advances parent", () => {
      const reader = new BufferReader(Buffer.from([0x01, 0x02, 0x03, 0x04, 0x05]));
      const sub = reader.subReader(3);
      assert.equal(reader.position, 3);
      assert.equal(sub.length, 3);
      assert.equal(sub.position, 0);
      assert.equal(sub.readUInt8(), 0x01);
      assert.equal(sub.readUInt8(), 0x02);
      assert.equal(sub.readUInt8(), 0x03);
    });

    it("throws RangeError when sub-reader exceeds remaining", () => {
      const reader = new BufferReader(Buffer.from([0x01, 0x02]));
      assert.throws(() => reader.subReader(3), RangeError);
    });
  });

  describe("sequential multi-field reading (protocol simulation)", () => {
    it("reads a TLS-like record header: type(1) + version(2) + length(2) + payload", () => {
      const buf = Buffer.from([0x17, 0x03, 0x03, 0x00, 0x05, 0x48, 0x65, 0x6c, 0x6c, 0x6f]);
      const reader = new BufferReader(buf);
      const type = reader.readUInt8();
      const version = reader.readUInt16();
      const length = reader.readUInt16();
      const payload = reader.readBytes(length);

      assert.equal(type, 0x17);
      assert.equal(version, 0x0303);
      assert.equal(length, 5);
      assert.deepStrictEqual(payload, Buffer.from("Hello"));
      assert.equal(reader.remaining, 0);
    });
  });
});
