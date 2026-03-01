/**
 * Binary writer for constructing TLS records, HTTP/2 frames, and other
 * network protocol structures.  All multi-byte integers are written in
 * network byte order (big-endian) unless stated otherwise.
 */

const INITIAL_CAPACITY = 1024;
const GROWTH_FACTOR = 2;

export class BufferWriter {
  private _buf: Buffer;
  private _pos: number;

  constructor(capacity: number = INITIAL_CAPACITY) {
    this._buf = Buffer.allocUnsafe(capacity);
    this._pos = 0;
  }

  get position(): number {
    return this._pos;
  }

  get length(): number {
    return this._pos;
  }

  /** Return a copy of the written portion. */
  toBuffer(): Buffer {
    return Buffer.from(this._buf.subarray(0, this._pos));
  }

  writeUInt8(value: number): this {
    this.ensureCapacity(1);
    this._buf[this._pos] = value & 0xff;
    this._pos += 1;
    return this;
  }

  writeUInt16(value: number): this {
    this.ensureCapacity(2);
    this._buf.writeUInt16BE(value, this._pos);
    this._pos += 2;
    return this;
  }

  writeUInt24(value: number): this {
    this.ensureCapacity(3);
    this._buf[this._pos] = (value >>> 16) & 0xff;
    this._buf[this._pos + 1] = (value >>> 8) & 0xff;
    this._buf[this._pos + 2] = value & 0xff;
    this._pos += 3;
    return this;
  }

  writeUInt32(value: number): this {
    this.ensureCapacity(4);
    this._buf.writeUInt32BE(value, this._pos);
    this._pos += 4;
    return this;
  }

  writeBytes(data: Buffer | Uint8Array): this {
    this.ensureCapacity(data.length);
    if (data instanceof Buffer) {
      data.copy(this._buf, this._pos);
    } else {
      this._buf.set(data, this._pos);
    }
    this._pos += data.length;
    return this;
  }

  /** Write a length-prefixed vector with 1-byte length field. */
  writeVector8(data: Buffer | Uint8Array): this {
    if (data.length > 0xff) {
      throw new RangeError(`Vector8 overflow: ${data.length} > 255`);
    }
    this.writeUInt8(data.length);
    this.writeBytes(data);
    return this;
  }

  /** Write a length-prefixed vector with 2-byte length field. */
  writeVector16(data: Buffer | Uint8Array): this {
    if (data.length > 0xffff) {
      throw new RangeError(`Vector16 overflow: ${data.length} > 65535`);
    }
    this.writeUInt16(data.length);
    this.writeBytes(data);
    return this;
  }

  /** Write a length-prefixed vector with 3-byte length field. */
  writeVector24(data: Buffer | Uint8Array): this {
    if (data.length > 0xffffff) {
      throw new RangeError(`Vector24 overflow: ${data.length} > 16777215`);
    }
    this.writeUInt24(data.length);
    this.writeBytes(data);
    return this;
  }

  /**
   * Reserve space and return the offset.  The caller must fill the
   * reserved bytes before calling toBuffer().
   */
  reserve(size: number): number {
    this.ensureCapacity(size);
    const offset = this._pos;
    this._pos += size;
    return offset;
  }

  /** Overwrite bytes at a specific offset (for back-patching lengths). */
  patchUInt16(offset: number, value: number): void {
    this._buf.writeUInt16BE(value, offset);
  }

  patchUInt24(offset: number, value: number): void {
    this._buf[offset] = (value >>> 16) & 0xff;
    this._buf[offset + 1] = (value >>> 8) & 0xff;
    this._buf[offset + 2] = value & 0xff;
  }

  private ensureCapacity(needed: number): void {
    const required = this._pos + needed;
    if (required <= this._buf.length) return;
    let newCap = this._buf.length;
    while (newCap < required) {
      newCap *= GROWTH_FACTOR;
    }
    const newBuf = Buffer.allocUnsafe(newCap);
    this._buf.copy(newBuf, 0, 0, this._pos);
    this._buf = newBuf;
  }
}
