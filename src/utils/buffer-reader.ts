/**
 * Binary reader for parsing TLS records, HTTP/2 frames, and other
 * network protocol structures.  All multi-byte integers are read in
 * network byte order (big-endian) unless stated otherwise.
 */

export class BufferReader {
  private _buf: Buffer;
  private _pos: number;

  constructor(buf: Buffer, offset: number = 0) {
    this._buf = buf;
    this._pos = offset;
  }

  get position(): number {
    return this._pos;
  }

  get remaining(): number {
    return this._buf.length - this._pos;
  }

  get length(): number {
    return this._buf.length;
  }

  get buffer(): Buffer {
    return this._buf;
  }

  peek(length: number): Buffer {
    this.assertAvailable(length);
    return this._buf.subarray(this._pos, this._pos + length);
  }

  readUInt8(): number {
    this.assertAvailable(1);
    const v = this._buf[this._pos]!;
    this._pos += 1;
    return v;
  }

  readUInt16(): number {
    this.assertAvailable(2);
    const v = this._buf.readUInt16BE(this._pos);
    this._pos += 2;
    return v;
  }

  readUInt24(): number {
    this.assertAvailable(3);
    const b0 = this._buf[this._pos]!;
    const b1 = this._buf[this._pos + 1]!;
    const b2 = this._buf[this._pos + 2]!;
    this._pos += 3;
    return (b0 << 16) | (b1 << 8) | b2;
  }

  readUInt32(): number {
    this.assertAvailable(4);
    const v = this._buf.readUInt32BE(this._pos);
    this._pos += 4;
    return v;
  }

  readBytes(length: number): Buffer {
    this.assertAvailable(length);
    const slice = Buffer.from(this._buf.subarray(this._pos, this._pos + length));
    this._pos += length;
    return slice;
  }

  /** Read a length-prefixed vector with 1-byte length field. */
  readVector8(): Buffer {
    const len = this.readUInt8();
    return this.readBytes(len);
  }

  /** Read a length-prefixed vector with 2-byte length field. */
  readVector16(): Buffer {
    const len = this.readUInt16();
    return this.readBytes(len);
  }

  /** Read a length-prefixed vector with 3-byte length field. */
  readVector24(): Buffer {
    const len = this.readUInt24();
    return this.readBytes(len);
  }

  skip(length: number): void {
    this.assertAvailable(length);
    this._pos += length;
  }

  seek(position: number): void {
    if (position < 0 || position > this._buf.length) {
      throw new RangeError(`Seek position ${position} out of bounds [0, ${this._buf.length}]`);
    }
    this._pos = position;
  }

  /** Create a sub-reader over the next `length` bytes without copying. */
  subReader(length: number): BufferReader {
    this.assertAvailable(length);
    const sub = new BufferReader(this._buf.subarray(this._pos, this._pos + length));
    this._pos += length;
    return sub;
  }

  private assertAvailable(n: number): void {
    if (this._pos + n > this._buf.length) {
      throw new RangeError(
        `Buffer underflow: need ${n} bytes at offset ${this._pos}, only ${this._buf.length - this._pos} available`
      );
    }
  }
}
