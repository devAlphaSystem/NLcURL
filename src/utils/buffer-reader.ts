/** Sequential big-endian reader over a fixed-size buffer. */
export class BufferReader {
  private _buf: Buffer;
  private _pos: number;

  /**
   * Create a reader over the given buffer.
   *
   * @param {Buffer} buf - Source buffer.
   * @param {number} offset - Initial read position.
   */
  constructor(buf: Buffer, offset: number = 0) {
    this._buf = buf;
    this._pos = offset;
  }

  /** Current read position within the buffer. */
  get position(): number {
    return this._pos;
  }

  /** Number of bytes remaining after the current position. */
  get remaining(): number {
    return this._buf.length - this._pos;
  }

  /** Total buffer length. */
  get length(): number {
    return this._buf.length;
  }

  /** Return the underlying buffer. */
  get buffer(): Buffer {
    return this._buf;
  }

  /**
   * Preview bytes at the current position without advancing.
   *
   * @param {number} length - Number of bytes to peek.
   * @returns {Buffer} Buffer slice.
   */
  peek(length: number): Buffer {
    this.assertAvailable(length);
    return this._buf.subarray(this._pos, this._pos + length);
  }

  /** Read a single unsigned 8-bit integer. */
  readUInt8(): number {
    this.assertAvailable(1);
    const v = this._buf[this._pos]!;
    this._pos += 1;
    return v;
  }

  /** Read an unsigned 16-bit big-endian integer. */
  readUInt16(): number {
    this.assertAvailable(2);
    const v = this._buf.readUInt16BE(this._pos);
    this._pos += 2;
    return v;
  }

  /** Read an unsigned 24-bit big-endian integer. */
  readUInt24(): number {
    this.assertAvailable(3);
    const b0 = this._buf[this._pos]!;
    const b1 = this._buf[this._pos + 1]!;
    const b2 = this._buf[this._pos + 2]!;
    this._pos += 3;
    return (b0 << 16) | (b1 << 8) | b2;
  }

  /** Read an unsigned 32-bit big-endian integer. */
  readUInt32(): number {
    this.assertAvailable(4);
    const v = this._buf.readUInt32BE(this._pos);
    this._pos += 4;
    return v;
  }

  /**
   * Read a fixed number of bytes and advance the position.
   *
   * @param {number} length - Number of bytes to read.
   * @returns {Buffer} Copied buffer slice.
   */
  readBytes(length: number): Buffer {
    this.assertAvailable(length);
    const slice = Buffer.from(this._buf.subarray(this._pos, this._pos + length));
    this._pos += length;
    return slice;
  }

  /** Read a length-prefixed vector with a 1-byte length prefix. */
  readVector8(): Buffer {
    const len = this.readUInt8();
    return this.readBytes(len);
  }

  /** Read a length-prefixed vector with a 2-byte big-endian length prefix. */
  readVector16(): Buffer {
    const len = this.readUInt16();
    return this.readBytes(len);
  }

  /** Read a length-prefixed vector with a 3-byte big-endian length prefix. */
  readVector24(): Buffer {
    const len = this.readUInt24();
    return this.readBytes(len);
  }

  /**
   * Advance the read position without returning data.
   *
   * @param {number} length - Number of bytes to skip.
   */
  skip(length: number): void {
    this.assertAvailable(length);
    this._pos += length;
  }

  /**
   * Set the read position to an absolute offset.
   *
   * @param {number} position - Target position.
   */
  seek(position: number): void {
    if (position < 0 || position > this._buf.length) {
      throw new RangeError(`Seek position ${position} out of bounds [0, ${this._buf.length}]`);
    }
    this._pos = position;
  }

  /**
   * Create a sub-reader covering the next `length` bytes and advance.
   *
   * @param {number} length - Number of bytes for the sub-reader.
   * @returns {BufferReader} New `BufferReader` over the sub-range.
   */
  subReader(length: number): BufferReader {
    this.assertAvailable(length);
    const sub = new BufferReader(this._buf.subarray(this._pos, this._pos + length));
    this._pos += length;
    return sub;
  }

  private assertAvailable(n: number): void {
    if (this._pos + n > this._buf.length) {
      throw new RangeError(`Buffer underflow: need ${n} bytes at offset ${this._pos}, only ${this._buf.length - this._pos} available`);
    }
  }
}
