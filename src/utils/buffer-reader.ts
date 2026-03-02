
/**
 * Stateful cursor for reading typed values from a `Buffer` in big-endian byte
 * order. Advances an internal position pointer after every read so callers
 * don't need to track offsets manually.
 *
 * @example
 * const r = new BufferReader(buf);
 * const version = r.readUInt8();
 * const length  = r.readUInt16();
 * const payload = r.readBytes(length);
 */
export class BufferReader {
  private _buf: Buffer;
  private _pos: number;

  /**
   * Creates a new BufferReader.
   *
   * @param {Buffer} buf      - Buffer to read from.
   * @param {number} [offset=0] - Initial cursor position.
   */
  constructor(buf: Buffer, offset: number = 0) {
    this._buf = buf;
    this._pos = offset;
  }

  /** Current byte offset of the read cursor. */
  get position(): number {
    return this._pos;
  }

  /** Number of bytes remaining after the current cursor position. */
  get remaining(): number {
    return this._buf.length - this._pos;
  }

  /** Total length of the underlying buffer. */
  get length(): number {
    return this._buf.length;
  }

  /** The underlying `Buffer` instance. */
  get buffer(): Buffer {
    return this._buf;
  }

  /**
   * Returns the next `length` bytes without advancing the cursor.
   *
   * @param {number} length - Number of bytes to peek at.
   * @returns {Buffer} A view into the underlying buffer (not a copy).
   * @throws {RangeError} If `length` bytes are not available.
   */
  peek(length: number): Buffer {
    this.assertAvailable(length);
    return this._buf.subarray(this._pos, this._pos + length);
  }

  /**
   * Reads one unsigned 8-bit integer and advances the cursor by 1.
   *
   * @returns {number} Unsigned byte value (0–255).
   * @throws {RangeError} If fewer than 1 byte remains.
   */
  readUInt8(): number {
    this.assertAvailable(1);
    const v = this._buf[this._pos]!;
    this._pos += 1;
    return v;
  }

  /**
   * Reads one big-endian unsigned 16-bit integer and advances the cursor by 2.
   *
   * @returns {number} Unsigned 16-bit value (0–65 535).
   * @throws {RangeError} If fewer than 2 bytes remain.
   */
  readUInt16(): number {
    this.assertAvailable(2);
    const v = this._buf.readUInt16BE(this._pos);
    this._pos += 2;
    return v;
  }

  /**
   * Reads one big-endian unsigned 24-bit integer and advances the cursor by 3.
   *
   * @returns {number} Unsigned 24-bit value (0–16 777 215).
   * @throws {RangeError} If fewer than 3 bytes remain.
   */
  readUInt24(): number {
    this.assertAvailable(3);
    const b0 = this._buf[this._pos]!;
    const b1 = this._buf[this._pos + 1]!;
    const b2 = this._buf[this._pos + 2]!;
    this._pos += 3;
    return (b0 << 16) | (b1 << 8) | b2;
  }

  /**
   * Reads one big-endian unsigned 32-bit integer and advances the cursor by 4.
   *
   * @returns {number} Unsigned 32-bit value (0–4 294 967 295).
   * @throws {RangeError} If fewer than 4 bytes remain.
   */
  readUInt32(): number {
    this.assertAvailable(4);
    const v = this._buf.readUInt32BE(this._pos);
    this._pos += 4;
    return v;
  }

  /**
   * Reads `length` bytes into a new `Buffer` and advances the cursor.
   *
   * @param {number} length - Number of bytes to read.
   * @returns {Buffer} Copy of the requested bytes.
   * @throws {RangeError} If `length` bytes are not available.
   */
  readBytes(length: number): Buffer {
    this.assertAvailable(length);
    const slice = Buffer.from(this._buf.subarray(this._pos, this._pos + length));
    this._pos += length;
    return slice;
  }

  /**
   * Reads a length-prefixed byte vector where the length is encoded as a
   * one-byte (8-bit) unsigned integer immediately preceding the data.
   *
   * @returns {Buffer} The vector payload bytes.
   * @throws {RangeError} If insufficient bytes remain.
   */
  readVector8(): Buffer {
    const len = this.readUInt8();
    return this.readBytes(len);
  }

  /**
   * Reads a length-prefixed byte vector where the length is encoded as a
   * big-endian two-byte (16-bit) unsigned integer immediately preceding the data.
   *
   * @returns {Buffer} The vector payload bytes.
   * @throws {RangeError} If insufficient bytes remain.
   */
  readVector16(): Buffer {
    const len = this.readUInt16();
    return this.readBytes(len);
  }

  /**
   * Reads a length-prefixed byte vector where the length is encoded as a
   * big-endian three-byte (24-bit) unsigned integer immediately preceding the data.
   *
   * @returns {Buffer} The vector payload bytes.
   * @throws {RangeError} If insufficient bytes remain.
   */
  readVector24(): Buffer {
    const len = this.readUInt24();
    return this.readBytes(len);
  }

  /**
   * Advances the cursor by `length` bytes without returning the data.
   *
   * @param {number} length - Number of bytes to skip.
   * @throws {RangeError} If `length` bytes are not available.
   */
  skip(length: number): void {
    this.assertAvailable(length);
    this._pos += length;
  }

  /**
   * Moves the cursor to an absolute byte position within the buffer.
   *
   * @param {number} position - Target byte offset (0 to `length` inclusive).
   * @throws {RangeError} If `position` is negative or beyond the buffer length.
   */
  seek(position: number): void {
    if (position < 0 || position > this._buf.length) {
      throw new RangeError(`Seek position ${position} out of bounds [0, ${this._buf.length}]`);
    }
    this._pos = position;
  }

  /**
   * Reads `length` bytes from the current position and returns a new
   * `BufferReader` positioned at offset 0 within that sub-slice. The parent
   * cursor advances by `length` bytes.
   *
   * @param {number} length - Byte count to slice into the sub-reader.
   * @returns {BufferReader} Reader over the requested sub-slice.
   * @throws {RangeError} If `length` bytes are not available.
   */
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
