const INITIAL_CAPACITY = 1024;
const GROWTH_FACTOR = 2;
const MAX_CAPACITY = 256 * 1024 * 1024;

/**
 * Growable binary buffer writer that serializes typed values in big-endian byte
 * order. The internal buffer doubles in capacity as needed. Call
 * {@link BufferWriter.toBuffer} to obtain the written bytes as a new `Buffer`.
 *
 * @example
 * const w = new BufferWriter();
 * w.writeUInt8(0x16);
 * w.writeUInt16(0x0303);
 * w.writeVector16(data);
 * return w.toBuffer();
 */
export class BufferWriter {
  private _buf: Buffer;
  private _pos: number;

  /**
   * Creates a new BufferWriter with an optional initial capacity.
   *
   * @param {number} [capacity=1024] - Initial internal buffer capacity in bytes.
   */
  constructor(capacity: number = INITIAL_CAPACITY) {
    this._buf = Buffer.allocUnsafe(capacity);
    this._pos = 0;
  }

  /** Current write position (equals the number of bytes written so far). */
  get position(): number {
    return this._pos;
  }

  /** Number of bytes that have been written (alias for {@link BufferWriter.position}). */
  get length(): number {
    return this._pos;
  }

  /**
   * Returns a copy of the written bytes as a new `Buffer`. The returned buffer
   * contains only the bytes that have been written, regardless of the internal
   * capacity.
   *
   * @returns {Buffer} Copy of all written data.
   */
  toBuffer(): Buffer {
    return Buffer.from(this._buf.subarray(0, this._pos));
  }

  /**
   * Writes one unsigned byte and advances the write position by 1.
   *
   * @param {number} value - Byte value (only the lowest 8 bits are used).
   * @returns {this} This instance for chaining.
   */
  writeUInt8(value: number): this {
    this.ensureCapacity(1);
    this._buf[this._pos] = value & 0xff;
    this._pos += 1;
    return this;
  }

  /**
   * Writes one big-endian unsigned 16-bit integer and advances the write position by 2.
   *
   * @param {number} value - 16-bit value to write.
   * @returns {this} This instance for chaining.
   */
  writeUInt16(value: number): this {
    this.ensureCapacity(2);
    this._buf.writeUInt16BE(value, this._pos);
    this._pos += 2;
    return this;
  }

  /**
   * Writes one big-endian unsigned 24-bit integer and advances the write position by 3.
   *
   * @param {number} value - 24-bit value to write.
   * @returns {this} This instance for chaining.
   */
  writeUInt24(value: number): this {
    this.ensureCapacity(3);
    this._buf[this._pos] = (value >>> 16) & 0xff;
    this._buf[this._pos + 1] = (value >>> 8) & 0xff;
    this._buf[this._pos + 2] = value & 0xff;
    this._pos += 3;
    return this;
  }

  /**
   * Writes one big-endian unsigned 32-bit integer and advances the write position by 4.
   *
   * @param {number} value - 32-bit value to write.
   * @returns {this} This instance for chaining.
   */
  writeUInt32(value: number): this {
    this.ensureCapacity(4);
    this._buf.writeUInt32BE(value, this._pos);
    this._pos += 4;
    return this;
  }

  /**
   * Appends raw bytes from `data` and advances the write position accordingly.
   *
   * @param {Buffer | Uint8Array} data - Data to write.
   * @returns {this} This instance for chaining.
   */
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

  /**
   * Writes a length-prefixed byte vector using an 8-bit length prefix.
   * Equivalent to `writeUInt8(data.length)` followed by `writeBytes(data)`.
   *
   * @param {Buffer | Uint8Array} data - Data to write (must be ≤ 255 bytes).
   * @returns {this} This instance for chaining.
   * @throws {RangeError} If `data.length` exceeds 255.
   */
  writeVector8(data: Buffer | Uint8Array): this {
    if (data.length > 0xff) {
      throw new RangeError(`Vector8 overflow: ${data.length} > 255`);
    }
    this.writeUInt8(data.length);
    this.writeBytes(data);
    return this;
  }

  /**
   * Writes a length-prefixed byte vector using a big-endian 16-bit length prefix.
   * Equivalent to `writeUInt16(data.length)` followed by `writeBytes(data)`.
   *
   * @param {Buffer | Uint8Array} data - Data to write (must be ≤ 65 535 bytes).
   * @returns {this} This instance for chaining.
   * @throws {RangeError} If `data.length` exceeds 65 535.
   */
  writeVector16(data: Buffer | Uint8Array): this {
    if (data.length > 0xffff) {
      throw new RangeError(`Vector16 overflow: ${data.length} > 65535`);
    }
    this.writeUInt16(data.length);
    this.writeBytes(data);
    return this;
  }

  /**
   * Writes a length-prefixed byte vector using a big-endian 24-bit length prefix.
   * Equivalent to `writeUInt24(data.length)` followed by `writeBytes(data)`.
   *
   * @param {Buffer | Uint8Array} data - Data to write (must be ≤ 16 777 215 bytes).
   * @returns {this} This instance for chaining.
   * @throws {RangeError} If `data.length` exceeds 16 777 215.
   */
  writeVector24(data: Buffer | Uint8Array): this {
    if (data.length > 0xffffff) {
      throw new RangeError(`Vector24 overflow: ${data.length} > 16777215`);
    }
    this.writeUInt24(data.length);
    this.writeBytes(data);
    return this;
  }

  /**
   * Reserves `size` bytes at the current position without writing any data,
   * advances the cursor, and returns the byte offset of the reserved region.
   * Use this to write a length prefix, then later patch it with
   * {@link BufferWriter.patchUInt16} or {@link BufferWriter.patchUInt24}.
   *
   * @param {number} size - Number of bytes to reserve.
   * @returns {number} Byte offset of the start of the reserved region.
   */
  reserve(size: number): number {
    this.ensureCapacity(size);
    const offset = this._pos;
    this._pos += size;
    return offset;
  }

  /**
   * Overwrites a previously reserved 16-bit slot with `value` in big-endian byte order.
   * Does not advance the write cursor.
   *
   * @param {number} offset - Byte offset returned by {@link BufferWriter.reserve}.
   * @param {number} value  - 16-bit value to patch in.
   */
  patchUInt16(offset: number, value: number): void {
    this._buf.writeUInt16BE(value, offset);
  }

  /**
   * Overwrites a previously reserved 24-bit slot with `value` in big-endian byte order.
   * Does not advance the write cursor.
   *
   * @param {number} offset - Byte offset returned by {@link BufferWriter.reserve}.
   * @param {number} value  - 24-bit value to patch in.
   */
  patchUInt24(offset: number, value: number): void {
    this._buf[offset] = (value >>> 16) & 0xff;
    this._buf[offset + 1] = (value >>> 8) & 0xff;
    this._buf[offset + 2] = value & 0xff;
  }

  private ensureCapacity(needed: number): void {
    const required = this._pos + needed;
    if (required <= this._buf.length) return;
    if (required > MAX_CAPACITY) {
      throw new Error(`BufferWriter: requested capacity ${required} exceeds ${MAX_CAPACITY} byte limit`);
    }
    let newCap = this._buf.length;
    while (newCap < required) {
      newCap *= GROWTH_FACTOR;
    }
    if (newCap > MAX_CAPACITY) newCap = MAX_CAPACITY;
    const newBuf = Buffer.allocUnsafe(newCap);
    this._buf.copy(newBuf, 0, 0, this._pos);
    this._buf = newBuf;
  }
}
