const INITIAL_CAPACITY = 1024;
const GROWTH_FACTOR = 2;
const MAX_CAPACITY = 256 * 1024 * 1024;

/** Auto-growing big-endian buffer builder. */
export class BufferWriter {
  private _buf: Buffer;
  private _pos: number;

  /**
   * Create a writer with the given initial capacity.
   *
   * @param {number} [capacity] - Initial buffer allocation in bytes.
   */
  constructor(capacity: number = INITIAL_CAPACITY) {
    this._buf = Buffer.allocUnsafe(capacity);
    this._pos = 0;
  }

  /** Current write position (identical to the number of bytes written). */
  get position(): number {
    return this._pos;
  }

  /** Number of bytes written so far. */
  get length(): number {
    return this._pos;
  }

  /** Copy the written region into a new buffer and return it. */
  toBuffer(): Buffer {
    return Buffer.from(this._buf.subarray(0, this._pos));
  }

  /**
   * Write an unsigned 8-bit integer.
   *
   * @param {number} value - Value to write.
   */
  writeUInt8(value: number): this {
    this.ensureCapacity(1);
    this._buf[this._pos] = value & 0xff;
    this._pos += 1;
    return this;
  }

  /**
   * Write an unsigned 16-bit big-endian integer.
   *
   * @param {number} value - Value to write.
   */
  writeUInt16(value: number): this {
    this.ensureCapacity(2);
    this._buf.writeUInt16BE(value, this._pos);
    this._pos += 2;
    return this;
  }

  /**
   * Write an unsigned 24-bit big-endian integer.
   *
   * @param {number} value - Value to write.
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
   * Write an unsigned 32-bit big-endian integer.
   *
   * @param {number} value - Value to write.
   */
  writeUInt32(value: number): this {
    this.ensureCapacity(4);
    this._buf.writeUInt32BE(value, this._pos);
    this._pos += 4;
    return this;
  }

  /**
   * Write raw bytes into the buffer.
   *
   * @param {Buffer | Uint8Array} data - Bytes to append.
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
   * Write a length-prefixed vector with a 1-byte length prefix.
   *
   * @param {Buffer | Uint8Array} data - Data to write.
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
   * Write a length-prefixed vector with a 2-byte big-endian length prefix.
   *
   * @param {Buffer | Uint8Array} data - Data to write.
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
   * Write a length-prefixed vector with a 3-byte big-endian length prefix.
   *
   * @param {Buffer | Uint8Array} data - Data to write.
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
   * Reserve space and return its offset for later patching.
   *
   * @param {number} size - Number of bytes to reserve.
   * @returns {number} Starting offset of the reserved region.
   */
  reserve(size: number): number {
    this.ensureCapacity(size);
    const offset = this._pos;
    this._pos += size;
    return offset;
  }

  /**
   * Overwrite a previously reserved 16-bit value.
   *
   * @param {number} offset - Byte offset to patch.
   * @param {number} value - New 16-bit value.
   */
  patchUInt16(offset: number, value: number): void {
    this._buf.writeUInt16BE(value, offset);
  }

  /**
   * Overwrite a previously reserved 24-bit value.
   *
   * @param {number} offset - Byte offset to patch.
   * @param {number} value - New 24-bit value.
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
