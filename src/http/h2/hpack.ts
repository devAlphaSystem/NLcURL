import { BufferWriter } from "../../utils/buffer-writer.js";

const STATIC_TABLE: ReadonlyArray<[string, string]> = [
  ["", ""],
  [":authority", ""],
  [":method", "GET"],
  [":method", "POST"],
  [":path", "/"],
  [":path", "/index.html"],
  [":scheme", "http"],
  [":scheme", "https"],
  [":status", "200"],
  [":status", "204"],
  [":status", "206"],
  [":status", "304"],
  [":status", "400"],
  [":status", "404"],
  [":status", "500"],
  ["accept-charset", ""],
  ["accept-encoding", "gzip, deflate"],
  ["accept-language", ""],
  ["accept-ranges", ""],
  ["accept", ""],
  ["access-control-allow-origin", ""],
  ["age", ""],
  ["allow", ""],
  ["authorization", ""],
  ["cache-control", ""],
  ["content-disposition", ""],
  ["content-encoding", ""],
  ["content-language", ""],
  ["content-length", ""],
  ["content-location", ""],
  ["content-range", ""],
  ["content-type", ""],
  ["cookie", ""],
  ["date", ""],
  ["etag", ""],
  ["expect", ""],
  ["expires", ""],
  ["from", ""],
  ["host", ""],
  ["if-match", ""],
  ["if-modified-since", ""],
  ["if-none-match", ""],
  ["if-range", ""],
  ["if-unmodified-since", ""],
  ["last-modified", ""],
  ["link", ""],
  ["location", ""],
  ["max-forwards", ""],
  ["proxy-authenticate", ""],
  ["proxy-authorization", ""],
  ["range", ""],
  ["referer", ""],
  ["refresh", ""],
  ["retry-after", ""],
  ["server", ""],
  ["set-cookie", ""],
  ["strict-transport-security", ""],
  ["transfer-encoding", ""],
  ["user-agent", ""],
  ["vary", ""],
  ["via", ""],
  ["www-authenticate", ""],
];

class DynamicTable {
  private entries: Array<[string, string]> = [];
  private currentSize = 0;
  maxSize: number;

  constructor(maxSize: number = 4096) {
    this.maxSize = maxSize;
  }

  add(name: string, value: string): void {
    const entrySize = name.length + value.length + 32;
    while (this.currentSize + entrySize > this.maxSize && this.entries.length > 0) {
      const evicted = this.entries.pop()!;
      this.currentSize -= evicted[0].length + evicted[1].length + 32;
    }
    if (entrySize <= this.maxSize) {
      this.entries.unshift([name, value]);
      this.currentSize += entrySize;
    }
  }

  get(index: number): [string, string] | undefined {
    return this.entries[index];
  }

  get length(): number {
    return this.entries.length;
  }

  updateMaxSize(newMax: number): void {
    this.maxSize = newMax;
    while (this.currentSize > this.maxSize && this.entries.length > 0) {
      const evicted = this.entries.pop()!;
      this.currentSize -= evicted[0].length + evicted[1].length + 32;
    }
  }
}

function encodeInteger(w: BufferWriter, value: number, prefix: number, mask: number): void {
  const maxPrefix = (1 << prefix) - 1;
  if (value < maxPrefix) {
    w.writeUInt8(mask | value);
  } else {
    w.writeUInt8(mask | maxPrefix);
    value -= maxPrefix;
    while (value >= 128) {
      w.writeUInt8((value & 0x7f) | 0x80);
      value >>= 7;
    }
    w.writeUInt8(value);
  }
}

function decodeInteger(data: Buffer, offset: number, prefix: number): { value: number; bytesRead: number } {
  const maxPrefix = (1 << prefix) - 1;
  let value = data[offset]! & maxPrefix;
  let bytesRead = 1;

  if (value === maxPrefix) {
    let shift = 0;
    let byte: number;
    do {
      if (offset + bytesRead >= data.length) {
        throw new Error("HPACK: unexpected end of integer encoding");
      }
      if (shift > 28) {
        throw new Error("HPACK: integer overflow in decoding");
      }
      byte = data[offset + bytesRead]!;
      bytesRead++;
      value += (byte & 0x7f) << shift;
      shift += 7;
    } while (byte & 0x80);
  }

  return { value, bytesRead };
}

function encodeString(w: BufferWriter, str: string, huffman: boolean = false): void {
  const buf = Buffer.from(str, "latin1");
  if (huffman) {
    const encoded = huffmanEncode(buf);
    encodeInteger(w, encoded.length, 7, 0x80);
    w.writeBytes(encoded);
  } else {
    encodeInteger(w, buf.length, 7, 0x00);
    w.writeBytes(buf);
  }
}

function decodeString(data: Buffer, offset: number): { value: string; bytesRead: number } {
  const isHuffman = !!(data[offset]! & 0x80);
  const { value: length, bytesRead: intBytes } = decodeInteger(data, offset, 7);
  const raw = data.subarray(offset + intBytes, offset + intBytes + length);
  const str = isHuffman ? huffmanDecode(raw).toString("latin1") : raw.toString("latin1");
  return { value: str, bytesRead: intBytes + length };
}

/**
 * HPACK header compression encoder (RFC 7541). Maintains a dynamic header
 * table and encodes header lists into compact HPACK binary format using
 * Huffman coding and indexed representations.
 *
 * @see {@link https://datatracker.ietf.org/doc/html/rfc7541}
 */
export class HPACKEncoder {
  private dynamicTable: DynamicTable;
  private staticIndex: Map<string, number>;
  private staticFullIndex: Map<string, number>;

  /**
   * Creates a new HPACKEncoder with the given initial dynamic table size.
   *
   * @param {number} [tableSize=4096] - Maximum size of the HPACK dynamic header table in bytes.
   */
  constructor(tableSize: number = 4096) {
    this.dynamicTable = new DynamicTable(tableSize);

    this.staticIndex = new Map();
    this.staticFullIndex = new Map();
    for (let i = 1; i < STATIC_TABLE.length; i++) {
      const [name, value] = STATIC_TABLE[i]!;
      const key = `${name}\0${value}`;
      if (!this.staticFullIndex.has(key)) {
        this.staticFullIndex.set(key, i);
      }
      if (!this.staticIndex.has(name)) {
        this.staticIndex.set(name, i);
      }
    }
  }

  /**
   * Encodes an ordered header list into an HPACK binary block ready to be
   * placed in an HTTP/2 HEADERS or PUSH_PROMISE frame payload.
   *
   * @param {Array<[string, string]>} headers - Header name-value pairs to encode.
   * @returns {Buffer} HPACK-encoded header block fragment.
   */
  encode(headers: Array<[string, string]>): Buffer {
    const w = new BufferWriter(1024);

    for (const [name, value] of headers) {
      const fullKey = `${name}\0${value}`;
      const fullIdx = this.staticFullIndex.get(fullKey);

      if (fullIdx !== undefined) {
        encodeInteger(w, fullIdx, 7, 0x80);
        continue;
      }

      const nameIdx = this.staticIndex.get(name);

      if (nameIdx !== undefined) {
        encodeInteger(w, nameIdx, 6, 0x40);
        encodeString(w, value, true);
        this.dynamicTable.add(name, value);
      } else {
        w.writeUInt8(0x40);
        encodeString(w, name, true);
        encodeString(w, value, true);
        this.dynamicTable.add(name, value);
      }
    }

    return w.toBuffer();
  }

  /**
   * Updates the encoder's dynamic table maximum size — call this whenever a
   * `SETTINGS_HEADER_TABLE_SIZE` value is received from the remote peer so
   * that subsequent {@link encode} calls respect the new limit.
   *
   * @param {number} newSize - New maximum dynamic table size in bytes.
   */
  updateTableSize(newSize: number): void {
    this.dynamicTable.updateMaxSize(newSize);
  }
}

/**
 * HPACK header decompression decoder (RFC 7541). Maintains a synchronized
 * dynamic header table and decodes HPACK binary blocks received in
 * HTTP/2 HEADERS and PUSH_PROMISE frames.
 *
 * @see {@link https://datatracker.ietf.org/doc/html/rfc7541}
 */
export class HPACKDecoder {
  private dynamicTable: DynamicTable;

  /**
   * Creates a new HPACKDecoder with the given initial dynamic table size.
   *
   * @param {number} [tableSize=4096] - Maximum size of the HPACK dynamic header table in bytes.
   */
  constructor(tableSize: number = 4096) {
    this.dynamicTable = new DynamicTable(tableSize);
  }

  /**
   * Decodes an HPACK-encoded header block fragment into an ordered list of
   * name-value pairs. Updates the internal dynamic table as required by the
   * HPACK state machine.
   *
   * @param {Buffer} data - HPACK-encoded header block fragment from a HEADERS or PUSH_PROMISE frame.
   * @returns {Array<[string, string]>} Decoded header name-value pairs in transmission order.
   * @throws {Error} If the encoded data references an invalid table index.
   */
  decode(data: Buffer): Array<[string, string]> {
    const headers: Array<[string, string]> = [];
    let offset = 0;

    while (offset < data.length) {
      const byte = data[offset]!;

      if (byte & 0x80) {
        const { value: index, bytesRead } = decodeInteger(data, offset, 7);
        offset += bytesRead;
        const entry = this.getEntry(index);
        headers.push(entry);
      } else if (byte & 0x40) {
        const { value: nameIndex, bytesRead: intBytes } = decodeInteger(data, offset, 6);
        offset += intBytes;

        let name: string;
        if (nameIndex > 0) {
          name = this.getEntry(nameIndex)[0];
        } else {
          const { value: n, bytesRead: strBytes } = decodeString(data, offset);
          name = n;
          offset += strBytes;
        }

        const { value, bytesRead: valBytes } = decodeString(data, offset);
        offset += valBytes;

        this.dynamicTable.add(name, value);
        headers.push([name, value]);
      } else if (byte & 0x20) {
        const { value: newSize, bytesRead } = decodeInteger(data, offset, 5);
        offset += bytesRead;
        this.dynamicTable.updateMaxSize(newSize);
      } else {
        const prefix = 4;
        const { value: nameIndex, bytesRead: intBytes } = decodeInteger(data, offset, prefix);
        offset += intBytes;

        let name: string;
        if (nameIndex > 0) {
          name = this.getEntry(nameIndex)[0];
        } else {
          const { value: n, bytesRead: strBytes } = decodeString(data, offset);
          name = n;
          offset += strBytes;
        }

        const { value, bytesRead: valBytes } = decodeString(data, offset);
        offset += valBytes;
        headers.push([name, value]);
      }
    }

    return headers;
  }

  private getEntry(index: number): [string, string] {
    if (index < STATIC_TABLE.length) {
      return STATIC_TABLE[index]!;
    }
    const dynIndex = index - STATIC_TABLE.length;
    const entry = this.dynamicTable.get(dynIndex);
    if (!entry) {
      throw new Error(`HPACK: invalid index ${index}`);
    }
    return entry;
  }
}

const HUFFMAN_TABLE: ReadonlyArray<[number, number]> = [
  [0x1ff8, 13],
  [0x7fffd8, 23],
  [0xfffffe2, 28],
  [0xfffffe3, 28],
  [0xfffffe4, 28],
  [0xfffffe5, 28],
  [0xfffffe6, 28],
  [0xfffffe7, 28],
  [0xfffffe8, 28],
  [0xffffea, 24],
  [0x3ffffffc, 30],
  [0xfffffe9, 28],
  [0xfffffea, 28],
  [0x3ffffffd, 30],
  [0xfffffeb, 28],
  [0xfffffec, 28],
  [0xfffffed, 28],
  [0xfffffee, 28],
  [0xfffffef, 28],
  [0xffffff0, 28],
  [0xffffff1, 28],
  [0xffffff2, 28],
  [0x3ffffffe, 30],
  [0xffffff3, 28],
  [0xffffff4, 28],
  [0xffffff5, 28],
  [0xffffff6, 28],
  [0xffffff7, 28],
  [0xffffff8, 28],
  [0xffffff9, 28],
  [0xffffffa, 28],
  [0xffffffb, 28],
  [0x14, 6],
  [0x3f8, 10],
  [0x3f9, 10],
  [0xffa, 12],
  [0x1ff9, 13],
  [0x15, 6],
  [0xf8, 8],
  [0x7fa, 11],
  [0x3fa, 10],
  [0x3fb, 10],
  [0xf9, 8],
  [0x7fb, 11],
  [0xfa, 8],
  [0x16, 6],
  [0x17, 6],
  [0x18, 6],
  [0x0, 5],
  [0x1, 5],
  [0x2, 5],
  [0x19, 6],
  [0x1a, 6],
  [0x1b, 6],
  [0x1c, 6],
  [0x1d, 6],
  [0x1e, 6],
  [0x1f, 6],
  [0x5c, 7],
  [0xfb, 8],
  [0x7ffc, 15],
  [0x20, 6],
  [0xffb, 12],
  [0x3fc, 10],
  [0x1ffa, 13],
  [0x21, 6],
  [0x5d, 7],
  [0x5e, 7],
  [0x5f, 7],
  [0x60, 7],
  [0x61, 7],
  [0x62, 7],
  [0x63, 7],
  [0x64, 7],
  [0x65, 7],
  [0x66, 7],
  [0x67, 7],
  [0x68, 7],
  [0x69, 7],
  [0x6a, 7],
  [0x6b, 7],
  [0x6c, 7],
  [0x6d, 7],
  [0x6e, 7],
  [0x6f, 7],
  [0x70, 7],
  [0x71, 7],
  [0x72, 7],
  [0xfc, 8],
  [0x73, 7],
  [0xfd, 8],
  [0x1ffb, 13],
  [0x7fff0, 19],
  [0x1ffc, 13],
  [0x3ffc, 14],
  [0x22, 6],
  [0x7ffd, 15],
  [0x3, 5],
  [0x23, 6],
  [0x4, 5],
  [0x24, 6],
  [0x5, 5],
  [0x25, 6],
  [0x26, 6],
  [0x27, 6],
  [0x6, 5],
  [0x74, 7],
  [0x75, 7],
  [0x28, 6],
  [0x29, 6],
  [0x2a, 6],
  [0x7, 5],
  [0x2b, 6],
  [0x76, 7],
  [0x2c, 6],
  [0x8, 5],
  [0x9, 5],
  [0x2d, 6],
  [0x77, 7],
  [0x78, 7],
  [0x79, 7],
  [0x7a, 7],
  [0x7b, 7],
  [0x7ffe, 15],
  [0x7fc, 11],
  [0x3ffd, 14],
  [0x1ffd, 13],
  [0xffffffc, 28],
  [0xfffe6, 20],
  [0x3fffd2, 22],
  [0xfffe7, 20],
  [0xfffe8, 20],
  [0x3fffd3, 22],
  [0x3fffd4, 22],
  [0x3fffd5, 22],
  [0x7fffd9, 23],
  [0x3fffd6, 22],
  [0x7fffda, 23],
  [0x7fffdb, 23],
  [0x7fffdc, 23],
  [0x7fffdd, 23],
  [0x7fffde, 23],
  [0xffffeb, 24],
  [0x7fffdf, 23],
  [0xffffec, 24],
  [0xffffed, 24],
  [0x3fffd7, 22],
  [0x7fffe0, 23],
  [0xffffee, 24],
  [0x7fffe1, 23],
  [0x7fffe2, 23],
  [0x7fffe3, 23],
  [0x7fffe4, 23],
  [0x1fffdc, 21],
  [0x3fffd8, 22],
  [0x7fffe5, 23],
  [0x3fffd9, 22],
  [0x7fffe6, 23],
  [0x7fffe7, 23],
  [0xffffef, 24],
  [0x3fffda, 22],
  [0x1fffdd, 21],
  [0xfffe9, 20],
  [0x3fffdb, 22],
  [0x3fffdc, 22],
  [0x7fffe8, 23],
  [0x7fffe9, 23],
  [0x1fffde, 21],
  [0x7fffea, 23],
  [0x3fffdd, 22],
  [0x3fffde, 22],
  [0xfffff0, 24],
  [0x1fffdf, 21],
  [0x3fffdf, 22],
  [0x7fffeb, 23],
  [0x7fffec, 23],
  [0x1fffe0, 21],
  [0x1fffe1, 21],
  [0x3fffe0, 22],
  [0x1fffe2, 21],
  [0x7fffed, 23],
  [0x3fffe1, 22],
  [0x7fffee, 23],
  [0x7fffef, 23],
  [0xfffea, 20],
  [0x3fffe2, 22],
  [0x3fffe3, 22],
  [0x3fffe4, 22],
  [0x7ffff0, 23],
  [0x3fffe5, 22],
  [0x3fffe6, 22],
  [0x7ffff1, 23],
  [0x3ffffe0, 26],
  [0x3ffffe1, 26],
  [0xfffeb, 20],
  [0x7fff1, 19],
  [0x3fffe7, 22],
  [0x7ffff2, 23],
  [0x3fffe8, 22],
  [0x1ffffec, 25],
  [0x3ffffe2, 26],
  [0x3ffffe3, 26],
  [0x3ffffe4, 26],
  [0x7ffffde, 27],
  [0x7ffffdf, 27],
  [0x3ffffe5, 26],
  [0xfffff1, 24],
  [0x1ffffed, 25],
  [0x7fff2, 19],
  [0x1fffe3, 21],
  [0x3ffffe6, 26],
  [0x7ffffe0, 27],
  [0x7ffffe1, 27],
  [0x3ffffe7, 26],
  [0x7ffffe2, 27],
  [0xfffff2, 24],
  [0x1fffe4, 21],
  [0x1fffe5, 21],
  [0x3ffffe8, 26],
  [0x3ffffe9, 26],
  [0xffffffd, 28],
  [0x7ffffe3, 27],
  [0x7ffffe4, 27],
  [0x7ffffe5, 27],
  [0xfffec, 20],
  [0xfffff3, 24],
  [0xfffed, 20],
  [0x1fffe6, 21],
  [0x3fffe9, 22],
  [0x1fffe7, 21],
  [0x1fffe8, 21],
  [0x7ffff3, 23],
  [0x3fffea, 22],
  [0x3fffeb, 22],
  [0x1ffffee, 25],
  [0x1ffffef, 25],
  [0xfffff4, 24],
  [0xfffff5, 24],
  [0x3ffffea, 26],
  [0x7ffff4, 23],
  [0x3ffffeb, 26],
  [0x7ffffe6, 27],
  [0x3ffffec, 26],
  [0x3ffffed, 26],
  [0x7ffffe7, 27],
  [0x7ffffe8, 27],
  [0x7ffffe9, 27],
  [0x7ffffea, 27],
  [0x7ffffeb, 27],
  [0xffffffe, 28],
  [0x7ffffec, 27],
  [0x7ffffed, 27],
  [0x7ffffee, 27],
  [0x7ffffef, 27],
  [0x7fffff0, 27],
  [0x3ffffee, 26],
  [0x3fffffff, 30],
];

function huffmanEncode(input: Buffer): Buffer {
  let bits = 0n;
  let bitLen = 0;

  for (let i = 0; i < input.length; i++) {
    const [code, codeLen] = HUFFMAN_TABLE[input[i]!]!;
    bits = (bits << BigInt(codeLen)) | BigInt(code);
    bitLen += codeLen;
  }

  const padding = (8 - (bitLen % 8)) % 8;
  if (padding > 0) {
    bits = (bits << BigInt(padding)) | ((1n << BigInt(padding)) - 1n);
    bitLen += padding;
  }

  const byteLen = bitLen / 8;
  const result = Buffer.alloc(Number(byteLen));
  for (let i = Number(byteLen) - 1; i >= 0; i--) {
    result[i] = Number(bits & 0xffn);
    bits >>= 8n;
  }

  return result;
}

interface HuffmanNode {
  value?: number;
  children: [HuffmanNode | null, HuffmanNode | null];
}

function buildHuffmanTree(): HuffmanNode {
  const root: HuffmanNode = { children: [null, null] };

  for (let i = 0; i < HUFFMAN_TABLE.length; i++) {
    const [code, bitLen] = HUFFMAN_TABLE[i]!;
    let node = root;

    for (let j = bitLen - 1; j >= 0; j--) {
      const bit = (code >> j) & 1;
      if (!node.children[bit]) {
        node.children[bit] = { children: [null, null] };
      }
      node = node.children[bit]!;
    }

    node.value = i;
  }

  return root;
}

const HUFFMAN_TREE = buildHuffmanTree();

function huffmanDecode(input: Buffer): Buffer {
  const output: number[] = [];
  let node = HUFFMAN_TREE;

  for (let i = 0; i < input.length; i++) {
    for (let j = 7; j >= 0; j--) {
      const bit = (input[i]! >> j) & 1;
      node = node.children[bit]!;
      if (!node) {
        throw new Error("HPACK: invalid Huffman code");
      }
      if (node.value !== undefined) {
        if (node.value === 256) return Buffer.from(output);
        output.push(node.value);
        node = HUFFMAN_TREE;
      }
    }
  }

  return Buffer.from(output);
}
