import * as crypto from "node:crypto";

/** WebSocket frame opcodes as defined in RFC 6455 §11.8. */
export const enum Opcode {
  CONTINUATION = 0x0,
  TEXT = 0x1,
  BINARY = 0x2,
  CLOSE = 0x8,
  PING = 0x9,
  PONG = 0xa,
}

/** Decoded WebSocket frame header and payload. */
export interface WebSocketFrame {
  /** Whether this is the final fragment. */
  fin: boolean;
  /** RSV1 bit — indicates per-message compression when negotiated. */
  rsv1: boolean;
  /** Frame opcode. */
  opcode: Opcode;
  /** Whether the payload is masked. */
  masked: boolean;
  /** Frame payload data. */
  payload: Buffer;
}

/**
 * Encode a WebSocket frame for transmission.
 *
 * @param {Opcode} opcode - Frame opcode.
 * @param {Buffer} payload - Frame payload bytes.
 * @param {boolean} mask - Apply a random masking key (default `true`).
 * @param {boolean} rsv1 - Set the RSV1 bit for compressed frames.
 * @returns {Buffer} Wire-format frame buffer.
 */
export function encodeFrame(opcode: Opcode, payload: Buffer, mask = true, rsv1 = false): Buffer {
  if (opcode >= 0x8 && payload.length > 125) {
    throw new Error("WebSocket control frame payload exceeds 125 bytes (RFC 6455 §5.5)");
  }

  const payloadLen = payload.length;
  let headerLen = 2;

  if (payloadLen > 65535) {
    headerLen += 8;
  } else if (payloadLen > 125) {
    headerLen += 2;
  }

  const maskKey = mask ? crypto.randomBytes(4) : null;
  if (mask) headerLen += 4;

  const frame = Buffer.allocUnsafe(headerLen + payloadLen);

  frame[0] = 0x80 | (rsv1 ? 0x40 : 0) | opcode;

  let offset = 1;
  if (payloadLen > 65535) {
    frame[offset] = (mask ? 0x80 : 0) | 127;
    offset++;
    frame.writeBigUInt64BE(BigInt(payloadLen), offset);
    offset += 8;
  } else if (payloadLen > 125) {
    frame[offset] = (mask ? 0x80 : 0) | 126;
    offset++;
    frame.writeUInt16BE(payloadLen, offset);
    offset += 2;
  } else {
    frame[offset] = (mask ? 0x80 : 0) | payloadLen;
    offset++;
  }

  if (maskKey) {
    maskKey.copy(frame, offset);
    offset += 4;

    for (let i = 0; i < payloadLen; i++) {
      frame[offset + i] = payload[i]! ^ maskKey[i & 3]!;
    }
  } else {
    payload.copy(frame, offset);
  }

  return frame;
}

/** Incremental parser that reassembles WebSocket frames from raw data. */
export class FrameParser {
  private chunks: Buffer[] = [];
  private totalLength = 0;
  private buffer: Buffer | null = null;

  /**
   * Append incoming bytes to the internal buffer.
   *
   * @param {Buffer} data - Raw data received from the transport.
   */
  push(data: Buffer): void {
    this.chunks.push(data);
    this.totalLength += data.length;
    this.buffer = null;
  }

  private compact(): Buffer {
    if (this.buffer) return this.buffer;
    if (this.chunks.length === 1) {
      this.buffer = this.chunks[0]!;
    } else {
      this.buffer = Buffer.concat(this.chunks, this.totalLength);
      this.chunks = [this.buffer];
    }
    return this.buffer;
  }

  /**
   * Attempt to decode the next complete frame from the buffer.
   *
   * @param {boolean} allowRsv1 - Permit the RSV1 bit for per-message deflate.
   * @returns {WebSocketFrame | null} Decoded frame, or `null` if insufficient data.
   */
  pull(allowRsv1 = false): WebSocketFrame | null {
    if (this.totalLength < 2) return null;

    const buf = this.compact();

    const byte0 = buf[0]!;
    const byte1 = buf[1]!;

    const fin = (byte0 & 0x80) !== 0;
    const rsv1 = (byte0 & 0x40) !== 0;
    const rsv = byte0 & 0x70;
    const opcode = (byte0 & 0x0f) as Opcode;
    const masked = (byte1 & 0x80) !== 0;

    const forbiddenRsv = allowRsv1 ? rsv & 0x30 : rsv;
    if (forbiddenRsv !== 0) {
      throw new Error("WebSocket frame has non-zero RSV bits without negotiated extensions");
    }

    if (!(opcode <= 0x2 || (opcode >= 0x8 && opcode <= 0xa))) {
      throw new Error(`WebSocket frame has unknown opcode 0x${opcode.toString(16)}`);
    }

    if (masked) {
      throw new Error("WebSocket frame from server is masked (RFC 6455 §5.1 violation)");
    }

    const isControl = opcode >= 0x8;

    let payloadLen = byte1 & 0x7f;
    let offset = 2;

    if (payloadLen === 126) {
      if (isControl) throw new Error("WebSocket control frame payload exceeds 125 bytes");
      if (buf.length < 4) return null;
      payloadLen = buf.readUInt16BE(2);
      offset = 4;
    } else if (payloadLen === 127) {
      if (isControl) throw new Error("WebSocket control frame payload exceeds 125 bytes");
      if (buf.length < 10) return null;
      const len64 = buf.readBigUInt64BE(2);
      if (len64 > 128n * 1024n * 1024n) {
        throw new Error("WebSocket frame too large");
      }
      payloadLen = Number(len64);
      offset = 10;
    }

    const totalLen = offset + payloadLen;
    if (buf.length < totalLen) return null;

    const payload = buf.subarray(offset, totalLen);

    const remaining = buf.subarray(totalLen);
    if (remaining.length > 0) {
      this.chunks = [remaining];
      this.totalLength = remaining.length;
    } else {
      this.chunks = [];
      this.totalLength = 0;
    }
    this.buffer = null;

    return { fin, rsv1, opcode, masked, payload };
  }
}

/**
 * Generate a random 16-byte Sec-WebSocket-Key encoded in base64.
 *
 * @returns {string} Base64-encoded key for the upgrade handshake.
 */
export function generateWebSocketKey(): string {
  return crypto.randomBytes(16).toString("base64");
}

/**
 * Compute the expected Sec-WebSocket-Accept value.
 *
 * @param {string} key - The Sec-WebSocket-Key sent by the client.
 * @returns {string} Base64-encoded SHA-1 accept hash.
 */
export function computeAcceptKey(key: string): string {
  return crypto
    .createHash("sha1")
    .update(key + "258EAFA5-E914-47DA-95CA-C5AB0DC85B11")
    .digest("base64");
}
