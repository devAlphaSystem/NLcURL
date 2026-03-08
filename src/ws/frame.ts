import * as crypto from "node:crypto";

/**
 * WebSocket frame opcode values as defined in RFC 6455 §5.2.
 *
 * @enum {number}
 */
export const enum Opcode {
  CONTINUATION = 0x0,
  TEXT = 0x1,
  BINARY = 0x2,
  CLOSE = 0x8,
  PING = 0x9,
  PONG = 0xa,
}

/**
 * A parsed WebSocket frame.
 *
 * @typedef  {Object}  WebSocketFrame
 * @property {boolean} fin     - Whether the FIN bit is set (final fragment).
 * @property {Opcode}  opcode  - Frame opcode.
 * @property {boolean} masked  - Whether the payload is masked.
 * @property {Buffer}  payload - Unmasked payload bytes.
 */
export interface WebSocketFrame {
  fin: boolean;
  rsv1: boolean;
  opcode: Opcode;
  masked: boolean;
  payload: Buffer;
}

/**
 * Encodes a WebSocket frame into a `Buffer` ready to be written to a socket.
 * The payload is masked by default using a cryptographically random 4-byte key
 * as required by RFC 6455 for client-to-server frames.
 *
 * @param {Opcode}  opcode      - Frame opcode.
 * @param {Buffer}  payload     - Frame payload.
 * @param {boolean} [mask=true] - Whether to mask the payload.
 * @returns {Buffer} Encoded frame bytes.
 */
export function encodeFrame(opcode: Opcode, payload: Buffer, mask = true, rsv1 = false): Buffer {
  const payloadLen = payload.length;
  let headerLen = 2;
  let extendedPayloadOffset = 2;

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

/**
 * Incremental WebSocket frame parser. Feed incoming data with
 * {@link FrameParser.push} and retrieve complete frames via
 * {@link FrameParser.pull}.
 */
export class FrameParser {
  private buffer = Buffer.alloc(0);

  /**
   * Appends `data` to the internal buffer.
   *
   * @param {Buffer} data - Bytes received from the transport socket.
   */
  push(data: Buffer): void {
    this.buffer = Buffer.concat([this.buffer, data]);
  }

  /**
   * Attempts to parse and return one complete WebSocket frame from the
   * internal buffer. If a complete frame is available, it is removed from
   * the buffer and returned. Returns `null` when more data is needed.
   *
   * @param {boolean} [allowRsv1=false] - When `true`, RSV1 is allowed (used by permessage-deflate).
   * @returns {WebSocketFrame | null} Parsed frame, or `null` if incomplete.
   * @throws {Error} If a frame payload exceeds the 128 MiB hard limit.
   */
  pull(allowRsv1 = false): WebSocketFrame | null {
    if (this.buffer.length < 2) return null;

    const byte0 = this.buffer[0]!;
    const byte1 = this.buffer[1]!;

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

    let payloadLen = byte1 & 0x7f;
    let offset = 2;

    if (payloadLen === 126) {
      if (this.buffer.length < 4) return null;
      payloadLen = this.buffer.readUInt16BE(2);
      offset = 4;
    } else if (payloadLen === 127) {
      if (this.buffer.length < 10) return null;
      const len64 = this.buffer.readBigUInt64BE(2);
      if (len64 > 128n * 1024n * 1024n) {
        throw new Error("WebSocket frame too large");
      }
      payloadLen = Number(len64);
      offset = 10;
    }

    const totalLen = offset + payloadLen;
    if (this.buffer.length < totalLen) return null;

    const payload = this.buffer.subarray(offset, totalLen);

    this.buffer = this.buffer.subarray(totalLen);

    return { fin, rsv1, opcode, masked, payload };
  }
}

/**
 * Generates a cryptographically random WebSocket handshake key.
 * The key is 16 random bytes encoded as Base64, as required by RFC 6455 §4.1.
 *
 * @returns {string} Base64-encoded 16-byte random key.
 */
export function generateWebSocketKey(): string {
  return crypto.randomBytes(16).toString("base64");
}

/**
 * Computes the expected `Sec-WebSocket-Accept` header value for the given
 * `Sec-WebSocket-Key` using the algorithm defined in RFC 6455 §4.2.2.
 *
 * @param {string} key - The `Sec-WebSocket-Key` value from the upgrade request.
 * @returns {string} Base64-encoded SHA-1 digest of the key concatenated with the GUID.
 */
export function computeAcceptKey(key: string): string {
  return crypto
    .createHash("sha1")
    .update(key + "258EAFA5-E914-47DA-95CA-C5AB0DC85B11")
    .digest("base64");
}
