/**
 * WebSocket frame encoding/decoding (RFC 6455).
 *
 * Handles frame construction and parsing at the byte level.
 */

import * as crypto from 'node:crypto';

// ---- Opcodes ----

export const enum Opcode {
  CONTINUATION = 0x0,
  TEXT = 0x1,
  BINARY = 0x2,
  CLOSE = 0x8,
  PING = 0x9,
  PONG = 0xA,
}

export interface WebSocketFrame {
  fin: boolean;
  opcode: Opcode;
  masked: boolean;
  payload: Buffer;
}

/**
 * Encode a WebSocket frame.
 *
 * Client frames MUST be masked (RFC 6455, section 5.3).
 */
export function encodeFrame(opcode: Opcode, payload: Buffer, mask = true): Buffer {
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

  // Byte 0: FIN + opcode
  frame[0] = 0x80 | opcode;

  // Byte 1: MASK + payload length
  let offset = 1;
  if (payloadLen > 65535) {
    frame[offset] = (mask ? 0x80 : 0) | 127;
    offset++;
    // 8-byte extended payload length (big-endian)
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

  // Mask key
  if (maskKey) {
    maskKey.copy(frame, offset);
    offset += 4;

    // Mask the payload
    for (let i = 0; i < payloadLen; i++) {
      frame[offset + i] = payload[i]! ^ maskKey[i & 3]!;
    }
  } else {
    payload.copy(frame, offset);
  }

  return frame;
}

/**
 * Incremental WebSocket frame parser.
 *
 * Feed data chunks via `push()` and collect completed frames via `pull()`.
 */
export class FrameParser {
  private buffer = Buffer.alloc(0);

  push(data: Buffer): void {
    this.buffer = Buffer.concat([this.buffer, data]);
  }

  pull(): WebSocketFrame | null {
    if (this.buffer.length < 2) return null;

    const byte0 = this.buffer[0]!;
    const byte1 = this.buffer[1]!;

    const fin = (byte0 & 0x80) !== 0;
    const opcode = (byte0 & 0x0F) as Opcode;
    const masked = (byte1 & 0x80) !== 0;
    let payloadLen = byte1 & 0x7F;
    let offset = 2;

    if (payloadLen === 126) {
      if (this.buffer.length < 4) return null;
      payloadLen = this.buffer.readUInt16BE(2);
      offset = 4;
    } else if (payloadLen === 127) {
      if (this.buffer.length < 10) return null;
      const len64 = this.buffer.readBigUInt64BE(2);
      // Guard against unreasonably large frames (128 MB)
      if (len64 > 128n * 1024n * 1024n) {
        throw new Error('WebSocket frame too large');
      }
      payloadLen = Number(len64);
      offset = 10;
    }

    let maskKey: Buffer | null = null;
    if (masked) {
      if (this.buffer.length < offset + 4) return null;
      maskKey = this.buffer.subarray(offset, offset + 4);
      offset += 4;
    }

    const totalLen = offset + payloadLen;
    if (this.buffer.length < totalLen) return null;

    let payload = this.buffer.subarray(offset, totalLen);

    // Unmask
    if (maskKey) {
      payload = Buffer.from(payload);
      for (let i = 0; i < payload.length; i++) {
        payload[i] = payload[i]! ^ maskKey[i & 3]!;
      }
    }

    // Advance buffer
    this.buffer = this.buffer.subarray(totalLen);

    return { fin, opcode, masked, payload };
  }
}

/**
 * Generate a Sec-WebSocket-Key for the opening handshake.
 */
export function generateWebSocketKey(): string {
  return crypto.randomBytes(16).toString('base64');
}

/**
 * Compute the expected Sec-WebSocket-Accept value.
 */
export function computeAcceptKey(key: string): string {
  return crypto
    .createHash('sha1')
    .update(key + '258EAFA5-E914-47DA-95CA-C5AB0DC85B11')
    .digest('base64');
}
