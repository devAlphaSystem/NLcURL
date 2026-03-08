import { BufferWriter } from "../../utils/buffer-writer.js";

/** HTTP/2 frame type identifiers. */
export const FrameType = {
  DATA: 0x0,
  HEADERS: 0x1,
  PRIORITY: 0x2,
  RST_STREAM: 0x3,
  SETTINGS: 0x4,
  PUSH_PROMISE: 0x5,
  PING: 0x6,
  GOAWAY: 0x7,
  WINDOW_UPDATE: 0x8,
  CONTINUATION: 0x9,
} as const;

/** HTTP/2 frame flag bitmasks. */
export const Flags = {
  END_STREAM: 0x1,
  ACK: 0x1,
  END_HEADERS: 0x4,
  PADDED: 0x8,
  PRIORITY: 0x20,
} as const;

/** HTTP/2 SETTINGS parameter identifiers. */
export const SettingsParam = {
  HEADER_TABLE_SIZE: 0x1,
  ENABLE_PUSH: 0x2,
  MAX_CONCURRENT_STREAMS: 0x3,
  INITIAL_WINDOW_SIZE: 0x4,
  MAX_FRAME_SIZE: 0x5,
  MAX_HEADER_LIST_SIZE: 0x6,
} as const;

/** Parsed HTTP/2 frame. */
export interface H2Frame {
  /** Frame type code. */
  type: number;
  /** Frame flags bitmask. */
  flags: number;
  /** Stream identifier. */
  streamId: number;
  /** Frame payload data. */
  payload: Buffer;
}

const PROTOCOL_MAX_FRAME_SIZE = 16_777_215;

/**
 * Read a single HTTP/2 frame from a buffer.
 *
 * @param {Buffer} data - Buffer to read from.
 * @param {number} offset - Byte offset to start reading.
 * @param {number} [maxFrameSize] - Maximum allowed frame payload size.
 * @returns {{ frame: H2Frame; bytesRead: number } | null} Parsed frame and bytes consumed, or `null` if insufficient data.
 */
export function readFrame(data: Buffer, offset: number, maxFrameSize: number = PROTOCOL_MAX_FRAME_SIZE): { frame: H2Frame; bytesRead: number } | null {
  if (data.length - offset < 9) return null;

  const length = (data[offset]! << 16) | (data[offset + 1]! << 8) | data[offset + 2]!;

  if (length > maxFrameSize) {
    throw new Error(`FRAME_SIZE_ERROR: frame payload length ${length} exceeds limit ${maxFrameSize}`);
  }

  const type = data[offset + 3]!;
  const flags = data[offset + 4]!;
  const streamId = ((data[offset + 5]! & 0x7f) << 24) | (data[offset + 6]! << 16) | (data[offset + 7]! << 8) | data[offset + 8]!;

  if (data.length - offset - 9 < length) return null;

  const payload = data.subarray(offset + 9, offset + 9 + length);

  return {
    frame: { type, flags, streamId, payload },
    bytesRead: 9 + length,
  };
}

/**
 * Serialize an HTTP/2 frame to a wire-format buffer.
 *
 * @param {H2Frame} frame - Frame to serialize.
 * @returns {Buffer} Wire-format buffer.
 */
export function writeFrame(frame: H2Frame): Buffer {
  const w = new BufferWriter(9 + frame.payload.length);
  w.writeUInt8((frame.payload.length >> 16) & 0xff);
  w.writeUInt8((frame.payload.length >> 8) & 0xff);
  w.writeUInt8(frame.payload.length & 0xff);
  w.writeUInt8(frame.type);
  w.writeUInt8(frame.flags);
  w.writeUInt32(frame.streamId & 0x7fffffff);
  w.writeBytes(frame.payload);
  return w.toBuffer();
}

/**
 * Build an HTTP/2 SETTINGS frame.
 *
 * @param {Array<{ id: number; value: number }>} settings - Setting id/value pairs.
 * @param {boolean} [ack] - Whether this is a SETTINGS acknowledgment.
 * @returns {Buffer} Serialized SETTINGS frame.
 */
export function buildSettingsFrame(settings: Array<{ id: number; value: number }>, ack = false): Buffer {
  if (ack) {
    return writeFrame({
      type: FrameType.SETTINGS,
      flags: Flags.ACK,
      streamId: 0,
      payload: Buffer.alloc(0),
    });
  }
  const w = new BufferWriter(settings.length * 6);
  for (const s of settings) {
    w.writeUInt16(s.id);
    w.writeUInt32(s.value);
  }
  return writeFrame({
    type: FrameType.SETTINGS,
    flags: 0,
    streamId: 0,
    payload: w.toBuffer(),
  });
}

/**
 * Build an HTTP/2 WINDOW_UPDATE frame.
 *
 * @param {number} streamId - Target stream (0 for connection-level).
 * @param {number} increment - Window size increment.
 * @returns {Buffer} Serialized WINDOW_UPDATE frame.
 */
export function buildWindowUpdateFrame(streamId: number, increment: number): Buffer {
  const w = new BufferWriter(4);
  w.writeUInt32(increment & 0x7fffffff);
  return writeFrame({
    type: FrameType.WINDOW_UPDATE,
    flags: 0,
    streamId,
    payload: w.toBuffer(),
  });
}

/**
 * Build an HTTP/2 HEADERS frame.
 *
 * @param {number} streamId - Target stream.
 * @param {Buffer} headerBlock - HPACK-encoded header block.
 * @param {boolean} endStream - Whether this completes the stream.
 * @param {boolean} endHeaders - Whether the header block is complete.
 * @returns {Buffer} Serialized HEADERS frame.
 */
export function buildHeadersFrame(streamId: number, headerBlock: Buffer, endStream: boolean, endHeaders: boolean): Buffer {
  let flags = 0;
  if (endStream) flags |= Flags.END_STREAM;
  if (endHeaders) flags |= Flags.END_HEADERS;
  return writeFrame({
    type: FrameType.HEADERS,
    flags,
    streamId,
    payload: headerBlock,
  });
}

/**
 * Build an HTTP/2 DATA frame.
 *
 * @param {number} streamId - Target stream.
 * @param {Buffer} data - Payload data.
 * @param {boolean} endStream - Whether this completes the stream.
 * @returns {Buffer} Serialized DATA frame.
 */
export function buildDataFrame(streamId: number, data: Buffer, endStream: boolean): Buffer {
  let flags = 0;
  if (endStream) flags |= Flags.END_STREAM;
  return writeFrame({
    type: FrameType.DATA,
    flags,
    streamId,
    payload: data,
  });
}

/**
 * Build an HTTP/2 PRIORITY frame.
 *
 * @param {number} streamId - Target stream.
 * @param {boolean} exclusive - Whether to use exclusive dependency.
 * @param {number} dependsOn - Stream dependency.
 * @param {number} weight - Priority weight (1–256).
 * @returns {Buffer} Serialized PRIORITY frame.
 */
export function buildPriorityFrame(streamId: number, exclusive: boolean, dependsOn: number, weight: number): Buffer {
  const w = new BufferWriter(5);
  let dep = dependsOn & 0x7fffffff;
  if (exclusive) dep |= 0x80000000;
  w.writeUInt32(dep);
  w.writeUInt8(weight - 1);
  return writeFrame({
    type: FrameType.PRIORITY,
    flags: 0,
    streamId,
    payload: w.toBuffer(),
  });
}

/**
 * Build an HTTP/2 GOAWAY frame.
 *
 * @param {number} lastStreamId - Last processed stream identifier.
 * @param {number} errorCode - Error code.
 * @returns {Buffer} Serialized GOAWAY frame.
 */
export function buildGoawayFrame(lastStreamId: number, errorCode: number): Buffer {
  const w = new BufferWriter(8);
  w.writeUInt32(lastStreamId & 0x7fffffff);
  w.writeUInt32(errorCode);
  return writeFrame({
    type: FrameType.GOAWAY,
    flags: 0,
    streamId: 0,
    payload: w.toBuffer(),
  });
}

/**
 * Build an HTTP/2 PING frame.
 *
 * @param {Buffer} data - 8-byte ping payload.
 * @param {boolean} [ack] - Whether this is a PING acknowledgment.
 * @returns {Buffer} Serialized PING frame.
 */
export function buildPingFrame(data: Buffer, ack = false): Buffer {
  const payload = Buffer.alloc(8);
  data.copy(payload, 0, 0, Math.min(8, data.length));
  return writeFrame({
    type: FrameType.PING,
    flags: ack ? Flags.ACK : 0,
    streamId: 0,
    payload,
  });
}

/**
 * Build an HTTP/2 RST_STREAM frame.
 *
 * @param {number} streamId - Stream to reset.
 * @param {number} errorCode - Error code.
 * @returns {Buffer} Serialized RST_STREAM frame.
 */
export function buildRstStreamFrame(streamId: number, errorCode: number): Buffer {
  const w = new BufferWriter(4);
  w.writeUInt32(errorCode);
  return writeFrame({
    type: FrameType.RST_STREAM,
    flags: 0,
    streamId,
    payload: w.toBuffer(),
  });
}

/** HTTP/2 connection preface sent by the client. */
export const H2_PREFACE = Buffer.from("PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n", "ascii");
