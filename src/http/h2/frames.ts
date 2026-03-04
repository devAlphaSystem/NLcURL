import { BufferReader } from "../../utils/buffer-reader.js";
import { BufferWriter } from "../../utils/buffer-writer.js";

/**
 * HTTP/2 frame type identifiers as defined in RFC 7540 §11.2.
 *
 * @see {@link https://datatracker.ietf.org/doc/html/rfc7540#section-11.2}
 */
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

/**
 * HTTP/2 frame flag bit masks as defined in RFC 7540. Flags are frame-type
 * specific; e.g. `END_STREAM` is valid on DATA and HEADERS frames while `ACK`
 * shares the same value `0x1` but applies to SETTINGS and PING frames.
 */
export const Flags = {
  END_STREAM: 0x1,
  ACK: 0x1,
  END_HEADERS: 0x4,
  PADDED: 0x8,
  PRIORITY: 0x20,
} as const;

/**
 * HTTP/2 SETTINGS parameter identifiers as defined in RFC 7540 §6.5.2.
 *
 * @see {@link https://datatracker.ietf.org/doc/html/rfc7540#section-6.5.2}
 */
export const SettingsParam = {
  HEADER_TABLE_SIZE: 0x1,
  ENABLE_PUSH: 0x2,
  MAX_CONCURRENT_STREAMS: 0x3,
  INITIAL_WINDOW_SIZE: 0x4,
  MAX_FRAME_SIZE: 0x5,
  MAX_HEADER_LIST_SIZE: 0x6,
} as const;

/**
 * Represents a decoded HTTP/2 frame.
 *
 * @typedef  {Object} H2Frame
 * @property {number} type     - Frame type identifier (see `FrameType`).
 * @property {number} flags    - Frame flags bitmask (see `Flags`).
 * @property {number} streamId - Associated stream identifier (0 for connection-level frames).
 * @property {Buffer} payload  - Raw frame payload (excludes the 9-byte header).
 */
export interface H2Frame {
  type: number;
  flags: number;
  streamId: number;
  payload: Buffer;
}

/** RFC 7540 §4.2: Maximum value for SETTINGS_MAX_FRAME_SIZE (2^24 - 1). */
const PROTOCOL_MAX_FRAME_SIZE = 16_777_215;

/**
 * Attempts to parse one HTTP/2 frame starting at `offset` in `data`.
 * Returns `null` if insufficient bytes are available for a complete frame.
 *
 * @param {Buffer} data          - Input buffer potentially containing one or more frames.
 * @param {number} offset        - Byte offset within `data` at which to start parsing.
 * @param {number} [maxFrameSize=16777215] - Maximum permitted payload length.
 *   Frames whose length field exceeds this value cause a `FRAME_SIZE_ERROR`.
 *   Callers should pass the peer's `SETTINGS_MAX_FRAME_SIZE` value here.
 * @returns {{ frame: H2Frame; bytesRead: number } | null} Parsed frame and total bytes consumed,
 *   or `null` if more data is required.
 * @throws {Error} If the frame's length field exceeds `maxFrameSize`.
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
 * Serializes an HTTP/2 frame into a `Buffer` including the 9-byte frame header.
 *
 * @param {H2Frame} frame - Frame to serialize.
 * @returns {Buffer} Complete frame bytes ready to be written to a transport stream.
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
 * Builds a SETTINGS frame optionally containing one or more settings parameters.
 * When `ack` is `true` the frame acknowledges a peer SETTINGS frame and the
 * `settings` array is ignored.
 *
 * @param {Array<{id: number; value: number}>} settings - Settings parameters to send.
 * @param {boolean} [ack=false] - Whether to create a SETTINGS acknowledgement (empty payload + ACK flag).
 * @returns {Buffer} Encoded SETTINGS frame.
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
 * Builds a WINDOW_UPDATE frame that enlarges a flow-control window.
 *
 * @param {number} streamId  - Stream to update (`0` for the connection-level window).
 * @param {number} increment - Number of octets to add to the flow-control window (1–2^31-1).
 * @returns {Buffer} Encoded WINDOW_UPDATE frame.
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
 * Builds a HEADERS frame carrying an HPACK-encoded header block fragment.
 *
 * @param {number}  streamId    - Stream identifier.
 * @param {Buffer}  headerBlock - HPACK-encoded header block.
 * @param {boolean} endStream   - Whether to set the END_STREAM flag (no DATA frames follow).
 * @param {boolean} endHeaders  - Whether to set the END_HEADERS flag (no CONTINUATION frames follow).
 * @returns {Buffer} Encoded HEADERS frame.
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
 * Builds a DATA frame carrying application payload bytes for a stream.
 *
 * @param {number}  streamId  - Stream identifier.
 * @param {Buffer}  data      - Payload to send.
 * @param {boolean} endStream - Whether to set the END_STREAM flag (last DATA frame for this stream).
 * @returns {Buffer} Encoded DATA frame.
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
 * Builds a PRIORITY frame that advises the peer about the relative priority
 * and dependency tree position of a stream.
 *
 * @param {number}  streamId  - Stream to set priority for.
 * @param {boolean} exclusive - Whether this stream is exclusive in the dependency tree.
 * @param {number}  dependsOn - Parent stream identifier.
 * @param {number}  weight    - Stream weight (1–256 per RFC 7540; value stored as `weight - 1`).
 * @returns {Buffer} Encoded PRIORITY frame.
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
 * Builds a GOAWAY frame notifying the peer that the connection is being
 * gracefully shut down.
 *
 * @param {number} lastStreamId - Highest-numbered stream ID that was processed.
 * @param {number} errorCode    - HTTP/2 error code (0 = NO_ERROR for graceful shutdown).
 * @returns {Buffer} Encoded GOAWAY frame.
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
 * Builds a PING frame used for measuring round-trip time or testing connectivity.
 *
 * @param {Buffer}  data     - 8-byte opaque payload to echo back.
 * @param {boolean} [ack=false] - When `true`, sets the ACK flag (reply to a received PING).
 * @returns {Buffer} Encoded PING frame.
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
 * Builds a RST_STREAM frame that immediately terminates a stream.
 *
 * @param {number} streamId  - Stream to reset.
 * @param {number} errorCode - HTTP/2 error code describing the reason for the reset.
 * @returns {Buffer} Encoded RST_STREAM frame.
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

/**
 * The HTTP/2 client connection preface as defined in RFC 7540 §3.5.
 * Must be the first bytes sent by a client after the transport connection is
 * established and before any SETTINGS frame.
 *
 * @see {@link https://datatracker.ietf.org/doc/html/rfc7540#section-3.5}
 */
export const H2_PREFACE = Buffer.from("PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n", "ascii");
