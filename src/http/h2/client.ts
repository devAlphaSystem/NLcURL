/**
 * HTTP/2 client.
 *
 * Multiplexed HTTP/2 client that runs over a TLS Duplex stream.
 * Sends the connection preface with browser-profile-matched SETTINGS
 * and WINDOW_UPDATE for Akamai HTTP/2 fingerprint control.
 */

import type { Duplex } from 'node:stream';
import type { NLcURLRequest, RequestTimings } from '../../core/request.js';
import { NLcURLResponse } from '../../core/response.js';
import { HTTPError, TimeoutError, ProtocolError } from '../../core/errors.js';
import { decompressBody } from '../../utils/encoding.js';
import type { H2Profile } from '../../fingerprints/types.js';
import { HPACKEncoder, HPACKDecoder } from './hpack.js';
import {
  readFrame,
  writeFrame,
  buildSettingsFrame,
  buildWindowUpdateFrame,
  buildHeadersFrame,
  buildDataFrame,
  buildPingFrame,
  buildGoawayFrame,
  H2_PREFACE,
  FrameType,
  Flags,
  type H2Frame,
} from './frames.js';

// ---- Stream state ----

interface H2Stream {
  id: number;
  request: NLcURLRequest;
  responseHeaders: Map<string, string>;
  responseRawHeaders: Array<[string, string]>;
  status: number;
  dataChunks: Buffer[];
  endStream: boolean;
  resolve: (resp: NLcURLResponse) => void;
  reject: (err: Error) => void;
  timings: Partial<RequestTimings>;
  timer?: ReturnType<typeof setTimeout>;
}

// ---- Client ----

export class H2Client {
  private readonly stream: Duplex;
  private readonly encoder: HPACKEncoder;
  private readonly decoder: HPACKDecoder;
  private readonly h2Profile: H2Profile | undefined;
  private readonly defaultHeaders: Array<[string, string]>;

  private nextStreamId = 1;
  private streams = new Map<number, H2Stream>();
  private readBuffer = Buffer.alloc(0);
  private prefaceSent = false;
  private closed = false;

  constructor(
    stream: Duplex,
    h2Profile?: H2Profile,
    defaultHeaders: Array<[string, string]> = [],
  ) {
    this.stream = stream;
    this.encoder = new HPACKEncoder();
    this.decoder = new HPACKDecoder();
    this.h2Profile = h2Profile;
    this.defaultHeaders = defaultHeaders;

    stream.on('data', (chunk: Buffer) => this.onData(chunk));
    stream.once('error', (err) => this.onError(err));
    stream.once('close', () => this.onClose());
  }

  /**
   * Send the HTTP/2 connection preface.
   *
   * Must be called before sending any requests.
   */
  sendPreface(): void {
    if (this.prefaceSent) return;
    this.prefaceSent = true;

    // 1. Magic octets
    this.write(H2_PREFACE);

    // 2. SETTINGS frame (ordered per profile)
    if (this.h2Profile) {
      this.write(buildSettingsFrame(this.h2Profile.settings));

      // 3. WINDOW_UPDATE on stream 0
      if (this.h2Profile.windowUpdate > 0) {
        this.write(buildWindowUpdateFrame(0, this.h2Profile.windowUpdate));
      }

      // 4. PRIORITY frames
      if (this.h2Profile.priorityFrames) {
        for (const pf of this.h2Profile.priorityFrames) {
          const payload = Buffer.allocUnsafe(5);
          let dep = pf.dependsOn & 0x7fffffff;
          if (pf.exclusive) dep |= 0x80000000;
          payload.writeUInt32BE(dep >>> 0, 0);
          payload[4] = (pf.weight - 1) & 0xff;
          this.write(writeFrame({
            type: FrameType.PRIORITY,
            flags: 0,
            streamId: pf.streamId,
            payload,
          }));
        }
      }
    } else {
      // Default settings
      this.write(buildSettingsFrame([
        { id: 1, value: 65536 },
        { id: 2, value: 0 },
        { id: 4, value: 6291456 },
        { id: 6, value: 262144 },
      ]));
      this.write(buildWindowUpdateFrame(0, 15663105));
    }
  }

  /**
   * Send an HTTP/2 request and return the response.
   */
  async request(
    req: NLcURLRequest,
    timings: Partial<RequestTimings> = {},
  ): Promise<NLcURLResponse> {
    if (this.closed) {
      throw new ProtocolError('HTTP/2 connection is closed');
    }

    if (!this.prefaceSent) this.sendPreface();

    const streamId = this.nextStreamId;
    if (streamId > 0x7fffffff) {
      throw new ProtocolError('HTTP/2 stream ID exhausted; open a new connection');
    }
    this.nextStreamId += 2; // Client streams are odd

    return new Promise<NLcURLResponse>((resolve, reject) => {
      const h2stream: H2Stream = {
        id: streamId,
        request: req,
        responseHeaders: new Map(),
        responseRawHeaders: [],
        status: 0,
        dataChunks: [],
        endStream: false,
        resolve,
        reject,
        timings,
      };

      this.streams.set(streamId, h2stream);

      // Build headers
      const headers = this.buildRequestHeaders(req);
      const headerBlock = this.encoder.encode(headers);

      const hasBody =
        req.body !== undefined &&
        req.body !== null &&
        req.method !== 'GET' &&
        req.method !== 'HEAD';

      // Send HEADERS frame
      this.write(buildHeadersFrame(streamId, headerBlock, !hasBody, true));

      // Send body if present
      if (hasBody) {
        const bodyBuf = serializeBody(req.body!);
        this.write(buildDataFrame(streamId, bodyBuf, true));
      }

      // Timeout
      const timeout = req.timeout;
      const timeoutMs = typeof timeout === 'number' ? timeout : (timeout?.total ?? timeout?.response ?? 0);
      if (timeoutMs > 0) {
        h2stream.timer = setTimeout(() => {
          if (this.streams.has(streamId)) {
            this.streams.delete(streamId);
            reject(new TimeoutError('HTTP/2 request timed out', 'response'));
          }
        }, timeoutMs);
      }
    });
  }

  /**
   * Gracefully close the HTTP/2 connection.
   */
  close(): void {
    if (this.closed) return;
    this.closed = true;
    this.write(buildGoawayFrame(0, 0));
    this.stream.end();
  }

  destroy(): void {
    this.closed = true;
    this.stream.destroy();
    for (const [, s] of this.streams) {
      if (s.timer) clearTimeout(s.timer);
      s.reject(new ProtocolError('HTTP/2 connection destroyed'));
    }
    this.streams.clear();
  }

  // ---- Internal ----

  private buildRequestHeaders(req: NLcURLRequest): Array<[string, string]> {
    const url = new URL(req.url);
    const authority = url.port ? `${url.hostname}:${url.port}` : url.hostname;
    const path = url.pathname + url.search;

    // Pseudo headers in profile-defined order
    const order = this.h2Profile?.pseudoHeaderOrder ?? [
      ':method',
      ':authority',
      ':scheme',
      ':path',
    ];

    const pseudoMap: Record<string, string> = {
      ':method': req.method ?? 'GET',
      ':authority': authority,
      ':scheme': url.protocol.replace(':', ''),
      ':path': path || '/',
    };

    const headers: Array<[string, string]> = [];

    // Emit pseudo headers in profile order
    for (const ph of order) {
      const v = pseudoMap[ph];
      if (v !== undefined) {
        headers.push([ph, v]);
      }
    }

    // Default headers
    const seen = new Set<string>(order);
    for (const [k, v] of this.defaultHeaders) {
      const lower = k.toLowerCase();
      if (!seen.has(lower)) {
        seen.add(lower);
        headers.push([lower, v]);
      }
    }

    // Request headers
    if (req.headers) {
      for (const [k, v] of Object.entries(req.headers)) {
        const lower = k.toLowerCase();
        if (!seen.has(lower)) {
          seen.add(lower);
          headers.push([lower, v]);
        }
      }
    }

    return headers;
  }

  private write(data: Buffer): void {
    if (!this.closed) {
      this.stream.write(data);
    }
  }

  private onData(chunk: Buffer): void {
    this.readBuffer = Buffer.concat([this.readBuffer, chunk]);
    this.processFrames();
  }

  private processFrames(): void {
    while (true) {
      const result = readFrame(this.readBuffer, 0);
      if (!result) break;

      this.readBuffer = this.readBuffer.subarray(result.bytesRead);
      this.handleFrame(result.frame);
    }
  }

  private handleFrame(frame: H2Frame): void {
    switch (frame.type) {
      case FrameType.SETTINGS:
        if (!(frame.flags & Flags.ACK)) {
          // Acknowledge server settings
          this.write(buildSettingsFrame([], true));
        }
        break;

      case FrameType.HEADERS: {
        const s = this.streams.get(frame.streamId);
        if (!s) break;

        const headers = this.decoder.decode(frame.payload);
        for (const [name, value] of headers) {
          if (name === ':status') {
            s.status = parseInt(value, 10);
          }
          s.responseRawHeaders.push([name, value]);
          const existing = s.responseHeaders.get(name);
          if (existing !== undefined) {
            s.responseHeaders.set(name, existing + ', ' + value);
          } else {
            s.responseHeaders.set(name, value);
          }
        }

        if (frame.flags & Flags.END_STREAM) {
          this.finalizeStream(s);
        }
        break;
      }

      case FrameType.DATA: {
        const s = this.streams.get(frame.streamId);
        if (!s) break;
        s.dataChunks.push(Buffer.from(frame.payload));

        if (frame.flags & Flags.END_STREAM) {
          this.finalizeStream(s);
        }
        break;
      }

      case FrameType.RST_STREAM: {
        const s = this.streams.get(frame.streamId);
        if (s) {
          if (s.timer) clearTimeout(s.timer);
          this.streams.delete(frame.streamId);
          const errorCode = frame.payload.readUInt32BE(0);
          s.reject(new ProtocolError(`HTTP/2 stream reset: error code ${errorCode}`));
        }
        break;
      }

      case FrameType.PING:
        if (!(frame.flags & Flags.ACK)) {
          this.write(buildPingFrame(frame.payload, true));
        }
        break;

      case FrameType.GOAWAY: {
        this.closed = true;
        const errorCode = frame.payload.readUInt32BE(4);
        if (errorCode !== 0) {
          for (const [, s] of this.streams) {
            if (s.timer) clearTimeout(s.timer);
            s.reject(new ProtocolError(`HTTP/2 GOAWAY: error code ${errorCode}`));
          }
          this.streams.clear();
        }
        break;
      }

      case FrameType.WINDOW_UPDATE:
        // Flow control -- in a full implementation we would track
        // per-stream and connection-level windows. For now, accepted.
        break;
    }
  }

  private async finalizeStream(s: H2Stream): Promise<void> {
    if (s.timer) clearTimeout(s.timer);
    this.streams.delete(s.id);

    const rawBody = Buffer.concat(s.dataChunks);
    const encoding = s.responseHeaders.get('content-encoding');
    let body: Buffer;
    try {
      body = encoding ? await decompressBody(rawBody, encoding) : rawBody;
    } catch {
      body = rawBody;
    }

    const responseHeaders: Record<string, string> = {};
    for (const [k, v] of s.responseHeaders) {
      if (!k.startsWith(':')) {
        responseHeaders[k] = v;
      }
    }

    const response = new NLcURLResponse({
      status: s.status,
      statusText: '',
      headers: responseHeaders,
      rawHeaders: s.responseRawHeaders.filter(([k]) => !k.startsWith(':')),
      rawBody: body,
      httpVersion: 'h2',
      url: s.request.url,
      redirectCount: 0,
      timings: {
        dns: s.timings.dns ?? 0,
        connect: s.timings.connect ?? 0,
        tls: s.timings.tls ?? 0,
        firstByte: s.timings.firstByte ?? 0,
        total: 0,
      },
      request: {
        url: s.request.url,
        method: s.request.method ?? 'GET',
        headers: s.request.headers ?? {},
      },
    });

    s.resolve(response);
  }

  private onError(err: Error): void {
    for (const [, s] of this.streams) {
      if (s.timer) clearTimeout(s.timer);
      s.reject(new HTTPError(err.message, 0));
    }
    this.streams.clear();
    this.closed = true;
  }

  private onClose(): void {
    for (const [, s] of this.streams) {
      if (s.timer) clearTimeout(s.timer);
      s.reject(new HTTPError('HTTP/2 connection closed', 0));
    }
    this.streams.clear();
    this.closed = true;
  }
}

// ---- Body serialization ----

function serializeBody(body: import('../../core/request.js').RequestBody): Buffer {
  if (body === null || body === undefined) return Buffer.alloc(0);
  if (Buffer.isBuffer(body)) return body;
  if (typeof body === 'string') return Buffer.from(body, 'utf-8');
  if (body instanceof URLSearchParams) {
    return Buffer.from(body.toString(), 'utf-8');
  }
  if (typeof body === 'object' && !(body instanceof ReadableStream)) {
    return Buffer.from(JSON.stringify(body), 'utf-8');
  }
  return Buffer.alloc(0);
}
