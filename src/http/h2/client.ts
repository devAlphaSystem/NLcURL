
import type { Duplex } from 'node:stream';
import { PassThrough } from 'node:stream';
import type { NLcURLRequest, RequestTimings } from '../../core/request.js';
import { NLcURLResponse } from '../../core/response.js';
import { HTTPError, TimeoutError, ProtocolError } from '../../core/errors.js';
import { decompressBody, createDecompressStream } from '../../utils/encoding.js';
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
  buildRstStreamFrame,
  H2_PREFACE,
  FrameType,
  Flags,
  type H2Frame,
} from './frames.js';

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
  bodyStream?: PassThrough;
}

const DEFAULT_INITIAL_WINDOW_SIZE = 65535;

const WINDOW_UPDATE_THRESHOLD_RATIO = 0.5;

/**
 * Multiplexed HTTP/2 client that operates over an existing duplex stream.
 * Handles all aspects of the HTTP/2 connection lifecycle: connection preface,
 * settings negotiation, flow control (both stream-level and connection-level),
 * HPACK header compression, and stream multiplexing.
 *
 * Create one `H2Client` per underlying TCP/TLS connection; each call to
 * {@link H2Client.request} or {@link H2Client.streamRequest} opens a new HTTP/2 stream.
 */
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
  private _closed = false;

  private connectionRecvWindow = DEFAULT_INITIAL_WINDOW_SIZE;
  private initialStreamRecvWindow = DEFAULT_INITIAL_WINDOW_SIZE;
  private streamRecvWindows = new Map<number, number>();

  private serverMaxConcurrentStreams = Infinity;
  private serverMaxFrameSize = 16384;

  private connectionSendWindow = DEFAULT_INITIAL_WINDOW_SIZE;
  private initialStreamSendWindow = DEFAULT_INITIAL_WINDOW_SIZE;
  private streamSendWindows = new Map<number, number>();
  private pendingSendData = new Map<number, { data: Buffer; endStream: boolean; resolve: () => void }[]>();

  private pendingHeaderStreamId: number | null = null;
  private pendingHeaderBlock: Buffer | null = null;
  private pendingHeaderFlags: number = 0;

  /**
   * Optional callback invoked when the underlying connection closes, regardless
   * of the reason (graceful GOAWAY, remote reset, or network error).
   *
   * @type {(() => void) | undefined}
   */
  onClose?: () => void;

  /**
   * Creates a new H2Client and begins listening for frames on `stream`.
   *
   * @param {Duplex}                   stream         - Connected transport stream (TLS or plain TCP).
   * @param {H2Profile}                [h2Profile]    - Browser HTTP/2 fingerprint settings (SETTINGS frame values,
   *   window update sizes, and priority frames). Defaults to Chrome-like settings when omitted.
   * @param {Array<[string, string]>}  [defaultHeaders=[]] - Profile-level request headers prepended to every request.
   */
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
    stream.once('error', (err) => this.handleError(err));
    stream.once('close', () => this.handleClose());
  }

  /**
   * Returns `true` if the connection has been closed or destroyed and is no
   * longer usable.
   *
   * @returns {boolean} Whether the connection is closed.
   */
  get isClosed(): boolean {
    return this._closed;
  }

  /**
   * Sends the HTTP/2 client connection preface (magic PRI bytes) and the
   * initial SETTINGS frame derived from the browser profile. Idempotent —
   * calling more than once has no effect.
   */
  sendPreface(): void {
    if (this.prefaceSent) return;
    this.prefaceSent = true;

    this.write(H2_PREFACE);

    if (this.h2Profile) {
      this.write(buildSettingsFrame(this.h2Profile.settings));

      for (const s of this.h2Profile.settings) {
        if (s.id === 4) this.initialStreamRecvWindow = s.value;
      }

      if (this.h2Profile.windowUpdate > 0) {
        this.connectionRecvWindow = DEFAULT_INITIAL_WINDOW_SIZE + this.h2Profile.windowUpdate;
        this.write(buildWindowUpdateFrame(0, this.h2Profile.windowUpdate));
      }

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
      this.initialStreamRecvWindow = 6291456;
      this.write(buildSettingsFrame([
        { id: 1, value: 65536 },
        { id: 2, value: 0 },
        { id: 4, value: 6291456 },
        { id: 6, value: 262144 },
      ]));
      this.connectionRecvWindow = DEFAULT_INITIAL_WINDOW_SIZE + 15663105;
      this.write(buildWindowUpdateFrame(0, 15663105));
    }
  }

  /**
   * Sends an HTTP/2 request and buffers the entire response body before
   * resolving. This is the standard (non-streaming) request path.
   *
   * @param {NLcURLRequest}             req      - Request descriptor.
   * @param {Partial<RequestTimings>}   [timings={}] - Partial timings object populated with `firstByte`.
   * @returns {Promise<NLcURLResponse>} Resolves with the fully received, decompressed response.
   * @throws {ProtocolError}  If the connection is already closed or stream IDs are exhausted.
   * @throws {TimeoutError}   If the per-request timeout elapses before a response is received.
   */
  async request(
    req: NLcURLRequest,
    timings: Partial<RequestTimings> = {},
  ): Promise<NLcURLResponse> {
    if (this._closed) {
      throw new ProtocolError('HTTP/2 connection is closed');
    }

    if (!this.prefaceSent) this.sendPreface();

    const streamId = this.nextStreamId;
    if (streamId > 0x7fffffff) {
      throw new ProtocolError('HTTP/2 stream ID exhausted; open a new connection');
    }
    this.nextStreamId += 2;

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
      this.streamRecvWindows.set(streamId, this.initialStreamRecvWindow);
      this.streamSendWindows.set(streamId, this.initialStreamSendWindow);

      const headers = this.buildRequestHeaders(req);
      const headerBlock = this.encoder.encode(headers);

      const hasBody =
        req.body !== undefined &&
        req.body !== null &&
        req.method !== 'GET' &&
        req.method !== 'HEAD';

      this.write(buildHeadersFrame(streamId, headerBlock, !hasBody, true));

      if (hasBody) {
        const bodyBuf = serializeBody(req.body!);
        this.sendDataWithFlowControl(streamId, bodyBuf, true);
      }

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
   * Sends an HTTP/2 request and returns a streaming response. The returned
   * `NLcURLResponse` resolves once the status and headers are received;
   * the response body is exposed as a `PassThrough` readable stream via
   * `response.body`.
   *
   * @param {NLcURLRequest}             req      - Request descriptor.
   * @param {Partial<RequestTimings>}   [timings={}] - Partial timings object populated with `firstByte`.
   * @returns {Promise<NLcURLResponse>} Resolves once headers are received; body is streamed via `response.body`.
   * @throws {ProtocolError}  If the connection is already closed or stream IDs are exhausted.
   * @throws {TimeoutError}   If the per-request timeout elapses before the stream begins.
   */
  async streamRequest(
    req: NLcURLRequest,
    timings: Partial<RequestTimings> = {},
  ): Promise<NLcURLResponse> {
    if (this._closed) {
      throw new ProtocolError('HTTP/2 connection is closed');
    }

    if (!this.prefaceSent) this.sendPreface();

    const streamId = this.nextStreamId;
    if (streamId > 0x7fffffff) {
      throw new ProtocolError('HTTP/2 stream ID exhausted; open a new connection');
    }
    this.nextStreamId += 2;

    return new Promise<NLcURLResponse>((resolve, reject) => {
      const bodyStream = new PassThrough();

      const h2stream: H2Stream = {
        id: streamId,
        request: req,
        responseHeaders: new Map(),
        responseRawHeaders: [],
        status: 0,
        dataChunks: [],
        endStream: false,
        resolve: (_resp: NLcURLResponse) => {  },
        reject,
        timings,
        bodyStream,
      };

      this.streams.set(streamId, h2stream);
      this.streamRecvWindows.set(streamId, this.initialStreamRecvWindow);
      this.streamSendWindows.set(streamId, this.initialStreamSendWindow);

      const headers = this.buildRequestHeaders(req);
      const headerBlock = this.encoder.encode(headers);

      const hasBody =
        req.body !== undefined &&
        req.body !== null &&
        req.method !== 'GET' &&
        req.method !== 'HEAD';

      this.write(buildHeadersFrame(streamId, headerBlock, !hasBody, true));

      if (hasBody) {
        const bodyBuf = serializeBody(req.body!);
        this.sendDataWithFlowControl(streamId, bodyBuf, true);
      }

      h2stream.resolve = (resp: NLcURLResponse) => {
        resolve(resp);
      };

      const timeout = req.timeout;
      const timeoutMs = typeof timeout === 'number' ? timeout : (timeout?.total ?? timeout?.response ?? 0);
      if (timeoutMs > 0) {
        h2stream.timer = setTimeout(() => {
          if (this.streams.has(streamId)) {
            this.streams.delete(streamId);
            bodyStream.destroy(new TimeoutError('HTTP/2 request timed out', 'response'));
            reject(new TimeoutError('HTTP/2 request timed out', 'response'));
          }
        }, timeoutMs);
      }
    });
  }

  /**
   * Initiates a graceful shutdown by sending a GOAWAY frame and ending the
   * underlying stream. In-flight requests will fail with `ProtocolError`.
   */
  close(): void {
    if (this._closed) return;
    this._closed = true;
    this.write(buildGoawayFrame(0, 0));
    this.stream.end();
    this.onClose?.();
  }

  /**
   * Immediately destroys the underlying transport stream, aborting all
   * pending requests with a `ProtocolError`.
   */
  destroy(): void {
    this._closed = true;
    this.stream.destroy();
    for (const [, s] of this.streams) {
      if (s.timer) clearTimeout(s.timer);
      s.reject(new ProtocolError('HTTP/2 connection destroyed'));
    }
    this.streams.clear();
    this.streamRecvWindows.clear();
    this.streamSendWindows.clear();
    this.pendingSendData.clear();
    this.onClose?.();
  }

  private buildRequestHeaders(req: NLcURLRequest): Array<[string, string]> {
    const url = new URL(req.url);
    const authority = url.port ? `${url.hostname}:${url.port}` : url.hostname;
    const path = url.pathname + url.search;

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

    for (const ph of order) {
      const v = pseudoMap[ph];
      if (v !== undefined) {
        headers.push([ph, v]);
      }
    }

    const seen = new Set<string>(order);
    for (const [k, v] of this.defaultHeaders) {
      const lower = k.toLowerCase();
      if (!seen.has(lower)) {
        seen.add(lower);
        headers.push([lower, v]);
      }
    }

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
    if (!this._closed) {
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
    if (this.pendingHeaderStreamId !== null && frame.type !== FrameType.CONTINUATION) {
      this._closed = true;
      this.write(buildGoawayFrame(0, 1));
      for (const [, s] of this.streams) {
        if (s.timer) clearTimeout(s.timer);
        s.reject(new ProtocolError('Protocol error: expected CONTINUATION frame', 1));
      }
      this.streams.clear();
      this.onClose?.();
      return;
    }

    switch (frame.type) {
      case FrameType.SETTINGS:
        if (!(frame.flags & Flags.ACK)) {
          this.applyServerSettings(frame.payload);
          this.write(buildSettingsFrame([], true));
        }
        break;

      case FrameType.HEADERS: {
        const s = this.streams.get(frame.streamId);
        if (!s) break;

        let headerPayload = frame.payload;
        if (frame.flags & Flags.PADDED) {
          if (headerPayload.length < 1) {
            s.reject(new ProtocolError('HEADERS frame with PADDED flag but no pad length'));
            this.streams.delete(frame.streamId);
            break;
          }
          const padLength = headerPayload[0]!;
          if (padLength >= headerPayload.length) {
            s.reject(new ProtocolError('HEADERS pad length exceeds payload'));
            this.streams.delete(frame.streamId);
            break;
          }
          headerPayload = headerPayload.subarray(1, headerPayload.length - padLength);
        }

        if (frame.flags & Flags.PRIORITY) {
          if (headerPayload.length < 5) {
            s.reject(new ProtocolError('HEADERS frame with PRIORITY but insufficient data'));
            this.streams.delete(frame.streamId);
            break;
          }
          headerPayload = headerPayload.subarray(5);
        }

        if (!(frame.flags & Flags.END_HEADERS)) {
          this.pendingHeaderStreamId = frame.streamId;
          this.pendingHeaderBlock = Buffer.from(headerPayload);
          this.pendingHeaderFlags = frame.flags;
          break;
        }

        this.processDecodedHeaders(s, headerPayload, frame.flags);
        break;
      }

      case FrameType.CONTINUATION: {
        if (this.pendingHeaderStreamId === null || frame.streamId !== this.pendingHeaderStreamId) {
          this._closed = true;
          this.write(buildGoawayFrame(0, 1));
          this.onClose?.();
          return;
        }

        this.pendingHeaderBlock = Buffer.concat([this.pendingHeaderBlock!, frame.payload]);

        if (frame.flags & Flags.END_HEADERS) {
          const s = this.streams.get(this.pendingHeaderStreamId);
          const headerBlock = this.pendingHeaderBlock;
          const flags = this.pendingHeaderFlags;
          this.pendingHeaderStreamId = null;
          this.pendingHeaderBlock = null;
          this.pendingHeaderFlags = 0;

          if (s) {
            this.processDecodedHeaders(s, headerBlock, flags);
          }
        }
        break;
      }

      case FrameType.DATA: {
        const s = this.streams.get(frame.streamId);
        if (!s) break;

        let dataPayload = frame.payload;
        if (frame.flags & Flags.PADDED) {
          if (dataPayload.length < 1) {
            s.reject(new ProtocolError('DATA frame with PADDED flag but no pad length'));
            this.streams.delete(frame.streamId);
            break;
          }
          const padLength = dataPayload[0]!;
          if (padLength >= dataPayload.length) {
            s.reject(new ProtocolError('DATA pad length exceeds payload'));
            this.streams.delete(frame.streamId);
            break;
          }
          dataPayload = dataPayload.subarray(1, dataPayload.length - padLength);
        }

        const data = Buffer.from(dataPayload);
        if (s.bodyStream) {
          s.bodyStream.write(data);
        } else {
          s.dataChunks.push(data);
        }

        this.consumeRecvWindow(frame.streamId, frame.payload.length);

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
          this.streamRecvWindows.delete(frame.streamId);
          this.streamSendWindows.delete(frame.streamId);
          this.pendingSendData.delete(frame.streamId);
          const errorCode = frame.payload.readUInt32BE(0);
          const err = new ProtocolError(`HTTP/2 stream reset: error code ${errorCode}`, errorCode);
          if (s.bodyStream) s.bodyStream.destroy(err);
          s.reject(err);
        }
        break;
      }

      case FrameType.PING:
        if (!(frame.flags & Flags.ACK)) {
          this.write(buildPingFrame(frame.payload, true));
        }
        break;

      case FrameType.GOAWAY: {
        this._closed = true;
        const errorCode = frame.payload.readUInt32BE(4);
        if (errorCode !== 0) {
          for (const [, s] of this.streams) {
            if (s.timer) clearTimeout(s.timer);
            s.reject(new ProtocolError(`HTTP/2 GOAWAY: error code ${errorCode}`, errorCode));
          }
          this.streams.clear();
        } else {
          for (const [, s] of this.streams) {
            if (s.timer) clearTimeout(s.timer);
            s.reject(new ProtocolError('HTTP/2 GOAWAY: graceful shutdown', 0));
          }
          this.streams.clear();
        }
        this.onClose?.();
        break;
      }

      case FrameType.WINDOW_UPDATE: {
        const increment = frame.payload.readUInt32BE(0) & 0x7fffffff;
        if (increment === 0) {
          if (frame.streamId === 0) {
            this._closed = true;
            this.write(buildGoawayFrame(0, 1));
            this.onClose?.();
          } else {
            this.write(buildRstStreamFrame(frame.streamId, 1));
          }
          break;
        }

        if (frame.streamId === 0) {
          this.connectionSendWindow += increment;
        } else {
          const current = this.streamSendWindows.get(frame.streamId) ?? this.initialStreamSendWindow;
          this.streamSendWindows.set(frame.streamId, current + increment);
        }
        this.flushPendingSendData(frame.streamId);
        break;
      }
    }
  }

  private processDecodedHeaders(s: H2Stream, headerBlock: Buffer, flags: number): void {
    const headers = this.decoder.decode(headerBlock);
    for (const [name, value] of headers) {
      if (name === ':status') {
        s.status = parseInt(value, 10);
      }
      s.responseRawHeaders.push([name, value]);
      const existing = s.responseHeaders.get(name);
      if (existing !== undefined) {
        const sep = name === 'set-cookie' ? '; ' : ', ';
        s.responseHeaders.set(name, existing + sep + value);
      } else {
        s.responseHeaders.set(name, value);
      }
    }

    if (flags & Flags.END_STREAM) {
      this.finalizeStream(s);
    } else if (s.bodyStream && s.status > 0) {
      this.resolveStreamingResponse(s);
    }
  }

  private resolveStreamingResponse(s: H2Stream): void {
    const responseHeaders: Record<string, string> = {};
    for (const [k, v] of s.responseHeaders) {
      if (!k.startsWith(':')) {
        responseHeaders[k] = v;
      }
    }

    const encoding = s.responseHeaders.get('content-encoding');
    const decompressor = createDecompressStream(encoding);
    const outputStream = decompressor ? s.bodyStream!.pipe(decompressor) : s.bodyStream!;

    const response = new NLcURLResponse({
      status: s.status,
      statusText: '',
      headers: responseHeaders,
      rawHeaders: s.responseRawHeaders.filter(([k]) => !k.startsWith(':')),
      rawBody: Buffer.alloc(0),
      body: outputStream,
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

  private async finalizeStream(s: H2Stream): Promise<void> {
    if (s.timer) clearTimeout(s.timer);
    this.streams.delete(s.id);
    this.streamRecvWindows.delete(s.id);

    if (s.bodyStream) {
      s.bodyStream.end();
      return;
    }

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

  private applyServerSettings(payload: Buffer): void {
    for (let i = 0; i + 5 < payload.length; i += 6) {
      const id = payload.readUInt16BE(i);
      const value = payload.readUInt32BE(i + 2);
      switch (id) {
        case 3:
          this.serverMaxConcurrentStreams = value;
          break;
        case 4:
          {
            const recvDelta = value - this.initialStreamRecvWindow;
            this.initialStreamRecvWindow = value;
            for (const [streamId, win] of this.streamRecvWindows) {
              this.streamRecvWindows.set(streamId, win + recvDelta);
            }
            const sendDelta = value - this.initialStreamSendWindow;
            this.initialStreamSendWindow = value;
            for (const [streamId, win] of this.streamSendWindows) {
              this.streamSendWindows.set(streamId, win + sendDelta);
            }
          }
          break;
        case 5:
          this.serverMaxFrameSize = value;
          break;
      }
    }
  }

  private consumeRecvWindow(streamId: number, length: number): void {
    this.connectionRecvWindow -= length;
    const connMax = this.h2Profile
      ? DEFAULT_INITIAL_WINDOW_SIZE + (this.h2Profile.windowUpdate || 0)
      : DEFAULT_INITIAL_WINDOW_SIZE + 15663105;
    const connThreshold = Math.floor(connMax * WINDOW_UPDATE_THRESHOLD_RATIO);
    if (this.connectionRecvWindow < connThreshold) {
      const increment = connMax - this.connectionRecvWindow;
      this.connectionRecvWindow += increment;
      this.write(buildWindowUpdateFrame(0, increment));
    }

    const streamWin = this.streamRecvWindows.get(streamId);
    if (streamWin !== undefined) {
      const newWin = streamWin - length;
      const streamThreshold = Math.floor(this.initialStreamRecvWindow * WINDOW_UPDATE_THRESHOLD_RATIO);
      if (newWin < streamThreshold) {
        const increment = this.initialStreamRecvWindow - newWin;
        this.streamRecvWindows.set(streamId, newWin + increment);
        this.write(buildWindowUpdateFrame(streamId, increment));
      } else {
        this.streamRecvWindows.set(streamId, newWin);
      }
    }
  }

  private handleError(err: Error): void {
    for (const [, s] of this.streams) {
      if (s.timer) clearTimeout(s.timer);
      s.reject(new HTTPError(err.message, 0));
    }
    this.streams.clear();
    this.streamRecvWindows.clear();
    this.streamSendWindows.clear();
    this.pendingSendData.clear();
    this._closed = true;
    this.onClose?.();
  }

  private handleClose(): void {
    for (const [, s] of this.streams) {
      if (s.timer) clearTimeout(s.timer);
      s.reject(new HTTPError('HTTP/2 connection closed', 0));
    }
    this.streams.clear();
    this.streamRecvWindows.clear();
    this.streamSendWindows.clear();
    this.pendingSendData.clear();
    this._closed = true;
    this.onClose?.();
  }

  private sendDataWithFlowControl(streamId: number, data: Buffer, endStream: boolean): void {
    let offset = 0;
    while (offset < data.length) {
      const streamWin = this.streamSendWindows.get(streamId) ?? this.initialStreamSendWindow;
      const maxSend = Math.min(this.connectionSendWindow, streamWin, this.serverMaxFrameSize);

      if (maxSend <= 0) {
        const remaining = data.subarray(offset);
        const pending = this.pendingSendData.get(streamId) ?? [];
        pending.push({ data: remaining, endStream, resolve: () => {} });
        this.pendingSendData.set(streamId, pending);
        return;
      }

      const chunkSize = Math.min(maxSend, data.length - offset);
      const chunk = data.subarray(offset, offset + chunkSize);
      offset += chunkSize;
      const isLast = offset >= data.length && endStream;

      this.write(buildDataFrame(streamId, chunk, isLast));
      this.connectionSendWindow -= chunkSize;
      const currentStreamWin = this.streamSendWindows.get(streamId) ?? this.initialStreamSendWindow;
      this.streamSendWindows.set(streamId, currentStreamWin - chunkSize);
    }
  }

  private flushPendingSendData(streamId: number): void {
    const streamIds = streamId === 0
      ? [...this.pendingSendData.keys()]
      : [streamId];

    for (const sid of streamIds) {
      const pending = this.pendingSendData.get(sid);
      if (!pending || pending.length === 0) continue;

      while (pending.length > 0) {
        const item = pending[0]!;
        const streamWin = this.streamSendWindows.get(sid) ?? this.initialStreamSendWindow;
        const maxSend = Math.min(this.connectionSendWindow, streamWin, this.serverMaxFrameSize);

        if (maxSend <= 0) break;

        const chunkSize = Math.min(maxSend, item.data.length);
        const chunk = item.data.subarray(0, chunkSize);
        const remaining = item.data.subarray(chunkSize);
        const isLast = remaining.length === 0 && item.endStream;

        this.write(buildDataFrame(sid, chunk, isLast));
        this.connectionSendWindow -= chunkSize;
        const currentStreamWin = this.streamSendWindows.get(sid) ?? this.initialStreamSendWindow;
        this.streamSendWindows.set(sid, currentStreamWin - chunkSize);

        if (remaining.length === 0) {
          pending.shift();
        } else {
          item.data = remaining;
          break;
        }
      }

      if (pending.length === 0) {
        this.pendingSendData.delete(sid);
      }
    }
  }
}

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
