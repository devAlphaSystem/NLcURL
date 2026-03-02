
import { EventEmitter } from 'node:events';
import type { Duplex } from 'node:stream';
import type { BrowserProfile } from '../fingerprints/types.js';
import type { ITLSEngine, TLSConnectOptions } from '../tls/types.js';
import { NodeTLSEngine } from '../tls/node-engine.js';
import { StealthTLSEngine } from '../tls/stealth/engine.js';
import { getProfile } from '../fingerprints/database.js';
import { NLcURLError, ConnectionError } from '../core/errors.js';
import {
  encodeFrame,
  FrameParser,
  Opcode,
  generateWebSocketKey,
  computeAcceptKey,
  type WebSocketFrame,
} from './frame.js';

/**
 * Options for creating a {@link WebSocketClient} connection.
 *
 * @typedef  {Object}    WebSocketOptions
 * @property {string}    [impersonate]  - Browser profile name for fingerprint impersonation.
 * @property {boolean}   [stealth]      - Use the stealth TLS engine for byte-level fingerprinting.
 * @property {Record<string, string>} [headers] - Additional HTTP upgrade request headers.
 * @property {string[]}  [protocols]    - Sub-protocol names to negotiate.
 * @property {boolean}   [insecure]     - Skip TLS certificate validation for `wss:` connections.
 * @property {number}    [timeout]      - Connection timeout in milliseconds.
 */
export interface WebSocketOptions {
  impersonate?: string;
  stealth?: boolean;
  headers?: Record<string, string>;
  protocols?: string[];
  insecure?: boolean;
  timeout?: number;
}

/**
 * WebSocket connection state.
 *
 * @typedef {'connecting' | 'open' | 'closing' | 'closed'} WebSocketState
 */
export type WebSocketState = 'connecting' | 'open' | 'closing' | 'closed';

/**
 * Typed event map for {@link WebSocketClient}.
 *
 * @typedef  {Object}                           WebSocketEvents
 * @property {[]}                               open    - Emitted when the connection is established.
 * @property {[data: string | Buffer, isBinary: boolean]} message - Emitted for each incoming message.
 * @property {[code: number, reason: string]}   close   - Emitted when the connection closes.
 * @property {[error: Error]}                   error   - Emitted on connection or protocol errors.
 * @property {[data: Buffer]}                   ping    - Emitted when a PING frame is received.
 * @property {[data: Buffer]}                   pong    - Emitted when a PONG frame is received.
 */
export interface WebSocketEvents {
  open: [];
  message: [data: string | Buffer, isBinary: boolean];
  close: [code: number, reason: string];
  error: [error: Error];
  ping: [data: Buffer];
  pong: [data: Buffer];
}

/**
 * WebSocket client with optional browser fingerprint impersonation. Emits
 * typed lifecycle events (`open`, `message`, `close`, `error`, `ping`, `pong`).
 * The connection is initiated asynchronously in the constructor; listen for
 * the `'open'` event before sending frames.
 *
 * @example
 * const ws = new WebSocketClient('wss://echo.example.com', { impersonate: 'chrome136' });
 * ws.on('open', () => ws.sendText('hello'));
 * ws.on('message', (data) => console.log(data));
 */
export class WebSocketClient extends EventEmitter {
  public state: WebSocketState = 'connecting';
  public protocol = '';
  public readonly url: string;

  private socket: Duplex | null = null;
  private parser = new FrameParser();
  private fragments: Buffer[] = [];
  private fragmentOpcode: Opcode = Opcode.TEXT;

  /**
   * Creates a new WebSocketClient and begins connecting to `url`.
   *
   * @param {string}           url       - WebSocket URL (`ws:` or `wss:`).
   * @param {WebSocketOptions} [options={}] - Connection and impersonation options.
   */
  constructor(url: string, options: WebSocketOptions = {}) {
    super();
    this.url = url;

    this.connect(url, options).catch((err) => {
      this.state = 'closed';
      this.emit('error', err);
    });
  }

  /**
   * Sends a UTF-8 text message.
   *
   * @param {string} data - Text to send.
   * @throws {NLcURLError} If the WebSocket is not in the `'open'` state.
   */
  sendText(data: string): void {
    this.assertOpen();
    const payload = Buffer.from(data, 'utf8');
    this.socket!.write(encodeFrame(Opcode.TEXT, payload));
  }

  /**
   * Sends a binary message.
   *
   * @param {Buffer} data - Binary data to send.
   * @throws {NLcURLError} If the WebSocket is not in the `'open'` state.
   */
  sendBinary(data: Buffer): void {
    this.assertOpen();
    this.socket!.write(encodeFrame(Opcode.BINARY, data));
  }

  /**
   * Sends a PING control frame.
   *
   * @param {Buffer} [data=Buffer.alloc(0)] - Optional ping payload (up to 125 bytes).
   * @throws {NLcURLError} If the WebSocket is not in the `'open'` state.
   */
  ping(data: Buffer = Buffer.alloc(0)): void {
    this.assertOpen();
    this.socket!.write(encodeFrame(Opcode.PING, data));
  }

  /**
   * Initiates a graceful close handshake by sending a CLOSE frame with the
   * given status code and reason. Does nothing if the connection is not open.
   *
   * @param {number} [code=1000]  - WebSocket close status code.
   * @param {string} [reason=''] - Human-readable close reason (UTF-8, max 123 bytes).
   */
  close(code = 1000, reason = ''): void {
    if (this.state !== 'open') return;
    this.state = 'closing';

    const reasonBuf = Buffer.from(reason, 'utf8');
    const payload = Buffer.allocUnsafe(2 + reasonBuf.length);
    payload.writeUInt16BE(code, 0);
    reasonBuf.copy(payload, 2);

    this.socket!.write(encodeFrame(Opcode.CLOSE, payload));
  }

  private assertOpen(): void {
    if (this.state !== 'open') {
      throw new NLcURLError('WebSocket is not open', 'ERR_WS_NOT_OPEN');
    }
  }

  private async connect(url: string, options: WebSocketOptions): Promise<void> {
    const parsed = new URL(url);
    const isSecure = parsed.protocol === 'wss:';
    const port = parsed.port
      ? parseInt(parsed.port, 10)
      : isSecure ? 443 : 80;
    const host = parsed.hostname;

    const profile: BrowserProfile | undefined = options.impersonate
      ? getProfile(options.impersonate) ?? undefined
      : undefined;

    let transport: Duplex;

    if (isSecure) {
      const engine: ITLSEngine = options.stealth
        ? new StealthTLSEngine()
        : new NodeTLSEngine();

      const tlsOpts: TLSConnectOptions = {
        host,
        port,
        servername: host,
        insecure: options.insecure ?? false,
        alpnProtocols: ['http/1.1'],
        timeout: options.timeout,
      };

      const tlsSocket = await engine.connect(tlsOpts, profile);
      transport = tlsSocket as unknown as Duplex;
    } else {
      const net = await import('node:net');
      transport = await new Promise<Duplex>((resolve, reject) => {
        const sock = net.createConnection({ host, port }, () => resolve(sock));
        sock.once('error', reject);
        if (options.timeout) {
          sock.setTimeout(options.timeout, () => {
            sock.destroy();
            reject(new ConnectionError('WebSocket connection timed out'));
          });
        }
      });
    }

    this.socket = transport;

    await this.performUpgrade(transport, parsed, options);

    this.state = 'open';
    this.emit('open');

    transport.on('data', (chunk: Buffer) => this.onData(chunk));
    transport.on('error', (err: Error) => {
      this.state = 'closed';
      this.emit('error', err);
    });
    transport.on('close', () => {
      if (this.state !== 'closed') {
        this.state = 'closed';
        this.emit('close', 1006, 'Connection lost');
      }
    });

    this.drainBufferedFrames();
  }

  private performUpgrade(
    socket: Duplex,
    url: URL,
    options: WebSocketOptions,
  ): Promise<void> {
    return new Promise<void>((resolve, reject) => {
      const key = generateWebSocketKey();
      const path = (url.pathname || '/') + (url.search || '');

      let request = `GET ${path} HTTP/1.1\r\n`;
      request += `Host: ${url.host}\r\n`;
      request += `Upgrade: websocket\r\n`;
      request += `Connection: Upgrade\r\n`;
      request += `Sec-WebSocket-Key: ${key}\r\n`;
      request += `Sec-WebSocket-Version: 13\r\n`;

      if (options.protocols && options.protocols.length > 0) {
        request += `Sec-WebSocket-Protocol: ${options.protocols.join(', ')}\r\n`;
      }

      if (options.headers) {
        for (const [k, v] of Object.entries(options.headers)) {
          request += `${k}: ${v}\r\n`;
        }
      }

      request += `\r\n`;
      socket.write(request);

      let responseData = Buffer.alloc(0);
      const expectedAccept = computeAcceptKey(key);

      const onData = (chunk: Buffer) => {
        responseData = Buffer.concat([responseData, chunk]);
        const text = responseData.toString('utf8');
        const headerEnd = text.indexOf('\r\n\r\n');
        if (headerEnd === -1) {
          if (responseData.length > 16384) {
            cleanup();
            reject(new NLcURLError('WebSocket upgrade response too large', 'ERR_WS_UPGRADE'));
          }
          return;
        }

        cleanup();

        const headerStr = text.substring(0, headerEnd);
        const [statusLine, ...headerLines] = headerStr.split('\r\n');

        if (!statusLine) {
          return reject(new NLcURLError('Empty upgrade response', 'ERR_WS_UPGRADE'));
        }

        const statusMatch = statusLine.match(/^HTTP\/\d\.\d (\d{3})/);
        if (!statusMatch || statusMatch[1] !== '101') {
          return reject(new NLcURLError(
            `WebSocket upgrade failed: ${statusLine}`,
            'ERR_WS_UPGRADE',
          ));
        }

        const headers = new Map<string, string>();
        for (const line of headerLines) {
          const colonIdx = line.indexOf(':');
          if (colonIdx > 0) {
            headers.set(
              line.substring(0, colonIdx).trim().toLowerCase(),
              line.substring(colonIdx + 1).trim(),
            );
          }
        }

        const accept = headers.get('sec-websocket-accept');
        if (accept !== expectedAccept) {
          return reject(new NLcURLError(
            'Invalid Sec-WebSocket-Accept header',
            'ERR_WS_UPGRADE',
          ));
        }

        this.protocol = headers.get('sec-websocket-protocol') ?? '';

        const remaining = responseData.subarray(headerEnd + 4);
        if (remaining.length > 0) {
          this.parser.push(remaining);
        }

        resolve();
      };

      const onError = (err: Error) => {
        cleanup();
        reject(err);
      };

      const cleanup = () => {
        socket.removeListener('data', onData);
        socket.removeListener('error', onError);
      };

      socket.on('data', onData);
      socket.on('error', onError);
    });
  }

  private onData(chunk: Buffer): void {
    this.parser.push(chunk);
    this.drainBufferedFrames();
  }

  private drainBufferedFrames(): void {
    let frame: WebSocketFrame | null;
    while ((frame = this.parser.pull()) !== null) {
      this.handleFrame(frame);
    }
  }

  private handleFrame(frame: WebSocketFrame): void {
    switch (frame.opcode) {
      case Opcode.TEXT:
      case Opcode.BINARY:
        if (frame.fin) {
          const isBinary = frame.opcode === Opcode.BINARY;
          const data = isBinary ? frame.payload : frame.payload.toString('utf8');
          this.emit('message', data, isBinary);
        } else {
          this.fragmentOpcode = frame.opcode;
          this.fragments = [frame.payload];
        }
        break;

      case Opcode.CONTINUATION:
        this.fragments.push(frame.payload);
        if (frame.fin) {
          const assembled = Buffer.concat(this.fragments);
          this.fragments = [];
          const isBinary = this.fragmentOpcode === Opcode.BINARY;
          const data = isBinary ? assembled : assembled.toString('utf8');
          this.emit('message', data, isBinary);
        }
        break;

      case Opcode.CLOSE: {
        let code = 1005;
        let reason = '';
        if (frame.payload.length >= 2) {
          code = frame.payload.readUInt16BE(0);
          reason = frame.payload.subarray(2).toString('utf8');
        }

        if (this.state === 'open') {
          this.state = 'closing';
          this.socket!.write(encodeFrame(Opcode.CLOSE, frame.payload));
        }

        this.state = 'closed';
        this.socket?.destroy();
        this.emit('close', code, reason);
        break;
      }

      case Opcode.PING:
        this.emit('ping', frame.payload);
        if (this.state === 'open') {
          this.socket!.write(encodeFrame(Opcode.PONG, frame.payload));
        }
        break;

      case Opcode.PONG:
        this.emit('pong', frame.payload);
        break;
    }
  }
}
