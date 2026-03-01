/**
 * WebSocket client with TLS fingerprint impersonation.
 *
 * Implements the WebSocket protocol (RFC 6455) over impersonated
 * TLS connections.  Supports text and binary messages, ping/pong,
 * and graceful close.
 */

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

export interface WebSocketOptions {
  /** Browser profile name to impersonate. */
  impersonate?: string;
  /** Use the stealth TLS engine. */
  stealth?: boolean;
  /** Extra headers for the upgrade request. */
  headers?: Record<string, string>;
  /** WebSocket sub-protocols. */
  protocols?: string[];
  /** Skip TLS certificate verification. */
  insecure?: boolean;
  /** Connection timeout in milliseconds. */
  timeout?: number;
}

export type WebSocketState = 'connecting' | 'open' | 'closing' | 'closed';

export interface WebSocketEvents {
  open: [];
  message: [data: string | Buffer, isBinary: boolean];
  close: [code: number, reason: string];
  error: [error: Error];
  ping: [data: Buffer];
  pong: [data: Buffer];
}

export class WebSocketClient extends EventEmitter {
  public state: WebSocketState = 'connecting';
  public protocol = '';
  public readonly url: string;

  private socket: Duplex | null = null;
  private parser = new FrameParser();
  private fragments: Buffer[] = [];
  private fragmentOpcode: Opcode = Opcode.TEXT;

  constructor(url: string, options: WebSocketOptions = {}) {
    super();
    this.url = url;

    // Start connection asynchronously
    this.connect(url, options).catch((err) => {
      this.state = 'closed';
      this.emit('error', err);
    });
  }

  /**
   * Send a text message.
   */
  sendText(data: string): void {
    this.assertOpen();
    const payload = Buffer.from(data, 'utf8');
    this.socket!.write(encodeFrame(Opcode.TEXT, payload));
  }

  /**
   * Send a binary message.
   */
  sendBinary(data: Buffer): void {
    this.assertOpen();
    this.socket!.write(encodeFrame(Opcode.BINARY, data));
  }

  /**
   * Send a ping frame.
   */
  ping(data: Buffer = Buffer.alloc(0)): void {
    this.assertOpen();
    this.socket!.write(encodeFrame(Opcode.PING, data));
  }

  /**
   * Initiate a graceful close handshake.
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

  // ---- Internal ----

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

    // Resolve profile
    const profile: BrowserProfile | undefined = options.impersonate
      ? getProfile(options.impersonate) ?? undefined
      : undefined;

    let transport: Duplex;

    if (isSecure) {
      // TLS connection with impersonation
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
      // Plain TCP (ws://)
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

    // Perform HTTP upgrade handshake
    await this.performUpgrade(transport, parsed, options);

    // Now in open state
    this.state = 'open';
    this.emit('open');

    // Start reading frames
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

      // Read the upgrade response
      let responseData = Buffer.alloc(0);
      const expectedAccept = computeAcceptKey(key);

      const onData = (chunk: Buffer) => {
        responseData = Buffer.concat([responseData, chunk]);
        const text = responseData.toString('utf8');
        const headerEnd = text.indexOf('\r\n\r\n');
        if (headerEnd === -1) {
          // Limit response header size
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

        // Validate Sec-WebSocket-Accept
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

        // Push any remaining data after headers into frame parser
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
          // Complete message
          const isBinary = frame.opcode === Opcode.BINARY;
          const data = isBinary ? frame.payload : frame.payload.toString('utf8');
          this.emit('message', data, isBinary);
        } else {
          // Start of fragmented message
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
          // Server-initiated close, echo it back
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
        // Auto-respond with pong
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
