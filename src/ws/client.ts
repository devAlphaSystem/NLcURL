import { EventEmitter } from "node:events";
import type { Duplex } from "node:stream";
import type { BrowserProfile } from "../fingerprints/types.js";
import type { ITLSEngine, TLSConnectOptions } from "../tls/types.js";
import { NodeTLSEngine } from "../tls/node-engine.js";
import { StealthTLSEngine } from "../tls/stealth/engine.js";
import { getProfile } from "../fingerprints/database.js";
import { NLcURLError, ConnectionError } from "../core/errors.js";
import { validateWebSocketUrl } from "../core/validation.js";
import { encodeFrame, FrameParser, Opcode, generateWebSocketKey, computeAcceptKey, type WebSocketFrame } from "./frame.js";
import { buildDeflateOffer, parseDeflateResponse, PerMessageDeflate } from "./permessage-deflate.js";

/** Configuration options for a WebSocket connection. */
export interface WebSocketOptions {
  /** Browser profile name to impersonate for TLS fingerprinting. */
  impersonate?: string;
  /** Use the stealth TLS engine for fingerprint impersonation. */
  stealth?: boolean;
  /** Additional HTTP headers to include in the upgrade request. */
  headers?: Record<string, string>;
  /** Subprotocols to offer during the upgrade handshake. */
  protocols?: string[];
  /** Skip TLS certificate verification. */
  insecure?: boolean;
  /** Connection timeout in milliseconds. */
  timeout?: number;
  /** Enable per-message deflate compression. */
  compress?: boolean;
}

/** Current lifecycle state of the WebSocket connection. */
export type WebSocketState = "connecting" | "open" | "closing" | "closed";

/** Event map for {@link WebSocketClient} emitter. */
export interface WebSocketEvents {
  /** Fired when the connection has been established. */
  open: [];
  /** Fired when a text or binary message is received. */
  message: [data: string | Buffer, isBinary: boolean];
  /** Fired when the connection has been cleanly closed. */
  close: [code: number, reason: string];
  /** Fired on transport or protocol errors. */
  error: [error: Error];
  /** Fired when a ping frame is received. */
  ping: [data: Buffer];
  /** Fired when a pong frame is received. */
  pong: [data: Buffer];
}

/** Strict UTF-8 text decoder that throws on invalid sequences (RFC 6455 §8.1). */
const strictUtf8Decoder = new TextDecoder("utf-8", { fatal: true });

/**
 * Validate and decode a buffer as UTF-8 text.
 * Returns the decoded string, or null if the buffer contains invalid UTF-8.
 */
function decodeUtf8Strict(buf: Buffer): string | null {
  try {
    return strictUtf8Decoder.decode(buf);
  } catch {
    return null;
  }
}

/**
 * RFC 6455 WebSocket client with optional TLS fingerprinting
 * and per-message deflate compression.
 */
export class WebSocketClient extends EventEmitter {
  /** Current connection lifecycle state. */
  public state: WebSocketState = "connecting";
  /** Negotiated subprotocol, or empty string if none. */
  public protocol = "";
  /** Original WebSocket URL. */
  public readonly url: string;

  private socket: Duplex | null = null;
  private parser = new FrameParser();
  private fragments: Buffer[] = [];
  private fragmentOpcode: Opcode = Opcode.TEXT;
  private fragmentSize = 0;
  private static readonly MAX_FRAGMENT_SIZE = 64 * 1024 * 1024;
  private deflate: PerMessageDeflate | null = null;

  /**
   * Create a new WebSocket connection.
   *
   * @param {string} url - `ws://` or `wss://` URL to connect to.
   * @param {WebSocketOptions} [options] - Connection and TLS options.
   */
  constructor(url: string, options: WebSocketOptions = {}) {
    super();
    validateWebSocketUrl(url);
    this.url = url;

    this.connect(url, options).catch((err) => {
      this.state = "closed";
      this.emit("error", err);
    });
  }

  /**
   * Send a UTF-8 text message.
   *
   * @param {string} data - Text payload to send.
   */
  sendText(data: string): void {
    this.assertOpen();
    const payload = Buffer.from(data, "utf8");
    if (this.deflate) {
      this.deflate
        .compress(payload)
        .then((compressed) => {
          this.socket!.write(encodeFrame(Opcode.TEXT, compressed, true, true));
        })
        .catch((err) => this.emit("error", err));
    } else {
      this.socket!.write(encodeFrame(Opcode.TEXT, payload));
    }
  }

  /**
   * Send a binary message.
   *
   * @param {Buffer} data - Binary payload to send.
   */
  sendBinary(data: Buffer): void {
    this.assertOpen();
    if (this.deflate) {
      this.deflate
        .compress(data)
        .then((compressed) => {
          this.socket!.write(encodeFrame(Opcode.BINARY, compressed, true, true));
        })
        .catch((err) => this.emit("error", err));
    } else {
      this.socket!.write(encodeFrame(Opcode.BINARY, data));
    }
  }

  /**
   * Send a WebSocket ping frame.
   *
   * @param {Buffer} [data] - Optional payload (up to 125 bytes).
   */
  ping(data: Buffer = Buffer.alloc(0)): void {
    this.assertOpen();
    this.socket!.write(encodeFrame(Opcode.PING, data));
  }

  /**
   * Initiate a graceful close handshake.
   *
   * @param {number} [code] - Close status code (default `1000`).
   * @param {string} [reason] - Human-readable close reason.
   */
  close(code = 1000, reason = ""): void {
    if (this.state !== "open") return;

    if (code !== 1000 && (code < 3000 || code > 4999)) {
      throw new NLcURLError(`Invalid WebSocket close code: ${code}. Must be 1000 or 3000-4999.`, "ERR_WS_INVALID_CLOSE_CODE");
    }

    this.state = "closing";

    const reasonBuf = Buffer.from(reason, "utf8");
    const payload = Buffer.allocUnsafe(2 + reasonBuf.length);
    payload.writeUInt16BE(code, 0);
    reasonBuf.copy(payload, 2);

    this.socket!.write(encodeFrame(Opcode.CLOSE, payload));
    this.deflate?.close();
  }

  private assertOpen(): void {
    if (this.state !== "open") {
      throw new NLcURLError("WebSocket is not open", "ERR_WS_NOT_OPEN");
    }
  }

  private async connect(url: string, options: WebSocketOptions): Promise<void> {
    const parsed = new URL(url);
    const isSecure = parsed.protocol === "wss:";
    const port = parsed.port ? parseInt(parsed.port, 10) : isSecure ? 443 : 80;
    const host = parsed.hostname;

    const profile: BrowserProfile | undefined = options.impersonate ? (getProfile(options.impersonate) ?? undefined) : undefined;

    let transport: Duplex;

    if (isSecure) {
      const engine: ITLSEngine = options.stealth ? new StealthTLSEngine() : new NodeTLSEngine();

      const tlsOpts: TLSConnectOptions = {
        host,
        port,
        servername: host,
        insecure: options.insecure ?? false,
        alpnProtocols: ["http/1.1"],
        timeout: options.timeout,
      };

      const tlsSocket = await engine.connect(tlsOpts, profile);
      transport = tlsSocket as unknown as Duplex;
    } else {
      const net = await import("node:net");
      transport = await new Promise<Duplex>((resolve, reject) => {
        const sock = net.createConnection({ host, port }, () => {
          resolve(sock);
        });
        sock.once("error", reject);
        if (options.timeout) {
          sock.setTimeout(options.timeout, () => {
            sock.destroy();
            reject(new ConnectionError("WebSocket connection timed out"));
          });
        }
      });
    }

    this.socket = transport;

    await this.performUpgrade(transport, parsed, options);

    this.state = "open";
    this.emit("open");

    transport.on("data", (chunk: Buffer) => {
      this.onData(chunk);
    });
    transport.on("error", (err: Error) => {
      this.state = "closed";
      this.emit("error", err);
    });
    transport.on("close", () => {
      if (this.state !== "closed") {
        this.state = "closed";
        this.emit("close", 1006, "Connection lost");
      }
    });

    this.drainBufferedFrames();
  }

  private performUpgrade(socket: Duplex, url: URL, options: WebSocketOptions): Promise<void> {
    return new Promise<void>((resolve, reject) => {
      const key = generateWebSocketKey();
      const path = (url.pathname || "/") + (url.search || "");

      let request = `GET ${path} HTTP/1.1\r\n`;
      request += `Host: ${url.host}\r\n`;
      request += `Upgrade: websocket\r\n`;
      request += `Connection: Upgrade\r\n`;
      request += `Sec-WebSocket-Key: ${key}\r\n`;
      request += `Sec-WebSocket-Version: 13\r\n`;

      const origin = url.protocol === "wss:" ? `https://${url.host}` : `http://${url.host}`;
      request += `Origin: ${origin}\r\n`;

      if (options.protocols && options.protocols.length > 0) {
        request += `Sec-WebSocket-Protocol: ${options.protocols.join(", ")}\r\n`;
      }

      if (options.compress) {
        request += `Sec-WebSocket-Extensions: ${buildDeflateOffer()}\r\n`;
      }

      if (options.headers) {
        for (const [k, v] of Object.entries(options.headers)) {
          if (/[\r\n\0]/.test(k) || /[\r\n\0]/.test(v)) {
            throw new NLcURLError(`WebSocket header "${k.substring(0, 40)}" contains forbidden characters`, "ERR_VALIDATION");
          }
          request += `${k}: ${v}\r\n`;
        }
      }

      request += `\r\n`;
      socket.write(request);

      let responseData = Buffer.alloc(0);
      const expectedAccept = computeAcceptKey(key);

      let upgradeTimer: ReturnType<typeof setTimeout> | undefined;
      if (options.timeout && options.timeout > 0) {
        upgradeTimer = setTimeout(() => {
          cleanup();
          reject(new NLcURLError("WebSocket upgrade timed out", "ERR_WS_TIMEOUT"));
        }, options.timeout);
      }

      const onData = (chunk: Buffer) => {
        responseData = Buffer.concat([responseData, chunk]);
        const text = responseData.toString("utf8");
        const headerEnd = text.indexOf("\r\n\r\n");
        if (headerEnd === -1) {
          if (responseData.length > 16384) {
            cleanup();
            reject(new NLcURLError("WebSocket upgrade response too large", "ERR_WS_UPGRADE"));
          }
          return;
        }

        cleanup();

        const headerStr = text.substring(0, headerEnd);
        const [statusLine, ...headerLines] = headerStr.split("\r\n");

        if (!statusLine) {
          reject(new NLcURLError("Empty upgrade response", "ERR_WS_UPGRADE"));
          return;
        }

        const statusMatch = statusLine.match(/^HTTP\/\d\.\d (\d{3})/);
        if (!statusMatch || statusMatch[1] !== "101") {
          reject(new NLcURLError(`WebSocket upgrade failed: ${statusLine}`, "ERR_WS_UPGRADE"));
          return;
        }

        const headers = new Map<string, string>();
        for (const line of headerLines) {
          const colonIdx = line.indexOf(":");
          if (colonIdx > 0) {
            headers.set(line.substring(0, colonIdx).trim().toLowerCase(), line.substring(colonIdx + 1).trim());
          }
        }

        const accept = headers.get("sec-websocket-accept");
        if (accept !== expectedAccept) {
          reject(new NLcURLError("Invalid Sec-WebSocket-Accept header", "ERR_WS_UPGRADE"));
          return;
        }

        this.protocol = headers.get("sec-websocket-protocol") ?? "";

        const extHeader = headers.get("sec-websocket-extensions");
        if (options.compress && extHeader) {
          const deflateParams = parseDeflateResponse(extHeader);
          if (deflateParams) {
            this.deflate = new PerMessageDeflate(deflateParams);
          }
        }

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
        if (upgradeTimer) clearTimeout(upgradeTimer);
        socket.removeListener("data", onData);
        socket.removeListener("error", onError);
      };

      socket.on("data", onData);
      socket.on("error", onError);
    });
  }

  private onData(chunk: Buffer): void {
    this.parser.push(chunk);
    this.drainBufferedFrames();
  }

  private drainBufferedFrames(): void {
    let frame: WebSocketFrame | null;
    while ((frame = this.parser.pull(this.deflate !== null)) !== null) {
      this.handleFrame(frame);
    }
  }

  private handleFrame(frame: WebSocketFrame): void {
    switch (frame.opcode) {
      case Opcode.TEXT:
      case Opcode.BINARY:
        if (frame.fin) {
          const isBinary = frame.opcode === Opcode.BINARY;
          if (frame.rsv1 && this.deflate) {
            this.deflate
              .decompress(frame.payload)
              .then((decompressed) => {
                if (isBinary) {
                  this.emit("message", decompressed, true);
                } else {
                  const text = decodeUtf8Strict(decompressed);
                  if (text === null) {
                    this.close(1007, "Invalid UTF-8");
                    return;
                  }
                  this.emit("message", text, false);
                }
              })
              .catch((err) => this.emit("error", err));
          } else {
            if (isBinary) {
              this.emit("message", frame.payload, true);
            } else {
              const text = decodeUtf8Strict(frame.payload);
              if (text === null) {
                this.close(1007, "Invalid UTF-8");
                return;
              }
              this.emit("message", text, false);
            }
          }
        } else {
          this.fragmentOpcode = frame.opcode;
          this.fragments = [frame.payload];
          this.fragmentSize = frame.payload.length;
        }
        break;

      case Opcode.CONTINUATION:
        this.fragmentSize += frame.payload.length;
        if (this.fragmentSize > WebSocketClient.MAX_FRAGMENT_SIZE) {
          this.close(1009, "Message too big");
          return;
        }
        this.fragments.push(frame.payload);
        if (frame.fin) {
          const assembled = Buffer.concat(this.fragments);
          this.fragments = [];
          this.fragmentSize = 0;
          const isBinary = this.fragmentOpcode === Opcode.BINARY;
          if (this.deflate) {
            this.deflate
              .decompress(assembled)
              .then((decompressed) => {
                if (isBinary) {
                  this.emit("message", decompressed, true);
                } else {
                  const text = decodeUtf8Strict(decompressed);
                  if (text === null) {
                    this.close(1007, "Invalid UTF-8");
                    return;
                  }
                  this.emit("message", text, false);
                }
              })
              .catch((err) => this.emit("error", err));
          } else {
            if (isBinary) {
              this.emit("message", assembled, true);
            } else {
              const text = decodeUtf8Strict(assembled);
              if (text === null) {
                this.close(1007, "Invalid UTF-8");
                return;
              }
              this.emit("message", text, false);
            }
          }
        }
        break;

      case Opcode.CLOSE: {
        let code = 1005;
        let reason = "";
        if (frame.payload.length >= 2) {
          code = frame.payload.readUInt16BE(0);
          reason = frame.payload.subarray(2).toString("utf8");
        }

        if (this.state === "open") {
          this.state = "closing";
          this.socket!.write(encodeFrame(Opcode.CLOSE, frame.payload));
        }

        this.state = "closed";
        this.socket?.destroy();
        this.deflate?.close();
        this.emit("close", code, reason);
        break;
      }

      case Opcode.PING:
        this.emit("ping", frame.payload);
        if (this.state === "open") {
          this.socket!.write(encodeFrame(Opcode.PONG, frame.payload));
        }
        break;

      case Opcode.PONG:
        this.emit("pong", frame.payload);
        break;
    }
  }
}
