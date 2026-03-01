/**
 * Stealth TLS engine.
 *
 * Implements ITLSEngine using raw TCP sockets and manual TLS 1.3
 * handshake construction.  This gives 100% control over the
 * ClientHello bytes, enabling perfect JA3 fingerprint matching.
 *
 * After the handshake completes, wraps the raw socket in a Duplex
 * stream that transparently encrypts/decrypts application data.
 */

import * as net from 'node:net';
import { Duplex } from 'node:stream';
import type { ITLSEngine, TLSConnectOptions, TLSConnectionInfo, TLSSocket } from '../types.js';
import type { BrowserProfile } from '../../fingerprints/types.js';
import { TLSError } from '../../core/errors.js';
import { performHandshake, type HandshakeResult } from './handshake.js';
import {
  wrapEncryptedRecord,
  unwrapEncryptedRecord,
  readRecord,
  type AEADAlgorithm,
  type TLSRecord,
} from './record-layer.js';
import { RecordType } from '../constants.js';
import { DEFAULT_PROFILE } from '../../fingerprints/database.js';

/**
 * A Duplex stream that wraps encrypted TLS 1.3 application data
 * over a raw TCP socket.
 */
class StealthTLSStream extends Duplex {
  private readonly rawSocket: net.Socket;
  private readonly aead: AEADAlgorithm;
  private readonly clientKey: Buffer;
  private readonly clientIV: Buffer;
  private readonly serverKey: Buffer;
  private readonly serverIV: Buffer;
  private clientSeq: bigint = 0n;
  private serverSeq: bigint = 0n;
  private readBuffer: Buffer = Buffer.alloc(0);
  private destroyed_ = false;

  readonly connectionInfo: TLSConnectionInfo;

  constructor(
    rawSocket: net.Socket,
    handshake: HandshakeResult,
  ) {
    super();
    this.rawSocket = rawSocket;
    this.aead = handshake.aead;
    this.clientKey = handshake.clientKey;
    this.clientIV = handshake.clientIV;
    this.serverKey = handshake.serverKey;
    this.serverIV = handshake.serverIV;

    this.connectionInfo = {
      version: handshake.version,
      alpnProtocol: handshake.alpnProtocol,
      cipher: handshake.cipher,
    };

    // Wire up raw socket events
    rawSocket.on('data', (chunk: Buffer) => this.handleRawData(chunk));
    rawSocket.on('error', (err) => this.destroy(err));
    rawSocket.once('close', () => {
      if (!this.destroyed_) this.push(null);
    });
  }

  override _read(): void {
    // Data is pushed from handleRawData; no action needed
  }

  override _write(
    chunk: Buffer,
    _encoding: BufferEncoding,
    callback: (error?: Error | null) => void,
  ): void {
    try {
      const encrypted = wrapEncryptedRecord(
        this.aead,
        this.clientKey,
        this.clientIV,
        this.clientSeq++,
        RecordType.APPLICATION_DATA,
        chunk,
      );
      this.rawSocket.write(encrypted, callback);
    } catch (err) {
      callback(err instanceof Error ? err : new Error(String(err)));
    }
  }

  override _destroy(
    err: Error | null,
    callback: (error: Error | null) => void,
  ): void {
    this.destroyed_ = true;
    this.rawSocket.destroy();
    callback(err);
  }

  destroyTLS(): void {
    this.destroy();
  }

  private handleRawData(chunk: Buffer): void {
    this.readBuffer = Buffer.concat([this.readBuffer, chunk]);
    this.processReadBuffer();
  }

  private processReadBuffer(): void {
    while (true) {
      const result = readRecord(this.readBuffer, 0);
      if (!result) break;

      this.readBuffer = this.readBuffer.subarray(result.bytesRead);
      const { record } = result;

      if (record.type === RecordType.APPLICATION_DATA) {
        try {
          const decrypted = unwrapEncryptedRecord(
            this.aead,
            this.serverKey,
            this.serverIV,
            this.serverSeq++,
            record,
          );

          if (decrypted.contentType === RecordType.APPLICATION_DATA) {
            this.push(decrypted.plaintext);
          } else if (decrypted.contentType === RecordType.ALERT) {
            const level = decrypted.plaintext[0];
            const desc = decrypted.plaintext[1];
            if (desc === 0) {
              // close_notify
              this.push(null);
            } else {
              this.destroy(
                new TLSError(`TLS alert: level=${level} desc=${desc}`, desc),
              );
            }
          }
          // Handshake messages (e.g. NewSessionTicket) are silently ignored
        } catch (err) {
          this.destroy(err instanceof Error ? err : new Error(String(err)));
          return;
        }
      } else if (record.type === RecordType.ALERT) {
        const desc = record.fragment.length >= 2 ? record.fragment[1] : 0;
        if (desc === 0) {
          this.push(null);
        } else {
          this.destroy(
            new TLSError(`Unencrypted alert: desc=${desc}`, desc),
          );
        }
      }
      // Ignore other record types
    }
  }
}

// ---- Engine ----

export class StealthTLSEngine implements ITLSEngine {
  async connect(
    options: TLSConnectOptions,
    profile?: BrowserProfile,
  ): Promise<TLSSocket> {
    const effectiveProfile = profile ?? DEFAULT_PROFILE;
    const hostname = options.servername ?? options.host;

    // Establish TCP connection (or use pre-connected socket)
    const rawSocket = options.socket
      ? (options.socket as net.Socket)
      : await tcpConnect(options.host, options.port, options.timeout, options.signal);

    try {
      // Perform TLS 1.3 handshake
      const handshake = await performHandshake(
        rawSocket,
        effectiveProfile,
        hostname,
        options.insecure ?? false,
      );

      // Wrap in Duplex stream
      const stream = new StealthTLSStream(rawSocket, handshake);

      return stream as unknown as TLSSocket;
    } catch (err) {
      rawSocket.destroy();
      throw err;
    }
  }
}

// ---- TCP connection helper ----

function tcpConnect(
  host: string,
  port: number,
  timeout?: number,
  signal?: AbortSignal,
): Promise<net.Socket> {
  return new Promise((resolve, reject) => {
    let settled = false;
    const socket = net.createConnection({ host, port });

    const timeoutMs = timeout ?? 30_000;
    let timer: ReturnType<typeof setTimeout> | undefined;

    if (timeoutMs > 0) {
      timer = setTimeout(() => {
        if (!settled) {
          settled = true;
          socket.destroy();
          reject(new TLSError('TCP connection timed out'));
        }
      }, timeoutMs);
    }

    if (signal) {
      const onAbort = () => {
        if (!settled) {
          settled = true;
          if (timer) clearTimeout(timer);
          socket.destroy();
          reject(new TLSError('Connection aborted'));
        }
      };
      if (signal.aborted) {
        socket.destroy();
        reject(new TLSError('Connection aborted'));
        return;
      }
      signal.addEventListener('abort', onAbort, { once: true });
    }

    socket.once('connect', () => {
      if (!settled) {
        settled = true;
        if (timer) clearTimeout(timer);
        resolve(socket);
      }
    });

    socket.once('error', (err) => {
      if (!settled) {
        settled = true;
        if (timer) clearTimeout(timer);
        reject(new TLSError(err.message));
      }
    });
  });
}
