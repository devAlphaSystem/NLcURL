import * as net from "node:net";
import { createCipheriv, createDecipheriv, type CipherGCMTypes } from "node:crypto";
import { Duplex } from "node:stream";
import type { ITLSEngine, TLSConnectOptions, TLSConnectionInfo, TLSSocket } from "../types.js";
import type { BrowserProfile } from "../../fingerprints/types.js";
import { TLSError } from "../../core/errors.js";
import { performHandshake, type HandshakeResult } from "./handshake.js";
import { wrapEncryptedRecord, unwrapEncryptedRecord, readRecord, writeRecord, type AEADAlgorithm, type TLSRecord } from "./record-layer.js";
import { RecordType, ProtocolVersion } from "../constants.js";
import { DEFAULT_PROFILE } from "../../fingerprints/database.js";
import { parseECHConfigList, extractFirstECHConfigRaw, type ECHEncryptionParams } from "../ech.js";

const AEAD_TAG_SIZE = 16;

class StealthTLSStream extends Duplex {
  private readonly rawSocket: net.Socket;
  private readonly aead: AEADAlgorithm;
  private readonly clientKey: Buffer;
  private readonly clientIV: Buffer;
  private readonly serverKey: Buffer;
  private readonly serverIV: Buffer;
  private readonly isTLS12: boolean;
  private clientSeq: bigint = 0n;
  private serverSeq: bigint = 0n;
  private readBuffer: Buffer = Buffer.alloc(0);
  private destroyed_ = false;

  readonly connectionInfo: TLSConnectionInfo;

  constructor(rawSocket: net.Socket, handshake: HandshakeResult) {
    super();
    this.rawSocket = rawSocket;
    this.aead = handshake.aead;
    this.clientKey = handshake.clientKey;
    this.clientIV = handshake.clientIV;
    this.serverKey = handshake.serverKey;
    this.serverIV = handshake.serverIV;
    this.isTLS12 = handshake.version === "TLSv1.2";

    this.connectionInfo = {
      version: handshake.version,
      alpnProtocol: handshake.alpnProtocol,
      cipher: handshake.cipher,
    };

    rawSocket.on("data", (chunk: Buffer) => {
      this.handleRawData(chunk);
    });
    rawSocket.on("error", (err) => this.destroy(err));
    rawSocket.once("close", () => {
      if (!this.destroyed_) this.push(null);
    });
  }

  override _read(): void {}

  override _write(chunk: Buffer, _encoding: BufferEncoding, callback: (error?: Error | null) => void): void {
    try {
      let encrypted: Buffer;
      if (this.isTLS12) {
        encrypted = this.tls12EncryptRecord(RecordType.APPLICATION_DATA, chunk);
      } else {
        encrypted = wrapEncryptedRecord(this.aead, this.clientKey, this.clientIV, this.clientSeq++, RecordType.APPLICATION_DATA, chunk);
      }
      this.rawSocket.write(encrypted, callback);
    } catch (err) {
      callback(err instanceof Error ? err : new Error(String(err)));
    }
  }

  override _destroy(err: Error | null, callback: (error: Error | null) => void): void {
    this.destroyed_ = true;
    this.rawSocket.destroy();
    callback(err);
  }

  destroyTLS(): void {
    this.destroy();
  }

  private tls12EncryptRecord(contentType: number, plaintext: Buffer): Buffer {
    const isChaCha = this.aead === "chacha20-poly1305";
    let nonce: Buffer;
    let prefix: Buffer;

    if (isChaCha) {
      nonce = Buffer.from(this.clientIV);
      const seqBuf = Buffer.alloc(8);
      seqBuf.writeBigUInt64BE(this.clientSeq);
      for (let i = 0; i < 8; i++) nonce[nonce.length - 8 + i]! ^= seqBuf[i]!;
      prefix = Buffer.alloc(0);
    } else {
      const explicitNonce = Buffer.alloc(8);
      explicitNonce.writeBigUInt64BE(this.clientSeq);
      nonce = Buffer.concat([this.clientIV, explicitNonce]);
      prefix = explicitNonce;
    }

    const aad = Buffer.alloc(13);
    aad.writeBigUInt64BE(this.clientSeq, 0);
    aad[8] = contentType;
    aad.writeUInt16BE(ProtocolVersion.TLS_1_2, 9);
    aad.writeUInt16BE(plaintext.length, 11);

    const cipher = createCipheriv(this.aead as CipherGCMTypes, this.clientKey, nonce, { authTagLength: AEAD_TAG_SIZE });
    cipher.setAAD(aad);
    const enc = cipher.update(plaintext);
    const final = cipher.final();
    const tag = cipher.getAuthTag();
    const payload = Buffer.concat([prefix, enc, final, tag]);

    this.clientSeq++;
    return writeRecord(contentType, ProtocolVersion.TLS_1_2, payload);
  }

  private tls12DecryptRecord(record: TLSRecord): Buffer {
    const isChaCha = this.aead === "chacha20-poly1305";
    let nonce: Buffer;
    let encData: Buffer;

    if (isChaCha) {
      nonce = Buffer.from(this.serverIV);
      const seqBuf = Buffer.alloc(8);
      seqBuf.writeBigUInt64BE(this.serverSeq);
      for (let i = 0; i < 8; i++) nonce[nonce.length - 8 + i]! ^= seqBuf[i]!;
      encData = record.fragment;
    } else {
      if (record.fragment.length < 8 + AEAD_TAG_SIZE) throw new TLSError("TLS 1.2 record too short");
      const explicitNonce = record.fragment.subarray(0, 8);
      nonce = Buffer.concat([this.serverIV, explicitNonce]);
      encData = record.fragment.subarray(8);
    }

    if (encData.length < AEAD_TAG_SIZE) throw new TLSError("TLS 1.2 record too short for tag");
    const encryptedData = encData.subarray(0, encData.length - AEAD_TAG_SIZE);
    const tag = encData.subarray(encData.length - AEAD_TAG_SIZE);

    const aad = Buffer.alloc(13);
    aad.writeBigUInt64BE(this.serverSeq, 0);
    aad[8] = record.type;
    aad.writeUInt16BE(ProtocolVersion.TLS_1_2, 9);
    aad.writeUInt16BE(encryptedData.length, 11);

    const decipher = createDecipheriv(this.aead as CipherGCMTypes, this.serverKey, nonce, { authTagLength: AEAD_TAG_SIZE });
    decipher.setAAD(aad);
    decipher.setAuthTag(tag);
    try {
      const decrypted = decipher.update(encryptedData);
      const final = decipher.final();
      this.serverSeq++;
      return Buffer.concat([decrypted, final]);
    } catch {
      throw new TLSError("TLS 1.2 AEAD decryption failed");
    }
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

      if (this.isTLS12) {
        this.processRecordTLS12(record);
      } else {
        this.processRecordTLS13(record);
      }
    }
  }

  private processRecordTLS12(record: TLSRecord): void {
    if (record.type === RecordType.APPLICATION_DATA) {
      try {
        const plaintext = this.tls12DecryptRecord(record);
        this.push(plaintext);
      } catch (err) {
        this.destroy(err instanceof Error ? err : new Error(String(err)));
      }
    } else if (record.type === RecordType.ALERT) {
      const desc = record.fragment.length >= 2 ? record.fragment[1] : 0;
      if (desc === 0) {
        this.push(null);
      } else {
        this.destroy(new TLSError(`TLS alert: desc=${desc}`, desc));
      }
    }
  }

  private processRecordTLS13(record: TLSRecord): void {
    if (record.type === RecordType.APPLICATION_DATA) {
      try {
        const decrypted = unwrapEncryptedRecord(this.aead, this.serverKey, this.serverIV, this.serverSeq++, record);

        if (decrypted.contentType === RecordType.APPLICATION_DATA) {
          this.push(decrypted.plaintext);
        } else if (decrypted.contentType === RecordType.ALERT) {
          const level = decrypted.plaintext[0];
          const desc = decrypted.plaintext[1];
          if (desc === 0) {
            this.push(null);
          } else {
            this.destroy(new TLSError(`TLS alert: level=${level} desc=${desc}`, desc));
          }
        }
      } catch (err) {
        this.destroy(err instanceof Error ? err : new Error(String(err)));
        return;
      }
    } else if (record.type === RecordType.ALERT) {
      const desc = record.fragment.length >= 2 ? record.fragment[1] : 0;
      if (desc === 0) {
        this.push(null);
      } else {
        this.destroy(new TLSError(`Unencrypted alert: desc=${desc}`, desc));
      }
    }
  }
}

/** TLS engine that performs a custom handshake for browser fingerprint impersonation. */
export class StealthTLSEngine implements ITLSEngine {
  /**
   * Connect to a remote host using the stealth TLS implementation.
   *
   * @param {TLSConnectOptions} options - TLS connection options.
   * @param {BrowserProfile} [profile] - Browser profile to impersonate (defaults to Chrome latest).
   * @returns {Promise<TLSSocket>} Connected TLS socket with fingerprint-accurate handshake.
   */
  async connect(options: TLSConnectOptions, profile?: BrowserProfile): Promise<TLSSocket> {
    const effectiveProfile = profile ?? DEFAULT_PROFILE;
    const hostname = options.servername ?? options.host;

    const rawSocket = options.socket ? options.socket : await tcpConnect(options.host, options.port, options.timeout, options.signal);

    try {
      let echParams: ECHEncryptionParams | undefined;
      if (options.echConfigList) {
        const parsed = parseECHConfigList(options.echConfigList);
        if (parsed && parsed.configs.length > 0) {
          const configRaw = extractFirstECHConfigRaw(options.echConfigList);
          if (configRaw) {
            echParams = { config: parsed.configs[0]!, configRaw };
          }
        }
      }

      const handshake = await performHandshake(rawSocket, effectiveProfile, hostname, options.insecure ?? false, options.pinnedPublicKey, echParams);

      const stream = new StealthTLSStream(rawSocket, handshake);

      return stream as unknown as TLSSocket;
    } catch (err) {
      rawSocket.destroy();
      throw err;
    }
  }
}

function tcpConnect(host: string, port: number, timeout?: number, signal?: AbortSignal): Promise<net.Socket> {
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
          reject(new TLSError("TCP connection timed out"));
        }
      }, timeoutMs);
    }

    if (signal) {
      const onAbort = () => {
        if (!settled) {
          settled = true;
          if (timer) clearTimeout(timer);
          socket.destroy();
          reject(new TLSError("Connection aborted"));
        }
      };
      if (signal.aborted) {
        socket.destroy();
        reject(new TLSError("Connection aborted"));
        return;
      }
      signal.addEventListener("abort", onAbort, { once: true });

      const cleanup = () => {
        signal.removeEventListener("abort", onAbort);
      };

      socket.once("connect", () => {
        if (!settled) {
          settled = true;
          if (timer) clearTimeout(timer);
          cleanup();
          resolve(socket);
        }
      });

      socket.once("error", (err) => {
        if (!settled) {
          settled = true;
          if (timer) clearTimeout(timer);
          cleanup();
          const e = err as NodeJS.ErrnoException & { reason?: string };
          const message = err.message || [e.code, e.reason].filter(Boolean).join(": ") || "TCP connection failed";
          reject(new TLSError(message));
        }
      });
    } else {
      socket.once("connect", () => {
        if (!settled) {
          settled = true;
          if (timer) clearTimeout(timer);
          resolve(socket);
        }
      });

      socket.once("error", (err) => {
        if (!settled) {
          settled = true;
          if (timer) clearTimeout(timer);
          const e = err as NodeJS.ErrnoException & { reason?: string };
          const message = err.message || [e.code, e.reason].filter(Boolean).join(": ") || "TCP connection failed";
          reject(new TLSError(message));
        }
      });
    }
  });
}
