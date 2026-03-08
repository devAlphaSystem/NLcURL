/**
 * WebSocket `permessage-deflate` extension (RFC 7692).
 *
 * Provides per-message DEFLATE compression for WebSocket frames. Negotiated
 * during the HTTP Upgrade handshake via the `Sec-WebSocket-Extensions` header.
 */
import * as zlib from "node:zlib";

/** The 4-byte DEFLATE flush trailer appended by RFC 7692 §7.2.1. */
const DEFLATE_TAIL = Buffer.from([0x00, 0x00, 0xff, 0xff]);

/**
 * Negotiated permessage-deflate parameters.
 *
 * @typedef  {Object}  DeflateParams
 * @property {boolean} serverNoContextTakeover - Server resets deflate context per-message.
 * @property {boolean} clientNoContextTakeover - Client resets deflate context per-message.
 * @property {number}  serverMaxWindowBits     - Server max window bits (8–15).
 * @property {number}  clientMaxWindowBits     - Client max window bits (8–15).
 */
export interface DeflateParams {
  serverNoContextTakeover: boolean;
  clientNoContextTakeover: boolean;
  serverMaxWindowBits: number;
  clientMaxWindowBits: number;
}

const DEFAULT_PARAMS: DeflateParams = {
  serverNoContextTakeover: false,
  clientNoContextTakeover: false,
  serverMaxWindowBits: 15,
  clientMaxWindowBits: 15,
};

/**
 * Builds the `Sec-WebSocket-Extensions` header value for the client offer.
 *
 * @returns {string} Extension offer string.
 */
export function buildDeflateOffer(): string {
  return "permessage-deflate; client_max_window_bits";
}

/**
 * Parses the server's `Sec-WebSocket-Extensions` response header to extract
 * the negotiated `permessage-deflate` parameters. Returns `null` when the
 * extension was not accepted by the server.
 *
 * @param {string} header - The `Sec-WebSocket-Extensions` response header value.
 * @returns {DeflateParams | null} Negotiated parameters, or `null`.
 */
export function parseDeflateResponse(header: string): DeflateParams | null {
  const extensions = header.split(",").map((s) => s.trim());
  for (const ext of extensions) {
    const parts = ext.split(";").map((s) => s.trim());
    if (parts[0] !== "permessage-deflate") continue;

    const params: DeflateParams = { ...DEFAULT_PARAMS };

    for (let i = 1; i < parts.length; i++) {
      const part = parts[i]!;
      const [key, val] = part.split("=").map((s) => s.trim());
      switch (key) {
        case "server_no_context_takeover":
          params.serverNoContextTakeover = true;
          break;
        case "client_no_context_takeover":
          params.clientNoContextTakeover = true;
          break;
        case "server_max_window_bits":
          if (val) params.serverMaxWindowBits = parseInt(val, 10);
          break;
        case "client_max_window_bits":
          if (val) params.clientMaxWindowBits = parseInt(val, 10);
          break;
      }
    }

    return params;
  }
  return null;
}

/**
 * Manages per-message DEFLATE compression and decompression for a single
 * WebSocket connection. Maintains stateful zlib contexts unless
 * `no_context_takeover` was negotiated.
 */
export class PerMessageDeflate {
  private readonly params: DeflateParams;
  private inflateContext: zlib.Inflate | null = null;
  private deflateContext: zlib.Deflate | null = null;

  constructor(params: DeflateParams) {
    this.params = params;
  }

  /**
   * Decompresses a received message payload.
   *
   * @param {Buffer} data - Compressed payload (without the DEFLATE flush tail).
   * @returns {Promise<Buffer>} Decompressed message data.
   */
  decompress(data: Buffer): Promise<Buffer> {
    return new Promise<Buffer>((resolve, reject) => {
      const input = Buffer.concat([data, DEFLATE_TAIL]);

      if (!this.inflateContext || this.params.serverNoContextTakeover) {
        this.inflateContext?.close();
        this.inflateContext = zlib.createInflateRaw({
          windowBits: this.params.serverMaxWindowBits,
        });
      }

      const chunks: Buffer[] = [];
      const inflate = this.inflateContext;

      inflate.on("data", (chunk: Buffer) => chunks.push(chunk));
      inflate.once("error", (err) => {
        inflate.removeAllListeners();
        reject(err);
      });

      inflate.write(input, () => {
        inflate.flush(() => {
          inflate.removeAllListeners("data");
          inflate.removeAllListeners("error");
          resolve(Buffer.concat(chunks));
        });
      });
    });
  }

  /**
   * Compresses a message payload for sending.
   *
   * @param {Buffer} data - Uncompressed message payload.
   * @returns {Promise<Buffer>} Compressed data (with DEFLATE flush tail stripped).
   */
  compress(data: Buffer): Promise<Buffer> {
    return new Promise<Buffer>((resolve, reject) => {
      if (!this.deflateContext || this.params.clientNoContextTakeover) {
        this.deflateContext?.close();
        this.deflateContext = zlib.createDeflateRaw({
          windowBits: this.params.clientMaxWindowBits,
        });
      }

      const chunks: Buffer[] = [];
      const deflate = this.deflateContext;

      deflate.on("data", (chunk: Buffer) => chunks.push(chunk));
      deflate.once("error", (err) => {
        deflate.removeAllListeners();
        reject(err);
      });

      deflate.write(data, () => {
        deflate.flush(zlib.constants.Z_SYNC_FLUSH, () => {
          deflate.removeAllListeners("data");
          deflate.removeAllListeners("error");
          let result = Buffer.concat(chunks);
          if (result.length >= 4 && result.subarray(result.length - 4).equals(DEFLATE_TAIL)) {
            result = result.subarray(0, result.length - 4);
          }
          resolve(result);
        });
      });
    });
  }

  /** Releases zlib resources. */
  close(): void {
    this.inflateContext?.close();
    this.deflateContext?.close();
    this.inflateContext = null;
    this.deflateContext = null;
  }
}
