import * as zlib from "node:zlib";

const DEFLATE_TAIL = Buffer.from([0x00, 0x00, 0xff, 0xff]);

/** Negotiated per-message deflate parameters. */
export interface DeflateParams {
  /** Server will not reuse its LZ77 sliding window between messages. */
  serverNoContextTakeover: boolean;
  /** Client will not reuse its LZ77 sliding window between messages. */
  clientNoContextTakeover: boolean;
  /** Maximum window bits for the server's decompressor. */
  serverMaxWindowBits: number;
  /** Maximum window bits for the client's compressor. */
  clientMaxWindowBits: number;
}

const DEFAULT_PARAMS: DeflateParams = {
  serverNoContextTakeover: false,
  clientNoContextTakeover: false,
  serverMaxWindowBits: 15,
  clientMaxWindowBits: 15,
};

/**
 * Build a `Sec-WebSocket-Extensions` offer string for per-message deflate.
 *
 * @returns {string} Extension offer suitable for the upgrade request.
 */
export function buildDeflateOffer(): string {
  return "permessage-deflate; client_max_window_bits";
}

/**
 * Parse the server's `Sec-WebSocket-Extensions` response for deflate params.
 *
 * @param {string} header - Raw extension header value from the server.
 * @returns {DeflateParams | null} Negotiated deflate parameters, or `null` if not accepted.
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

/** Stateful per-message deflate compressor and decompressor (RFC 7692). */
export class PerMessageDeflate {
  private readonly params: DeflateParams;
  private inflateContext: zlib.Inflate | null = null;
  private deflateContext: zlib.Deflate | null = null;

  /**
   * Create a per-message deflate handler.
   *
   * @param {DeflateParams} params - Negotiated deflate parameters.
   */
  constructor(params: DeflateParams) {
    this.params = params;
  }

  /**
   * Decompress a compressed WebSocket payload.
   *
   * @param {Buffer} data - Compressed frame payload.
   * @returns {Promise<Buffer>} Decompressed data.
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
   * Compress a WebSocket payload before framing.
   *
   * @param {Buffer} data - Uncompressed payload.
   * @returns {Promise<Buffer>} Compressed data with the deflate tail stripped.
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

  /** Release inflate and deflate contexts and free associated memory. */
  close(): void {
    this.inflateContext?.close();
    this.deflateContext?.close();
    this.inflateContext = null;
    this.deflateContext = null;
  }
}
