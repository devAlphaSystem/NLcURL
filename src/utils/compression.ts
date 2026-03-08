import * as zlib from "node:zlib";
import { promisify } from "node:util";

const gzipAsync = promisify(zlib.gzip);
const deflateAsync = promisify(zlib.deflate);
const brotliCompressAsync = promisify(zlib.brotliCompress);

/** Supported request body compression encodings. */
export type RequestEncoding = "gzip" | "deflate" | "br";

/**
 * Compress a request body buffer with the specified encoding.
 *
 * @param {Buffer} body - Uncompressed body bytes.
 * @param {RequestEncoding} encoding - Compression algorithm.
 * @returns {Promise<Buffer>} Compressed buffer.
 */
export async function compressBody(body: Buffer, encoding: RequestEncoding): Promise<Buffer> {
  switch (encoding) {
    case "gzip":
      return gzipAsync(body) as Promise<Buffer>;
    case "deflate":
      return deflateAsync(body) as Promise<Buffer>;
    case "br":
      return brotliCompressAsync(body) as Promise<Buffer>;
    default:
      return body;
  }
}

/**
 * Determine whether a body is large enough to benefit from compression.
 *
 * @param {number} bodySize - Body size in bytes.
 * @returns {boolean} `true` if the body meets the minimum threshold.
 */
export function shouldCompress(bodySize: number): boolean {
  return bodySize >= 1024;
}
