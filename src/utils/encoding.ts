import * as zlib from "node:zlib";
import { promisify } from "node:util";
import { Transform, type Readable } from "node:stream";

const gunzipAsync = promisify(zlib.gunzip);
const inflateAsync = promisify(zlib.inflate);
const brotliDecompressAsync = promisify(zlib.brotliDecompress);

const _zstdFn = (zlib as Record<string, unknown>)["zstdDecompress"];
const zstdDecompressAsync: ((buf: Buffer) => Promise<Buffer>) | null = typeof _zstdFn === "function" ? (promisify(_zstdFn as Parameters<typeof promisify>[0]) as unknown as (buf: Buffer) => Promise<Buffer>) : null;

/**
 * `true` when the current Node.js runtime provides native Zstandard
 * decompression support (`zlib.zstdDecompress`). `false` on older Node.js
 * versions that lack the API.
 */
export const supportsZstd: boolean = zstdDecompressAsync !== null;

/**
 * Decompresses a response body buffer using the algorithm indicated by
 * `contentEncoding`. Supports `gzip`, `x-gzip`, `deflate`, `br` (Brotli),
 * `zstd` (when available), and `identity`. Unrecognized encodings are
 * returned as-is.
 *
 * @param {Buffer}            body            - Raw compressed body bytes.
 * @param {string | undefined} contentEncoding - Value of the `Content-Encoding` header.
 * @returns {Promise<Buffer>} Decompressed body bytes.
 */
export async function decompressBody(body: Buffer, contentEncoding: string | undefined): Promise<Buffer> {
  if (!contentEncoding || body.length === 0) return body;

  const encoding = contentEncoding.trim().toLowerCase();

  switch (encoding) {
    case "gzip":
    case "x-gzip":
      return gunzipAsync(body) as Promise<Buffer>;

    case "deflate":
      return inflateAsync(body) as Promise<Buffer>;

    case "br":
      return brotliDecompressAsync(body) as Promise<Buffer>;

    case "zstd":
      if (zstdDecompressAsync) {
        return zstdDecompressAsync(body);
      }
      return body;

    case "identity":
      return body;

    default:
      return body;
  }
}

/**
 * Creates a Node.js `Transform` stream that decompresses data on-the-fly
 * using the algorithm indicated by `contentEncoding`. Returns `null` when
 * no transform is needed (unknown or `identity` encoding).
 *
 * @param {string | undefined} contentEncoding - Value of the `Content-Encoding` header.
 * @returns {Transform | null} Decompressor stream, or `null` if no decompression is required.
 */
export function createDecompressStream(contentEncoding: string | undefined): Transform | null {
  if (!contentEncoding) return null;

  const encoding = contentEncoding.trim().toLowerCase();

  switch (encoding) {
    case "gzip":
    case "x-gzip":
      return zlib.createGunzip();

    case "deflate":
      return zlib.createInflate();

    case "br":
      return zlib.createBrotliDecompress();

    case "zstd": {
      const factory = (zlib as Record<string, unknown>)["createZstdDecompress"];
      if (typeof factory === "function") {
        return factory() as Transform;
      }
      return null;
    }

    case "identity":
      return null;

    default:
      return null;
  }
}

/**
 * Returns the default `Accept-Encoding` header value supported by this
 * Node.js runtime. Includes `zstd` when Zstandard is available.
 *
 * @returns {string} E.g. `"gzip, deflate, br, zstd"` or `"gzip, deflate, br"`.
 */
export function defaultAcceptEncoding(): string {
  return supportsZstd ? "gzip, deflate, br, zstd" : "gzip, deflate, br";
}

/**
 * Filters `zstd` from a caller-supplied `Accept-Encoding` value when the
 * current runtime does not support Zstandard decompression. Otherwise returns
 * the value unchanged.
 *
 * @param {string} value - Caller-supplied `Accept-Encoding` header value.
 * @returns {string} Sanitized encoding list compatible with the runtime.
 */
export function sanitizeAcceptEncoding(value: string): string {
  if (supportsZstd) return value;
  return value
    .split(",")
    .map((s) => s.trim())
    .filter((s) => !s.startsWith("zstd"))
    .join(", ");
}
