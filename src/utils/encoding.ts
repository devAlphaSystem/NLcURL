/**
 * Content-Encoding decompression using only node:zlib.
 * Supports gzip, deflate, brotli, and zstd (Node 22+).
 */

import * as zlib from 'node:zlib';
import { promisify } from 'node:util';

const gunzipAsync = promisify(zlib.gunzip);
const inflateAsync = promisify(zlib.inflate);
const brotliDecompressAsync = promisify(zlib.brotliDecompress);

// zstd is natively supported in Node 22+ via node:zlib
const _zstdFn = (zlib as Record<string, unknown>)['zstdDecompress'];
const zstdDecompressAsync: ((buf: Buffer) => Promise<Buffer>) | null =
  typeof _zstdFn === 'function'
    ? (promisify(_zstdFn as Parameters<typeof promisify>[0]) as unknown as (buf: Buffer) => Promise<Buffer>)
    : null;

/** Whether this Node.js runtime can decompress zstd content. */
export const supportsZstd: boolean = zstdDecompressAsync !== null;

/**
 * Decompress a response body according to the Content-Encoding header.
 * Returns the original buffer if the encoding is not recognised or empty.
 */
export async function decompressBody(
  body: Buffer,
  contentEncoding: string | undefined
): Promise<Buffer> {
  if (!contentEncoding || body.length === 0) return body;

  const encoding = contentEncoding.trim().toLowerCase();

  switch (encoding) {
    case 'gzip':
    case 'x-gzip':
      return gunzipAsync(body) as Promise<Buffer>;

    case 'deflate':
      return inflateAsync(body) as Promise<Buffer>;

    case 'br':
      return brotliDecompressAsync(body) as Promise<Buffer>;

    case 'zstd':
      if (zstdDecompressAsync) {
        return zstdDecompressAsync(body);
      }
      // Node < 22: zstd not available natively, return raw bytes.
      return body;

    case 'identity':
      return body;

    default:
      // Unknown encoding -- return as-is rather than throwing.
      return body;
  }
}

/** Return the canonical Accept-Encoding value for browser impersonation. */
export function defaultAcceptEncoding(): string {
  return supportsZstd ? 'gzip, deflate, br, zstd' : 'gzip, deflate, br';
}

/**
 * Strip unsupported encodings (e.g. zstd on Node < 22) from an
 * accept-encoding header value so servers never send what we can't decode.
 */
export function sanitizeAcceptEncoding(value: string): string {
  if (supportsZstd) return value;
  return value
    .split(',')
    .map(s => s.trim())
    .filter(s => !s.startsWith('zstd'))
    .join(', ');
}
