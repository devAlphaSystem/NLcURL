import * as zlib from "node:zlib";
import { promisify } from "node:util";
import { Transform } from "node:stream";

const gunzipAsync = promisify(zlib.gunzip);
const inflateAsync = promisify(zlib.inflate);
const brotliDecompressAsync = promisify(zlib.brotliDecompress);

const _zstdFn = (zlib as Record<string, unknown>)["zstdDecompress"];
const zstdDecompressAsync: ((buf: Buffer) => Promise<Buffer>) | null = typeof _zstdFn === "function" ? (promisify(_zstdFn) as unknown as (buf: Buffer) => Promise<Buffer>) : null;

/** Whether the current Node.js build supports zstd decompression. */
export const supportsZstd: boolean = zstdDecompressAsync !== null;

const MAX_CONTENT_ENCODING_LAYERS = 5;
/** D1: Maximum decompression ratio to prevent decompression bomb attacks. */
const MAX_DECOMPRESSION_RATIO = 100;
/** D1: Minimum compressed size before ratio check applies (avoids false positives on tiny payloads). */
const MIN_SIZE_FOR_RATIO_CHECK = 1024;

function parseEncodings(contentEncoding: string): string[] {
  const encodings = contentEncoding
    .split(",")
    .map((s) => s.trim().toLowerCase())
    .filter((s) => s.length > 0 && s !== "identity");

  if (encodings.length > MAX_CONTENT_ENCODING_LAYERS) {
    throw new Error(`Content-Encoding exceeds maximum layer count (${encodings.length} > ${MAX_CONTENT_ENCODING_LAYERS})`);
  }

  return encodings;
}

async function decompressSingle(body: Buffer, encoding: string): Promise<Buffer> {
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

    default:
      return body;
  }
}

/**
 * Decompress a response body according to `Content-Encoding` layers.
 *
 * @param {Buffer} body - Compressed body bytes.
 * @param {string | undefined} contentEncoding - Comma-separated encoding list.
 * @returns {Promise<Buffer>} Decompressed buffer.
 */
export async function decompressBody(body: Buffer, contentEncoding: string | undefined): Promise<Buffer> {
  if (!contentEncoding || body.length === 0) return body;

  const encodings = parseEncodings(contentEncoding);
  if (encodings.length === 0) return body;

  const originalSize = body.length;
  let result = body;
  for (let i = encodings.length - 1; i >= 0; i--) {
    result = await decompressSingle(result, encodings[i]!);
  }

  if (originalSize >= MIN_SIZE_FOR_RATIO_CHECK && result.length > originalSize * MAX_DECOMPRESSION_RATIO) {
    throw new Error(`Decompression bomb detected: ratio ${(result.length / originalSize).toFixed(1)}:1 exceeds limit of ${MAX_DECOMPRESSION_RATIO}:1`);
  }

  return result;
}

function createSingleDecompressStream(encoding: string): Transform | null {
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

    default:
      return null;
  }
}

/**
 * Create a streaming decompressor for the given `Content-Encoding`.
 *
 * @param {string | undefined} contentEncoding - Comma-separated encoding list.
 * @returns {Transform | null} Transform stream, or `null` if no decompression is needed.
 */
export function createDecompressStream(contentEncoding: string | undefined): Transform | null {
  if (!contentEncoding) return null;

  const encodings = parseEncodings(contentEncoding);
  if (encodings.length === 0) return null;

  if (encodings.length === 1) {
    return createSingleDecompressStream(encodings[0]!);
  }

  const decompressors: Transform[] = [];
  for (let i = encodings.length - 1; i >= 0; i--) {
    const d = createSingleDecompressStream(encodings[i]!);
    if (d) decompressors.push(d);
  }

  if (decompressors.length === 0) return null;
  if (decompressors.length === 1) return decompressors[0]!;

  for (let i = 0; i < decompressors.length - 1; i++) {
    decompressors[i]!.pipe(decompressors[i + 1]!);
  }

  const first = decompressors[0]!;
  const last = decompressors[decompressors.length - 1]!;

  const compound = new Transform({
    transform(chunk, _encoding, callback) {
      first.write(chunk, _encoding, callback);
    },
    flush(callback) {
      first.end();
      last.once("end", () => {
        callback();
      });
    },
  });

  last.on("data", (chunk: Buffer) => compound.push(chunk));
  last.on("error", (err: Error) => compound.destroy(err));

  return compound;
}

/** Return the default `Accept-Encoding` header value for this runtime. */
export function defaultAcceptEncoding(): string {
  return supportsZstd ? "gzip, deflate, br, zstd" : "gzip, deflate, br";
}

/**
 * Strip unsupported encodings (e.g. `zstd`) from an `Accept-Encoding` value.
 *
 * @param {string} value - Original `Accept-Encoding` header value.
 * @returns {string} Sanitized header value.
 */
export function sanitizeAcceptEncoding(value: string): string {
  if (supportsZstd) return value;
  return value
    .split(",")
    .map((s) => s.trim())
    .filter((s) => !s.startsWith("zstd"))
    .join(", ");
}
