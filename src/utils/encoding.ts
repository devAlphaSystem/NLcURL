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
 * Maximum number of Content-Encoding layers permitted. Prevents
 * decompression bomb attacks that nest many encoding layers to cause
 * exponential memory/CPU usage. Matches undici's limit.
 */
const MAX_CONTENT_ENCODING_LAYERS = 5;

/**
 * Parses a Content-Encoding header value into individual encoding tokens,
 * filters out `identity`, and validates the layer count.
 */
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

/**
 * Decompresses a single buffer using the specified encoding algorithm.
 */
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
 * Decompresses a response body buffer handling potentially multiple
 * Content-Encoding layers (e.g. `"gzip, br"`). Layers are applied in
 * reverse order per RFC 9110 §8.4. Throws if the number of layers
 * exceeds {@link MAX_CONTENT_ENCODING_LAYERS}.
 *
 * @param {Buffer}            body            - Raw compressed body bytes.
 * @param {string | undefined} contentEncoding - Value of the `Content-Encoding` header.
 * @returns {Promise<Buffer>} Decompressed body bytes.
 */
export async function decompressBody(body: Buffer, contentEncoding: string | undefined): Promise<Buffer> {
  if (!contentEncoding || body.length === 0) return body;

  const encodings = parseEncodings(contentEncoding);
  if (encodings.length === 0) return body;

  let result = body;
  for (let i = encodings.length - 1; i >= 0; i--) {
    result = await decompressSingle(result, encodings[i]!);
  }
  return result;
}

/**
 * Creates a decompressor Transform for a single encoding algorithm.
 */
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
 * Creates a Node.js `Transform` stream that decompresses data on-the-fly
 * using the algorithm(s) indicated by `contentEncoding`. Supports multiple
 * comma-separated encodings (e.g. `"gzip, br"`). Returns `null` when no
 * transform is needed. Throws if the number of encoding layers exceeds
 * {@link MAX_CONTENT_ENCODING_LAYERS}.
 *
 * @param {string | undefined} contentEncoding - Value of the `Content-Encoding` header.
 * @returns {Transform | null} Decompressor stream, or `null` if no decompression is required.
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
      last.once("end", () => callback());
    },
  });

  last.on("data", (chunk: Buffer) => compound.push(chunk));
  last.on("error", (err: Error) => compound.destroy(err));

  return compound;
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
