import type { NLcURLRequest, RequestBody } from "../../core/request.js";
import { FormData } from "../form-data.js";
import { validateHeaderName, validateHeaderValue } from "../../core/validation.js";

/**
 * Serializes an HTTP/1.1 request into a `Buffer` ready to be written to a
 * socket. Merges `defaultHeaders` (lowest priority) with `request.headers`
 * (highest priority), computes `Content-Length` when a body is present,
 * and validates header names and values for forbidden characters.
 *
 * @param {NLcURLRequest}          request        - The request to encode.
 * @param {Array<[string,string]>} defaultHeaders - Profile-level default headers.
 * @returns {Buffer} Encoded HTTP/1.1 request bytes including headers and body.
 * @throws {Error} If any header name or value contains CR, LF, or NUL characters.
 */
export function encodeRequest(request: NLcURLRequest, defaultHeaders: Array<[string, string]>): Buffer {
  const url = new URL(request.url);
  const path = url.pathname + url.search;
  const host = url.port ? `${url.hostname}:${url.port}` : url.hostname;

  const lines: string[] = [];
  lines.push(`${request.method} ${path} HTTP/1.1`);

  const headerMap = new Map<string, string>();

  for (const [k, v] of defaultHeaders) {
    headerMap.set(k.toLowerCase(), v);
  }

  if (!headerMap.has("host")) {
    headerMap.set("host", host);
  }

  if (request.headers) {
    for (const [k, v] of Object.entries(request.headers)) {
      headerMap.set(k.toLowerCase(), v);
    }
  }

  let bodyBuffer: Buffer | undefined;
  if (request.body !== undefined && request.body !== null) {
    bodyBuffer = serializeBody(request.body);
    if (!headerMap.has("content-length")) {
      headerMap.set("content-length", String(bodyBuffer.length));
    }
    if (!headerMap.has("content-type")) {
      if (request.body instanceof FormData) {
        headerMap.set("content-type", request.body.contentType);
      } else if (request.body !== null && request.body !== undefined && typeof request.body === "object" && !Buffer.isBuffer(request.body) && !(request.body instanceof URLSearchParams) && !(request.body instanceof ReadableStream)) {
        headerMap.set("content-type", "application/json");
      } else if (request.body instanceof URLSearchParams) {
        headerMap.set("content-type", "application/x-www-form-urlencoded");
      } else if (typeof request.body === "string") {
        headerMap.set("content-type", "text/plain; charset=utf-8");
      }
    }
  }

  for (const [k, v] of headerMap) {
    validateHeaderName(k);
    validateHeaderValue(k, v);
    lines.push(`${k}: ${v}`);
  }

  lines.push("");
  lines.push("");

  const head = Buffer.from(lines.join("\r\n"), "latin1");
  if (bodyBuffer) {
    return Buffer.concat([head, bodyBuffer]);
  }
  return head;
}

function serializeBody(body: RequestBody): Buffer {
  if (body === null || body === undefined) return Buffer.alloc(0);
  if (Buffer.isBuffer(body)) return body;
  if (typeof body === "string") return Buffer.from(body, "utf-8");
  if (body instanceof URLSearchParams) {
    return Buffer.from(body.toString(), "utf-8");
  }
  if (body instanceof FormData) {
    return body.encode();
  }
  if (body instanceof ReadableStream) {
    throw new Error("ReadableStream body must be pre-drained before encoding. Use drainRequestBody() first.");
  }
  if (typeof body === "object") {
    return Buffer.from(JSON.stringify(body), "utf-8");
  }
  return Buffer.alloc(0);
}

/**
 * Reads all bytes from a `ReadableStream<Uint8Array>` and returns a single `Buffer`.
 *
 * @param {ReadableStream<Uint8Array>} stream - The readable stream to drain.
 * @returns {Promise<Buffer>} A buffer containing all bytes from the stream.
 */
export async function drainReadableStream(stream: ReadableStream<Uint8Array>): Promise<Buffer> {
  const reader = stream.getReader();
  const chunks: Uint8Array[] = [];
  try {
    while (true) {
      const { done, value } = await reader.read();
      if (done) break;
      chunks.push(value);
    }
  } finally {
    reader.releaseLock();
  }
  return Buffer.concat(chunks);
}

/**
 * If the request body is a `ReadableStream`, drains it into a `Buffer` and
 * returns a new request with the buffered body. Otherwise returns the request
 * unchanged. This must be called before passing the request to
 * `encodeRequest()` for HTTP/1.1 requests.
 *
 * @param {NLcURLRequest} request - The request to pre-process.
 * @returns {Promise<NLcURLRequest>} Request with body fully buffered (if needed).
 */
export async function drainRequestBody(request: NLcURLRequest): Promise<NLcURLRequest> {
  if (request.body instanceof ReadableStream) {
    const buffered = await drainReadableStream(request.body);
    return { ...request, body: buffered };
  }
  return request;
}
