import type { NLcURLRequest, RequestBody } from "../../core/request.js";
import type { Duplex } from "node:stream";
import { FormData } from "../form-data.js";
import { validateHeaderName, validateHeaderValue } from "../../core/validation.js";

/**
 * Encode an HTTP/1.1 request into a wire-format buffer.
 *
 * @param {NLcURLRequest} request - Request to encode.
 * @param {Array<[string, string]>} defaultHeaders - Default headers to merge.
 * @returns {Buffer} Wire-format request buffer.
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
  let isStreamBody = false;
  if (request.body !== undefined && request.body !== null) {
    if (request.body instanceof ReadableStream) {
      isStreamBody = true;
      if (!headerMap.has("transfer-encoding")) {
        headerMap.set("transfer-encoding", "chunked");
      }
    } else {
      bodyBuffer = serializeBody(request.body);
      if (headerMap.has("content-length")) {
        const declaredLength = parseInt(headerMap.get("content-length")!, 10);
        if (!Number.isNaN(declaredLength) && declaredLength !== bodyBuffer.length) {
          throw new Error(`Content-Length mismatch: header declares ${declaredLength} bytes but body is ${bodyBuffer.length} bytes`);
        }
      } else {
        headerMap.set("content-length", String(bodyBuffer.length));
      }
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

/**
 * Write a streaming request body using chunked transfer-encoding.
 * The request headers (including Transfer-Encoding: chunked) must already
 * be written to the socket via `encodeRequest()`.
 *
 * @param {Duplex} socket - The transport socket.
 * @param {ReadableStream<Uint8Array>} body - Streaming body.
 * @returns {Promise<void>} Resolves when body is fully sent.
 */
export async function writeChunkedBody(socket: Duplex, body: ReadableStream<Uint8Array>): Promise<void> {
  const reader = body.getReader();
  try {
    while (true) {
      const { done, value } = await reader.read();
      if (done) break;
      const chunk = Buffer.from(value);
      const sizeHex = chunk.length.toString(16);
      await new Promise<void>((resolve, reject) => {
        socket.write(`${sizeHex}\r\n`, (err) => {
          if (err) return reject(err);
          socket.write(chunk, (err2) => {
            if (err2) return reject(err2);
            socket.write("\r\n", (err3) => {
              if (err3) return reject(err3);
              resolve();
            });
          });
        });
      });
    }
    await new Promise<void>((resolve, reject) => {
      socket.write("0\r\n\r\n", (err) => {
        if (err) reject(err);
        else resolve();
      });
    });
  } catch (err) {
    reader.releaseLock();
    throw err;
  } finally {
    reader.releaseLock();
  }
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
 * Drain a ReadableStream into a single buffer.
 *
 * @param {ReadableStream<Uint8Array>} stream - Web ReadableStream.
 * @returns {Promise<Buffer>} Concatenated buffer of all chunks.
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
 * Drain a request's streaming body into a buffered request.
 *
 * @param {NLcURLRequest} request - Request with a possible streaming body.
 * @returns {Promise<NLcURLRequest>} Request with the body fully buffered.
 */
export async function drainRequestBody(request: NLcURLRequest): Promise<NLcURLRequest> {
  if (request.body instanceof ReadableStream) {
    const buffered = await drainReadableStream(request.body);
    return { ...request, body: buffered };
  }
  return request;
}
