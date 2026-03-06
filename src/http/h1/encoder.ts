import type { NLcURLRequest, RequestBody } from "../../core/request.js";

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
      if (request.body !== null && request.body !== undefined && typeof request.body === "object" && !Buffer.isBuffer(request.body) && !(request.body instanceof URLSearchParams) && !(request.body instanceof ReadableStream)) {
        headerMap.set("content-type", "application/json");
      } else if (request.body instanceof URLSearchParams) {
        headerMap.set("content-type", "application/x-www-form-urlencoded");
      } else if (typeof request.body === "string") {
        headerMap.set("content-type", "text/plain; charset=utf-8");
      }
    }
  }

  for (const [k, v] of headerMap) {
    if (/[\r\n\0]/.test(k) || /[\r\n\0]/.test(v)) {
      throw new Error(`Invalid header: name or value contains forbidden characters`);
    }
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
  if (typeof body === "object" && !(body instanceof ReadableStream)) {
    return Buffer.from(JSON.stringify(body), "utf-8");
  }
  return Buffer.alloc(0);
}
