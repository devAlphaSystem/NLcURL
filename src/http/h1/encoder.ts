/**
 * HTTP/1.1 request encoder.
 *
 * Serializes NLcURLRequest objects into raw HTTP/1.1 wire format.
 */

import type { NLcURLRequest, RequestBody } from '../../core/request.js';

/**
 * Encode an HTTP/1.1 request to a Buffer ready to write to a socket.
 */
export function encodeRequest(
  request: NLcURLRequest,
  defaultHeaders: Array<[string, string]>,
): Buffer {
  const url = new URL(request.url);
  const path = url.pathname + url.search;
  const host = url.port
    ? `${url.hostname}:${url.port}`
    : url.hostname;

  const lines: string[] = [];
  lines.push(`${request.method} ${path} HTTP/1.1`);

  // Collect headers -- merge defaults under request headers
  const headerMap = new Map<string, string>();

  // Apply default headers first (lowercase keys)
  for (const [k, v] of defaultHeaders) {
    headerMap.set(k.toLowerCase(), v);
  }

  // Host header
  if (!headerMap.has('host')) {
    headerMap.set('host', host);
  }

  // Apply request headers (override defaults)
  if (request.headers) {
    for (const [k, v] of Object.entries(request.headers)) {
      headerMap.set(k.toLowerCase(), v);
    }
  }

  // Body handling
  let bodyBuffer: Buffer | undefined;
  if (request.body !== undefined && request.body !== null) {
    bodyBuffer = serializeBody(request.body);
    if (!headerMap.has('content-length')) {
      headerMap.set('content-length', String(bodyBuffer.length));
    }
    if (!headerMap.has('content-type')) {
      headerMap.set('content-type', 'application/x-www-form-urlencoded');
    }
  }

  // Emit headers (validate against CRLF injection)
  for (const [k, v] of headerMap) {
    if (/[\r\n\0]/.test(k) || /[\r\n\0]/.test(v)) {
      throw new Error(`Invalid header: name or value contains forbidden characters`);
    }
    lines.push(`${k}: ${v}`);
  }

  lines.push('');
  lines.push('');

  const head = Buffer.from(lines.join('\r\n'), 'latin1');
  if (bodyBuffer) {
    return Buffer.concat([head, bodyBuffer]);
  }
  return head;
}

function serializeBody(body: RequestBody): Buffer {
  if (body === null || body === undefined) return Buffer.alloc(0);
  if (Buffer.isBuffer(body)) return body;
  if (typeof body === 'string') return Buffer.from(body, 'utf-8');
  if (body instanceof URLSearchParams) {
    return Buffer.from(body.toString(), 'utf-8');
  }
  if (typeof body === 'object' && !(body instanceof ReadableStream)) {
    return Buffer.from(JSON.stringify(body), 'utf-8');
  }
  // ReadableStream: not supported in synchronous encoding
  return Buffer.alloc(0);
}
