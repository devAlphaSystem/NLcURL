/**
 * HTTP/1.1 client.
 *
 * Sends requests and receives responses over a TLS (or plain TCP)
 * Duplex stream.  Supports connection reuse (keep-alive).
 */

import type { Duplex } from 'node:stream';
import type { NLcURLRequest } from '../../core/request.js';
import { NLcURLResponse } from '../../core/response.js';
import { HTTPError, TimeoutError } from '../../core/errors.js';
import { encodeRequest } from './encoder.js';
import { HttpResponseParser, type ParsedResponse } from './parser.js';
import { decompressBody } from '../../utils/encoding.js';
import type { RequestTimings } from '../../core/request.js';

export interface H1ClientOptions {
  /** Default headers to merge with each request. */
  defaultHeaders?: Array<[string, string]>;
}

/**
 * Send a single HTTP/1.1 request over an already-connected stream.
 *
 * Returns a fully parsed NLcURLResponse.
 */
export async function sendH1Request(
  stream: Duplex,
  request: NLcURLRequest,
  options: H1ClientOptions = {},
  timings: Partial<RequestTimings> = {},
): Promise<NLcURLResponse> {
  const encoded = encodeRequest(request, options.defaultHeaders ?? []);

  // Write request
  await new Promise<void>((resolve, reject) => {
    stream.write(encoded, (err) => {
      if (err) reject(new HTTPError(err.message, 0));
      else resolve();
    });
  });

  // Read response
  const parser = new HttpResponseParser(request.method ?? 'GET');
  const parsed = await readResponse(stream, parser, request);

  const firstByteTime = Date.now();
  if (timings.connect) {
    timings.firstByte = firstByteTime - timings.connect;
  }

  // Decompress body
  const encoding = parsed.headers.get('content-encoding');
  let body: Buffer;
  if (encoding) {
    body = await decompressBody(parsed.body, encoding);
  } else {
    body = parsed.body;
  }

  // Build response headers
  const responseHeaders: Record<string, string> = {};
  for (const [k, v] of parsed.headers) {
    responseHeaders[k] = v;
  }

  return new NLcURLResponse({
    status: parsed.statusCode,
    statusText: parsed.statusMessage,
    headers: responseHeaders,
    rawHeaders: parsed.rawHeaders.map(([k, v]) => [k.toLowerCase(), v] as [string, string]),
    rawBody: body,
    httpVersion: parsed.httpVersion,
    url: request.url,
    redirectCount: 0,
    timings: {
      dns: timings.dns ?? 0,
      connect: timings.connect ?? 0,
      tls: timings.tls ?? 0,
      firstByte: timings.firstByte ?? 0,
      total: 0, // Filled after return
    },
    request: {
      url: request.url,
      method: request.method ?? 'GET',
      headers: request.headers ?? {},
    },
  });
}

// ---- Internals ----

function readResponse(
  stream: Duplex,
  parser: HttpResponseParser,
  request: NLcURLRequest,
): Promise<ParsedResponse> {
  return new Promise<ParsedResponse>((resolve, reject) => {
    let settled = false;
    let timer: ReturnType<typeof setTimeout> | undefined;

    const timeout = request.timeout;
    const timeoutMs = typeof timeout === 'number' ? timeout : (timeout?.total ?? timeout?.response ?? 0);
    if (timeoutMs > 0) {
      timer = setTimeout(() => {
        if (!settled) {
          settled = true;
          cleanup();
          reject(new TimeoutError('Response timed out', 'response'));
        }
      }, timeoutMs);
    }

    const onData = (chunk: Buffer) => {
      try {
        if (parser.feed(chunk)) {
          settled = true;
          cleanup();
          resolve(parser.getResult());
        }
      } catch (err) {
        settled = true;
        cleanup();
        reject(err);
      }
    };

    const onEnd = () => {
      if (!settled) {
        parser.connectionClosed();
        try {
          settled = true;
          cleanup();
          resolve(parser.getResult());
        } catch {
          settled = true;
          cleanup();
          reject(new HTTPError('Connection closed before response complete', 0));
        }
      }
    };

    const onError = (err: Error) => {
      if (!settled) {
        settled = true;
        cleanup();
        reject(new HTTPError(err.message, 0));
      }
    };

    const cleanup = () => {
      if (timer) clearTimeout(timer);
      stream.removeListener('data', onData);
      stream.removeListener('end', onEnd);
      stream.removeListener('error', onError);
    };

    stream.on('data', onData);
    stream.once('end', onEnd);
    stream.once('error', onError);
  });
}
