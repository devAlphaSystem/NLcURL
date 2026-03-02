
import type { Duplex } from 'node:stream';
import { PassThrough } from 'node:stream';
import type { NLcURLRequest } from '../../core/request.js';
import { NLcURLResponse } from '../../core/response.js';
import { HTTPError, TimeoutError } from '../../core/errors.js';
import { encodeRequest } from './encoder.js';
import { HttpResponseParser, type ParsedResponse } from './parser.js';
import { decompressBody, createDecompressStream } from '../../utils/encoding.js';
import type { RequestTimings } from '../../core/request.js';

/**
 * Options shared across all HTTP/1.1 client functions.
 *
 * @typedef  {Object}              H1ClientOptions
 * @property {Array<[string,string]>} [defaultHeaders] - Profile-level headers prepended before request-specific headers.
 */
export interface H1ClientOptions {
  defaultHeaders?: Array<[string, string]>;
}

/**
 * Sends an HTTP/1.1 request over the given duplex stream and returns the
 * fully buffered response. Blocks until all response body bytes are received.
 *
 * @param {Duplex}              stream  - Connected transport stream.
 * @param {NLcURLRequest}       request - Request descriptor.
 * @param {H1ClientOptions}     [options={}] - Client options.
 * @param {Partial<RequestTimings>} [timings={}] - Partial timings object to populate with `firstByte`.
 * @returns {Promise<NLcURLResponse>} Resolves with the fully received and decompressed response.
 * @throws {HTTPError}   If the connection is closed before the response completes.
 * @throws {TimeoutError} If the response timeout is exceeded.
 */
export async function sendH1Request(
  stream: Duplex,
  request: NLcURLRequest,
  options: H1ClientOptions = {},
  timings: Partial<RequestTimings> = {},
): Promise<NLcURLResponse> {
  const encoded = encodeRequest(request, options.defaultHeaders ?? []);

  await new Promise<void>((resolve, reject) => {
    stream.write(encoded, (err) => {
      if (err) reject(new HTTPError(err.message, 0));
      else resolve();
    });
  });

  const parser = new HttpResponseParser(request.method ?? 'GET');
  const parsed = await readResponse(stream, parser, request);

  const firstByteTime = Date.now();
  if (timings.connect) {
    timings.firstByte = firstByteTime - timings.connect;
  }

  const encoding = parsed.headers.get('content-encoding');
  let body: Buffer;
  if (encoding) {
    body = await decompressBody(parsed.body, encoding);
  } else {
    body = parsed.body;
  }

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
      total: 0,
    },
    request: {
      url: request.url,
      method: request.method ?? 'GET',
      headers: request.headers ?? {},
    },
  });
}

/**
 * Sends an HTTP/1.1 request over the given duplex stream and returns a
 * streaming response whose body is available as a `Readable` stream on
 * `response.body`. The headers are fully parsed before resolving;
 * the body is streamed asynchronously.
 *
 * @param {Duplex}              stream  - Connected transport stream.
 * @param {NLcURLRequest}       request - Request descriptor.
 * @param {H1ClientOptions}     [options={}] - Client options.
 * @param {Partial<RequestTimings>} [timings={}] - Partial timings object to populate with `firstByte`.
 * @returns {Promise<NLcURLResponse>} Resolves once headers are received; body is streamed via `response.body`.
 * @throws {HTTPError}   If the connection is closed before headers are received.
 * @throws {TimeoutError} If the response timeout is exceeded.
 */
export async function sendH1StreamingRequest(
  stream: Duplex,
  request: NLcURLRequest,
  options: H1ClientOptions = {},
  timings: Partial<RequestTimings> = {},
): Promise<NLcURLResponse> {
  const encoded = encodeRequest(request, options.defaultHeaders ?? []);

  await new Promise<void>((resolve, reject) => {
    stream.write(encoded, (err) => {
      if (err) reject(new HTTPError(err.message, 0));
      else resolve();
    });
  });

  const parser = new HttpResponseParser(request.method ?? 'GET');
  const bodyStream = new PassThrough();

  parser.onBodyChunk = (chunk: Buffer) => {
    bodyStream.write(chunk);
  };

  const headersMeta = await readStreamingHeaders(stream, parser, request, bodyStream);

  const firstByteTime = Date.now();
  if (timings.connect) {
    timings.firstByte = firstByteTime - timings.connect;
  }

  const responseHeaders: Record<string, string> = {};
  for (const [k, v] of headersMeta.headers) {
    responseHeaders[k] = v;
  }

  const encoding = headersMeta.headers.get('content-encoding');
  const decompressor = createDecompressStream(encoding);
  const outputStream = decompressor ? bodyStream.pipe(decompressor) : bodyStream;

  return new NLcURLResponse({
    status: headersMeta.statusCode,
    statusText: headersMeta.statusMessage,
    headers: responseHeaders,
    rawHeaders: headersMeta.rawHeaders.map(([k, v]) => [k.toLowerCase(), v] as [string, string]),
    rawBody: Buffer.alloc(0),
    body: outputStream,
    httpVersion: headersMeta.httpVersion,
    url: request.url,
    redirectCount: 0,
    timings: {
      dns: timings.dns ?? 0,
      connect: timings.connect ?? 0,
      tls: timings.tls ?? 0,
      firstByte: timings.firstByte ?? 0,
      total: 0,
    },
    request: {
      url: request.url,
      method: request.method ?? 'GET',
      headers: request.headers ?? {},
    },
  });
}

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

function readStreamingHeaders(
  stream: Duplex,
  parser: HttpResponseParser,
  request: NLcURLRequest,
  bodyStream: PassThrough,
): Promise<Omit<ParsedResponse, 'body'>> {
  return new Promise<Omit<ParsedResponse, 'body'>>((resolve, reject) => {
    let settled = false;
    let headersResolved = false;
    let timer: ReturnType<typeof setTimeout> | undefined;

    const timeout = request.timeout;
    const timeoutMs = typeof timeout === 'number' ? timeout : (timeout?.total ?? timeout?.response ?? 0);
    if (timeoutMs > 0) {
      timer = setTimeout(() => {
        if (!settled) {
          settled = true;
          cleanup();
          bodyStream.destroy(new TimeoutError('Response timed out', 'response'));
          reject(new TimeoutError('Response timed out', 'response'));
        }
      }, timeoutMs);
    }

    const onData = (chunk: Buffer) => {
      try {
        const done = parser.feed(chunk);

        if (!headersResolved && parser.headersParsed) {
          headersResolved = true;
          resolve(parser.getHeadersResult());
        }

        if (done) {
          settled = true;
          cleanup();
          bodyStream.end();
        }
      } catch (err) {
        settled = true;
        cleanup();
        bodyStream.destroy(err instanceof Error ? err : new Error(String(err)));
        if (!headersResolved) reject(err);
      }
    };

    const onEnd = () => {
      if (!settled) {
        settled = true;
        parser.connectionClosed();
        cleanup();
        if (!headersResolved) {
          try {
            resolve(parser.getHeadersResult());
          } catch {
            reject(new HTTPError('Connection closed before headers complete', 0));
          }
        }
        bodyStream.end();
      }
    };

    const onError = (err: Error) => {
      if (!settled) {
        settled = true;
        cleanup();
        bodyStream.destroy(err);
        if (!headersResolved) reject(new HTTPError(err.message, 0));
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
