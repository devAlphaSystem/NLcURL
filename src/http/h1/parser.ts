
import { TLSError } from '../../core/errors.js';

/**
 * Represents a fully parsed HTTP/1.1 response, including status, headers, and
 * the buffered body.
 *
 * @typedef  {Object}              ParsedResponse
 * @property {string}              httpVersion    - HTTP version string (e.g. `"HTTP/1.1"`).
 * @property {number}              statusCode     - HTTP status code.
 * @property {string}              statusMessage  - HTTP status text.
 * @property {Map<string,string>}  headers        - Normalized, lowercase header map.
 * @property {Array<[string,string]>} rawHeaders  - Original header pairs in transmission order.
 * @property {Buffer}              body           - Fully buffered, unchunked response body.
 */
export interface ParsedResponse {
  httpVersion: string;
  statusCode: number;
  statusMessage: string;
  headers: Map<string, string>;
  rawHeaders: Array<[string, string]>;
  body: Buffer;
}

enum ParserState {
  StatusLine,
  Headers,
  Body,
  ChunkedBody,
  Complete,
}

/**
 * Incremental HTTP/1.1 response parser. Feed data buffers via {@link HttpResponseParser.feed}
 * until it returns `true`, then retrieve the result via {@link HttpResponseParser.getResult}.
 * Supports chunked transfer encoding, content-length delimited bodies, and
 * connection-close terminated bodies.
 */
export class HttpResponseParser {
  private requestMethod: string;
  private state = ParserState.StatusLine;
  private buffer = Buffer.alloc(0);
  private httpVersion = '';
  private statusCode = 0;
  private statusMessage = '';
  private headers = new Map<string, string>();
  private rawHeaders: Array<[string, string]> = [];
  private contentLength = -1;
  private isChunked = false;
  private bodyChunks: Buffer[] = [];
  private bodyBytesRead = 0;
  private result: ParsedResponse | null = null;

  /**
   * Optional callback invoked for each body chunk received in streaming mode.
   * When set, each chunk is forwarded here in addition to being buffered
   * internally.
   *
   * @type {((chunk: Buffer) => void) | undefined}
   */
  public onBodyChunk?: (chunk: Buffer) => void;

  private static readonly MAX_HEADER_SIZE = 262144;
  private static readonly MAX_BODY_SIZE = 134217728;

  /**
   * Creates a new HttpResponseParser.
   *
   * @param {string} [requestMethod='GET'] - HTTP method of the originating request.
   *   Required to correctly determine whether a body is expected (e.g. HEAD has no body).
   */
  constructor(requestMethod = 'GET') {
    this.requestMethod = requestMethod.toUpperCase();
  }

  /**
   * Appends `data` to the internal buffer and advances the parser state
   * machine. Returns `true` when a complete response has been parsed.
   *
   * @param {Buffer} data - Bytes received from the transport stream.
   * @returns {boolean} `true` if the response is complete and
   *   {@link HttpResponseParser.getResult} may be called; `false` if more data is needed.
   * @throws {Error} If any parse error is encountered (malformed status line, invalid header, etc.).
   */
  feed(data: Buffer): boolean {
    this.buffer = Buffer.concat([this.buffer, data]);

    while (this.state !== ParserState.Complete) {
      switch (this.state) {
        case ParserState.StatusLine:
          if (!this.parseStatusLine()) return false;
          break;
        case ParserState.Headers:
          if (!this.parseHeaders()) return false;
          break;
        case ParserState.Body:
          if (!this.parseBody()) return false;
          break;
        case ParserState.ChunkedBody:
          if (!this.parseChunkedBody()) return false;
          break;
      }
    }

    return true;
  }

  /**
   * Returns the fully parsed response. Must only be called after
   * {@link HttpResponseParser.feed} has returned `true`.
   *
   * @returns {ParsedResponse} The complete parsed response.
   * @throws {Error} If the response has not been fully parsed yet.
   */
  getResult(): ParsedResponse {
    if (!this.result) {
      throw new Error('Response not fully parsed');
    }
    return this.result;
  }

  /**
   * Returns `true` once all response headers have been parsed, regardless
   * of whether the body is complete.
   *
   * @returns {boolean} Whether headers have been fully parsed.
   */
  get headersParsed(): boolean {
    return this.state === ParserState.Body
      || this.state === ParserState.ChunkedBody
      || this.state === ParserState.Complete;
  }

  /**
   * Returns the parsed status line and headers without requiring a complete
   * body. May be called as soon as {@link HttpResponseParser.headersParsed} is `true`.
   *
   * @returns {Omit<ParsedResponse, 'body'>} Status and header data without the body.
   * @throws {Error} If headers have not been fully parsed yet.
   */
  getHeadersResult(): Omit<ParsedResponse, 'body'> {
    if (!this.headersParsed) {
      throw new Error('Headers not fully parsed');
    }
    return {
      httpVersion: this.httpVersion,
      statusCode: this.statusCode,
      statusMessage: this.statusMessage,
      headers: this.headers,
      rawHeaders: this.rawHeaders,
    };
  }

  /**
   * Returns any bytes remaining in the internal buffer after the last
   * complete response. Useful when the transport stream carries pipelined
   * responses.
   *
   * @returns {Buffer} Unconsumed bytes beyond the end of the current response.
   */
  getRemainder(): Buffer {
    return this.buffer;
  }

  private parseStatusLine(): boolean {
    const idx = this.buffer.indexOf('\r\n');
    if (idx === -1) {
      if (this.buffer.length > HttpResponseParser.MAX_HEADER_SIZE) {
        throw new Error('Status line too long');
      }
      return false;
    }

    const line = this.buffer.subarray(0, idx).toString('latin1');
    this.buffer = this.buffer.subarray(idx + 2);

    const match = /^(HTTP\/\d\.\d)\s+(\d{3})\s*(.*)$/.exec(line);
    if (!match) {
      throw new Error(`Invalid HTTP status line: ${line.substring(0, 100)}`);
    }

    this.httpVersion = match[1]!;
    this.statusCode = parseInt(match[2]!, 10);
    this.statusMessage = match[3] ?? '';
    this.state = ParserState.Headers;
    return true;
  }

  private parseHeaders(): boolean {
    while (true) {
      const idx = this.buffer.indexOf('\r\n');
      if (idx === -1) {
        if (this.buffer.length > HttpResponseParser.MAX_HEADER_SIZE) {
          throw new Error('Header section too large');
        }
        return false;
      }

      const line = this.buffer.subarray(0, idx).toString('latin1');
      this.buffer = this.buffer.subarray(idx + 2);

      if (line === '') {
        this.finalizeHeaders();
        return true;
      }

      const colonIdx = line.indexOf(':');
      if (colonIdx === -1) {
        throw new Error(`Invalid header line: ${line.substring(0, 100)}`);
      }

      const name = line.substring(0, colonIdx);
      const value = line.substring(colonIdx + 1).trim();
      this.rawHeaders.push([name, value]);

      const lower = name.toLowerCase();
      const existing = this.headers.get(lower);
      if (existing !== undefined) {
        const sep = lower === 'set-cookie' ? '; ' : ', ';
        this.headers.set(lower, existing + sep + value);
      } else {
        this.headers.set(lower, value);
      }
    }
  }

  private finalizeHeaders(): void {
    if (this.requestMethod === 'HEAD') {
      this.finalize();
      return;
    }

    const te = this.headers.get('transfer-encoding');
    if (te && te.toLowerCase().includes('chunked')) {
      this.isChunked = true;
      this.state = ParserState.ChunkedBody;
      return;
    }

    const cl = this.headers.get('content-length');
    if (cl !== undefined) {
      this.contentLength = parseInt(cl, 10);
      if (Number.isNaN(this.contentLength) || this.contentLength < 0) {
        throw new Error(`Invalid content-length: ${cl}`);
      }
      if (this.contentLength === 0) {
        this.finalize();
        return;
      }
      this.state = ParserState.Body;
      return;
    }

    if (
      this.statusCode === 204 ||
      this.statusCode === 304 ||
      (this.statusCode >= 100 && this.statusCode < 200)
    ) {
      this.finalize();
      return;
    }

    this.contentLength = -1;
    this.state = ParserState.Body;
  }

  private parseBody(): boolean {
    if (this.contentLength >= 0) {
      const needed = this.contentLength - this.bodyBytesRead;
      if (this.buffer.length >= needed) {
        const chunk = this.buffer.subarray(0, needed);
        this.emitOrAccumulate(chunk);
        this.bodyBytesRead += needed;
        this.buffer = this.buffer.subarray(needed);
        this.finalize();
        return true;
      }
      const chunk = Buffer.from(this.buffer);
      this.emitOrAccumulate(chunk);
      this.bodyBytesRead += this.buffer.length;
      this.buffer = Buffer.alloc(0);
      return false;
    }

    if (this.buffer.length > 0) {
      const chunk = Buffer.from(this.buffer);
      this.emitOrAccumulate(chunk);
      this.bodyBytesRead += this.buffer.length;
      if (!this.onBodyChunk && this.bodyBytesRead > HttpResponseParser.MAX_BODY_SIZE) {
        throw new Error('Response body exceeds maximum size');
      }
      this.buffer = Buffer.alloc(0);
    }
    return false;
  }

  private parseChunkedBody(): boolean {
    while (true) {
      const idx = this.buffer.indexOf('\r\n');
      if (idx === -1) return false;

      const sizeLine = this.buffer.subarray(0, idx).toString('latin1').trim();
      const semiIdx = sizeLine.indexOf(';');
      const sizeStr = semiIdx >= 0 ? sizeLine.substring(0, semiIdx) : sizeLine;
      const chunkSize = parseInt(sizeStr, 16);

      if (Number.isNaN(chunkSize)) {
        throw new Error(`Invalid chunk size: ${sizeLine.substring(0, 20)}`);
      }

      const totalNeeded = idx + 2 + chunkSize + 2;
      if (this.buffer.length < totalNeeded) return false;

      if (chunkSize === 0) {
        this.buffer = this.buffer.subarray(totalNeeded);
        const trailerEnd = this.buffer.indexOf('\r\n');
        if (trailerEnd >= 0) {
          this.buffer = this.buffer.subarray(trailerEnd + 2);
        }
        this.finalize();
        return true;
      }

      const chunkData = this.buffer.subarray(idx + 2, idx + 2 + chunkSize);
      this.emitOrAccumulate(Buffer.from(chunkData));
      this.bodyBytesRead += chunkSize;

      if (!this.onBodyChunk && this.bodyBytesRead > HttpResponseParser.MAX_BODY_SIZE) {
        throw new Error('Response body exceeds maximum size');
      }

      this.buffer = this.buffer.subarray(totalNeeded);
    }
  }

  private emitOrAccumulate(chunk: Buffer): void {
    if (this.onBodyChunk) {
      this.onBodyChunk(chunk);
    } else {
      this.bodyChunks.push(chunk);
    }
  }

  private finalize(): void {
    this.state = ParserState.Complete;
    this.result = {
      httpVersion: this.httpVersion,
      statusCode: this.statusCode,
      statusMessage: this.statusMessage,
      headers: this.headers,
      rawHeaders: this.rawHeaders,
      body: Buffer.concat(this.bodyChunks),
    };
  }

  /**
   * Signals the parser that the underlying TCP connection was closed by the
   * remote peer — used for HTTP/1.x responses whose body is delimited by
   * connection closure rather than a `Content-Length` header or chunked
   * transfer encoding. Triggers finalization so callers can retrieve the
   * accumulated body via {@link getResult}.
   */
  connectionClosed(): void {
    if (this.state === ParserState.Body && this.contentLength === -1) {
      this.finalize();
    }
  }
}
