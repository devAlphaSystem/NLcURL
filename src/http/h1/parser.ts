/**
 * HTTP/1.1 response parser.
 *
 * Incrementally parses HTTP/1.1 responses from a byte stream.
 * Handles chunked transfer encoding and content-length framing.
 */

import { TLSError } from '../../core/errors.js';

export interface ParsedResponse {
  httpVersion: string;
  statusCode: number;
  statusMessage: string;
  headers: Map<string, string>;
  /** Raw header entries preserving order and case. */
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
 * Incremental HTTP/1.1 response parser.
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

  /** Maximum header section size (256 KB). */
  private static readonly MAX_HEADER_SIZE = 262144;
  /** Maximum body size (128 MB). */
  private static readonly MAX_BODY_SIZE = 134217728;

  constructor(requestMethod = 'GET') {
    this.requestMethod = requestMethod.toUpperCase();
  }

  /**
   * Feed data into the parser.
   *
   * Returns `true` when the response is fully parsed.
   * After that, call `getResult()` to retrieve the parsed response,
   * and `getRemainder()` for any trailing bytes.
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

  getResult(): ParsedResponse {
    if (!this.result) {
      throw new Error('Response not fully parsed');
    }
    return this.result;
  }

  /** Get remaining data after the response (for connection reuse). */
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
        // End of headers
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
        this.headers.set(lower, existing + ', ' + value);
      } else {
        this.headers.set(lower, value);
      }
    }
  }

  private finalizeHeaders(): void {
    // HEAD responses never have a body (RFC 9110 §9.3.2)
    if (this.requestMethod === 'HEAD') {
      this.finalize();
      return;
    }

    // Determine body framing
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

    // No content-length, no chunked -- could be:
    //   1xx, 204, 304 → no body
    //   Everything else → read until connection close
    if (
      this.statusCode === 204 ||
      this.statusCode === 304 ||
      (this.statusCode >= 100 && this.statusCode < 200)
    ) {
      this.finalize();
      return;
    }

    // Read until close -- set contentLength to a sentinel
    this.contentLength = -1;
    this.state = ParserState.Body;
  }

  private parseBody(): boolean {
    if (this.contentLength >= 0) {
      const needed = this.contentLength - this.bodyBytesRead;
      if (this.buffer.length >= needed) {
        this.bodyChunks.push(this.buffer.subarray(0, needed));
        this.bodyBytesRead += needed;
        this.buffer = this.buffer.subarray(needed);
        this.finalize();
        return true;
      }
      // Not enough data yet
      this.bodyChunks.push(Buffer.from(this.buffer));
      this.bodyBytesRead += this.buffer.length;
      this.buffer = Buffer.alloc(0);
      return false;
    }

    // Read until close -- accumulate everything
    if (this.buffer.length > 0) {
      this.bodyChunks.push(Buffer.from(this.buffer));
      this.bodyBytesRead += this.buffer.length;
      if (this.bodyBytesRead > HttpResponseParser.MAX_BODY_SIZE) {
        throw new Error('Response body exceeds maximum size');
      }
      this.buffer = Buffer.alloc(0);
    }
    return false;
  }

  private parseChunkedBody(): boolean {
    while (true) {
      // Read chunk size line
      const idx = this.buffer.indexOf('\r\n');
      if (idx === -1) return false;

      const sizeLine = this.buffer.subarray(0, idx).toString('latin1').trim();
      // Chunk extensions are ignored (per spec)
      const semiIdx = sizeLine.indexOf(';');
      const sizeStr = semiIdx >= 0 ? sizeLine.substring(0, semiIdx) : sizeLine;
      const chunkSize = parseInt(sizeStr, 16);

      if (Number.isNaN(chunkSize)) {
        throw new Error(`Invalid chunk size: ${sizeLine.substring(0, 20)}`);
      }

      // Need: chunk-size-line + \r\n + chunk-data + \r\n
      const totalNeeded = idx + 2 + chunkSize + 2;
      if (this.buffer.length < totalNeeded) return false;

      if (chunkSize === 0) {
        // Terminal chunk
        this.buffer = this.buffer.subarray(totalNeeded);
        // Skip optional trailers
        const trailerEnd = this.buffer.indexOf('\r\n');
        if (trailerEnd >= 0) {
          this.buffer = this.buffer.subarray(trailerEnd + 2);
        }
        this.finalize();
        return true;
      }

      const chunkData = this.buffer.subarray(idx + 2, idx + 2 + chunkSize);
      this.bodyChunks.push(Buffer.from(chunkData));
      this.bodyBytesRead += chunkSize;

      if (this.bodyBytesRead > HttpResponseParser.MAX_BODY_SIZE) {
        throw new Error('Response body exceeds maximum size');
      }

      this.buffer = this.buffer.subarray(totalNeeded);
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
   * Signal that the connection was closed.
   * Finalizes a "read until close" body.
   */
  connectionClosed(): void {
    if (this.state === ParserState.Body && this.contentLength === -1) {
      this.finalize();
    }
  }
}
