/** Parsed HTTP/1.x response. */
export interface ParsedResponse {
  /** HTTP version string (e.g. "1.1"). */
  httpVersion: string;
  /** Response status code. */
  statusCode: number;
  /** Response status message. */
  statusMessage: string;
  /** Case-insensitive header map (last value wins). */
  headers: Map<string, string>;
  /** Raw header pairs preserving original casing and order. */
  rawHeaders: Array<[string, string]>;
  /** Response body buffer. */
  body: Buffer;
}

enum ParserState {
  StatusLine,
  Headers,
  Body,
  ChunkedBody,
  Complete,
}

/** Incremental HTTP/1.x response parser. */
export class HttpResponseParser {
  private requestMethod: string;
  private state = ParserState.StatusLine;
  private buffer = Buffer.alloc(0);
  private httpVersion = "";
  private statusCode = 0;
  private statusMessage = "";
  private headers = new Map<string, string>();
  private rawHeaders: Array<[string, string]> = [];
  private contentLength = -1;
  private isChunked = false;
  private bodyChunks: Buffer[] = [];
  private bodyBytesRead = 0;
  private result: ParsedResponse | null = null;

  /** Callback for body chunks during incremental parsing. */
  public onBodyChunk?: (chunk: Buffer) => void;

  private static readonly MAX_HEADER_SIZE = 262144;
  private static readonly MAX_BODY_SIZE = 134217728;
  private static readonly MAX_HEADER_COUNT = 500;

  /**
   * Create a new HTTP response parser.
   *
   * @param {string} [requestMethod] - HTTP method of the originating request.
   */
  constructor(requestMethod = "GET") {
    this.requestMethod = requestMethod.toUpperCase();
  }

  /**
   * Feed data into the parser.
   *
   * @param {Buffer} data - Incoming data chunk.
   * @returns {boolean} `true` when the response is fully parsed.
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
   * Return the fully parsed response.
   *
   * @returns {ParsedResponse} Parsed response including body.
   */
  getResult(): ParsedResponse {
    if (!this.result) {
      throw new Error("Response not fully parsed");
    }
    return this.result;
  }

  /** Whether response headers have been fully parsed. */
  get headersParsed(): boolean {
    return this.state === ParserState.Body || this.state === ParserState.ChunkedBody || this.state === ParserState.Complete;
  }

  /**
   * Return parsed headers without body data.
   *
   * @returns {Omit<ParsedResponse, "body">} Response metadata excluding the body.
   */
  getHeadersResult(): Omit<ParsedResponse, "body"> {
    if (!this.headersParsed) {
      throw new Error("Headers not fully parsed");
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
   * Return unconsumed data remaining in the parser buffer.
   *
   * @returns {Buffer} Leftover bytes after the parsed response.
   */
  getRemainder(): Buffer {
    return this.buffer;
  }

  private parseStatusLine(): boolean {
    const idx = this.buffer.indexOf("\r\n");
    if (idx === -1) {
      if (this.buffer.length > HttpResponseParser.MAX_HEADER_SIZE) {
        throw new Error("Status line too long");
      }
      return false;
    }

    const line = this.buffer.subarray(0, idx).toString("latin1");
    this.buffer = this.buffer.subarray(idx + 2);

    const match = /^(HTTP\/\d\.\d)\s+(\d{3})\s*(.*)$/.exec(line);
    if (!match) {
      throw new Error(`Invalid HTTP status line: ${line.substring(0, 100)}`);
    }

    this.httpVersion = match[1]!;
    this.statusCode = parseInt(match[2]!, 10);
    this.statusMessage = match[3] ?? "";
    this.state = ParserState.Headers;
    return true;
  }

  private parseHeaders(): boolean {
    while (true) {
      const idx = this.buffer.indexOf("\r\n");
      if (idx === -1) {
        if (this.buffer.length > HttpResponseParser.MAX_HEADER_SIZE) {
          throw new Error("Header section too large");
        }
        return false;
      }

      const line = this.buffer.subarray(0, idx).toString("latin1");
      this.buffer = this.buffer.subarray(idx + 2);

      if (line === "") {
        this.finalizeHeaders();
        return true;
      }

      if ((line.startsWith(" ") || line.startsWith("\t")) && this.rawHeaders.length > 0) {
        const lastPair = this.rawHeaders[this.rawHeaders.length - 1]!;
        lastPair[1] = lastPair[1] + " " + line.trim();
        const lower = lastPair[0].toLowerCase();
        this.headers.set(lower, lastPair[1]);
        continue;
      }

      const colonIdx = line.indexOf(":");
      if (colonIdx === -1) {
        throw new Error(`Invalid header line: ${line.substring(0, 100)}`);
      }

      const name = line.substring(0, colonIdx);
      if (!name) {
        throw new Error("Empty header name");
      }
      const value = line.substring(colonIdx + 1).trim();
      this.rawHeaders.push([name, value]);

      if (this.rawHeaders.length > HttpResponseParser.MAX_HEADER_COUNT) {
        throw new Error("Too many response headers");
      }

      const lower = name.toLowerCase();
      const existing = this.headers.get(lower);
      if (existing !== undefined) {
        const sep = lower === "set-cookie" ? "; " : ", ";
        this.headers.set(lower, existing + sep + value);
      } else {
        this.headers.set(lower, value);
      }
    }
  }

  private finalizeHeaders(): void {
    if (this.requestMethod === "HEAD") {
      this.finalize();
      return;
    }

    const te = this.headers.get("transfer-encoding");
    const cl = this.headers.get("content-length");

    if (te && cl !== undefined) {
      this.headers.delete("content-length");
    }

    if (te && te.toLowerCase().includes("chunked")) {
      this.isChunked = true;
      this.state = ParserState.ChunkedBody;
      return;
    }

    const clVal = this.headers.get("content-length");
    if (clVal !== undefined) {
      this.contentLength = parseInt(clVal, 10);
      if (Number.isNaN(this.contentLength) || this.contentLength < 0) {
        throw new Error(`Invalid content-length: ${clVal}`);
      }
      if (this.contentLength === 0) {
        this.finalize();
        return;
      }
      this.state = ParserState.Body;
      return;
    }

    if (this.statusCode === 204 || this.statusCode === 304 || (this.statusCode >= 100 && this.statusCode < 200)) {
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
      if (this.bodyBytesRead > HttpResponseParser.MAX_BODY_SIZE) {
        throw new Error("Response body exceeds maximum size");
      }
      this.buffer = Buffer.alloc(0);
    }
    return false;
  }

  private parseChunkedBody(): boolean {
    while (true) {
      const idx = this.buffer.indexOf("\r\n");
      if (idx === -1) return false;

      const sizeLine = this.buffer.subarray(0, idx).toString("latin1").trim();
      const semiIdx = sizeLine.indexOf(";");
      const sizeStr = semiIdx >= 0 ? sizeLine.substring(0, semiIdx) : sizeLine;
      const chunkSize = parseInt(sizeStr, 16);

      if (Number.isNaN(chunkSize) || chunkSize < 0) {
        throw new Error(`Invalid chunk size: ${sizeLine.substring(0, 20)}`);
      }
      if (chunkSize > HttpResponseParser.MAX_BODY_SIZE) {
        throw new Error("Chunk size exceeds maximum body size");
      }

      const totalNeeded = idx + 2 + chunkSize + 2;
      if (this.buffer.length < totalNeeded) return false;

      if (chunkSize === 0) {
        this.buffer = this.buffer.subarray(idx + 2);
        while (true) {
          const trailerIdx = this.buffer.indexOf("\r\n");
          if (trailerIdx === -1) return false;
          if (trailerIdx === 0) {
            this.buffer = this.buffer.subarray(2);
            break;
          }
          const trailerLine = this.buffer.subarray(0, trailerIdx).toString("latin1");
          this.buffer = this.buffer.subarray(trailerIdx + 2);
          const colonIdx = trailerLine.indexOf(":");
          if (colonIdx > 0) {
            const name = trailerLine.substring(0, colonIdx);
            const value = trailerLine.substring(colonIdx + 1).trim();
            this.rawHeaders.push([name, value]);
            const lower = name.toLowerCase();
            if (lower !== "transfer-encoding" && lower !== "content-length" && lower !== "host" && lower !== "trailer") {
              const existing = this.headers.get(lower);
              if (existing !== undefined) {
                this.headers.set(lower, existing + ", " + value);
              } else {
                this.headers.set(lower, value);
              }
            }
          }
        }
        this.finalize();
        return true;
      }

      const chunkData = this.buffer.subarray(idx + 2, idx + 2 + chunkSize);
      this.emitOrAccumulate(Buffer.from(chunkData));
      this.bodyBytesRead += chunkSize;

      if (this.bodyBytesRead > HttpResponseParser.MAX_BODY_SIZE) {
        throw new Error("Response body exceeds maximum size");
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

  /** Signal that the connection has closed, finalizing any in-progress response. */
  connectionClosed(): void {
    if (this.state === ParserState.Body && this.contentLength === -1) {
      this.finalize();
    }
  }
}
