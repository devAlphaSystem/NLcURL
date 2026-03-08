import type { RequestTimings, HttpMethod } from "./request.js";
import type { Readable } from "node:stream";

/**
 * Metadata about the request that produced a given response.
 */
export interface ResponseMeta {
  url: string;
  method: HttpMethod;
  headers: Record<string, string>;
  command?: string;
  tlsVersion?: string;
  tlsCipher?: string;
  alpnProtocol?: string;
}

/**
 * Encapsulates an HTTP response with status, headers, body, timing data,
 * and convenience accessors for common header values and body parsing.
 *
 * @class
 * @template T - The expected JSON body type.
 */
export class NLcURLResponse<T = unknown> {
  /** The HTTP status code. */
  public readonly status: number;
  /** The HTTP reason phrase. */
  public readonly statusText: string;
  /** Response headers as a case-insensitive key-value map. */
  public readonly headers: Record<string, string>;
  /** Raw header pairs preserving original casing and duplicates. */
  public readonly rawHeaders: Array<[string, string]>;
  /** The full response body as a Buffer. */
  public readonly rawBody: Buffer;
  /** A readable stream for streaming responses, or `null` for buffered responses. */
  public readonly body: Readable | null;
  /** The negotiated HTTP version (e.g. "1.1", "2"). */
  public readonly httpVersion: string;
  /** The final URL after any redirects. */
  public readonly url: string;
  /** The number of redirects followed to reach this response. */
  public readonly redirectCount: number;
  /** Timing measurements for each request phase. */
  public readonly timings: RequestTimings;
  /** Metadata about the originating request. */
  public readonly request: ResponseMeta;

  private _json: T | undefined;
  private _text: string | undefined;

  /**
   * Creates a new NLcURLResponse from the provided initialization fields.
   *
   * @param {Object} init - Response initialization fields.
   */
  constructor(init: { status: number; statusText: string; headers: Record<string, string>; rawHeaders?: Array<[string, string]>; rawBody: Buffer; body?: Readable | null; httpVersion: string; url: string; redirectCount: number; timings: RequestTimings; request: ResponseMeta }) {
    this.status = init.status;
    this.statusText = init.statusText;
    this.headers = init.headers;
    this.rawHeaders = init.rawHeaders ?? Object.entries(init.headers);
    this.rawBody = init.rawBody;
    this.body = init.body ?? null;
    this.httpVersion = init.httpVersion;
    this.url = init.url;
    this.redirectCount = init.redirectCount;
    this.timings = init.timings;
    this.request = init.request;
  }

  /**
   * Returns `true` if the response status is in the 2xx range.
   *
   * @returns {boolean} Whether the response indicates success.
   */
  get ok(): boolean {
    return this.status >= 200 && this.status < 300;
  }

  /**
   * Decodes the raw body as a UTF-8 string. Throws if the response is streaming.
   *
   * @returns {string} The response body as text.
   * @throws {Error} If the response is a streaming response.
   */
  text(): string {
    if (this.body) {
      throw new Error("Cannot read text from a streaming response. Consume the .body stream instead.");
    }
    let cached = this._text;
    if (cached === undefined) {
      cached = this.rawBody.toString("utf8");
      this._text = cached;
    }
    return cached;
  }

  /**
   * Parses the response body as JSON. Throws if the response is streaming.
   *
   * @template R - The expected parsed type.
   * @returns {R} The parsed JSON value.
   * @throws {Error} If the response is a streaming response.
   * @throws {SyntaxError} If the body is not valid JSON.
   */
  json<R = T>(): R {
    if (this.body) {
      throw new Error("Cannot read JSON from a streaming response. Consume the .body stream instead.");
    }
    if (this._json === undefined) {
      this._json = JSON.parse(this.text());
    }
    return this._json as R;
  }

  /**
   * Returns the Content-Length header value, or the raw body length as a fallback.
   *
   * @returns {number} The content length in bytes.
   */
  get contentLength(): number {
    const cl = this.headers["content-length"];
    if (cl !== undefined) {
      const n = parseInt(cl, 10);
      if (!Number.isNaN(n)) return n;
    }
    return this.rawBody.length;
  }

  /**
   * Returns the Content-Type header value.
   *
   * @returns {string} The content type, or an empty string if absent.
   */
  get contentType(): string {
    return this.headers["content-type"] ?? "";
  }

  /**
   * Returns the ETag header value, if present.
   *
   * @returns {string|undefined} The entity tag.
   */
  get etag(): string | undefined {
    return this.headers["etag"];
  }

  /**
   * Returns the Last-Modified header value, if present.
   *
   * @returns {string|undefined} The last modified date string.
   */
  get lastModified(): string | undefined {
    return this.headers["last-modified"];
  }

  /**
   * Returns the Cache-Control header value, if present.
   *
   * @returns {string|undefined} The cache control directive string.
   */
  get cacheControl(): string | undefined {
    return this.headers["cache-control"];
  }

  /**
   * Returns the Content-Range header value, if present.
   *
   * @returns {string|undefined} The content range descriptor.
   */
  get contentRange(): string | undefined {
    return this.headers["content-range"];
  }

  /**
   * Returns the Accept-Ranges header value, if present.
   *
   * @returns {string|undefined} The accepted range unit.
   */
  get acceptRanges(): string | undefined {
    return this.headers["accept-ranges"];
  }

  /**
   * Retrieves all values for a given header name from the raw headers array.
   *
   * @param {string} name - The header name (case-insensitive).
   * @returns {string[]} All values for the specified header.
   */
  getAll(name: string): string[] {
    const lower = name.toLowerCase();
    return this.rawHeaders.filter(([k]) => k.toLowerCase() === lower).map(([, v]) => v);
  }
}
