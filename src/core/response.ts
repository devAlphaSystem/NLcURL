import type { RequestTimings, HttpMethod } from "./request.js";
import type { Readable } from "node:stream";

/**
 * Metadata about the originating request that produced a response.
 *
 * @typedef  {Object}              ResponseMeta
 * @property {string}              url     - The final URL after all redirects.
 * @property {HttpMethod}          method  - The HTTP method used for the request.
 * @property {Record<string,string>} headers - The request headers that were sent.
 * @property {string}              [command] - An optional cURL-equivalent command string for debugging.
 */
export interface ResponseMeta {
  url: string;
  method: HttpMethod;
  headers: Record<string, string>;
  command?: string;
}

/**
 * Represents the complete HTTP response from a successful request. Provides
 * convenience accessors for common content-type parsing, streaming, and
 * header inspection.
 *
 * @template T - Expected shape of the JSON-decoded body when calling {@link NLcURLResponse.json}.
 */
export class NLcURLResponse<T = unknown> {
  /** HTTP status code (e.g. `200`, `404`). */
  public readonly status: number;
  /** HTTP status text (e.g. `"OK"`, `"Not Found"`). */
  public readonly statusText: string;
  /** Normalized, lowercase response headers. Duplicate values are joined by `, `. */
  public readonly headers: Record<string, string>;
  /** All response header name-value pairs exactly as received, in transmission order. */
  public readonly rawHeaders: Array<[string, string]>;
  /** Fully buffered response body. Empty when the response was opened in streaming mode. */
  public readonly rawBody: Buffer;
  /** Readable stream of the response body, or `null` for buffered responses. */
  public readonly body: Readable | null;
  /** HTTP protocol version string (e.g. `"HTTP/1.1"`, `"HTTP/2.0"`). */
  public readonly httpVersion: string;
  /** Final URL of the response after any redirects. */
  public readonly url: string;
  /** Number of redirects followed before this response was received. */
  public readonly redirectCount: number;
  /** Granular timing measurements for each phase of the request lifecycle. */
  public readonly timings: RequestTimings;
  /** Metadata about the originating request. */
  public readonly request: ResponseMeta;

  private _json: T | undefined;
  private _text: string | undefined;

  /**
   * Creates a new NLcURLResponse instance.
   *
   * @param {Object}                         init                 - Response initialization data.
   * @param {number}                         init.status          - HTTP status code.
   * @param {string}                         init.statusText      - HTTP status text.
   * @param {Record<string,string>}          init.headers         - Normalized response headers.
   * @param {Array<[string,string]>}         [init.rawHeaders]    - Raw header pairs; defaults to entries of `headers`.
   * @param {Buffer}                         init.rawBody         - Fully buffered response body.
   * @param {Readable|null}                  [init.body]          - Streaming body, or `null`.
   * @param {string}                         init.httpVersion     - Protocol version string.
   * @param {string}                         init.url             - Final URL after redirects.
   * @param {number}                         init.redirectCount   - Number of redirects followed.
   * @param {RequestTimings}                 init.timings         - Lifecycle timing measurements.
   * @param {ResponseMeta}                   init.request         - Originating request metadata.
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
   * Returns `true` when the HTTP status code is in the 200–299 (successful)
   * range, `false` otherwise.
   *
   * @returns {boolean} Whether the response indicates success.
   */
  get ok(): boolean {
    return this.status >= 200 && this.status < 300;
  }

  /**
   * Decodes the raw body as a UTF-8 string and returns it. The result is
   * memoized after the first call.
   *
   * @returns {string} The response body decoded as UTF-8.
   * @throws {Error} If the response was opened in streaming mode (`stream: true`).
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
   * Parses the raw body as JSON and returns the decoded value. The result is
   * memoized after the first call.
   *
   * @template R - Expected type of the decoded JSON value; defaults to `T`.
   * @returns {R} The JSON-decoded response body.
   * @throws {Error} If the response was opened in streaming mode (`stream: true`).
   * @throws {SyntaxError} If the body is not valid JSON.
   *
   * @example
   * const data = response.json<{ id: number; name: string }>();
   * console.log(data.id);
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
   * Returns the `Content-Length` as a number. Falls back to the buffer byte
   * length when the header is absent or unparseable.
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
   * Returns the value of the `Content-Type` response header, or an empty
   * string when the header is absent.
   *
   * @returns {string} The `Content-Type` header value.
   */
  get contentType(): string {
    return this.headers["content-type"] ?? "";
  }

  /**
   * Returns the `ETag` response header value, or `undefined` when absent.
   */
  get etag(): string | undefined {
    return this.headers["etag"];
  }

  /**
   * Returns the `Last-Modified` response header value, or `undefined` when absent.
   */
  get lastModified(): string | undefined {
    return this.headers["last-modified"];
  }

  /**
   * Returns the `Cache-Control` response header value, or `undefined` when absent.
   */
  get cacheControl(): string | undefined {
    return this.headers["cache-control"];
  }

  /**
   * Returns the `Content-Range` response header value, or `undefined` when absent.
   * Present on 206 Partial Content responses (RFC 9110 §14.4).
   */
  get contentRange(): string | undefined {
    return this.headers["content-range"];
  }

  /**
   * Returns the `Accept-Ranges` response header value, or `undefined` when absent.
   * Indicates whether the server supports range requests (RFC 9110 §14.3).
   */
  get acceptRanges(): string | undefined {
    return this.headers["accept-ranges"];
  }

  /**
   * Returns all values for a response header, in transmission order,
   * supporting multi-value headers such as `Set-Cookie` which are joined
   * when accessed through `headers`.
   *
   * @param {string} name - The case-insensitive header name to look up.
   * @returns {string[]} All header values for the given name, or an empty array.
   */
  getAll(name: string): string[] {
    const lower = name.toLowerCase();
    return this.rawHeaders.filter(([k]) => k.toLowerCase() === lower).map(([, v]) => v);
  }
}
