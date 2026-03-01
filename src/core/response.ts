/**
 * NLcURL response model.
 */

import type { RequestTimings, HttpMethod } from './request.js';

export interface ResponseMeta {
  url: string;
  method: HttpMethod;
  headers: Record<string, string>;
  command?: string;
}

export class NLcURLResponse<T = unknown> {
  public readonly status: number;
  public readonly statusText: string;
  public readonly headers: Record<string, string>;
  /** Raw header pairs preserving duplicates (e.g. multiple Set-Cookie). */
  public readonly rawHeaders: Array<[string, string]>;
  public readonly rawBody: Buffer;
  public readonly httpVersion: string;
  public readonly url: string;
  public readonly redirectCount: number;
  public readonly timings: RequestTimings;
  public readonly request: ResponseMeta;

  private _json: T | undefined;
  private _text: string | undefined;

  constructor(init: {
    status: number;
    statusText: string;
    headers: Record<string, string>;
    rawHeaders?: Array<[string, string]>;
    rawBody: Buffer;
    httpVersion: string;
    url: string;
    redirectCount: number;
    timings: RequestTimings;
    request: ResponseMeta;
  }) {
    this.status = init.status;
    this.statusText = init.statusText;
    this.headers = init.headers;
    this.rawHeaders = init.rawHeaders ?? Object.entries(init.headers);
    this.rawBody = init.rawBody;
    this.httpVersion = init.httpVersion;
    this.url = init.url;
    this.redirectCount = init.redirectCount;
    this.timings = init.timings;
    this.request = init.request;
  }

  /** Whether the status code is 2xx. */
  get ok(): boolean {
    return this.status >= 200 && this.status < 300;
  }

  /** Decode the body as UTF-8 text. Result is cached. */
  text(): string {
    let cached = this._text;
    if (cached === undefined) {
      cached = this.rawBody.toString('utf8');
      this._text = cached;
    }
    return cached;
  }

  /** Parse the body as JSON. Result is cached. Throws on invalid JSON. */
  json<R = T>(): R {
    if (this._json === undefined) {
      this._json = JSON.parse(this.text());
    }
    return this._json as R;
  }

  /** Content-Length as reported by the server, or the actual body size. */
  get contentLength(): number {
    const cl = this.headers['content-length'];
    if (cl !== undefined) {
      const n = parseInt(cl, 10);
      if (!Number.isNaN(n)) return n;
    }
    return this.rawBody.length;
  }

  /** Shorthand for the content-type header value. */
  get contentType(): string {
    return this.headers['content-type'] ?? '';
  }
}
