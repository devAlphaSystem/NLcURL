/**
 * Request and configuration types for NLcURL.
 */

export type HttpMethod = 'GET' | 'POST' | 'PUT' | 'PATCH' | 'DELETE' | 'HEAD' | 'OPTIONS';

export interface RequestTimings {
  /** Milliseconds from start to DNS lookup completion. */
  dns: number;
  /** Milliseconds from start to TCP connection established. */
  connect: number;
  /** Milliseconds from start to TLS handshake completed. */
  tls: number;
  /** Milliseconds from start to first byte received. */
  firstByte: number;
  /** Milliseconds total. */
  total: number;
}

export interface TimeoutConfig {
  /** TCP connect timeout in milliseconds. */
  connect?: number;
  /** TLS handshake timeout in milliseconds. */
  tls?: number;
  /** Time to first byte timeout in milliseconds. */
  response?: number;
  /** Total request timeout in milliseconds. */
  total?: number;
}

export type RequestBody =
  | string
  | Buffer
  | URLSearchParams
  | Record<string, unknown>
  | ReadableStream<Uint8Array>
  | null;

export interface NLcURLRequest {
  url: string;
  method?: HttpMethod;
  headers?: Record<string, string>;
  body?: RequestBody;
  timeout?: number | TimeoutConfig;
  signal?: AbortSignal;

  /** Browser profile name to impersonate, e.g. "chrome136", "firefox135". */
  impersonate?: string;
  /** Custom JA3 fingerprint string. Overrides profile TLS settings. */
  ja3?: string;
  /** Custom Akamai HTTP/2 fingerprint string. Overrides profile h2 settings. */
  akamai?: string;

  /** Use stealth TLS engine for byte-level ClientHello control. */
  stealth?: boolean;

  /** Follow redirects. Default: true. */
  followRedirects?: boolean;
  /** Maximum number of redirects to follow. Default: 20. */
  maxRedirects?: number;
  /** Skip TLS certificate verification. Default: false. */
  insecure?: boolean;

  /** Proxy URL (http, https, socks4, socks5). */
  proxy?: string;
  /** Proxy authentication as [username, password]. */
  proxyAuth?: [string, string];

  /** Force HTTP version: "1.1" or "2". */
  httpVersion?: '1.1' | '2';

  /** Base URL prepended to relative URLs. */
  baseURL?: string;
  /** Query parameters merged into the URL. */
  params?: Record<string, string | number | boolean>;

  /** Cookie jar instance or boolean to enable automatic cookie management. */
  cookieJar?: boolean | string;

  /** Accept-Encoding. Default: "gzip, deflate, br". */
  acceptEncoding?: string;
  /** Extra header ordering hint, if the profile needs headers in exact order. */
  headerOrder?: string[];
}

export interface RetryConfig {
  /** Number of retry attempts. Default: 0. */
  count: number;
  /** Base delay in milliseconds between retries. Default: 1000. */
  delay: number;
  /** Backoff strategy. Default: "exponential". */
  backoff: 'linear' | 'exponential';
  /** Maximum random jitter in milliseconds added to each delay. Default: 200. */
  jitter: number;
  /** Predicate to decide whether to retry. */
  retryOn?: (error: Error | null, statusCode?: number) => boolean;
}

export interface NLcURLSessionConfig {
  baseURL?: string;
  headers?: Record<string, string>;
  timeout?: number | TimeoutConfig;
  impersonate?: string;
  ja3?: string;
  akamai?: string;
  stealth?: boolean;
  proxy?: string;
  proxyAuth?: [string, string];
  followRedirects?: boolean;
  maxRedirects?: number;
  insecure?: boolean;
  httpVersion?: '1.1' | '2';
  cookieJar?: boolean | string;
  retry?: Partial<RetryConfig>;
  acceptEncoding?: string;
}
