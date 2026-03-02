
import type { CookieJar } from '../cookies/jar.js';

/**
 * Union of all HTTP method strings accepted by the library.
 *
 * @typedef {'GET'|'POST'|'PUT'|'PATCH'|'DELETE'|'HEAD'|'OPTIONS'} HttpMethod
 */
export type HttpMethod = 'GET' | 'POST' | 'PUT' | 'PATCH' | 'DELETE' | 'HEAD' | 'OPTIONS';

/**
 * Granular timing measurements recorded during a single request, in
 * milliseconds elapsed from request initiation.
 *
 * @typedef  {Object} RequestTimings
 * @property {number} dns       - Time spent resolving the hostname via DNS.
 * @property {number} connect   - Time spent establishing the TCP connection.
 * @property {number} tls       - Time spent completing the TLS handshake.
 * @property {number} firstByte - Time from connection open to the first response byte received.
 * @property {number} total     - Total wall-clock time for the entire request.
 */
export interface RequestTimings {
  dns: number;
  connect: number;
  tls: number;
  firstByte: number;
  total: number;
}

/**
 * Per-phase timeout limits for a single request, in milliseconds. Omitting
 * a field means no limit is applied for that phase.
 *
 * @typedef  {Object}  TimeoutConfig
 * @property {number}  [connect]  - Maximum milliseconds to establish the TCP connection.
 * @property {number}  [tls]      - Maximum milliseconds to complete the TLS handshake.
 * @property {number}  [response] - Maximum milliseconds to receive the first response byte.
 * @property {number}  [total]    - Maximum total milliseconds for the whole request.
 */
export interface TimeoutConfig {
  connect?: number;
  tls?: number;
  response?: number;
  total?: number;
}

/**
 * Accepted body types for an outgoing request. Arrays, plain objects, and
 * plain strings are serialized automatically; raw `Buffer`s and
 * `URLSearchParams` are used verbatim.
 *
 * @typedef {string|Buffer|URLSearchParams|Record<string,unknown>|ReadableStream<Uint8Array>|null} RequestBody
 */
export type RequestBody =
  | string
  | Buffer
  | URLSearchParams
  | Record<string, unknown>
  | ReadableStream<Uint8Array>
  | null;

/**
 * Describes a single HTTP request. All options at the request level override
 * any matching session-level defaults set on {@link NLcURLSessionConfig}.
 *
 * @typedef  {Object}                          NLcURLRequest
 * @property {string}                          url              - Absolute or relative URL to request.
 * @property {HttpMethod}                      [method='GET']   - HTTP method.
 * @property {Record<string,string>}           [headers]        - Request headers to merge with session defaults.
 * @property {RequestBody}                     [body]           - Request body payload.
 * @property {number|TimeoutConfig}            [timeout]        - Timeout in ms (flat) or per-phase config object.
 * @property {AbortSignal}                     [signal]         - Signal used to cancel the request early.
 * @property {string}                          [impersonate]    - Browser profile name (e.g. `"chrome136"`).
 * @property {string}                          [ja3]            - Custom JA3 fingerprint string override.
 * @property {string}                          [akamai]         - Custom Akamai HTTP/2 fingerprint override.
 * @property {boolean}                         [stealth]        - Use the custom stealth TLS engine.
 * @property {boolean}                         [followRedirects=true]  - Follow HTTP redirects automatically.
 * @property {number}                          [maxRedirects=20]       - Maximum number of redirects to follow.
 * @property {boolean}                         [insecure]       - Skip TLS certificate verification.
 * @property {string}                          [proxy]          - Proxy URL (`http://`, `socks4://`, `socks5://`).
 * @property {[string,string]}                 [proxyAuth]      - Proxy credentials as `[username, password]`.
 * @property {'1.1'|'2'}                       [httpVersion]    - Force a specific HTTP protocol version.
 * @property {string}                          [baseURL]        - Base URL prepended to relative `url` values.
 * @property {Record<string,string|number|boolean>} [params]   - Query parameters appended to the URL.
 * @property {boolean|string}                  [cookieJar]      - Enable a per-request cookie jar.
 * @property {string}                          [acceptEncoding] - Override the `Accept-Encoding` header value.
 * @property {string[]}                        [headerOrder]    - Explicit header ordering for fingerprinting.
 * @property {4|6}                             [dnsFamily]      - Force IPv4 (`4`) or IPv6 (`6`) DNS resolution.
 * @property {boolean}                         [stream]         - Return a streaming response body.
 */
export interface NLcURLRequest {
  url: string;
  method?: HttpMethod;
  headers?: Record<string, string>;
  body?: RequestBody;
  timeout?: number | TimeoutConfig;
  signal?: AbortSignal;

  impersonate?: string;
  ja3?: string;
  akamai?: string;

  stealth?: boolean;

  followRedirects?: boolean;
  maxRedirects?: number;
  insecure?: boolean;

  proxy?: string;
  proxyAuth?: [string, string];

  httpVersion?: '1.1' | '2';

  baseURL?: string;
  params?: Record<string, string | number | boolean>;

  cookieJar?: boolean | string | CookieJar;

  acceptEncoding?: string;
  headerOrder?: string[];

  dnsFamily?: 4 | 6;

  stream?: boolean;
}

/**
 * Configuration for automatic request retry with backoff.
 *
 * @typedef  {Object}   RetryConfig
 * @property {number}   count      - Maximum number of retry attempts after the initial request.
 * @property {number}   delay      - Base delay in milliseconds between attempts.
 * @property {'linear'|'exponential'} backoff - Strategy for increasing the delay on repeated failures.
 * @property {number}   jitter     - Maximum random jitter in milliseconds added to each delay.
 * @property {Function} [retryOn]  - Optional predicate; return `true` to allow a retry.
 */
export interface RetryConfig {
  count: number;
  delay: number;
  backoff: 'linear' | 'exponential';
  jitter: number;
  retryOn?: (error: Error | null, statusCode?: number) => boolean;
}

/**
 * Session-level defaults applied to every request issued through an
 * {@link NLcURLSession}. Individual request options always take precedence.
 *
 * @typedef  {Object}                NLcURLSessionConfig
 * @property {string}                [baseURL]        - Base URL prepended to relative request URLs.
 * @property {Record<string,string>} [headers]        - Headers merged into every request.
 * @property {number|TimeoutConfig}  [timeout]        - Default timeout applied to all requests.
 * @property {string}                [impersonate]    - Default browser profile for fingerprinting.
 * @property {string}                [ja3]            - Default JA3 fingerprint string.
 * @property {string}                [akamai]         - Default Akamai HTTP/2 fingerprint.
 * @property {boolean}               [stealth]        - Use the stealth TLS engine by default.
 * @property {string}                [proxy]          - Default proxy URL.
 * @property {[string,string]}       [proxyAuth]      - Default proxy credentials.
 * @property {boolean}               [followRedirects=true] - Follow redirects by default.
 * @property {number}                [maxRedirects=20]      - Default maximum redirect count.
 * @property {boolean}               [insecure]       - Skip TLS verification by default.
 * @property {'1.1'|'2'}             [httpVersion]    - Force an HTTP protocol version for all requests.
 * @property {boolean|string}        [cookieJar]      - Persistent cookie jar for the session.
 * @property {Partial<RetryConfig>}  [retry]          - Automatic retry configuration.
 * @property {string}                [acceptEncoding] - Default `Accept-Encoding` header value.
 * @property {4|6}                   [dnsFamily]      - Force IPv4 or IPv6 for DNS resolution.
 */
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
  cookieJar?: boolean | string | CookieJar;
  retry?: Partial<RetryConfig>;
  acceptEncoding?: string;
  dnsFamily?: 4 | 6;
}
