import type { CookieJar } from "../cookies/jar.js";
import type { Logger } from "../utils/logger.js";
import type { FormData } from "../http/form-data.js";
import type { TLSOptions } from "../tls/types.js";
import type { CacheConfig, CacheMode } from "../cache/types.js";
import type { HSTSConfig } from "../hsts/types.js";
import type { DNSConfig } from "../dns/types.js";
import type { ECHOptions } from "../tls/ech.js";
import type { AuthConfig } from "./auth.js";
import type { EarlyHintsCallback } from "../http/early-hints.js";
import type { RequestEncoding } from "../utils/compression.js";
import type { ReferrerPolicy } from "../http/referrer-policy.js";

/**
 * Describes the progress of an upload or download operation.
 */
export interface ProgressEvent {
  bytes: number;
  totalBytes: number;
  percent: number;
}

/**
 * Callback invoked during upload or download progress.
 *
 * @callback ProgressCallback
 * @param {ProgressEvent} event - The current progress snapshot.
 */
export type ProgressCallback = (event: ProgressEvent) => void;

/**
 * Supported HTTP request methods.
 */
export type HttpMethod = "GET" | "POST" | "PUT" | "PATCH" | "DELETE" | "HEAD" | "OPTIONS" | "QUERY";

/**
 * Timing measurements for each phase of a request lifecycle, in milliseconds.
 */
export interface RequestTimings {
  dns: number;
  connect: number;
  tls: number;
  firstByte: number;
  total: number;
}

/**
 * Per-phase timeout thresholds for a request, in milliseconds.
 */
export interface TimeoutConfig {
  connect?: number;
  tls?: number;
  response?: number;
  total?: number;
}

/**
 * Acceptable request body types for outgoing HTTP requests.
 */
export type RequestBody = string | Buffer | URLSearchParams | Record<string, unknown> | ReadableStream<Uint8Array> | FormData | null;

/**
 * Full request descriptor for a single HTTP request, including URL, method,
 * headers, body, TLS fingerprinting, proxy, caching, and timeout options.
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

  httpVersion?: "1.1" | "2";

  baseURL?: string;
  params?: Record<string, string | number | boolean>;

  cookieJar?: boolean | string | CookieJar;

  acceptEncoding?: string;
  headerOrder?: string[];

  dnsFamily?: 4 | 6;

  stream?: boolean;

  logger?: Logger;

  tls?: TLSOptions;

  dns?: DNSConfig;

  ech?: ECHOptions;

  onUploadProgress?: ProgressCallback;
  onDownloadProgress?: ProgressCallback;

  throwOnError?: boolean;

  cache?: CacheMode;

  range?: string;

  auth?: AuthConfig;

  onEarlyHints?: EarlyHintsCallback;

  expect100Continue?: boolean;

  compressBody?: RequestEncoding;

  methodOverride?: "QUERY";

  /** Block requests to private/reserved IP addresses (SSRF protection). */
  blockPrivateIPs?: boolean;

  /** Block requests to dangerous ports from the WHATWG blocklist. */
  blockDangerousPorts?: boolean;

  /** Referrer-Policy to control Referer header emission (W3C Referrer Policy). */
  referrerPolicy?: ReferrerPolicy;

  /** Maximum response body size in bytes. Responses exceeding this will be rejected. */
  maxResponseSize?: number;

  /** Subresource Integrity hash for response body verification (e.g. "sha256-..."). */
  integrity?: string;
}

/**
 * Represents a single server-sent event from an SSE stream.
 */
export interface ServerSentEvent {
  event: string;
  data: string;
  id: string;
  retry?: number;
}

/**
 * Configuration for automatic request retry behavior.
 */
export interface RetryConfig {
  count: number;
  delay: number;
  backoff: "linear" | "exponential";
  jitter: number;
  retryOn?: (error: Error | null, statusCode?: number) => boolean;
}

/**
 * Session-level configuration shared across all requests in a session.
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
  httpVersion?: "1.1" | "2";
  cookieJar?: boolean | string | CookieJar;
  retry?: Partial<RetryConfig>;
  acceptEncoding?: string;
  dnsFamily?: 4 | 6;
  logger?: Logger;
  tls?: TLSOptions;

  throwOnError?: boolean;
  onUploadProgress?: ProgressCallback;
  onDownloadProgress?: ProgressCallback;

  cacheConfig?: CacheConfig;

  hsts?: HSTSConfig;

  dns?: DNSConfig;

  ech?: ECHOptions;

  altSvc?: boolean;

  auth?: AuthConfig;

  compressBody?: RequestEncoding;

  /** Block requests to private/reserved IP addresses (SSRF protection). */
  blockPrivateIPs?: boolean;

  /** Block requests to dangerous ports from the WHATWG blocklist. */
  blockDangerousPorts?: boolean;

  /** Default Referrer-Policy for all requests. */
  referrerPolicy?: ReferrerPolicy;

  /** Default maximum response body size in bytes. */
  maxResponseSize?: number;

  /** Cookie name to read XSRF token from (e.g. "XSRF-TOKEN"). */
  xsrfCookieName?: string;

  /** Header name to set XSRF token on (e.g. "X-XSRF-TOKEN"). */
  xsrfHeaderName?: string;
}
