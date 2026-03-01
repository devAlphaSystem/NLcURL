/**
 * NLcURL -- Pure TypeScript HTTP client with browser fingerprint impersonation.
 *
 * Zero runtime dependencies. Uses Node.js built-in modules exclusively.
 *
 * @module nlcurl
 */

// ---- Core types ----
export type {
  HttpMethod,
  NLcURLRequest,
  NLcURLSessionConfig,
  RequestBody,
  RequestTimings,
  RetryConfig,
  TimeoutConfig,
} from './core/request.js';

export { NLcURLResponse } from './core/response.js';
export type { ResponseMeta } from './core/response.js';

// ---- Error types ----
export {
  NLcURLError,
  TLSError,
  HTTPError,
  TimeoutError,
  ProxyError,
  AbortError,
  ConnectionError,
  ProtocolError,
} from './core/errors.js';

// ---- Session and client ----
export { NLcURLSession, type RequestOptions } from './core/session.js';
export {
  createSession,
  request,
  get,
  post,
  put,
  patch,
  del,
  head,
} from './core/client.js';

// ---- Fingerprints ----
export {
  getProfile,
  listProfiles,
  DEFAULT_PROFILE,
} from './fingerprints/database.js';

export type {
  BrowserProfile,
  TLSProfile,
  H2Profile,
  HeaderProfile,
} from './fingerprints/types.js';

// ---- Middleware ----
export type {
  RequestInterceptor,
  ResponseInterceptor,
} from './middleware/interceptor.js';

export type { RateLimitConfig } from './middleware/rate-limiter.js';

// ---- Cookies ----
export { CookieJar } from './cookies/jar.js';

// ---- WebSocket ----
export { WebSocketClient, type WebSocketOptions, type WebSocketEvents } from './ws/client.js';

// ---- Utilities ----
export { ja3Hash, ja3String } from './fingerprints/ja3.js';
export { akamaiFingerprint } from './fingerprints/akamai.js';
