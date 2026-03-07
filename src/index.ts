/**
 * Public API entry point for the NLcURL library. Re-exports all types, classes,
 * and functions that form the stable public surface of the package.
 *
 * @module nlcurl
 */
export type { HttpMethod, NLcURLRequest, NLcURLSessionConfig, RequestBody, RequestTimings, RetryConfig, TimeoutConfig } from "./core/request.js";

export { NLcURLResponse } from "./core/response.js";
export type { ResponseMeta } from "./core/response.js";

export { NLcURLError, TLSError, HTTPError, TimeoutError, ProxyError, AbortError, ConnectionError, ProtocolError } from "./core/errors.js";

export { NLcURLSession, type RequestOptions } from "./core/session.js";
export { createSession, request, get, post, put, patch, del, head } from "./core/client.js";

export { getProfile, listProfiles, DEFAULT_PROFILE } from "./fingerprints/database.js";

export type { BrowserProfile, TLSProfile, H2Profile, HeaderProfile } from "./fingerprints/types.js";

export type { RequestInterceptor, ResponseInterceptor } from "./middleware/interceptor.js";

export type { RateLimitConfig } from "./middleware/rate-limiter.js";

export type { Logger, LogLevel, LogBindings } from "./utils/logger.js";
export { ConsoleLogger, SILENT_LOGGER, setDefaultLogger, getDefaultLogger } from "./utils/logger.js";

export { CookieJar } from "./cookies/jar.js";
export { isPublicSuffix, getRegistrableDomain } from "./cookies/public-suffix.js";

export { FormData, type FormFile, type FormValue } from "./http/form-data.js";

export type { TLSOptions } from "./tls/types.js";

export { WebSocketClient, type WebSocketOptions, type WebSocketEvents } from "./ws/client.js";

export { ja3Hash, ja3String } from "./fingerprints/ja3.js";
export { akamaiFingerprint } from "./fingerprints/akamai.js";
