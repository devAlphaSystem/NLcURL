/**
 * Public API entry point for the NLcURL library. Re-exports all types, classes,
 * and functions that form the stable public surface of the package.
 *
 * @module nlcurl
 */
export type { HttpMethod, NLcURLRequest, NLcURLSessionConfig, RequestBody, RequestTimings, RetryConfig, TimeoutConfig, ProgressEvent, ProgressCallback, ServerSentEvent } from "./core/request.js";

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

export { TLSSessionCache, type SessionTicketEntry, type SessionCacheOptions } from "./tls/session-cache.js";

export { resolveEnvProxy } from "./proxy/env-proxy.js";

export { SSEParser, parseSSEStream } from "./sse/parser.js";

export { PerMessageDeflate, type DeflateParams, buildDeflateOffer, parseDeflateResponse } from "./ws/permessage-deflate.js";

export { isQuicAvailable } from "./http/h3/detection.js";

export { CacheStore, parseCacheControl } from "./cache/store.js";
export type { CacheConfig, CacheMode, CacheDirectives, CacheEntry } from "./cache/types.js";

export { HSTSStore } from "./hsts/store.js";
export type { HSTSConfig, HSTSEntry, HSTSPreloadEntry } from "./hsts/types.js";

export { DoHResolver } from "./dns/doh-resolver.js";
export { HTTPSRRResolver, type HTTPSRRResult } from "./dns/https-rr.js";
export type { DoHConfig, DNSConfig, DNSRecord, SVCBRecord, ResolvedAddress } from "./dns/types.js";
export { RTYPE, SvcParamKey } from "./dns/types.js";

export { AltSvcStore, type AltSvcEntry } from "./http/alt-svc.js";

export { parseECHConfigList, generateGreaseECH, type ECHConfig, type ECHParameters, type ECHOptions } from "./tls/ech.js";
