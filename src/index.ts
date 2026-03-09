export type { HttpMethod, NLcURLRequest, NLcURLSessionConfig, RequestBody, RequestTimings, RetryConfig, TimeoutConfig, ProgressEvent, ProgressCallback, ServerSentEvent } from "./core/request.js";

export { NLcURLResponse } from "./core/response.js";
export type { ResponseMeta } from "./core/response.js";

export { NLcURLError, TLSError, HTTPError, TimeoutError, ProxyError, AbortError, ConnectionError, ProtocolError } from "./core/errors.js";

export { validateUrlSafety } from "./core/validation.js";

export { NLcURLSession, type RequestOptions } from "./core/session.js";
export { createSession, request, get, post, put, patch, del, head } from "./core/client.js";

export { buildAuthHeader, parseAuthenticateScheme, type AuthConfig, type DigestChallenge as CoreDigestChallenge } from "./core/auth.js";

export { getProfile, listProfiles, DEFAULT_PROFILE } from "./fingerprints/database.js";

export type { BrowserProfile, TLSProfile, H2Profile, HeaderProfile } from "./fingerprints/types.js";

export type { RequestInterceptor, ResponseInterceptor } from "./middleware/interceptor.js";

export type { RateLimitConfig } from "./middleware/rate-limiter.js";

export { CircuitBreaker, CircuitState, type CircuitBreakerConfig } from "./middleware/circuit-breaker.js";

export { parseRetryAfter, getRetryAfterMs } from "./middleware/retry-after.js";

export type { Logger, LogLevel, LogBindings } from "./utils/logger.js";
export { ConsoleLogger, JsonLogger, SILENT_LOGGER, setDefaultLogger, getDefaultLogger } from "./utils/logger.js";

export { CookieJar } from "./cookies/jar.js";
export { isPublicSuffix, getRegistrableDomain } from "./cookies/public-suffix.js";

export { FormData, type FormFile, type FormValue } from "./http/form-data.js";

export type { TLSOptions } from "./tls/types.js";

export { SAFE_DEFAULT_CIPHERS } from "./tls/constants.js";

export { WebSocketClient, type WebSocketOptions, type WebSocketEvents } from "./ws/client.js";

export { ja3Hash, ja3String } from "./fingerprints/ja3.js";
export { ja4Fingerprint, ja4aSection } from "./fingerprints/ja4.js";
export { akamaiFingerprint } from "./fingerprints/akamai.js";

export { TLSSessionCache, type SessionTicketEntry, type SessionCacheOptions } from "./tls/session-cache.js";

export { setKeylogFile, getKeylogFile } from "./tls/keylog.js";

export { resolveEnvProxy } from "./proxy/env-proxy.js";

export { SSEParser, parseSSEStream } from "./sse/parser.js";
export { SSEClient, type SSEClientOptions, type SSEFetchResult, type SSEClientEvents } from "./sse/client.js";

export { computeReferrer, parseReferrerPolicy, type ReferrerPolicy } from "./http/referrer-policy.js";

export { verifyIntegrity } from "./utils/integrity.js";

export { PerMessageDeflate, type DeflateParams, buildDeflateOffer, parseDeflateResponse } from "./ws/permessage-deflate.js";

export { CacheStore, parseCacheControl } from "./cache/store.js";
export type { CacheConfig, CacheMode, CacheDirectives, CacheEntry } from "./cache/types.js";

export { HSTSStore } from "./hsts/store.js";
export type { HSTSConfig, HSTSEntry, HSTSPreloadEntry } from "./hsts/types.js";

export { DoHResolver } from "./dns/doh-resolver.js";
export { DNSCache, type DNSCacheConfig, type DNSCacheEntry } from "./dns/cache.js";
export { HTTPSRRResolver, type HTTPSRRResult } from "./dns/https-rr.js";
export type { DoHConfig, DNSConfig, DNSRecord, SVCBRecord, ResolvedAddress } from "./dns/types.js";
export { RTYPE, SvcParamKey } from "./dns/types.js";

export { AltSvcStore, type AltSvcEntry } from "./http/alt-svc.js";

export { parseLinkHeader, type EarlyHint, type EarlyHintsCallback } from "./http/early-hints.js";

export { compressBody, shouldCompress, type RequestEncoding } from "./utils/compression.js";

export { parseECHConfigList, generateGreaseECH, parseECHRetryConfigs, shouldRetryECH, type ECHConfig, type ECHParameters, type ECHOptions } from "./tls/ech.js";

export { parseOCSPResponse, isOCSPValid, validateOCSPStapling, OCSPResponseStatus, OCSPCertStatus, type OCSPResult } from "./tls/ocsp.js";

export { parseSCTList, validateSCTs, extractSCTsFromSocket, SCTVersion, SCTHashAlgorithm, SCTSignatureAlgorithm, type SCT, type SCTValidationResult } from "./tls/ct.js";

export { canSendEarlyData, prepareEarlyData, checkEarlyDataAccepted, type EarlyDataConfig, type EarlyDataResult } from "./tls/early-data.js";

export { isValidTrailerField, serializeTrailers, parseTrailers, buildTrailerHeader } from "./http/trailers.js";

export { buildUploadCreationHeaders, buildUploadResumeHeaders, buildUploadOffsetHeaders, parseUploadOffset, isUploadComplete, splitIntoChunks, parseUploadUrl, type UploadSession, type ResumableUploadConfig } from "./http/resumable-upload.js";

export { RangeCache, parseContentRange, parseRangeHeader, type ContentRange, type RangeSegment, type RangeCacheEntry } from "./cache/range.js";

export { parseNoVarySearch, urlsMatchWithNoVarySearch, normalizeUrlForCache, type NoVarySearchDirective } from "./cache/no-vary-search.js";

export { CacheGroupStore, parseCacheGroups, type CacheGroup } from "./cache/groups.js";

export { DictionaryStore, parseUseAsDictionary, computeDictionaryHash, buildAvailableDictionaryHeader, buildDictionaryAcceptEncoding, type CompressionDictionary, type DictionaryConfig } from "./utils/dictionary-transport.js";

export { isTFOSupported, buildTFOSocketOptions, getTFOStatus, type TFOOptions } from "./utils/tcp-fast-open.js";

export { DoTResolver, DOT_SERVERS, type DoTConfig } from "./dns/dot-resolver.js";

export { parseProxyAuthenticate, parseDigestChallenge, buildDigestAuth, buildBasicProxyAuth, buildProxyAuthorization, type ProxyAuthConfig, type ProxyAuthScheme, type DigestChallenge } from "./proxy/auth.js";
