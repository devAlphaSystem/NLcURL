# API Reference

Complete API reference for NLcURL v0.11.0. All exports are available from the `"nlcurl"` package entry point.

---

## Table of Contents

- [Top-Level Functions](#top-level-functions)
- [NLcURLSession](#nlcurlsession)
- [NLcURLResponse](#nlcurlresponse)
- [Request Types](#request-types)
- [Error Classes](#error-classes)
- [Browser Fingerprints](#browser-fingerprints)
- [TLS](#tls)
- [Cookies](#cookies)
- [Cache](#cache)
- [HSTS](#hsts)
- [DNS](#dns)
- [Proxy](#proxy)
- [WebSocket](#websocket)
- [Server-Sent Events](#server-sent-events)
- [HTTP Utilities](#http-utilities)
- [Middleware](#middleware)
- [Logging](#logging)

---

## Top-Level Functions

### `createSession(config?)`

Creates a new persistent session with connection pooling, cookie storage, caching, and middleware support.

```typescript
function createSession(config?: NLcURLSessionConfig): NLcURLSession
```

**Parameters:**
- `config` — Optional session-level configuration. See [NLcURLSessionConfig](#nlcurlsessionconfig).

**Returns:** A new `NLcURLSession` instance.

---

### `request(input)`

Sends a one-shot HTTP request using a temporary session. The session is closed automatically after the response is consumed.

```typescript
function request(input: NLcURLRequest): Promise<NLcURLResponse>
```

When `input.stream` is `true`, the session remains open until the response body stream emits `close`.

---

### `get(url, options?)`

```typescript
function get(url: string, options?: RequestOptions & { impersonate?: string }): Promise<NLcURLResponse>
```

### `post(url, body?, options?)`

```typescript
function post(url: string, body?: RequestBody, options?: RequestOptions & { impersonate?: string }): Promise<NLcURLResponse>
```

### `put(url, body?, options?)`

```typescript
function put(url: string, body?: RequestBody, options?: RequestOptions & { impersonate?: string }): Promise<NLcURLResponse>
```

### `patch(url, body?, options?)`

```typescript
function patch(url: string, body?: RequestBody, options?: RequestOptions & { impersonate?: string }): Promise<NLcURLResponse>
```

### `del(url, options?)`

```typescript
function del(url: string, options?: RequestOptions & { impersonate?: string }): Promise<NLcURLResponse>
```

### `head(url, options?)`

```typescript
function head(url: string, options?: RequestOptions & { impersonate?: string }): Promise<NLcURLResponse>
```

All convenience functions delegate to `request()` with the appropriate HTTP method set.

---

## NLcURLSession

A persistent HTTP session managing connection pooling, cookie storage, caching, HSTS enforcement, interceptors, rate limiting, and retry logic.

### Constructor

```typescript
new NLcURLSession(config?: NLcURLSessionConfig)
```

Throws `NLcURLError` if configuration values are invalid.

### Methods

#### `session.request(input)`

```typescript
session.request(input: NLcURLRequest): Promise<NLcURLResponse>
```

Sends a request through the full session pipeline: validation → rate limiting → interceptors → compression → caching → HSTS upgrade → cookie attachment → retry → redirect following → response processing.

Throws `NLcURLError` with code `ERR_SESSION_CLOSED` if the session has been closed. Throws `HTTPError` if `throwOnError` is enabled and the response status is outside the 2xx range.

#### `session.get(url, options?)`

```typescript
session.get(url: string, options?: RequestOptions): Promise<NLcURLResponse>
```

#### `session.post(url, body?, options?)`

```typescript
session.post(url: string, body?: RequestBody, options?: RequestOptions): Promise<NLcURLResponse>
```

#### `session.put(url, body?, options?)`

```typescript
session.put(url: string, body?: RequestBody, options?: RequestOptions): Promise<NLcURLResponse>
```

#### `session.patch(url, body?, options?)`

```typescript
session.patch(url: string, body?: RequestBody, options?: RequestOptions): Promise<NLcURLResponse>
```

#### `session.delete(url, options?)`

```typescript
session.delete(url: string, options?: RequestOptions): Promise<NLcURLResponse>
```

#### `session.head(url, options?)`

```typescript
session.head(url: string, options?: RequestOptions): Promise<NLcURLResponse>
```

#### `session.options(url, options?)`

```typescript
session.options(url: string, options?: RequestOptions): Promise<NLcURLResponse>
```

#### `session.query(url, body?, options?)`

Sends an HTTP QUERY request (RFC 9110).

```typescript
session.query(url: string, body?: RequestBody, options?: RequestOptions): Promise<NLcURLResponse>
```

#### `session.onRequest(fn)`

Registers a request interceptor invoked before each outgoing request.

```typescript
session.onRequest(fn: RequestInterceptor): this
```

#### `session.onResponse(fn)`

Registers a response interceptor invoked after each incoming response.

```typescript
session.onResponse(fn: ResponseInterceptor): this
```

#### `session.setRateLimit(config)`

Configures a token-bucket rate limiter for the session.

```typescript
session.setRateLimit(config: RateLimitConfig): this
```

#### `session.getCookies()`

```typescript
session.getCookies(): CookieJar | null
```

Returns the session's cookie jar, or `null` if cookies are disabled.

#### `session.getCache()`

```typescript
session.getCache(): CacheStore | null
```

#### `session.getHSTS()`

```typescript
session.getHSTS(): HSTSStore | null
```

#### `session.getAltSvc()`

```typescript
session.getAltSvc(): AltSvcStore
```

#### `session.close()`

Closes the session and releases all pooled connections. Subsequent requests throw `ERR_SESSION_CLOSED`.

```typescript
session.close(): void
```

---

## NLcURLResponse

Encapsulates an HTTP response.

### Properties

| Property | Type | Description |
|----------|------|-------------|
| `status` | `number` | HTTP status code |
| `statusText` | `string` | HTTP reason phrase |
| `headers` | `Record<string, string>` | Response headers (lowercase keys) |
| `rawHeaders` | `Array<[string, string]>` | Raw header pairs preserving original casing |
| `rawBody` | `Buffer` | Full response body as a Buffer |
| `body` | `Readable \| null` | Readable stream for streaming responses, `null` for buffered |
| `httpVersion` | `string` | Negotiated HTTP version (e.g. `"1.1"`, `"2"`) |
| `url` | `string` | Final URL after redirects |
| `redirectCount` | `number` | Number of redirects followed |
| `timings` | `RequestTimings` | Per-phase timing measurements in milliseconds |
| `request` | `ResponseMeta` | Metadata about the originating request |

### Accessors

| Accessor | Type | Description |
|----------|------|-------------|
| `ok` | `boolean` | `true` if status is 200–299 |
| `contentLength` | `number` | Content-Length header value, or raw body length |
| `contentType` | `string` | Content-Type header value, or empty string |
| `etag` | `string \| undefined` | ETag header value |
| `lastModified` | `string \| undefined` | Last-Modified header value |
| `cacheControl` | `string \| undefined` | Cache-Control header value |
| `contentRange` | `string \| undefined` | Content-Range header value |
| `acceptRanges` | `string \| undefined` | Accept-Ranges header value |

### Methods

#### `response.text()`

Decodes the raw body as UTF-8 text. Throws if the response is streaming.

```typescript
response.text(): string
```

#### `response.json<R>()`

Parses the response body as JSON. Throws if the response is streaming. Caches the parsed result.

```typescript
response.json<R = T>(): R
```

#### `response.getAll(name)`

Returns all header values for the given header name from the raw headers array.

```typescript
response.getAll(name: string): string[]
```

---

## Request Types

### `NLcURLRequest`

Full request descriptor.

```typescript
interface NLcURLRequest {
  url: string;
  method?: HttpMethod;                    // Default: "GET"
  headers?: Record<string, string>;
  body?: RequestBody;
  timeout?: number | TimeoutConfig;
  signal?: AbortSignal;

  // Fingerprinting
  impersonate?: string;                   // Browser profile name
  ja3?: string;                           // Custom JA3 fingerprint string
  akamai?: string;                        // Custom Akamai HTTP/2 fingerprint
  stealth?: boolean;                      // Use custom stealth TLS engine

  // Redirects
  followRedirects?: boolean;              // Default: true
  maxRedirects?: number;                  // Default: 20

  // TLS
  insecure?: boolean;                     // Skip certificate verification
  tls?: TLSOptions;                       // Client certs, CA, pins

  // Proxy
  proxy?: string;                         // Proxy URL (http/https/socks4/socks5)
  proxyAuth?: [string, string];           // [username, password]

  // Protocol
  httpVersion?: "1.1" | "2" | "3";

  // URL
  baseURL?: string;
  params?: Record<string, string | number | boolean>;

  // Cookies
  cookieJar?: boolean | string | CookieJar;

  // Headers
  acceptEncoding?: string;
  headerOrder?: string[];

  // DNS
  dnsFamily?: 4 | 6;
  dns?: DNSConfig;
  ech?: ECHOptions;

  // Streaming
  stream?: boolean;

  // Auth
  auth?: AuthConfig;

  // Caching
  cache?: CacheMode;

  // Range
  range?: string;

  // Callbacks
  onUploadProgress?: ProgressCallback;
  onDownloadProgress?: ProgressCallback;
  onEarlyHints?: EarlyHintsCallback;

  // Behavior
  throwOnError?: boolean;
  expect100Continue?: boolean;
  compressBody?: RequestEncoding;
  methodOverride?: "QUERY";

  // Security & Standards
  referrerPolicy?: ReferrerPolicy;        // W3C Referrer-Policy for redirects
  integrity?: string;                     // SRI hash for response verification
  maxResponseSize?: number;               // Maximum response body in bytes

  // Logging
  logger?: Logger;
}
```

### `HttpMethod`

```typescript
type HttpMethod = "GET" | "POST" | "PUT" | "PATCH" | "DELETE" | "HEAD" | "OPTIONS" | "QUERY";
```

### `RequestBody`

```typescript
type RequestBody = string | Buffer | URLSearchParams | Record<string, unknown> | ReadableStream<Uint8Array> | FormData | null;
```

Body type detection:
- `Record<string, unknown>` → serialized as JSON with `application/json` content type.
- `URLSearchParams` → serialized with `application/x-www-form-urlencoded` content type.
- `FormData` → serialized as multipart with the form's boundary in the content type.
- `string` → sent as-is with `text/plain; charset=utf-8` content type.
- `Buffer` → sent as-is.
- `ReadableStream<Uint8Array>` → drained to a Buffer before encoding.

### `TimeoutConfig`

Per-phase timeout thresholds in milliseconds.

```typescript
interface TimeoutConfig {
  connect?: number;
  tls?: number;
  response?: number;
  total?: number;
}
```

### `RequestTimings`

```typescript
interface RequestTimings {
  dns: number;
  connect: number;
  tls: number;
  firstByte: number;
  total: number;
}
```

### `ProgressEvent`

```typescript
interface ProgressEvent {
  bytes: number;
  totalBytes: number;
  percent: number;
}
```

### `RetryConfig`

```typescript
interface RetryConfig {
  count: number;              // Max retry attempts
  delay: number;              // Base delay in ms (default: 1000)
  backoff: "linear" | "exponential";  // Default: "exponential"
  jitter: number;             // Max jitter in ms (default: 200)
  retryOn?: (error: Error | null, statusCode?: number) => boolean;
}
```

Exponential backoff uses `2^(attempt-1)` as the factor, capped at 32×. Linear backoff uses the attempt number as the factor. The `Retry-After` response header is respected, capped at 5 minutes.

Default retryable conditions: `ConnectionError`, `TimeoutError`, `TLSError`, specific HTTP/2 error codes (PROTOCOL_ERROR, INTERNAL_ERROR, REFUSED_STREAM, CANCEL, ENHANCE_YOUR_CALM, HTTP_1_1_REQUIRED), and status codes 429, 500, 502, 503, 504.

### `NLcURLSessionConfig`

```typescript
interface NLcURLSessionConfig {
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
  httpVersion?: "1.1" | "2" | "3";
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
  referrerPolicy?: ReferrerPolicy;
  maxResponseSize?: number;
  xsrfCookieName?: string;
  xsrfHeaderName?: string;
}
```

### `AuthConfig`

```typescript
interface AuthConfig {
  type: "basic" | "bearer" | "digest" | "aws-sigv4" | "negotiate" | "ntlm";
  username?: string;        // Required for "basic" and "digest"
  password?: string;        // Optional for "basic" and "digest"
  token?: string;           // Required for "bearer", "negotiate", and "ntlm"
  awsRegion?: string;       // Required for "aws-sigv4"
  awsService?: string;      // Required for "aws-sigv4"
  awsAccessKeyId?: string;  // Required for "aws-sigv4"
  awsSecretKey?: string;    // Required for "aws-sigv4"
  awsSessionToken?: string; // Optional for "aws-sigv4"
}
```

### `DigestChallenge`

Parsed Digest challenge from a `WWW-Authenticate` header (RFC 7616).

```typescript
interface DigestChallenge {
  realm: string;
  nonce: string;
  qop?: string;
  opaque?: string;
  algorithm?: string;
  stale?: boolean;
}
```

`buildAuthHeader()` accepts an optional `context` parameter for stateful schemes:

```typescript
function buildAuthHeader(
  auth: AuthConfig,
  context?: {
    method?: string;          // HTTP method (Digest/SigV4)
    url?: string;             // Request URL (Digest/SigV4)
    wwwAuthenticate?: string; // WWW-Authenticate header (Digest)
    headers?: Record<string, string>;  // Request headers (SigV4)
    body?: Buffer;            // Request body (SigV4)
  },
): string | undefined;
```

The session automatically retries 401 responses with Digest authentication when `auth.type` is `"digest"`.

**Digest `auth-int` support:** When `qop="auth-int"` is requested by the server, NLcURL automatically hashes the request body into the digest computation. If no body is present, it falls back to `qop="auth"`.

**Negotiate/NTLM authentication:** Set `auth.type` to `"negotiate"` or `"ntlm"` and provide a base64-encoded `token` for Kerberos/NTLM authentication.

### `ResponseMeta`

```typescript
interface ResponseMeta {
  url: string;
  method: HttpMethod;
  headers: Record<string, string>;
  command?: string;
  tlsVersion?: string;
  tlsCipher?: string;
  alpnProtocol?: string;
}
```

---

## Error Classes

All errors extend `NLcURLError`, which extends `Error` and includes a machine-readable `code` property. All errors support `toJSON()` serialization.

### `NLcURLError`

```typescript
class NLcURLError extends Error {
  readonly code: string;
  constructor(message: string, code: string, cause?: Error);
  toJSON(): Record<string, unknown>;
}
```

### `TLSError`

TLS-level errors with optional alert code.

```typescript
class TLSError extends NLcURLError {
  readonly alertCode?: number;
  constructor(message: string, alertCode?: number, cause?: Error);
}
```

Code: `ERR_TLS`

### `HTTPError`

HTTP-level errors with status code.

```typescript
class HTTPError extends NLcURLError {
  readonly statusCode: number;
  constructor(message: string, statusCode: number, cause?: Error);
}
```

Code: `ERR_HTTP`

### `TimeoutError`

Timeout during a specific request phase.

```typescript
class TimeoutError extends NLcURLError {
  readonly phase: "connect" | "tls" | "response" | "total";
  constructor(message: string, phase: "connect" | "tls" | "response" | "total", cause?: Error);
}
```

Code: `ERR_TIMEOUT`

### `ProxyError`

Proxy connection or tunneling failure. Code: `ERR_PROXY`.

### `AbortError`

Request cancelled via `AbortSignal`. Code: `ERR_ABORTED`.

### `ConnectionError`

TCP or socket-level failure. Code: `ERR_CONNECTION`.

### `ProtocolError`

HTTP protocol violation with optional HTTP/2 error code.

```typescript
class ProtocolError extends NLcURLError {
  readonly errorCode?: number;
}
```

Code: `ERR_PROTOCOL`

### Error Code Reference

| Code | Class | Description |
|------|-------|-------------|
| `ERR_TLS` | `TLSError` | TLS handshake or record-layer failure |
| `ERR_HTTP` | `HTTPError` | Non-2xx status when `throwOnError` is enabled |
| `ERR_TIMEOUT` | `TimeoutError` | Per-phase timeout exceeded |
| `ERR_PROXY` | `ProxyError` | Proxy connection failure |
| `ERR_ABORTED` | `AbortError` | Request cancelled via AbortSignal |
| `ERR_CONNECTION` | `ConnectionError` | TCP/socket connection failure |
| `ERR_PROTOCOL` | `ProtocolError` | HTTP/2 protocol violation |
| `ERR_VALIDATION` | `NLcURLError` | Invalid request or configuration parameter |
| `ERR_SESSION_CLOSED` | `NLcURLError` | Request on a closed session |
| `ERR_UNKNOWN_PROFILE` | `NLcURLError` | Unrecognized browser profile name |

---

## Browser Fingerprints

### `getProfile(name)`

Resolves a browser profile by name. Names are normalized (lowercased, dashes/spaces stripped). Supports exact names (`"chrome136"`) and generic aliases (`"chrome"`).

```typescript
function getProfile(name: string): BrowserProfile | undefined
```

### `listProfiles()`

Returns all registered profile name strings.

```typescript
function listProfiles(): string[]
```

### `DEFAULT_PROFILE`

The default browser profile (`chrome_latest`).

```typescript
const DEFAULT_PROFILE: BrowserProfile
```

### `BrowserProfile`

```typescript
interface BrowserProfile {
  name: string;
  browser: "chrome" | "firefox" | "safari" | "edge" | "tor";
  version: string;
  tls: TLSProfile;
  h2: H2Profile;
  headers: HeaderProfile;
}
```

### `TLSProfile`

Defines the complete TLS ClientHello structure for fingerprint impersonation.

```typescript
interface TLSProfile {
  recordVersion: number;
  clientVersion: number;
  cipherSuites: number[];
  compressionMethods: number[];
  extensions: TLSExtensionDef[];
  supportedGroups: number[];
  signatureAlgorithms: number[];
  alpnProtocols: string[];
  grease: boolean;
  randomSessionId: boolean;
  certCompressAlgorithms?: number[];
  keyShareGroups: number[];
  pskKeyExchangeModes?: number[];
  supportedVersions: number[];
  ecPointFormats?: number[];
  delegatedCredentials?: number[];
  recordSizeLimit?: number;
  applicationSettings?: string[];
}
```

### `H2Profile`

Defines the HTTP/2 fingerprint structure (Akamai fingerprint components).

```typescript
interface H2Profile {
  settings: Array<{ id: number; value: number }>;
  windowUpdate: number;
  pseudoHeaderOrder: string[];
  priorityFrames?: Array<{ streamId: number; exclusive: boolean; dependsOn: number; weight: number }>;
  headerOrder?: string[];
}
```

### `HeaderProfile`

```typescript
interface HeaderProfile {
  headers: Array<[string, string]>;
  userAgent: string;
}
```

### Fingerprint Functions

#### `ja3Hash(profile)`

Computes the JA3 hash (MD5) of a TLS profile.

```typescript
function ja3Hash(profile: TLSProfile): string
```

#### `ja3String(profile)`

Returns the raw JA3 string (comma-separated fields: TLS version, cipher suites, extensions, groups, ec point formats). GREASE values are filtered out.

```typescript
function ja3String(profile: TLSProfile): string
```

#### `ja4Fingerprint(profile, hasSNI?)`

Computes the JA4 fingerprint (3-section, SHA-256 truncated).

```typescript
function ja4Fingerprint(profile: TLSProfile, hasSNI?: boolean): string
```

#### `ja4aSection(profile, hasSNI?)`

Returns only the `a` section of the JA4 fingerprint.

```typescript
function ja4aSection(profile: TLSProfile, hasSNI?: boolean): string
```

#### `akamaiFingerprint(profile)`

Computes the Akamai HTTP/2 fingerprint (settings, window update, priority frames, pseudo-header order).

```typescript
function akamaiFingerprint(profile: H2Profile): string
```

---

## TLS

### `TLSOptions`

Client certificate and pinning options.

```typescript
interface TLSOptions {
  cert?: string | Buffer;
  key?: string | Buffer;
  passphrase?: string;
  pfx?: Buffer;
  ca?: string | Buffer | Array<string | Buffer>;
  pinnedPublicKey?: string | string[];
}
```

The `pinnedPublicKey` field accepts SHA-256 SPKI pin(s) in the format `sha256//<base64>` per RFC 7469. A `TLSError` is thrown on mismatch.

### `TLSSessionCache`

LRU cache for TLS session tickets enabling session resumption.

```typescript
class TLSSessionCache {
  constructor(options?: SessionCacheOptions);
  set(origin: string, ticket: Buffer, lifetimeMs?: number, alpn?: string): void;
  get(origin: string): SessionTicketEntry | undefined;
  delete(origin: string): boolean;
  clear(): void;
  get size(): number;
}
```

Defaults: max 256 entries, 2-hour default lifetime.

The stealth TLS engine integrates with `TLSSessionCache` — pass it to the `StealthTLSEngine` constructor. Session tickets received via NewSessionTicket messages (RFC 8446 §4.6.1) are automatically stored, and PSKs are derived for subsequent session resumption.

### `ECHOptions`

```typescript
interface ECHOptions {
  enabled?: boolean;
  echConfigList?: Buffer | string;    // Base64-encoded ECHConfigList
  grease?: boolean;                   // Generate GREASE ECH if no real config
  maxRetries?: number;                // Max ECH retry attempts
}
```

### ECH Functions

```typescript
function parseECHConfigList(data: Buffer): ECHParameters | null;
function generateGreaseECH(): Buffer;
function parseECHRetryConfigs(data: Buffer): ECHParameters | null;
function shouldRetryECH(retryCount: number, maxRetries: number, retryConfigs: ECHParameters | null): boolean;
```

### OCSP Functions

```typescript
function parseOCSPResponse(derResponse: Buffer): OCSPResult;
function isOCSPValid(result: OCSPResult): boolean;
function validateOCSPStapling(socket: unknown, options?: { timeout?: number }): Promise<OCSPResult | undefined>;
```

### Certificate Transparency Functions

```typescript
function parseSCTList(data: Buffer): SCT[];
function validateSCTs(scts: SCT[]): SCTValidationResult;
function extractSCTsFromSocket(socket: unknown): SCTValidationResult | undefined;
```

### Early Data (0-RTT)

```typescript
function canSendEarlyData(method: string, config?: EarlyDataConfig): boolean;
function prepareEarlyData(requestData: Buffer, config?: EarlyDataConfig): Buffer | null;
function checkEarlyDataAccepted(socket: unknown): EarlyDataResult;
```

Safe methods for 0-RTT: GET, HEAD, OPTIONS. Default max size: 16384 bytes.

### Keylog

```typescript
function setKeylogFile(path: string | undefined): void;
function getKeylogFile(): string | undefined;
```

Outputs NSS Key Log format (compatible with Wireshark) to the specified file or the `SSLKEYLOGFILE` environment variable.

---

## Cookies

### `CookieJar`

RFC 6265-compliant cookie storage with Public Suffix List validation.

```typescript
class CookieJar {
  constructor(options?: { maxCookies?: number; maxCookiesPerDomain?: number });
  setCookies(headers: Record<string, string>, requestUrl: URL, rawHeaders?: Array<[string, string]>): void;
  getCookieHeader(url: URL, context?: {
    siteOrigin?: URL;
    isSameSite?: boolean;
    type?: "navigate" | "subresource";
    method?: string;
  }): string;
  clear(): void;
  clearDomain(domain: string): void;
  all(options?: { includeHttpOnly?: boolean }): ReadonlyArray<Cookie>;
  get size(): number;
  toNetscapeString(): string;
  loadNetscapeString(content: string): void;
}
```

Defaults: max 3000 cookies total, 180 per domain. Enforces `__Host-` and `__Secure-` prefix rules. `SameSite` defaults to `"lax"`. Supports `Partitioned` cookies (CHIPS). LRU eviction targets the domain with the most cookies first.

**`all()` security:** By default, `all()` excludes `httpOnly` cookies to prevent accidental exposure to client-side code. Pass `{ includeHttpOnly: true }` to include them.

**`loadNetscapeString()` validation:** Validates `__Host-` and `__Secure-` prefix constraints, caps expiry to 400 days, skips expired cookies, and rejects domains without a dot (except localhost).

The optional `context` parameter on `getCookieHeader()` enables SameSite enforcement: `Strict` cookies are excluded on cross-site requests, `Lax` cookies are only sent on top-level navigations with safe methods, and `None` cookies require the `Secure` flag. The parser rejects `SameSite=None` cookies that lack the `Secure` attribute (RFC 6265bis §4.1.2.7).

### Public Suffix Functions

```typescript
function isPublicSuffix(domain: string): boolean;
function getRegistrableDomain(hostname: string): string | null;
```

Uses a trie-based lookup against the Mozilla Public Suffix List, supporting exact rules, wildcard rules, and exception rules.

---

## Cache

### `CacheStore`

In-memory HTTP cache implementing RFC 9111.

```typescript
class CacheStore {
  constructor(config?: CacheConfig);
  static cacheKey(method: string, url: string): string;
  evaluate(req: NLcURLRequest, modeOverride?: CacheMode): CacheDecision;
  store(req: NLcURLRequest, response: NLcURLResponse): void;
  mergeNotModified(entry: CacheEntry, response304: NLcURLResponse): NLcURLResponse;
  responseFromEntry(entry: CacheEntry, req: NLcURLRequest): NLcURLResponse;
  delete(method: string, url: string): boolean;
  clear(): void;
  get size(): number;
  get totalSize(): number;
}
```

Defaults: max 1000 entries, 50 MB total size. Cacheable methods: GET, HEAD. Cacheable status codes: 200, 203, 204, 206, 300, 301, 308, 404, 405, 410, 414, 501.

**RFC 9111 compliance features:**
- **Multi-variant Vary:** Stores multiple response variants per URL based on `Vary` header values.
- **`s-maxage` priority:** Shared cache directive takes precedence over `max-age` for freshness.
- **`must-revalidate`:** Stale responses are never served without revalidation.
- **`no-cache`:** Stored but always revalidated before use.
- **Age header:** Responses include a corrected `Age` header (initial age + resident time).
- **Request Cache-Control:** Honors `max-age`, `min-fresh`, `max-stale`, `no-store`, and `no-cache` directives from the request.
- **Unsafe method invalidation:** POST, PUT, DELETE, and PATCH requests invalidate matching cached entries.
- **LRU eviction across variants:** Size-based eviction considers all variants for each key.

```typescript
function parseCacheControl(value: string): CacheDirectives;
```

### `CacheMode`

```typescript
type CacheMode = "default" | "no-store" | "no-cache" | "force-cache" | "only-if-cached";
```

- `"default"` — Serve fresh cached responses; conditionally revalidate stale ones.
- `"no-store"` — Never read from or write to the cache.
- `"no-cache"` — Always revalidate with the origin server.
- `"force-cache"` — Serve cached responses regardless of freshness.
- `"only-if-cached"` — Return cached response or 504 Gateway Timeout.

### `CacheConfig`

```typescript
interface CacheConfig {
  enabled?: boolean;
  maxEntries?: number;     // Default: 1000
  maxSize?: number;        // Default: 50 MB
  mode?: CacheMode;
}
```

### `RangeCache`

Caches partial content (byte-range responses) with segment management.

```typescript
class RangeCache {
  constructor(config?: { maxEntries?: number; maxSegmentsPerEntry?: number });
  store(url: string, range: ContentRange, data: Buffer, meta?: object): void;
  lookup(url: string, start: number, end: number): Buffer | null;
  isComplete(url: string): boolean;
  get size(): number;
  clear(): void;
}
```

```typescript
function parseContentRange(header: string): ContentRange | null;
function parseRangeHeader(header: string): Array<[number, number | undefined]> | null;
```

### No-Vary-Search

```typescript
function parseNoVarySearch(header: string): NoVarySearchDirective | null;
function urlsMatchWithNoVarySearch(cachedUrl: string, requestUrl: string, directive: NoVarySearchDirective): boolean;
function normalizeUrlForCache(url: string, directive: NoVarySearchDirective): string;
```

### Cache Groups

```typescript
class CacheGroupStore {
  addToGroups(cacheKey: string, groupNames: string[]): void;
  removeFromAll(cacheKey: string): void;
  invalidate(groupName: string): string[];
  invalidateAll(): string[];
  isInvalidatedSince(cacheKey: string, storedAt: number): boolean;
  get size(): number;
  clear(): void;
}

function parseCacheGroups(header: string): string[];
```

---

## HSTS

### `HSTSStore`

RFC 6797 HTTP Strict Transport Security implementation.

```typescript
class HSTSStore {
  constructor(config?: HSTSConfig);
  parseHeader(host: string, value: string, isSecure: boolean): void;
  isSecure(host: string): boolean;
  upgradeURL(urlString: string): string;
  toJSON(): string;
  loadJSON(json: string): void;
  get size(): number;
  clear(): void;
}
```

Ignores HSTS headers from non-secure origins and IP addresses. `max-age=0` removes the policy. Supports `includeSubDomains` with domain hierarchy walking. Preloaded entries use a 20-year expiration.

**Persistence:** Use `toJSON()` to serialize the policy store to disk and `loadJSON()` to restore it. Expired entries are automatically excluded during serialization.

```typescript
interface HSTSConfig {
  enabled?: boolean;
  preload?: HSTSPreloadEntry[];
}

interface HSTSPreloadEntry {
  host: string;
  includeSubDomains?: boolean;
}
```

---

## DNS

### `DoHResolver`

DNS-over-HTTPS resolver using wire-format queries (RFC 8484).

```typescript
class DoHResolver {
  constructor(config: DoHConfig);
  query(name: string, type: "A" | "AAAA" | "HTTPS" | "SVCB", signal?: AbortSignal): Promise<DNSRecord[]>;
  getCache(): DNSCache;
}
```

Supports both GET (base64url query parameter) and POST (binary body) methods. Bootstraps the DoH server's own hostname via system DNS to avoid circular dependency. Default timeout: 5 seconds. Max response: 64 KB. Uses EDNS(0) with padding by default to improve DNS privacy (RFC 6891, RFC 7830).

```typescript
interface DoHConfig {
  server: string;
  method?: "GET" | "POST";
  timeout?: number;
  bootstrap?: boolean;
  cache?: DNSCacheConfig;
}
```

### `DoTResolver`

DNS-over-TLS resolver (RFC 7858).

```typescript
class DoTResolver {
  constructor(config?: DoTConfig);
  resolve(name: string, type?: number): Promise<DNSRecord[]>;
  resolve4(name: string): Promise<string[]>;
  resolve6(name: string): Promise<string[]>;
  close(): void;
}
```

Default: Cloudflare (`1.1.1.1`, port 853). Supports persistent TLS connections.

Pre-configured servers available via `DOT_SERVERS`:

| Key | Server | Provider |
|-----|--------|----------|
| `cloudflare` | `1.1.1.1` | Cloudflare |
| `cloudflare-ipv6` | `2606:4700:4700::1111` | Cloudflare |
| `google` | `8.8.8.8` | Google |
| `google-ipv6` | `2001:4860:4860::8888` | Google |
| `quad9` | `9.9.9.9` | Quad9 |
| `adguard` | `94.140.14.14` | AdGuard |

### `HTTPSRRResolver`

Resolves SVCB/HTTPS DNS Resource Records (RFC 9460).

```typescript
class HTTPSRRResolver {
  constructor(dohConfig?: DoHConfig, logger?: Logger);
  resolve(hostname: string, signal?: AbortSignal): Promise<HTTPSRRResult | null>;
}
```

```typescript
interface HTTPSRRResult {
  svcb: SVCBRecord[];
  echConfigList?: Buffer;
  alpn?: string[];
  addresses: ResolvedAddress[];
  port?: number;
}
```

### `DNSCache`

TTL-aware LRU DNS cache.

```typescript
class DNSCache {
  constructor(config?: DNSCacheConfig);
  get(name: string, type: string): DNSRecord[] | undefined;
  set(name: string, type: string, records: DNSRecord[]): void;
  clear(): void;
  get size(): number;
}
```

Defaults: max 500 entries, min TTL 30s, max TTL 86400s (24h).

---

## Proxy

### Environment Variable Resolution

```typescript
function resolveEnvProxy(url: string): string | undefined
```

Checks `HTTP_PROXY`/`http_proxy`, `HTTPS_PROXY`/`https_proxy`, and `ALL_PROXY`/`all_proxy` based on URL scheme. Respects `NO_PROXY`/`no_proxy` with wildcard (`*`), domain suffix, and exact match support.

### Proxy Authentication

```typescript
function parseProxyAuthenticate(header: string): { scheme: ProxyAuthScheme; challenge: string } | null;
function parseDigestChallenge(challenge: string): DigestChallenge | null;
function buildDigestAuth(method: string, uri: string, auth: ProxyAuthConfig, challenge: DigestChallenge): string;
function buildBasicProxyAuth(auth: ProxyAuthConfig): string;
function buildProxyAuthorization(method: string, uri: string, auth: ProxyAuthConfig, proxyAuthHeader?: string): string | null;
```

Supports Basic (RFC 7617) and Digest (RFC 7616) proxy authentication with MD5 and SHA-256 algorithms.

---

## WebSocket

### `WebSocketClient`

RFC 6455 WebSocket client with optional TLS fingerprinting and per-message deflate compression.

```typescript
class WebSocketClient extends EventEmitter {
  readonly url: string;
  state: WebSocketState;
  protocol: string;

  constructor(url: string, options?: WebSocketOptions);
  sendText(data: string): void;
  sendBinary(data: Buffer): void;
  ping(data?: Buffer): void;
  close(code?: number, reason?: string): void;
}
```

The `close()` method validates the close code: only `1000` and `3000`–`4999` are allowed. Invalid codes throw `ERR_WS_INVALID_CLOSE_CODE`. Custom headers are validated to reject values containing CR, LF, or NUL characters (`ERR_VALIDATION`).

Control frames (ping, pong, close) are validated to have payloads ≤ 125 bytes per RFC 6455 §5.5. Oversized control frames are rejected with a protocol error.

**Events:**

| Event | Arguments | Description |
|-------|-----------|-------------|
| `open` | — | Connection established |
| `message` | `data: string \| Buffer`, `isBinary: boolean` | Message received |
| `close` | `code: number`, `reason: string` | Connection closed |
| `error` | `error: Error` | Error occurred |
| `ping` | `data: Buffer` | Ping frame received |
| `pong` | `data: Buffer` | Pong frame received |

```typescript
interface WebSocketOptions {
  impersonate?: string;
  stealth?: boolean;
  headers?: Record<string, string>;
  protocols?: string[];
  insecure?: boolean;
  timeout?: number;
  compress?: boolean;     // Enable permessage-deflate (RFC 7692)
}
```

### Per-Message Deflate

```typescript
class PerMessageDeflate {
  constructor(params: DeflateParams);
  decompress(data: Buffer): Promise<Buffer>;
  compress(data: Buffer): Promise<Buffer>;
  close(): void;
}

function buildDeflateOffer(): string;
function parseDeflateResponse(header: string): DeflateParams | null;
```

---

## Server-Sent Events

### `SSEParser`

W3C EventSource-compliant parser.

```typescript
class SSEParser {
  static readonly MAX_LINE_LENGTH: number;     // 65536
  static readonly MAX_EVENT_SIZE: number;       // 1048576 (1 MB)

  feed(text: string): void;
  pull(): ServerSentEvent | null;
  flush(): void;
}
```

The parser automatically strips a leading UTF-8 BOM (U+FEFF) on the first `feed()` call. It handles `\r\n`, `\r`, and `\n` line endings, including `\r\n` split across chunk boundaries.

### `parseSSEStream(stream)`

```typescript
function parseSSEStream(stream: Readable): AsyncGenerator<ServerSentEvent, void, undefined>
```

```typescript
interface ServerSentEvent {
  event: string;
  data: string;
  id: string;
  retry?: number;
}
```

### `SSEClient`

EventSource-compatible SSE client with automatic reconnection and `Last-Event-ID` tracking per the WHATWG EventSource specification.

```typescript
class SSEClient extends EventEmitter {
  constructor(url: string, options: SSEClientOptions);
  state: "connecting" | "open" | "closed";
  readonly url: string;
  close(): void;
}

interface SSEClientOptions {
  headers?: Record<string, string>;
  retryMs?: number;           // Default: 3000
  maxRetries?: number;        // Default: Infinity
  fetch: (url: string, headers: Record<string, string>) => Promise<SSEFetchResult>;
}

interface SSEFetchResult {
  status: number;
  headers: Record<string, string>;
  body: AsyncIterable<Buffer | string>;
}
```

**Events:**
- `"event"` — `(event: ServerSentEvent)` — Fired for each received SSE event.
- `"open"` — `()` — Connection established.
- `"error"` — `(error: Error)` — Connection error (before reconnect).
- `"close"` — `()` — Client closed.

Reconnects automatically on network errors and non-4xx server errors, sending `Last-Event-ID` if one was received. Respects the server's `retry:` field to adjust delay between attempts.
```

---

## Security Utilities

### `verifyIntegrity(body, integrity)`

Subresource Integrity (SRI) verification per the W3C spec. Supports `sha256`, `sha384`, and `sha512` with base64 encoding.

```typescript
function verifyIntegrity(body: Buffer, integrity: string): boolean
```

Accepts space-separated integrity strings — returns `true` if any hash matches.

### `ReferrerPolicy`

W3C Referrer-Policy implementation with all 8 policy values.

```typescript
type ReferrerPolicy =
  | "no-referrer"
  | "no-referrer-when-downgrade"
  | "origin"
  | "origin-when-cross-origin"
  | "same-origin"
  | "strict-origin"
  | "strict-origin-when-cross-origin"
  | "unsafe-url";

function parseReferrerPolicy(header: string): ReferrerPolicy;
function computeReferrer(from: URL, to: URL, policy: ReferrerPolicy): string;
```

`parseReferrerPolicy` interprets comma-separated values per the spec (last recognized token wins). `computeReferrer` returns the Referer header value (or empty string to suppress). Automatically integrated into session redirect handling.

### XSRF/CSRF Protection

Configure `xsrfCookieName` and `xsrfHeaderName` on a session to automatically extract the named cookie and inject it as a request header:

```typescript
const session = createSession({
  xsrfCookieName: "XSRF-TOKEN",
  xsrfHeaderName: "X-XSRF-TOKEN",
});
```

---

## HTTP Utilities

### `FormData`

Multipart form-data encoder (RFC 7578).

```typescript
class FormData {
  append(name: string, value: FormValue): this;
  get contentType(): string;
  getBoundary(): string;
  encode(): Buffer;
}

type FormValue = string | FormFile;

interface FormFile {
  data: Buffer;
  filename: string;
  contentType?: string;     // Default: "application/octet-stream"
}
```

### Alt-Svc

```typescript
class AltSvcStore {
  constructor(config?: AltSvcConfig);
  parseHeader(origin: string, headerValue: string): void;
  lookup(origin: string): AltSvcEntry | undefined;
  toJSON(): string;
  loadJSON(json: string): void;
  clear(origin: string): void;
  clearAll(): void;
  get size(): number;
}
```

### Early Hints

```typescript
function parseLinkHeader(linkHeader: string): EarlyHint[];

interface EarlyHint {
  uri: string;
  rel?: string;
  as?: string;
  type?: string;
  crossorigin?: string;
}
```

### HTTP Trailers

```typescript
function isValidTrailerField(name: string): boolean;
function serializeTrailers(trailers: Record<string, string>): Buffer;
function parseTrailers(data: Buffer): Record<string, string>;
function buildTrailerHeader(fieldNames: string[]): string;
```

### Resumable Upload

Implements draft-ietf-httpbis-resumable-upload (interop version 7).

```typescript
function buildUploadCreationHeaders(totalSize: number, contentType?: string): Record<string, string>;
function buildUploadResumeHeaders(offset: number, chunkSize: number, isLast: boolean): Record<string, string>;
function buildUploadOffsetHeaders(): Record<string, string>;
function parseUploadOffset(headers: Record<string, string>): number;
function isUploadComplete(headers: Record<string, string>): boolean;
function splitIntoChunks(data: Buffer, chunkSize?: number): Array<[number, Buffer]>;
function parseUploadUrl(headers: Record<string, string>, requestUrl: string): string | null;
```

Default chunk size: 5 MB.

### Compression

```typescript
function compressBody(body: Buffer, encoding: RequestEncoding): Promise<Buffer>;
function shouldCompress(bodySize: number): boolean;   // Threshold: ≥ 1024 bytes

type RequestEncoding = "gzip" | "deflate" | "br";
```

### Dictionary Transport

Implements draft-ietf-httpbis-compression-dictionary.

```typescript
class DictionaryStore {
  constructor(config?: DictionaryConfig);
  store(url: string, data: Buffer, metadata?: object, maxAge?: number): void;
  findForUrl(requestUrl: string): CompressionDictionary | undefined;
  getByHash(hash: string): CompressionDictionary | undefined;
  get size(): number;
  clear(): void;
}

function parseUseAsDictionary(header: string): { match?: string; matchDest?: string; id?: string } | null;
function computeDictionaryHash(data: Buffer): string;
function buildAvailableDictionaryHeader(hash: string): string;
function buildDictionaryAcceptEncoding(existingEncoding?: string): string;
```

### TCP Fast Open

```typescript
function isTFOSupported(): boolean;           // true on Linux and macOS
function buildTFOSocketOptions(tfo?: TFOOptions): Record<string, unknown>;
function getTFOStatus(): { supported: boolean; platform: string };
```

---

## Middleware

### Interceptors

```typescript
type RequestInterceptor = (request: NLcURLRequest) => NLcURLRequest | Promise<NLcURLRequest>;
type ResponseInterceptor = (response: NLcURLResponse) => NLcURLResponse | Promise<NLcURLResponse>;
```

Interceptors execute sequentially in registration order. Each interceptor receives the output of the previous one.

### Rate Limiter

```typescript
interface RateLimitConfig {
  maxRequests: number;
  windowMs: number;
}
```

Token-bucket algorithm with full batch refill per time window. When tokens are exhausted, requests are queued and drained automatically after the next refill.

### Retry-After Parsing

```typescript
function parseRetryAfter(value: string): number | undefined;
function getRetryAfterMs(headers: Record<string, string>): number | undefined;
```

Supports both integer seconds and HTTP-date formats per RFC 7231.

### Circuit Breaker

Per-origin circuit breaker for preventing cascading failures.

```typescript
const enum CircuitState {
  CLOSED = 0,
  OPEN = 1,
  HALF_OPEN = 2,
}

interface CircuitBreakerConfig {
  failureThreshold: number;           // Consecutive failures before opening
  resetTimeoutMs: number;             // Time in ms before allowing a probe
  successThreshold?: number;          // Successful probes to close (default: 1)
  isFailure?: (statusCode: number) => boolean;  // Failure predicate (default: status >= 500)
}

class CircuitBreaker {
  constructor(config: CircuitBreakerConfig);
  allowRequest(origin: string): void;          // Throws if circuit is open
  recordSuccess(origin: string): void;
  recordFailure(origin: string): void;
  recordResponse(origin: string, statusCode: number): void;
  getState(origin: string): CircuitState;
  reset(origin: string): void;
  resetAll(): void;
}
```

**States:**
- `CLOSED` — Requests flow normally. Failures are counted.
- `OPEN` — Requests fail fast with `ERR_CIRCUIT_OPEN`. After `resetTimeoutMs`, transitions to HALF_OPEN.
- `HALF_OPEN` — A single probe request is allowed. On success, transitions to CLOSED. On failure, transitions back to OPEN.

---

## Logging

### `Logger` Interface

```typescript
interface Logger {
  debug(message: string, ...args: unknown[]): void;
  info(message: string, ...args: unknown[]): void;
  warn(message: string, ...args: unknown[]): void;
  error(message: string, ...args: unknown[]): void;
}
```

### `ConsoleLogger`

Outputs to stderr in the format `[nlcurl:component:level] message`.

```typescript
class ConsoleLogger implements Logger {
  constructor(level?: LogLevel, prefix?: string, bindings?: LogBindings);
  child(bindings: LogBindings): ConsoleLogger;
  setLevel(level: LogLevel): void;
}
```

### `JsonLogger`

Outputs structured JSON to stderr.

```typescript
class JsonLogger implements Logger {
  constructor(level?: LogLevel, service?: string, bindings?: LogBindings);
  child(bindings: LogBindings): JsonLogger;
  setLevel(level: LogLevel): void;
}
```

### `SILENT_LOGGER`

A no-op logger that discards all messages.

### `setDefaultLogger(logger)` / `getDefaultLogger()`

Get or set the process-wide default logger. Sessions created without an explicit logger use the default (initially `ConsoleLogger("warn")`).