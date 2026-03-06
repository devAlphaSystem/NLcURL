# API Reference

This document describes the public API exported by `nlcurl` (`src/index.ts`).

## Imports

```ts
import { createSession, request, get, post, put, patch, del, head, NLcURLSession, NLcURLResponse, NLcURLError, TimeoutError, ConnectionError, ProtocolError, CookieJar, getProfile, listProfiles, ja3Hash, ja3String } from "nlcurl";
```

## Core Types

### `HttpMethod`

```ts
type HttpMethod = "GET" | "POST" | "PUT" | "PATCH" | "DELETE" | "HEAD" | "OPTIONS";
```

### `TimeoutConfig`

```ts
interface TimeoutConfig {
  connect?: number;
  tls?: number;
  response?: number;
  total?: number;
}
```

All values are milliseconds.

### `RetryConfig`

```ts
interface RetryConfig {
  count: number;
  delay: number;
  backoff: "linear" | "exponential";
  jitter: number;
  retryOn?: (error: Error | null, statusCode?: number) => boolean;
}
```

`RetryConfig` is used by `NLcURLSession` when `retry.count > 0` is set in the session config. The session automatically wraps request execution with `withRetry()`, supporting exponential/linear backoff, jitter, and custom retry predicates.

### `NLcURLRequest`

```ts
interface NLcURLRequest {
  url: string;
  method?: HttpMethod;
  headers?: Record<string, string>;
  body?: string | Buffer | URLSearchParams | Record<string, unknown> | ReadableStream<Uint8Array> | null;
  // When body is a plain object and no Content-Type is set, it is serialized with
  // JSON.stringify() and Content-Type defaults to "application/json".
  // String bodies default to "text/plain; charset=utf-8".
  // URLSearchParams bodies default to "application/x-www-form-urlencoded".
  // Buffer and stream bodies have no default Content-Type.
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
  cookieJar?: boolean | string;
  // Per-request cookieJar is forwarded to the temporary session when using
  // one-shot functions (request(), get(), post(), etc.).

  acceptEncoding?: string;
  headerOrder?: string[];

  stream?: boolean;
  dnsFamily?: 4 | 6;
}
```

### `NLcURLSessionConfig`

```ts
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
  httpVersion?: "1.1" | "2";
  cookieJar?: boolean | string;
  retry?: Partial<RetryConfig>;
  acceptEncoding?: string;
  dnsFamily?: 4 | 6;
}
```

### `NLcURLResponse<T = unknown>`

Key members:

- `status: number`
- `statusText: string`
- `headers: Record<string, string>` — lowercased keys, combined values
- `rawHeaders: Array<[string, string]>` — header name-value pairs in original transmission order with **original casing preserved** (e.g. `Content-Type`, not `content-type`); use `getAll()` to retrieve individual `Set-Cookie` values without comma-joining
- `rawBody: Buffer`
- `body: Readable | null` — populated when `stream: true` was set on the request; `null` otherwise
- `httpVersion: string`
- `url: string`
- `redirectCount: number`
- `timings: RequestTimings` — all values in milliseconds:
  - `dns` — time spent resolving the hostname
  - `connect` — time to establish the TCP connection
  - `tls` — time to complete the TLS handshake
  - `firstByte` — time from sending the request to receiving the first response byte
  - `total` — total wall-clock time for the entire request
- `request: ResponseMeta`
- `ok: boolean`
- `text(): string` — throws if response is streaming
- `json<R = T>(): R` — throws if response is streaming
- `getAll(name: string): string[]` — returns all raw header values for a given name (case-insensitive); avoids multi-value collapse for `Set-Cookie`
- `contentLength: number`
- `contentType: string`

## Client Functions

### `createSession(config?)`

```ts
function createSession(config?: NLcURLSessionConfig): NLcURLSession;
```

Creates a persistent session with shared defaults and connection reuse.

### `request(input)`

```ts
function request(input: NLcURLRequest): Promise<NLcURLResponse>;
```

Executes a one-shot request using a temporary session.

### Convenience methods

```ts
get(url, options?)
post(url, body?, options?)
put(url, body?, options?)
patch(url, body?, options?)
del(url, options?)
head(url, options?)
```

Each method returns `Promise<NLcURLResponse>`.

## Session API

### `class NLcURLSession`

#### Request methods

- `request(input: NLcURLRequest)`
- `get(url, options?)`
- `post(url, body?, options?)`
- `put(url, body?, options?)`
- `patch(url, body?, options?)`
- `delete(url, options?)`
- `head(url, options?)`
- `options(url, options?)`

#### Middleware methods

- `onRequest(fn: RequestInterceptor): this`
- `onResponse(fn: ResponseInterceptor): this`
- `setRateLimit(config: RateLimitConfig): this`

#### Cookie and lifecycle methods

- `getCookies(): CookieJar | null`
- `close(): void`

## Error Types

All typed errors inherit from `NLcURLError`.

- `NLcURLError` (`code`)
- `TLSError` (`alertCode?`)
- `HTTPError` (`statusCode`)
- `TimeoutError` (`phase`: `connect | tls | response | total`)
- `ProxyError`
- `AbortError`
- `ConnectionError`
- `ProtocolError` (`errorCode?: number` — numeric H2 RST_STREAM/GOAWAY code when applicable)

## Fingerprint API

### Profile lookup

- `getProfile(name: string): BrowserProfile | undefined`
- `listProfiles(): string[]`
- `DEFAULT_PROFILE: BrowserProfile`

### JA3 and Akamai helpers

- `ja3String(profile: TLSProfile): string`
- `ja3Hash(profile: TLSProfile): string`
- `akamaiFingerprint(profile: H2Profile): string`

## Middleware and Cookies

### Interceptor types

```ts
type RequestInterceptor = (request: NLcURLRequest) => NLcURLRequest | Promise<NLcURLRequest>;
type ResponseInterceptor = (response: NLcURLResponse) => NLcURLResponse | Promise<NLcURLResponse>;
```

### Rate limiter

```ts
interface RateLimitConfig {
  maxRequests: number;
  windowMs: number;
}
```

### Cookie jar

`CookieJar` is exported for direct use when needed.

Methods:

- `setCookies(headers, requestUrl, rawHeaders?)` — store cookies from response headers
- `getCookieHeader(url): string` — get Cookie header value for a request URL
- `clear()` — remove all cookies
- `clearDomain(domain)` — remove cookies for a specific domain
- `all(): ReadonlyArray<Cookie>` — get all stored cookies
- `toNetscapeString(): string` — serialize all cookies in Netscape cookie-jar format (compatible with curl `--cookie-jar`)
- `loadNetscapeString(content: string)` — load cookies from Netscape cookie-jar format string
- `size: number` — number of stored cookies

## WebSocket API

### `WebSocketClient`

```ts
new WebSocketClient(url: string, options?: WebSocketOptions)
```

Methods:

- `sendText(data: string)`
- `sendBinary(data: Buffer)`
- `ping(data?: Buffer)`
- `close(code?: number, reason?: string)`

State and properties:

- `state: 'connecting' | 'open' | 'closing' | 'closed'`
- `protocol: string`
- `url: string`

Events:

- `open`
- `message(data, isBinary)`
- `close(code, reason)`
- `error(error)`
- `ping(data)`
- `pong(data)`
