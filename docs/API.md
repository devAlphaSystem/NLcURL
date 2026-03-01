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

`RetryConfig` is part of configuration types and middleware helper API. See integration status in `README.md`.

### `NLcURLRequest`

```ts
interface NLcURLRequest {
  url: string;
  method?: HttpMethod;
  headers?: Record<string, string>;
  body?: string | Buffer | URLSearchParams | Record<string, unknown> | ReadableStream<Uint8Array> | null;
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

  acceptEncoding?: string;
  headerOrder?: string[];
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
}
```

### `NLcURLResponse<T = unknown>`

Key members:

- `status: number`
- `statusText: string`
- `headers: Record<string, string>`
- `rawHeaders: Array<[string, string]>`
- `rawBody: Buffer`
- `httpVersion: string`
- `url: string`
- `redirectCount: number`
- `timings: RequestTimings`
- `request: ResponseMeta`
- `ok: boolean`
- `text(): string`
- `json<R = T>(): R`
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
- `ProtocolError`

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
