# Configuration Reference

Complete reference for all NLcURL configuration options, their defaults, and valid values.

---

## Table of Contents

- [Request Options](#request-options)
- [Session Options](#session-options)
- [TLS Options](#tls-options)
- [Timeout Options](#timeout-options)
- [Retry Options](#retry-options)
- [Cache Options](#cache-options)
- [HSTS Options](#hsts-options)
- [DNS Options](#dns-options)
- [ECH Options](#ech-options)
- [Proxy Options](#proxy-options)
- [Cookie Options](#cookie-options)
- [Rate Limiting](#rate-limiting)
- [Logging](#logging)
- [Connection Pool](#connection-pool)
- [CLI Flags](#cli-flags)
- [Environment Variables](#environment-variables)

---

## Request Options

Options that can be set on individual requests via `NLcURLRequest`.

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `url` | `string` | *required* | Target URL. Must use `http:` or `https:` scheme. |
| `method` | `HttpMethod` | `"GET"` | HTTP method. Valid: `GET`, `POST`, `PUT`, `PATCH`, `DELETE`, `HEAD`, `OPTIONS`, `QUERY`. |
| `headers` | `Record<string, string>` | `{}` | Request headers. Keys are lowercased internally. Validated against RFC 7230 token syntax. |
| `body` | `RequestBody` | `null` | Request body. Accepts `string`, `Buffer`, `URLSearchParams`, objects (JSON), `ReadableStream`, or `FormData`. |
| `timeout` | `number \| TimeoutConfig` | Session default | Timeout in ms or per-phase config. |
| `signal` | `AbortSignal` | — | Abort signal for request cancellation. |
| `impersonate` | `string` | Session default | Browser profile name for TLS/HTTP/2 fingerprinting. |
| `ja3` | `string` | — | Custom JA3 fingerprint string. |
| `akamai` | `string` | — | Custom Akamai HTTP/2 fingerprint string. |
| `stealth` | `boolean` | `false` | Use the custom stealth TLS engine instead of Node.js TLS. |
| `followRedirects` | `boolean` | `true` | Automatically follow HTTP redirects (301, 302, 303, 307, 308). |
| `maxRedirects` | `number` | `20` | Maximum number of redirects to follow. |
| `insecure` | `boolean` | `false` | Skip TLS certificate verification. |
| `proxy` | `string` | Auto-detected | Proxy URL. Supports `http://`, `https://`, `socks4://`, `socks5://`. |
| `proxyAuth` | `[string, string]` | — | Proxy credentials as `[username, password]`. |
| `httpVersion` | `"1.1" \| "2" \| "3"` | Auto (ALPN) | Force a specific HTTP protocol version. |
| `baseURL` | `string` | Session default | Base URL for relative URL resolution. |
| `params` | `Record<string, string \| number \| boolean>` | — | Query parameters appended to the URL. `null`/`undefined` values are skipped. |
| `cookieJar` | `boolean \| string \| CookieJar` | `true` | Cookie storage. `true` creates a new jar, `false` disables cookies, or pass an existing `CookieJar`. |
| `acceptEncoding` | `string` | `"gzip, deflate, br, zstd"` | Accept-Encoding header value. `zstd` is automatically stripped if Node.js doesn't support it. |
| `headerOrder` | `string[]` | — | Custom header ordering for wire-level control. |
| `dnsFamily` | `4 \| 6` | Auto | DNS address family preference. |
| `stream` | `boolean` | `false` | Return a streaming response. When `true`, `response.body` is a `Readable` stream. |
| `logger` | `Logger` | Session default | Logger instance for this request. |
| `tls` | `TLSOptions` | — | TLS client certificate and pinning options. |
| `dns` | `DNSConfig` | — | DNS-over-HTTPS configuration. |
| `ech` | `ECHOptions` | — | Encrypted Client Hello configuration. |
| `auth` | `AuthConfig` | — | HTTP authentication (Basic, Bearer, Digest, or AWS SigV4). |
| `cache` | `CacheMode` | `"default"` | Cache mode for this request. |
| `range` | `string` | — | Range header value (e.g., `"bytes=0-499"`). |
| `onUploadProgress` | `ProgressCallback` | — | Called during request body upload. |
| `onDownloadProgress` | `ProgressCallback` | — | Called after response body download. |
| `onEarlyHints` | `EarlyHintsCallback` | — | Called when 103 Early Hints are received. |
| `throwOnError` | `boolean` | `false` | Throw `HTTPError` on non-2xx status codes. |
| `expect100Continue` | `boolean` | `false` | Send `Expect: 100-continue` header before the body. |
| `compressBody` | `RequestEncoding` | — | Compress the request body. Valid: `"gzip"`, `"deflate"`, `"br"`. Only applied to bodies ≥ 1024 bytes. |
| `methodOverride` | `"QUERY"` | — | Send as POST with `X-HTTP-Method-Override: QUERY` header. |
| `blockPrivateIPs` | `boolean` | `false` | Block requests to private/reserved IP addresses (SSRF protection). Also enforced on redirect targets. |
| `blockDangerousPorts` | `boolean` | `false` | Block requests to dangerous ports from the WHATWG blocklist. Also enforced on redirect targets. |

---

## Session Options

Options set on `NLcURLSessionConfig` that apply as defaults to all requests in a session.

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `baseURL` | `string` | — | Base URL for resolving relative URLs. |
| `headers` | `Record<string, string>` | `{}` | Default headers merged into every request. |
| `timeout` | `number \| TimeoutConfig` | — | Default timeout for all requests. |
| `impersonate` | `string` | — | Default browser profile. |
| `ja3` | `string` | — | Default JA3 fingerprint. |
| `akamai` | `string` | — | Default Akamai fingerprint. |
| `stealth` | `boolean` | `false` | Use stealth TLS engine for all requests. |
| `proxy` | `string` | — | Default proxy URL. |
| `proxyAuth` | `[string, string]` | — | Default proxy credentials. |
| `followRedirects` | `boolean` | `true` | Follow redirects by default. |
| `maxRedirects` | `number` | `20` | Max redirects for all requests. |
| `insecure` | `boolean` | `false` | Skip TLS verification for all requests. |
| `httpVersion` | `"1.1" \| "2" \| "3"` | Auto | Default HTTP version. |
| `cookieJar` | `boolean \| string \| CookieJar` | `true` | Session-wide cookie storage. |
| `retry` | `Partial<RetryConfig>` | — | Automatic retry configuration. |
| `acceptEncoding` | `string` | Auto-detected | Default Accept-Encoding value. |
| `dnsFamily` | `4 \| 6` | Auto | Default DNS family. |
| `logger` | `Logger` | `ConsoleLogger("warn")` | Session logger. |
| `tls` | `TLSOptions` | — | Default TLS options. |
| `throwOnError` | `boolean` | `false` | Throw on non-2xx responses. |
| `onUploadProgress` | `ProgressCallback` | — | Default upload progress callback. |
| `onDownloadProgress` | `ProgressCallback` | — | Default download progress callback. |
| `cacheConfig` | `CacheConfig` | — | Cache store configuration. |
| `hsts` | `HSTSConfig` | — | HSTS store configuration. |
| `dns` | `DNSConfig` | — | DNS configuration. |
| `ech` | `ECHOptions` | — | ECH configuration. |
| `altSvc` | `boolean` | `true` | Enable Alt-Svc tracking and protocol upgrades. |
| `auth` | `AuthConfig` | — | Default authentication (Basic, Bearer, Digest, or AWS SigV4). |
| `compressBody` | `RequestEncoding` | — | Default request body compression. |
| `blockPrivateIPs` | `boolean` | `false` | Block all requests (including redirects) to private/reserved IPs. |
| `blockDangerousPorts` | `boolean` | `false` | Block all requests (including redirects) to dangerous ports. |

**Merge precedence:** Request-level options always override session-level defaults. Headers are merged with request headers taking precedence over session headers.

---

## TLS Options

```typescript
interface TLSOptions {
  cert?: string | Buffer;        // Client certificate (PEM or DER)
  key?: string | Buffer;         // Client private key (PEM or DER)
  passphrase?: string;           // Private key passphrase
  pfx?: Buffer;                  // PKCS#12 bundle
  ca?: string | Buffer | Array<string | Buffer>;  // Custom CA certificates
  pinnedPublicKey?: string | string[];  // sha256//<base64> SPKI pins
}
```

**Certificate pinning:** Pins are in the format `sha256//<base64-SHA256-of-SPKI-DER>`. A `TLSError` is thrown if the server certificate's SPKI hash does not match any pin. An empty array disables pinning.

**Stealth TLS engine:** When `stealth: true` is set, the request uses NLcURL's custom TLS 1.2/1.3 implementation instead of Node.js's built-in TLS. This engine generates ClientHello messages that exactly match the specified browser profile's fingerprint (cipher suite order, extension order, GREASE values, supported groups, signature algorithms).

**Minimum TLS version:** TLS 1.2 (enforced by both the Node.js engine and stealth engine).

---

## Timeout Options

A numeric timeout value applies to all phases. Use `TimeoutConfig` for per-phase control.

```typescript
// Single timeout for everything
{ timeout: 30000 }

// Per-phase timeouts
{
  timeout: {
    connect: 10000,    // TCP connection timeout
    tls: 10000,        // TLS handshake timeout
    response: 15000,   // Time to first byte
    total: 60000,      // Total request timeout
  }
}
```

All values are in milliseconds. Must be positive finite numbers.

**Defaults:**
- CLI: 30000ms
- Node.js TLS engine connect timeout: 30000ms
- DoH resolver: 5000ms
- DoT resolver: 5000ms
- Happy Eyeballs: 30000ms per attempt, 250ms stagger delay
- SOCKS proxy: 30000ms
- HTTP proxy: 30000ms
- OCSP stapling validation: 5000ms

---

## Retry Options

```typescript
interface RetryConfig {
  count: number;              // Max retry attempts (default: 3)
  delay: number;              // Base delay in ms (default: 1000)
  backoff: "linear" | "exponential";  // Backoff strategy (default: "exponential")
  jitter: number;             // Max random jitter in ms (default: 200)
  retryOn?: (error: Error | null, statusCode?: number) => boolean;
}
```

**Backoff calculation:**
- `exponential`: delay × 2^(attempt-1), capped at 32× base delay.
- `linear`: delay × attempt number.
- Final delay = computed delay + random(0, jitter).

**Retry-After header:** When the server sends a `Retry-After` header (integer seconds or HTTP-date), the retry delay is set to the header value, capped at 5 minutes (300,000ms).

**Default retryable conditions:**
- Error types: `ConnectionError`, `TimeoutError`, `TLSError`
- HTTP/2 error codes: PROTOCOL_ERROR (1), INTERNAL_ERROR (2), REFUSED_STREAM (7), CANCEL (8), ENHANCE_YOUR_CALM (11), HTTP_1_1_REQUIRED (13)
- HTTP status codes: 429, 500, 502, 503, 504

**Never retried:** `AbortError` always propagates immediately.

---

## Cache Options

```typescript
interface CacheConfig {
  enabled?: boolean;          // Default: true (when cacheConfig is provided)
  maxEntries?: number;        // Default: 1000
  maxSize?: number;           // Default: 52428800 (50 MB)
  mode?: CacheMode;           // Default: "default"
}
```

**Cache modes:**

| Mode | Behavior |
|------|----------|
| `"default"` | Serve fresh responses from cache. Conditionally revalidate stale responses using `If-None-Match` / `If-Modified-Since`. Supports `stale-while-revalidate`. |
| `"no-store"` | Bypass cache entirely. Never read from or write to cache. |
| `"no-cache"` | Always revalidate with the origin server, even if cached response is fresh. |
| `"force-cache"` | Serve cached responses regardless of freshness. |
| `"only-if-cached"` | Return cached response or a synthetic 504 Gateway Timeout. |

**Freshness calculation (RFC 9111):**
1. `s-maxage` directive (highest priority for shared caches)
2. `max-age` directive
3. `Expires` header minus `Date` header
4. Heuristic: 10% of (`Date` − `Last-Modified`), capped at 86400 seconds (24 hours)

**Request-side Cache-Control directives:** The cache also honors request-side `Cache-Control`: `max-age`, `min-fresh`, `max-stale`, `no-store`, and `no-cache`.

**Age header:** Cached responses include a corrected `Age` header (initial age + resident time per RFC 9111 §4.2.3).

**Unsafe method invalidation:** POST, PUT, DELETE, and PATCH requests invalidate matching cached entries.

**Eviction:** LRU by access time. Size-based eviction when total stored bytes exceed `maxSize`. Multi-variant Vary entries are evicted across all variants.

---

## HSTS Options

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

HSTS is disabled by default. When enabled, the session:
- Parses `Strict-Transport-Security` headers from HTTPS responses.
- Automatically upgrades `http://` URLs to `https://` for known HSTS hosts.
- Supports `includeSubDomains` with domain hierarchy traversal.
- Ignores HSTS headers from non-HTTPS responses and IP addresses.
- Removes HSTS entries when `max-age=0` is received.
- Preloaded entries receive a 20-year expiration.

---

## DNS Options

```typescript
interface DNSConfig {
  doh?: DoHConfig;
  httpsRR?: boolean;      // Default: true (HTTPS RR resolution)
}

interface DoHConfig {
  server: string;          // DoH server URL (e.g., "https://1.1.1.1/dns-query")
  method?: "GET" | "POST"; // Default: "GET"
  timeout?: number;        // Default: 5000ms
  bootstrap?: boolean;     // Default: true (resolve DoH server via system DNS)
  cache?: DNSCacheConfig;
}

interface DNSCacheConfig {
  maxEntries?: number;     // Default: 500
  minTTL?: number;         // Default: 30 seconds
  maxTTL?: number;         // Default: 86400 seconds (24 hours)
}
```

**DNS resolution order:**
1. If `doh` is configured, use DNS-over-HTTPS.
2. If `httpsRR` is not disabled, resolve HTTPS RR records for ECH config and ALPN hints.
3. Happy Eyeballs v2 dual-stack connection racing with 250ms stagger.

**EDNS(0):** DNS queries include EDNS(0) OPT records (RFC 6891) with padding (RFC 7830) by default when using the DoH resolver, improving DNS privacy by obscuring query size.

**DNS-over-TLS configuration:**

```typescript
interface DoTConfig {
  server?: string;         // Default: "1.1.1.1" (Cloudflare)
  port?: number;           // Default: 853
  servername?: string;     // Default: "cloudflare-dns.com"
  timeout?: number;        // Default: 5000ms
  keepAlive?: boolean;     // Default: false
  insecure?: boolean;      // Default: false
}
```

---

## ECH Options

```typescript
interface ECHOptions {
  enabled?: boolean;       // Default: true
  echConfigList?: Buffer | string;  // ECHConfigList (or base64-encoded)
  grease?: boolean;        // Generate GREASE ECH extension
  maxRetries?: number;     // Max retry attempts with retry_configs
}
```

When enabled, NLcURL:
1. Checks for ECHConfigList from HTTPS DNS records (automatic).
2. Uses the provided `echConfigList` if specified.
3. Falls back to GREASE ECH if `grease: true` and no real config is available.
4. Supports ECH retry via server-provided `retry_configs`.

Supported HPKE cipher: DHKEM(X25519, HKDF-SHA256) with AES-128-GCM or ChaCha20-Poly1305.

---

## Proxy Options

**Supported proxy schemes:**

| Scheme | Description |
|--------|-------------|
| `http://` | HTTP CONNECT tunneling (proxy port default: 8080) |
| `https://` | HTTPS CONNECT tunneling (proxy port default: 443) |
| `socks4://` | SOCKS4/4a proxy (proxy port default: 1080) |
| `socks5://` | SOCKS5 proxy with optional auth (proxy port default: 1080) |

**Proxy authentication:**
- HTTP proxies: `Proxy-Authorization: Basic` header via `proxyAuth`.
- SOCKS5: Username/password sub-negotiation (RFC 1929).
- Digest proxy auth available via `buildDigestAuth()`.

**Proxy resolution priority:**
1. Request-level `proxy` option.
2. Session-level `proxy` option.
3. Environment variables (see [Environment Variables](#environment-variables)).

---

## Cookie Options

**Session-level:**
- `cookieJar: true` (default) — Create a new cookie jar for the session.
- `cookieJar: false` — Disable cookie handling.
- `cookieJar: existingJar` — Share a `CookieJar` instance across sessions.

**CookieJar configuration:**

```typescript
new CookieJar({
  maxCookies: 3000,             // Default: 3000
  maxCookiesPerDomain: 180,     // Default: 180
})
```

**Cookie security enforcement:**
- `__Host-` prefixed cookies must be `Secure`, have no `Domain`, and have `Path=/`.
- `__Secure-` prefixed cookies must be `Secure`.
- `SameSite` defaults to `"lax"` when not specified.
- `Partitioned` cookies require `Secure`.
- Cookies on IP addresses cannot set the `Domain` attribute.
- Public suffix domains are rejected via the Mozilla Public Suffix List.

---

## Rate Limiting

```typescript
session.setRateLimit({
  maxRequests: 10,    // Bucket capacity
  windowMs: 1000,     // Refill window in milliseconds
});
```

Token-bucket algorithm: tokens are fully refilled to `maxRequests` at the start of each window. When tokens are exhausted, subsequent requests are queued and automatically drained after the next refill.

---

## Logging

### Log Levels

| Level | Priority | Description |
|-------|----------|-------------|
| `"debug"` | 0 | Verbose debugging information |
| `"info"` | 1 | General informational messages |
| `"warn"` | 2 | Warning conditions (default) |
| `"error"` | 3 | Error conditions |
| `"silent"` | 4 | No output |

### Logger Implementations

| Logger | Output | Format |
|--------|--------|--------|
| `ConsoleLogger` | stderr | `[nlcurl:component:level] message` |
| `JsonLogger` | stderr | `{ timestamp, level, message, service, ...bindings }` |
| `SILENT_LOGGER` | none | No-op |

```typescript
import { ConsoleLogger, JsonLogger, setDefaultLogger } from "nlcurl";

// Set process-wide default logger
setDefaultLogger(new ConsoleLogger("debug"));

// Or use JSON structured logging
setDefaultLogger(new JsonLogger("info", "my-service"));

// Child loggers inherit level and add bindings
const childLogger = logger.child({ component: "auth" });
```

---

## Connection Pool

Connection pooling is managed internally per session. These are the default values:

| Parameter | Default |
|-----------|---------|
| Max connections per origin | 6 |
| Max total connections | 64 |
| Idle timeout | 60,000ms (60s) |
| Max connection age | 300,000ms (5min) |
| Cleanup interval | 30,000ms (30s) |

HTTP/2 connections are multiplexed (shared across concurrent requests to the same origin). HTTP/1.1 connections are one-request-at-a-time.

---

## CLI Flags

### Request Options

| Flag | Short | Description |
|------|-------|-------------|
| `--request METHOD` | `-X` | HTTP method |
| `--header "Name: Value"` | `-H` | Add request header |
| `--data DATA` | `-d` | Request body (auto-promotes to POST) |
| `--data-raw DATA` | — | Request body without interpretation |
| `--user-agent STRING` | `-A` | User-Agent header |
| `--output FILE` | `-o` | Write output to file |
| `--head` | `-I` | HEAD request |
| `--include` | `-i` | Include response headers in output |
| `--verbose` | `-v` | Verbose mode (request and response headers to stderr) |
| `--silent` | `-s` | Suppress progress output |
| `--compressed` | — | Set Accept-Encoding header |

### Impersonation

| Flag | Description |
|------|-------------|
| `--impersonate NAME` | Browser profile for TLS/H2 fingerprinting |
| `--ja3 STRING` | Custom JA3 fingerprint |
| `--akamai STRING` | Custom Akamai H2 fingerprint |
| `--stealth` | Use custom stealth TLS engine |

### Connection

| Flag | Short | Description |
|------|-------|-------------|
| `--proxy URL` | `-x` | Proxy URL |
| `--proxy-user USER:PASS` | `-U` | Proxy credentials |
| `--insecure` | `-k` | Skip TLS certificate verification |
| `--location` | `-L` | Follow redirects |
| `--max-redirs N` | — | Maximum redirects |
| `--max-time SECS` | `-m` | Total timeout in seconds |
| `--http1.1` | — | Force HTTP/1.1 |
| `--http2` | — | Force HTTP/2 |

### Cookies

| Flag | Short | Description |
|------|-------|-------------|
| `--cookie STRING` | `-b` | Send cookies |
| `--cookie-jar FILE` | `-c` | Read/write cookies in Netscape format |

### Meta

| Flag | Short | Description |
|------|-------|-------------|
| `--help` | `-h` | Show help text |
| `--version` | `-V` | Show version |
| `--list-profiles` | — | List available browser profiles |

---

## Environment Variables

| Variable | Description |
|----------|-------------|
| `HTTP_PROXY` / `http_proxy` | Proxy for HTTP requests |
| `HTTPS_PROXY` / `https_proxy` | Proxy for HTTPS requests |
| `ALL_PROXY` / `all_proxy` | Fallback proxy for all requests |
| `NO_PROXY` / `no_proxy` | Comma-separated bypass list. Supports `*` (all), exact match, and suffix match. |
| `SSLKEYLOGFILE` | Path for NSS key log output (Wireshark-compatible TLS decryption) |

**NO_PROXY format:** Comma-separated list of hostnames or domains. A leading dot (`.example.com`) matches all subdomains. A bare domain (`example.com`) matches the domain and all subdomains. The wildcard `*` bypasses the proxy for all URLs. Lowercase env vars take precedence over uppercase.