# Module Reference

Architecture overview and internal module documentation for NLcURL.

---

## Table of Contents

- [Architecture Overview](#architecture-overview)
- [Request Pipeline](#request-pipeline)
- [Module Map](#module-map)
- [Core](#core)
- [HTTP](#http)
- [TLS](#tls)
- [Fingerprints](#fingerprints)
- [Cookies](#cookies)
- [Cache](#cache)
- [HSTS](#hsts)
- [DNS](#dns)
- [Proxy](#proxy)
- [WebSocket](#websocket)
- [SSE](#sse)
- [Middleware](#middleware)
- [Utilities](#utilities)
- [CLI](#cli)

---

## Architecture Overview

NLcURL is organized as a layered system of modules. The top-level entry point (`src/index.ts`) re-exports all public API surface. At the center sits `NLcURLSession`, which orchestrates the entire request lifecycle by delegating to specialized subsystems.

```
                  ┌─────────────────┐
                  │  Public API      │  get(), post(), createSession()
                  │  src/index.ts    │
                  └────────┬────────┘
                           │
                  ┌────────▼────────┐
                  │  NLcURLSession   │  Session state, config, pipeline
                  │  core/session.ts │
                  └────────┬────────┘
                           │
        ┌──────────────────┼──────────────────┐
        │                  │                  │
  ┌─────▼─────┐   ┌───────▼───────┐   ┌──────▼──────┐
  │ Middleware │   │    Cache      │   │  Cookies    │
  │ Interceptor│   │  HSTS         │   │  CookieJar  │
  │ Rate Limit │   │  Validation   │   │  PSL        │
  │ Retry      │   │               │   │             │
  └─────┬─────┘   └───────┬───────┘   └──────┬──────┘
        │                  │                  │
        └──────────────────┼──────────────────┘
                           │
                  ┌────────▼────────┐
                  │ ProtocolNego.   │  TLS engine, ALPN, Happy Eyeballs
                  │ http/negotiator │
                  └────────┬────────┘
                           │
              ┌────────────┼────────────┐
              │                         │
     ┌────────▼────────┐     ┌─────────▼─────────┐
     │  Connection Pool │     │   DNS Resolution  │
     │  http/pool.ts    │     │   dns/            │
     └────────┬────────┘     └───────────────────┘
              │
    ┌─────────┼─────────┐
    │                    │
┌───▼───┐          ┌────▼────┐
│  H1   │          │   H2    │
│ Client │          │  Client │
│ Encoder│          │  HPACK  │
│ Parser │          │  Frames │
└───┬───┘          └────┬────┘
    │                    │
    └─────────┬──────────┘
              │
    ┌─────────▼──────────┐
    │   TLS Engine        │
    │   Node / Stealth    │
    └─────────────────────┘
```

---

## Request Pipeline

When `session.get(url)` (or any request method) is called, the request passes through these stages in order:

1. **Input Validation** (`core/validation.ts`) — Validates URL, method, headers, body, and timeout values. Rejects malformed input before any network activity.

2. **Rate Limiting** (`middleware/rate-limiter.ts`) — If a rate limit is configured, the request waits in queue until a slot becomes available within the configured window.

3. **Request Interceptors** (`middleware/interceptor.ts`) — Each registered `onRequest` interceptor is called sequentially. Interceptors can modify the request or add headers.

4. **Body Compression** (`utils/compression.ts`) — If `compressBody` is set and the body exceeds 1024 bytes, the body is compressed with the specified algorithm (gzip, deflate, or br) and `Content-Encoding` is set.

5. **Method Override** — If the server does not support the requested method (e.g., PATCH), and `methodOverride` is configured, the method is rewritten and `X-HTTP-Method-Override` is set.

6. **Cache Evaluation** (`cache/store.ts`) — For cacheable methods, the cache is consulted. A fresh cached response is returned directly. A stale response triggers conditional revalidation via `If-None-Match` / `If-Modified-Since`.

7. **HSTS Upgrade** (`hsts/store.ts`) — If the target host has an active HSTS entry (via prior `Strict-Transport-Security` header or preload list), `http://` URLs are upgraded to `https://`.

8. **Cookie Attachment** (`cookies/jar.ts`) — Matching cookies from the jar are serialized into the `Cookie` header. Domain, path, secure, httpOnly, expiry, and SameSite attributes are evaluated.

9. **Retry Loop** (`middleware/retry.ts`) — The actual network call is wrapped in a retry loop. On failure (matching retryable conditions), the request is retried with configurable delay, backoff, and jitter.

10. **Protocol Negotiation** (`http/negotiator.ts`) — Selects the TLS engine (Node.js built-in or stealth), resolves the target address via Happy Eyeballs (DNS + parallel IPv4/IPv6 connect), establishes or reuses a pooled connection, and negotiates ALPN. Handles HTTPS RR, ECH, and Alt-Svc.

11. **HTTP Transport** (`http/h1/` or `http/h2/`) — The request is serialized and sent over the negotiated protocol. H1 uses a streaming encoder/parser. H2 uses multiplexed streams with HPACK header compression.

12. **Response Processing** — The raw response is wrapped in `NLcURLResponse`. Headers are parsed. `Set-Cookie` headers update the cookie jar. `Strict-Transport-Security` updates the HSTS store. Cache headers determine storage. Auto-decompression is applied.

13. **Redirect Following** — If a 3xx redirect is received and `followRedirects` is enabled (default: true, max: 20), the pipeline restarts at step 6 with the new URL. Cross-origin redirects strip authorization headers.

14. **Response Interceptors** (`middleware/interceptor.ts`) — Each registered `onResponse` interceptor is called sequentially, allowing logging, metrics, or response transformation.

---

## Module Map

| Directory | Purpose |
|---|---|
| `src/core/` | Public API, session management, request/response types, errors |
| `src/http/` | Protocol negotiation, connection pooling, H1 and H2 implementations |
| `src/http/h1/` | HTTP/1.1 client, request encoder, response parser |
| `src/http/h2/` | HTTP/2 client, binary frame codec, HPACK compression |
| `src/tls/` | TLS configuration, session caching, certificate verification |
| `src/tls/stealth/` | Custom TLS 1.2/1.3 engine for fingerprint impersonation |
| `src/fingerprints/` | Browser profile database, JA3/JA4/Akamai fingerprinting |
| `src/fingerprints/profiles/` | Individual browser profile data files |
| `src/cookies/` | Cookie jar, Set-Cookie parser, public suffix list |
| `src/cache/` | RFC 9111 HTTP cache, range requests, cache groups |
| `src/hsts/` | RFC 6797 HSTS store with preload support |
| `src/dns/` | DNS-over-HTTPS, DNS-over-TLS, HTTPS RR, DNS cache |
| `src/proxy/` | HTTP CONNECT, HTTPS proxy, SOCKS4/5, proxy auth |
| `src/ws/` | WebSocket client, frame codec, permessage-deflate |
| `src/sse/` | Server-Sent Events parser |
| `src/middleware/` | Interceptors, retry logic, rate limiting, circuit breaker |
| `src/utils/` | Compression, encoding, logging, Happy Eyeballs, buffers |
| `src/cli/` | Command-line interface, argument parsing, output formatting |

---

## Core

### `src/core/session.ts` — NLcURLSession

The central orchestrator. Holds all subsystem instances and executes the request pipeline.

**State managed:**
- `ProtocolNegotiator` — connection pooling and TLS engine selection
- `CookieJar` — per-session cookie storage
- `CacheStore` — HTTP response cache
- `HSTSStore` — HSTS policy enforcement
- `InterceptorChain` — request/response interceptors
- `RateLimiter` — request throttling
- Internal redirect counter and abort handling

**Key methods:** `get()`, `post()`, `put()`, `patch()`, `delete()`, `head()`, `request()`, `close()`, `onRequest()`, `onResponse()`, `setRateLimit()`, `getCache()`.

### `src/core/client.ts` — Convenience Functions

Exports `get`, `post`, `put`, `patch`, `del`, `head`, `request`, and `createSession`. Each one-shot function creates a temporary session, executes the request, and closes the session. `createSession` returns a persistent `NLcURLSession`.

### `src/core/request.ts` — Request Types

Defines all TypeScript interfaces:
- `NLcURLRequest` — full request options
- `NLcURLSessionConfig` — session-level defaults
- `TimeoutConfig` — per-phase timeouts (`connect`, `tls`, `response`, `total`)
- `RetryConfig` — retry policy (`count`, `delay`, `backoff`, `jitter`, `retryOn`)
- `TLSOptions` — TLS configuration
- `ProxyConfig` — proxy settings
- `AuthConfig` — Basic/Bearer/Digest/AWS SigV4 auth
- `HttpMethod` — `GET | POST | PUT | PATCH | DELETE | HEAD | OPTIONS | QUERY`

### `src/core/response.ts` — NLcURLResponse

Wraps HTTP responses. Stores status code, headers (including raw header array), body buffer, and timing data.

**Properties:** `status`, `headers`, `rawHeaders`, `rawBody`, `body` (stream, if streamed), `url`, `redirectUrls`, `httpVersion`, `timings`.

**Accessors:** `ok`, `contentLength`, `contentType`, `etag`, `lastModified`, `cacheControl`, `contentRange`, `acceptRanges`.

**Methods:** `text()` (decoded string), `json()` (parsed object), `getAll(name)` (all values for a header).

### `src/core/errors.ts` — Error Hierarchy

Base class `NLcURLError` extends `Error` with a `code` property and `toJSON()` serialization.

| Class | Code | Cause |
|---|---|---|
| `NLcURLError` | `ERR_NLCURL` | Generic library error |
| `TLSError` | `ERR_TLS` | Handshake failure, certificate issues, alert codes |
| `HTTPError` | `ERR_HTTP` | Non-2xx status (when `throwOnError` is true) |
| `TimeoutError` | `ERR_TIMEOUT` | Deadline exceeded (`phase` indicates where) |
| `ProxyError` | `ERR_PROXY` | Proxy connection or auth failure |
| `AbortError` | `ERR_ABORTED` | Request cancelled via AbortController |
| `ConnectionError` | `ERR_CONNECTION` | TCP connection failure |
| `ProtocolError` | `ERR_PROTOCOL` | HTTP protocol violation |

### `src/core/auth.ts` — Authentication

Applies HTTP authentication to requests. Supports four schemes:
- **Basic** — `base64(username:password)` encoding.
- **Bearer** — `Authorization: Bearer <token>` header.
- **Digest** — RFC 7616 challenge-response with MD5/SHA-256, nonce counting, and qop handling. The session auto-retries 401 responses.
- **AWS SigV4** — AWS Signature Version 4 signing with region, service, access key, secret key, and optional session token.

Exports `AuthConfig`, `DigestChallenge`, and `buildAuthHeader(auth, context?)`.

### `src/core/validation.ts` — Input Validation

Validates request parameters before pipeline execution. Checks URL format, HTTP method, header types, body compatibility, timeout ranges, and proxy URL format.

---

## HTTP

### `src/http/negotiator.ts` — ProtocolNegotiator

The bridge between sessions and transport. Responsibilities:
- Selects TLS engine (Node.js `tls.connect` or stealth engine) based on `stealth` flag
- Manages the `ConnectionPool`
- Performs Happy Eyeballs v2 (RFC 8305) for dual-stack address resolution
- Resolves HTTPS RR records for ECH configuration
- Handles Alt-Svc protocol switching
- Applies proxy tunneling (HTTP CONNECT or SOCKS)

### `src/http/pool.ts` — ConnectionPool

Manages reusable TCP/TLS connections keyed by origin (`scheme://host:port`).

**Defaults:**
- Per-origin limit: 6 connections
- Total limit: 64 connections
- Idle timeout: 60 seconds
- Max connection age: 5 minutes
- Cleanup interval: 30 seconds

HTTP/2 connections are multiplexed — one connection per origin handles concurrent streams. HTTP/1.1 connections are reused sequentially with keep-alive.

### `src/http/h1/client.ts` — H1Client

HTTP/1.1 client implementation with buffered and streaming modes. Manages request serialization via the encoder and response parsing via the parser. Supports chunked transfer encoding and `Content-Length` body framing.

### `src/http/h1/encoder.ts` — H1Encoder

Serializes HTTP/1.1 requests to wire format. Detects body type (Buffer, string, stream, JSON object) and sets appropriate headers. Computes `Content-Length` for known-size bodies and uses chunked transfer encoding for `ReadableStream` bodies.

### `src/http/h1/parser.ts` — H1Parser

State-machine HTTP/1.1 response parser.

**States:** `StatusLine` → `Headers` → `Body` → `Complete`.

**Constraints:**
- Maximum header size: 256 KB
- Maximum body size: 128 MB
- Supports chunked transfer encoding with trailer parsing
- Handles `Content-Length` delimited and connection-close framing
- Unfolds obsolete header line folding (obs-fold per RFC 7230 §3.2.4)
- Rejects ambiguous `Transfer-Encoding` + `Content-Length` conflicts as potential smuggling attacks

### `src/http/h2/client.ts` — H2Client

HTTP/2 multiplexed client built on binary framing.

**Features:**
- SETTINGS exchange and acknowledgment
- Stream creation with HEADERS and CONTINUATION frames
- DATA frames with flow control (connection and stream windows)
- GOAWAY handling with graceful shutdown and reconnection
- WINDOW_UPDATE frame management
- RST_STREAM for stream cancellation
- Priority frame support
- MAX_CONCURRENT_STREAMS enforcement (respects server limit)
- PUSH_PROMISE rejection (sends RST_STREAM with REFUSED_STREAM)
- CONTINUATION frame size limit (1 MB) to prevent memory exhaustion

### `src/http/h2/frames.ts` — H2Frames

Encodes and decodes all HTTP/2 binary frame types: DATA, HEADERS, PRIORITY, RST_STREAM, SETTINGS, PUSH_PROMISE, PING, GOAWAY, WINDOW_UPDATE, CONTINUATION.

### `src/http/h2/hpack.ts` — HPACK

Full HPACK header compression (RFC 7541).

**Components:**
- Static table: 61 predefined header entries
- Dynamic table: configurable max size with 32-byte per-entry overhead
- Huffman coding: encode and decode using the HPACK Huffman table
- Integer encoding: prefix-based variable-length integers
- Indexed / incremental / literal (never-indexed) header representations

### `src/http/alt-svc.ts` — Alt-Svc

Parses `Alt-Svc` response headers (RFC 7838). Extracts alternative protocol names, hosts, ports, and `ma` (max-age) values. Used by the negotiator to discover HTTP/2 or alternative endpoints.

### `src/http/early-hints.ts` — Early Hints

Processes HTTP 103 Early Hints responses. Extracts `Link` headers with `rel=preload` / `rel=preconnect` for resource optimization.

### `src/http/form-data.ts` — FormData

Multipart form-data encoder. Generates RFC 7578 compliant multipart bodies with boundary generation, field and file parts, content-type detection, and streaming support.

### `src/http/trailers.ts` — Trailers

Parses HTTP trailer headers that follow chunked transfer-encoded bodies. Validates trailer names against the disallowed list.

### `src/http/resumable-upload.ts` — Resumable Upload

Implements the IETF resumable upload draft. Provides utilities for creating upload sessions, computing chunk offsets, building Upload-Offset and Upload-Complete headers, and resuming interrupted transfers.

---

## TLS

### `src/tls/node-engine.ts` — Node.js TLS Engine

Wraps Node.js `tls.connect` with full options mapping: ALPN protocols, client certificates, CA certificates, cipher suites, min/max TLS version, session reuse, server name indication. Implements the `ITLSEngine` interface.

### `src/tls/session-cache.ts` — TLS Session Cache

Caches TLS session tickets for 0-RTT resumption. Keyed by `host:port`. Configurable max entries (default: 100) and expiry time. Session tickets are stored as Buffers for reuse on subsequent connections.

### `src/tls/keylog.ts` — TLS Keylog

Writes TLS key material in NSS Key Log format for Wireshark/tcpdump decryption. Activated via `SSLKEYLOGFILE` environment variable or `setKeylogFile()` function.

### `src/tls/ech.ts` — Encrypted Client Hello

Implements ECH (RFC 9180) for encrypting the SNI extension. Builds the ECH extension from HTTPS RR-delivered ECHConfig, generates HPKE shared secrets, encrypts the inner ClientHello, and handles retry configs.

### `src/tls/ocsp.ts` — OCSP Stapling

Validates OCSP responses stapled in the TLS handshake. Checks certificate status (good, revoked, unknown), verifies the OCSP response signature, and validates the response freshness window.

### `src/tls/ct.ts` — Certificate Transparency

Validates Signed Certificate Timestamps (SCTs) from TLS handshakes. Supports SCTs delivered via the TLS extension, OCSP staple, or embedded in the certificate. Verifies SCT signatures against known CT log public keys.

### `src/tls/early-data.ts` — TLS Early Data (0-RTT)

Manages TLS 1.3 early data for 0-RTT request sending. Tracks which origins support early data, enforces replay safety (only safe HTTP methods), and limits early data size to the server-advertised maximum.

### `src/tls/pin-verification.ts` — Public Key Pinning

Verifies TLS certificate public key pins. Extracts the SubjectPublicKeyInfo from the peer certificate, computes its SHA-256 hash, and compares against the configured pin set. Fails closed on mismatch.

### `src/tls/constants.ts` — TLS Constants

Defines all TLS protocol constants: cipher suite identifiers, extension types, named groups, signature algorithms, AEAD parameters, alert codes, handshake message types, and content types.

### `src/tls/types.ts` — TLS Types

TypeScript interfaces for TLS configuration: `ITLSEngine`, `TLSOptions`, `TLSSessionTicket`, and related types used throughout the TLS subsystem.

---

### Stealth TLS Engine — `src/tls/stealth/`

A complete TLS 1.2/1.3 implementation written from scratch. Bypasses Node.js OpenSSL to produce exact ClientHello fingerprints matching real browsers.

### `src/tls/stealth/engine.ts` — StealthTLSEngine

Implements `ITLSEngine`. Creates raw TCP sockets and performs the full TLS handshake internally. Routes to TLS 1.3 or 1.2 handshake based on server negotiation. Accepts an optional `TLSSessionCache` — session tickets received via NewSessionTicket messages (RFC 8446 §4.6.1) are automatically stored, with PSKs derived for subsequent session resumption.

### `src/tls/stealth/client-hello.ts` — ClientHello Builder

Constructs exact binary ClientHello messages matching browser profiles. Controls: cipher order, extension order, named groups, signature algorithms, ALPN, compression methods, session tickets, key share groups, supported versions, GREASE values, ECH extension placement, padding.

### `src/tls/stealth/handshake.ts` — TLS 1.3 Handshake

Full TLS 1.3 state machine (RFC 8446).

**States:** `Initial` → `WaitServerHello` → `WaitEncryptedExtensions` → `WaitCertificate` → `WaitCertificateVerify` → `WaitFinished` → `Connected` → `Closed`.

Handles: key share negotiation, HelloRetryRequest (re-sends ClientHello with updated key share), certificate chain verification, signature verification, Finished message MAC, session ticket processing, and KeyUpdate messages for post-handshake key rotation. `HandshakeResult` includes `masterSecret` and `clientFinishedHash` for resumption.

### `src/tls/stealth/key-schedule.ts` — Key Schedule

TLS 1.3 key derivation (RFC 8446 §7).

Functions: `hkdfExtract`, `hkdfExpandLabel`, `deriveSecret`, `deriveHandshakeKeys`, `deriveApplicationKeys`, `deriveFinishedKey`, `deriveResumptionMasterSecret`, `derivePSK`. Supports SHA-256 and SHA-384 hash algorithms. Manages early, handshake, application, and resumption traffic secrets.

### `src/tls/stealth/record-layer.ts` — Record Layer

TLS record encoding and decoding. Handles AEAD encryption (AES-128-GCM, AES-256-GCM, ChaCha20-Poly1305), nonce construction (XOR of implicit IV and sequence number), content type byte appending for TLS 1.3, and record fragmentation for messages exceeding 16384 bytes.

### `src/tls/stealth/tls12-handshake.ts` — TLS 1.2 Handshake

TLS 1.2 handshake implementation for servers that do not support 1.3. Implements ECDHE key exchange (X25519, P-256, P-384, P-521), ServerKeyExchange signature verification, PRF-based key derivation, ChangeCipherSpec transition, and 6 cipher suites: TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256, TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256, TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384, TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384, TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256, TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256.

---

## Fingerprints

### `src/fingerprints/database.ts` — Profile Database

Registry of 49 browser profiles. Each profile contains a `TLSProfile` (cipher suites, extensions, named groups, ALPN), an `H2Profile` (SETTINGS, window size, priority frames, header table size), and a `HeaderProfile` (default header order and values).

**Functions:**
- `getProfile(name)` — returns a `BrowserProfile` or `undefined`
- `listProfiles()` — returns all profile names

**Default profile:** `chromeLatest` (alias for the highest Chrome version).

### `src/fingerprints/types.ts` — Profile Types

Defines `BrowserProfile`, `TLSProfile`, `H2Profile`, `HeaderProfile`, and related interfaces. Used by the database, TLS engines, and HTTP clients.

### `src/fingerprints/ja3.ts` — JA3 Fingerprinting

Computes JA3 and JA3n fingerprint strings and MD5 hashes from a `TLSProfile`. JA3 format: `TLSVersion,Ciphers,Extensions,EllipticCurves,EllipticCurvePointFormats`. GREASE values are excluded.

### `src/fingerprints/ja4.ts` — JA4 Fingerprinting

Computes JA4 fingerprints (3-section format) from a `TLSProfile`. Section a: protocol, version, SNI, cipher count, extension count, ALPN. Section b: sorted cipher suites hash. Section c: sorted extensions + signature algorithms hash.

### `src/fingerprints/akamai.ts` — Akamai Fingerprinting

Computes Akamai-style HTTP/2 fingerprint from an `H2Profile`. Format encodes SETTINGS frame values, WINDOW_UPDATE size, and PRIORITY frame parameters.

### `src/fingerprints/extensions.ts` — TLS Extension Builders

19 functions that build binary TLS extension data for ClientHello construction: `server_name`, `supported_versions`, `signature_algorithms`, `key_share`, `supported_groups`, `ec_point_formats`, `application_layer_protocol_negotiation`, `session_ticket`, `extended_master_secret`, `compress_certificate`, `delegated_credentials`, `record_size_limit`, `psk_key_exchange_modes`, `status_request`, `signed_certificate_timestamp`, `padding`, `application_settings`, `encrypted_client_hello`, `pre_shared_key`.

---

## Cookies

### `src/cookies/jar.ts` — CookieJar

RFC 6265 cookie jar implementation.

**Limits:**
- Max cookies: 3000
- Max per domain: 180
- Max cookie size: 4096 bytes
- Eviction: LRU (least recently used)

**Security enforcement:**
- `__Host-` prefix: requires Secure, no Domain, Path must be `/`
- `__Secure-` prefix: requires Secure
- `SameSite` attribute: Lax default
- `HttpOnly` flag: respected in storage (not sent in non-HTTP contexts)
- Domain scope: rejects public suffix domains

**Features:** `setCookie(header, url)`, `getCookies(url)`, `getCookieHeader(url, context?)` (SameSite-aware with optional context for `siteOrigin`, `isSameSite`, `type`, `method`), `toNetscapeString()`, `loadNetscapeString(text)`, `clear()`, `clearDomain(domain)`.

### `src/cookies/parser.ts` — Set-Cookie Parser

Parses `Set-Cookie` header values into structured cookie objects. Handles attributes: `Expires`, `Max-Age`, `Domain`, `Path`, `Secure`, `HttpOnly`, `SameSite`, `Partitioned`. Correctly resolves default path from request URL. Rejects `SameSite=None` cookies that lack the `Secure` flag (RFC 6265bis §4.1.2.7).

### `src/cookies/public-suffix.ts` — Public Suffix List

Trie-based lookup of the Mozilla Public Suffix List. Determines the registrable domain for cookie domain scoping. Handles exception rules (e.g., `!www.ck`) and wildcard rules (e.g., `*.ck`).

### `src/cookies/psl-data.ts` — PSL Data

Compressed Public Suffix List data, updated via `scripts/update-psl.ts`.

---

## Cache

### `src/cache/store.ts` — CacheStore

RFC 9111 HTTP response cache.

**Defaults:**
- Max entries: 1000
- Max total size: 50 MB
- Eviction: LRU

**Cache modes (per-request):**
- `default` — standard cache behavior: serve fresh, revalidate stale
- `no-store` — bypass cache entirely
- `no-cache` — always revalidate before serving
- `force-cache` — serve stale without revalidation
- `only-if-cached` — return cached response or 504

**Features:**
- Freshness calculation from `Cache-Control` (max-age, s-maxage, must-revalidate, no-cache, no-store, private, stale-while-revalidate) and `Expires`
- `s-maxage` takes priority over `max-age` for freshness
- Multi-variant `Vary` support — stores multiple response variants per URL
- Age header included in cached responses (initial age + resident time per RFC 9111 §4.2.3)
- Request-side `Cache-Control` honored: `max-age`, `min-fresh`, `max-stale`, `no-store`, `no-cache`
- Conditional revalidation via `If-None-Match` (ETag) and `If-Modified-Since`
- Automatic invalidation on unsafe methods (POST, PUT, PATCH, DELETE)
- LRU eviction across variants when total size exceeds `maxSize`

### `src/cache/range.ts` — RangeCache

Caches partial content (HTTP 206) responses. Manages byte-range segments, merges adjacent ranges, and serves cached segments for subsequent range requests against the same resource.

### `src/cache/no-vary-search.ts` — No-Vary-Search

Implements the No-Vary-Search response header. Allows cache entries to match requests that differ only in specified query parameters, as configured by the server.

### `src/cache/groups.ts` — Cache Groups

Batch cache invalidation based on the Cache-Groups response header. Groups related cache entries by label for collective purging.

### `src/cache/types.ts` — Cache Types

TypeScript interfaces for `CacheEntry`, `CacheConfig`, `CacheMode`, `CacheControl`, and related types.

---

## HSTS

### `src/hsts/store.ts` — HSTSStore

RFC 6797 HSTS implementation.

**Behavior:**
- Stores `Strict-Transport-Security` directives (max-age, includeSubDomains)
- Automatically upgrades `http://` to `https://` for known hosts
- Respects `includeSubDomains` for subdomain matching
- `max-age=0` removes the entry
- IP addresses are rejected (HSTS is domain-only)
- Preload entries can be supplied at construction (20-year expiry)

### `src/hsts/types.ts` — HSTS Types

Interfaces for `HSTSEntry`, `HSTSConfig`, and `HSTSPreloadEntry`.

---

## DNS

### `src/dns/doh-resolver.ts` — DoH Resolver

DNS-over-HTTPS resolver (RFC 8484).

- Supports GET (base64url query parameter) and POST (binary body) methods
- Bootstrap mode for resolving the DoH server's own address
- Uses EDNS(0) with padding by default for improved DNS privacy
- Configurable timeout (default: 5000 ms)
- Returns A and AAAA records

### `src/dns/dot-resolver.ts` — DoT Resolver

DNS-over-TLS resolver (RFC 7858).

- Persistent TLS connection with keep-alive
- 6 pre-configured servers: Cloudflare (`1.1.1.1`, `1.0.0.1`), Google (`8.8.8.8`, `8.8.4.4`), Quad9 (`9.9.9.9`, `149.112.112.112`)
- Connection reuse for multiple queries
- Automatic reconnection on connection loss

### `src/dns/https-rr.ts` — HTTPS RR Resolver

Resolves HTTPS resource records (RFC 9460). Extracts SVCB parameters: ALPN protocols, IPv4/IPv6 hints, ECH configuration data, port, and priority. ECH configs are used by the TLS engine for Encrypted Client Hello.

### `src/dns/cache.ts` — DNS Cache

In-memory DNS response cache.

**Defaults:**
- Max entries: 500
- Min TTL: 30 seconds
- Max TTL: 86400 seconds (24 hours)

### `src/dns/codec.ts` — DNS Codec

Encodes DNS queries to wire format and decodes responses. Supports A, AAAA, HTTPS, and SVCB record types. Implements domain name compression, label encoding, and SVCB parameter parsing (ALPN, ECHConfig, IPv4/IPv6 hints). `buildDNSQuery()` accepts an optional `edns` parameter for EDNS(0) OPT records (RFC 6891) with UDP payload size, DNSSEC OK bit, and padding option (RFC 7830).

### `src/dns/types.ts` — DNS Types

Interfaces for `DNSRecord`, `DNSResponse`, `DoHConfig`, `DoTConfig`, `SVCBParams`, and resolver options.

---

## Proxy

### `src/proxy/env-proxy.ts` — Environment Proxy

Resolves proxy settings from environment variables: `HTTP_PROXY`, `HTTPS_PROXY`, `ALL_PROXY`, `NO_PROXY` (and lowercase variants). `NO_PROXY` supports domain matching, wildcard prefix, IP addresses, and CIDR notation.

### `src/proxy/http-proxy.ts` — HTTP Proxy

Implements HTTP CONNECT tunneling for HTTPS traffic through HTTP/HTTPS proxies. Sends `CONNECT host:port` to the proxy, reads the 200 response, then upgrades the socket for end-to-end TLS.

### `src/proxy/socks.ts` — SOCKS Proxy

SOCKS4, SOCKS4a, and SOCKS5 client implementation (RFC 1928).

- SOCKS4: IPv4 connect only
- SOCKS4a: adds domain name resolution on the proxy side
- SOCKS5: IPv4, IPv6, and domain name support with optional username/password authentication

### `src/proxy/auth.ts` — Proxy Authentication

Handles `Proxy-Authenticate` / `Proxy-Authorization` header exchange. Supports Basic and Digest authentication schemes. Digest implementation includes MD5 and SHA-256 hash algorithms, nonce counting, and qop (quality of protection) handling.

---

## WebSocket

### `src/ws/client.ts` — WebSocketClient

Full WebSocket client (RFC 6455) extending `EventEmitter`.

**Features:**
- TLS fingerprint impersonation during the HTTP upgrade
- Automatic masking of client frames (required by RFC)
- Ping/pong heartbeat handling
- Clean close handshake (close frame exchange)
- Binary and text message support
- Per-message deflate compression (RFC 7692) via `compress` option
- Subprotocol negotiation via `protocols` option

**Events:** `open`, `message(data, isBinary)`, `close(code, reason)`, `error(error)`, `ping(data)`, `pong(data)`.

**Methods:** `sendText(data)`, `sendBinary(data)`, `ping(data?)`, `close(code?, reason?)`.

### `src/ws/frame.ts` — WebSocket Frames

Encodes and decodes WebSocket frames (RFC 6455 §5). Handles fin bit, opcode, masking, payload length (7-bit, 16-bit, 64-bit), and control frame validation. Control frames (ping, pong, close) are validated to have payloads ≤ 125 bytes per RFC 6455 §5.5. Maximum payload size: 128 MB.

### `src/ws/permessage-deflate.ts` — Per-Message Deflate

Implements the permessage-deflate WebSocket extension (RFC 7692). Negotiates compression parameters during the upgrade handshake: `server_max_window_bits`, `client_max_window_bits`, `server_no_context_takeover`, `client_no_context_takeover`.

---

## SSE

### `src/sse/parser.ts` — SSE Parser

Server-Sent Events parser (W3C EventSource specification).

**Parsing:**
- Processes `event:`, `data:`, `id:`, `retry:` fields
- Multi-line `data:` fields are joined with newlines
- Empty `id:` resets the last event ID
- `retry:` must be a valid integer
- Strips leading UTF-8 BOM (U+FEFF) on initial input
- Handles `\r\n`, `\r`, and `\n` line endings, including `\r\n` split across chunk boundaries

**Limits:**
- Maximum line length: 64 KB
- Maximum event data size: 1 MB

**Exports:**
- `SSEParser` class with `feed(text)` and `pull()` methods
- `parseSSEStream(readable)` async generator function

---

## Middleware

### `src/middleware/interceptor.ts` — Interceptor Chain

Manages ordered sequences of request and response interceptors. Interceptors are async functions that receive the request/response and return a modified version. They execute sequentially in registration order.

### `src/middleware/retry.ts` — Retry Logic

Configurable retry with:
- **Count**: maximum retry attempts
- **Delay**: base delay between retries (ms)
- **Backoff**: `linear` (delay × attempt) or `exponential` (delay × 2^attempt)
- **Jitter**: random 0–jitter ms added to each delay
- **Default retryable conditions**: status 429, 500, 502, 503, 504; connection errors; timeout errors

### `src/middleware/retry-after.ts` — Retry-After

Parses the `Retry-After` response header. Handles both delay-seconds format (`Retry-After: 120`) and HTTP-date format (`Retry-After: Thu, 01 Dec 2025 16:00:00 GMT`). Returns the number of milliseconds to wait.

### `src/middleware/rate-limiter.ts` — Rate Limiter

Token bucket rate limiter. Limits the number of requests within a sliding time window. Requests that exceed the limit are queued and released as tokens become available.

**Configuration:** `maxRequests` (tokens per window) and `windowMs` (window duration in milliseconds).

### `src/middleware/circuit-breaker.ts` — Circuit Breaker

Per-origin circuit breaker for preventing cascading failures. Tracks consecutive failures per origin and transitions through three states:

- **CLOSED** — Requests flow normally. Consecutive failures are counted.
- **OPEN** — Requests fail fast with `ERR_CIRCUIT_OPEN`. After `resetTimeoutMs`, transitions to HALF_OPEN.
- **HALF_OPEN** — A single probe request is allowed. On success (meeting `successThreshold`), transitions to CLOSED. On failure, transitions back to OPEN.

Configurable via `CircuitBreakerConfig`: `failureThreshold`, `resetTimeoutMs`, `successThreshold`, `isFailure` predicate (default: status ≥ 500).

---

## Utilities

### `src/utils/encoding.ts` — Encoding

Multi-layer response body decompression. Supports gzip, deflate, brotli, and zstd. Detects `Content-Encoding` headers and applies the appropriate decompressor(s). Handles multiple layers (e.g., `gzip, br`).

### `src/utils/compression.ts` — Body Compression

Compresses request bodies before sending. Supports gzip, deflate, and brotli algorithms. Only compresses bodies exceeding 1024 bytes. Sets `Content-Encoding` header on the outgoing request.

### `src/utils/logger.ts` — Logger

Logging system with 4 levels: `debug`, `info`, `warn`, `error`.

**Implementations:**
- `ConsoleLogger` — writes to `process.stderr` with format `[nlcurl:level] message`
- `JsonLogger` — writes structured JSON lines with timestamp, level, message, context, and optional source tag
- `SILENT_LOGGER` — discards all output (used as default)

### `src/utils/happy-eyeballs.ts` — Happy Eyeballs v2

RFC 8305 address sorting and connection racing. Resolves DNS A and AAAA records, interleaves IPv6 and IPv4 addresses, and races connections with a 250 ms stagger delay. Returns the first successful connection.

### `src/utils/url.ts` — URL Utilities

URL parsing, normalization, query parameter merging, base URL resolution, and origin extraction.

### `src/utils/buffer-reader.ts` — BufferReader

Sequential binary buffer reader for TLS protocol parsing. Methods: `readUint8`, `readUint16`, `readUint24`, `readUint32`, `readBytes(n)`, `peek`, `remaining`, `skip`.

### `src/utils/buffer-writer.ts` — BufferWriter

Sequential binary buffer writer for TLS protocol construction. Methods: `writeUint8`, `writeUint16`, `writeUint24`, `writeUint32`, `writeBytes`, `writeLengthPrefixed`, `toBuffer`.

### `src/utils/tcp-fast-open.ts` — TCP Fast Open

Enables TCP Fast Open (RFC 7413) on supported platforms (Linux, macOS). Sends data in the SYN packet to eliminate one round trip on connection establishment. Falls back silently on unsupported systems.

### `src/utils/dictionary-transport.ts` — Dictionary Transport

Implements shared dictionary compression transport (draft specification). Manages shared Brotli/Zstandard dictionaries negotiated via the `Use-As-Dictionary` response header and `Available-Dictionary` request header.

---

## CLI

### `src/cli/index.ts` — CLI Entry Point

Main CLI entry point. Parses arguments, constructs a session, executes the request, and outputs the result. Supports auto-HTTPS (prefixes `https://` if no scheme), cookie jar file persistence (`-c`), and verbose mode (`-v`).

### `src/cli/args.ts` — Argument Parser

Parses 28 command-line flags into a structured options object.

**Flags:**
| Flag | Alias | Purpose |
|---|---|---|
| `--method` | `-X` | HTTP method |
| `--header` | `-H` | Custom header (repeatable) |
| `--data` | `-d` | Request body |
| `--output` | `-o` | Write response body to file |
| `--verbose` | `-v` | Show detailed request/response |
| `--impersonate` | | Browser profile name |
| `--stealth` | | Use stealth TLS engine |
| `--proxy` | `-x` | Proxy URL |
| `--cookie-jar` | `-c` | Cookie jar file path |
| `--timeout` | | Request timeout in ms |
| `--max-redirects` | | Maximum redirects to follow |
| `--http1.1` | | Force HTTP/1.1 |
| `--http2` | | Force HTTP/2 |
| `--compressed` | | Request compressed response |
| `--insecure` | `-k` | Skip TLS certificate verification |
| `--cert` | | Client certificate file |
| `--key` | | Client key file |
| `--cacert` | | CA certificate file |
| `--list-profiles` | | Print all browser profiles and exit |
| `--json` | | Set Content-Type to application/json |
| `--no-follow` | | Disable redirect following |
| `--include` | `-i` | Include response headers in output |
| `--silent` | `-s` | Suppress progress output |
| `--user` | `-u` | Basic auth (user:password) |
| `--retry` | | Retry count |
| `--retry-delay` | | Retry delay in ms |
| `--doh-url` | | DNS-over-HTTPS server URL |
| `--resolve` | | Custom host:port:address mapping |

### `src/cli/output.ts` — Output Formatting

Formats verbose output in curl-compatible style. Shows request headers (`> GET / HTTP/1.1`), response headers (`< HTTP/2 200`), and timing information. Handles file output (`-o`) and response body display.