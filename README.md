# NLcURL

A pure TypeScript HTTP client with native TLS fingerprint impersonation. Zero runtime dependencies.

NLcURL provides HTTP/1.1 and HTTP/2 request capabilities with a custom stealth TLS engine that reproduces browser-grade TLS and HTTP/2 fingerprints. It is designed for environments where accurate browser impersonation, advanced protocol control, and strict standards compliance are required.

> **Note:** HTTP/3 (QUIC) is not supported. NLcURL supports HTTP/1.1 and HTTP/2 only.

## Features

- **TLS Fingerprint Impersonation** — Reproduce the exact TLS ClientHello of Chrome, Firefox, Safari, Edge, and Tor across 49 resolvable browser profiles, covering JA3, JA4, and Akamai HTTP/2 fingerprints.
- **Custom Stealth TLS Engine** — A from-scratch TLS 1.2/1.3 implementation with GREASE injection (RFC 8701), configurable cipher suites, extension ordering, Encrypted Client Hello (ECH) support, HelloRetryRequest handling, KeyUpdate post-handshake rekeying, and session resumption via PSK.
- **HTTP/1.1 & HTTP/2** — Full HTTP/1.1 with chunked transfer encoding, obs-fold header handling, and TE/CL conflict detection. HTTP/2 with HPACK compression, stream multiplexing, configurable flow control, MAX_CONCURRENT_STREAMS enforcement, PUSH_PROMISE rejection, and CONTINUATION size limits.
- **Connection Pooling** — Per-origin connection reuse with idle eviction, configurable pool limits, and automatic HTTP/2 multiplexing.
- **RFC 6265 Cookie Jar** — Persistent cookie storage with Public Suffix List validation, `__Host-`/`__Secure-` prefix enforcement, `SameSite` enforcement (Strict/Lax/None with Secure requirement per RFC 6265bis), CHIPS partitioned cookies, and Netscape file format import/export.
- **HTTP Caching (RFC 9111)** — In-memory cache with multi-variant `Vary` support, `s-maxage`/`max-age` freshness, `ETag`/`Last-Modified` conditional revalidation, `Age` header, request-side `Cache-Control`, unsafe method invalidation, `stale-while-revalidate`, heuristic freshness, and five cache modes.
- **HSTS (RFC 6797)** — Automatic `http://` to `https://` upgrading with `includeSubDomains` support and configurable preload lists.
- **DNS-over-HTTPS (RFC 8484)** — Wire-format DoH with GET/POST methods, EDNS(0) with padding (RFC 6891/7830), bootstrap resolution, and integrated DNS caching.
- **DNS-over-TLS (RFC 7858)** — Secure DNS resolution over TLS port 853 with persistent connection support and pre-configured public resolvers.
- **HTTPS Resource Records (RFC 9460)** — SVCB/HTTPS DNS record resolution for ALPN hints, ECH config delivery, and address hints.
- **Proxy Support** — HTTP CONNECT tunneling, HTTPS proxies, SOCKS4/4a, and SOCKS5 with optional username/password authentication. Environment variable resolution (`HTTP_PROXY`, `HTTPS_PROXY`, `NO_PROXY`).
- **WebSocket (RFC 6455)** — Full WebSocket client with TLS fingerprinting, per-message deflate compression (RFC 7692), control frame validation (≤125 bytes), ping/pong, and binary/text framing.
- **Server-Sent Events** — W3C EventSource-compliant SSE parser with streaming async generator interface, UTF-8 BOM stripping, and cross-chunk CRLF handling.
- **Request/Response Interceptors** — Middleware pipeline for modifying requests before send and responses after receipt.
- **Retry with Backoff** — Configurable automatic retry with linear or exponential backoff, jitter, `Retry-After` header respect, and custom retry predicates.
- **Rate Limiting** — Token-bucket rate limiter with configurable request quotas and automatic queuing.
- **Circuit Breaker** — Per-origin circuit breaker with configurable failure thresholds, half-open probing, and automatic recovery.
- **Request Body Compression** — Outgoing body compression with gzip, deflate, and Brotli.
- **Response Decompression** — Automatic decompression of gzip, deflate, Brotli, and zstd (Node.js 20.10+) with multi-layer encoding support.
- **Happy Eyeballs v2 (RFC 8305)** — Dual-stack connection racing with 250ms stagger for optimal latency.
- **Alt-Svc (RFC 7838)** — HTTP Alternative Services tracking with automatic protocol upgrade preference.
- **FormData (RFC 7578)** — Multipart form-data encoding with file upload support.
- **Authentication** — Built-in Basic, Bearer, Digest (RFC 7616), and AWS Signature V4 authentication, plus Digest proxy authentication.
- **Progress Callbacks** — Upload and download progress events with byte counts and percentages.
- **Structured Logging** — Console and JSON logger implementations with child logger support and configurable log levels.
- **CLI Tool** — `nlcurl` command-line interface with curl-compatible flags for scripting and interactive use.
- **Zero Dependencies** — Pure TypeScript with no runtime dependencies. Requires only Node.js ≥ 18.17.0.

## Installation

```bash
npm install nlcurl
```

**Requirements:** Node.js ≥ 18.17.0

## Quick Start

### One-Shot Requests

```typescript
import { get, post } from "nlcurl";

// Simple GET
const response = await get("https://httpbin.org/get");
console.log(response.status);      // 200
console.log(response.json());      // parsed JSON body

// POST with JSON body
const res = await post("https://httpbin.org/post", { key: "value" });
console.log(res.text());
```

### Browser Impersonation

```typescript
import { get } from "nlcurl";

const response = await get("https://example.com", {
  impersonate: "chrome136",
});
```

### Session with Connection Reuse

```typescript
import { createSession } from "nlcurl";

const session = createSession({
  baseURL: "https://api.example.com",
  impersonate: "chrome136",
  headers: { "authorization": "Bearer token" },
  retry: { count: 3, backoff: "exponential" },
});

const users = await session.get("/users");
const user = await session.post("/users", { name: "Alice" });

session.close();
```

### Stealth TLS

```typescript
import { get } from "nlcurl";

// Uses the custom stealth TLS engine (bypasses Node.js TLS)
const response = await get("https://example.com", {
  stealth: true,
  impersonate: "chrome136",
});
```

### WebSocket

```typescript
import { WebSocketClient } from "nlcurl";

const ws = new WebSocketClient("wss://echo.websocket.events", {
  impersonate: "chrome136",
  compress: true,
});

ws.on("open", () => ws.sendText("Hello"));
ws.on("message", (data) => console.log(data));
ws.on("close", (code, reason) => console.log("Closed:", code));
```

### CLI

```bash
# Simple GET
nlcurl https://httpbin.org/get

# Impersonate Chrome with verbose output
nlcurl -v --impersonate chrome136 https://example.com

# POST with data
nlcurl -X POST -d '{"key":"value"}' -H "Content-Type: application/json" https://httpbin.org/post

# Through a proxy
nlcurl -x socks5://127.0.0.1:1080 https://example.com
```

## Documentation

| Document | Description |
|----------|-------------|
| [API Reference](docs/API.md) | Complete API for all exported classes, functions, types, and interfaces |
| [Configuration](docs/CONFIGURATION.md) | All configuration options for requests, sessions, TLS, DNS, caching, and proxies |
| [Examples](docs/EXAMPLES.md) | Practical usage patterns covering common and advanced scenarios |
| [Modules](docs/MODULES.md) | Architecture overview and detailed breakdown of every module |
| [Onboarding](docs/ONBOARDING.md) | Getting started guide for new contributors and integrators |
| [Setup](docs/SETUP.md) | Build, test, and development environment instructions |

## Browser Profiles

49 resolvable browser profile names across 5 browser families:

| Browser | Profiles |
|---------|----------|
| Chrome | `chrome99` through `chrome136`, `chrome_latest`, `chrome` |
| Firefox | `firefox133` through `firefox138`, `firefox_latest`, `firefox` |
| Safari | `safari153` through `safari182`, `safari_latest`, `safari` |
| Edge | `edge99` through `edge136`, `edge_latest`, `edge` |
| Tor | `tor133` through `tor145`, `tor_latest`, `tor` |

Each profile includes a complete TLS fingerprint (cipher suites, extensions, supported groups, signature algorithms), HTTP/2 settings fingerprint (SETTINGS frame, WINDOW_UPDATE, pseudo-header order, priority frames), and default HTTP headers with an accurate User-Agent string.

## Standards Compliance

NLcURL implements or references the following RFCs and standards:

| Standard | Coverage |
|----------|----------|
| RFC 8446 | TLS 1.3 — full handshake, key schedule, AEAD record encryption |
| RFC 5246 | TLS 1.2 — ECDHE key exchange, GCM/ChaCha20 cipher suites |
| RFC 8701 | GREASE — randomized TLS extension values for anti-fingerprinting |
| RFC 9113 | HTTP/2 — frames, HPACK, flow control, GOAWAY, stream multiplexing |
| RFC 7541 | HPACK — header compression with Huffman encoding |
| RFC 9112 | HTTP/1.1 — message syntax, chunked transfer encoding |
| RFC 9111 | HTTP Caching — freshness, conditional requests, cache modes |
| RFC 9110 | HTTP Semantics — methods, status codes, range requests |
| RFC 6265 | HTTP Cookies — Set-Cookie parsing, domain/path scoping, prefixes |
| RFC 6797 | HSTS — Strict-Transport-Security header processing |
| RFC 8484 | DNS-over-HTTPS — wire-format queries, GET/POST methods |
| RFC 7858 | DNS-over-TLS — encrypted DNS over port 853 |
| RFC 9460 | SVCB/HTTPS DNS Records — service binding, ALPN, ECH delivery |
| RFC 8305 | Happy Eyeballs v2 — dual-stack connection racing |
| RFC 6455 | WebSocket — upgrade handshake, framing, close protocol |
| RFC 7692 | WebSocket Compression — permessage-deflate negotiation |
| RFC 7838 | HTTP Alt-Svc — alternative service advertisement |
| RFC 7578 | Multipart Form Data — multipart/form-data encoding |
| RFC 7616 | HTTP Digest Authentication — MD5/SHA-256, qop=auth |
| RFC 1928 | SOCKS5 — proxy protocol with auth negotiation |
| RFC 5869 | HKDF — key derivation for TLS key schedule |
| RFC 9180 | HPKE — Hybrid Public Key Encryption for ECH |
| RFC 7413 | TCP Fast Open — platform-aware TFO support |
| RFC 8297 | 103 Early Hints — Link header parsing |
| RFC 6891 | EDNS(0) — Extension Mechanisms for DNS OPT records |
| RFC 7830 | DNS Padding — query size obfuscation for privacy |
| RFC 6265bis | Cookie SameSite — Strict/Lax/None enforcement, Secure requirement |

## License

MIT