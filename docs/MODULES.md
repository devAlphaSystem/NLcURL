# Module Usage Guide

This guide explains when to use each module area and how modules interact.

## `core/`

### `core/client.ts`

Use for convenience-style API:

- One-shot requests: `request(...)`
- Shorthand methods: `get/post/put/patch/del/head`

Best for scripts or low-volume usage.

### `core/session.ts`

Use for sustained request workloads:

- Connection reuse
- Session defaults
- Cookie persistence
- Interceptors and rate limiting

Example:

```ts
import { createSession } from "nlcurl";

const s = createSession({
  baseURL: "https://api.example.com",
  impersonate: "chrome136",
});

s.onRequest((req) => ({
  ...req,
  headers: { ...(req.headers ?? {}), "x-request-id": "abc-123" },
}));

const resp = await s.get("/v1/users");
s.close();
```

### `core/request.ts`

Contains shared request and config types. Use these in typed wrappers and integrations.

### `core/response.ts`

Use `NLcURLResponse` methods to decode payload safely:

- `text()` for raw UTF-8 string
- `json()` for parsed JSON

### `core/errors.ts`

Catch `NLcURLError` for all library-originated faults.

## `fingerprints/`

### `fingerprints/database.ts`

Use `getProfile` and `listProfiles` for profile discovery/selection.

### `fingerprints/ja3.ts` and `fingerprints/akamai.ts`

Use to calculate diagnostic fingerprints from known profile objects.

### `fingerprints/profiles/*`

Profile definitions by browser family. Not typically imported directly in application code.

## `http/`

### `http/negotiator.ts`

Internal protocol dispatching and connection management.

### `http/pool.ts`

Reusable pool implementation for origin-scoped TLS sockets.

### `http/h1/*` and `http/h2/*`

Low-level protocol code for request encoding, parsing, and framing.

## `cookies/`

### `cookies/jar.ts`

In-memory cookie jar with path/domain/secure matching and eviction limits.

### `cookies/parser.ts`

Set-Cookie parsing and Cookie header serialization helpers.

## `middleware/`

### `middleware/interceptor.ts`

Request/response interceptor chain used by session API.

### `middleware/rate-limiter.ts`

Token-bucket request rate control.

### `middleware/retry.ts`

Reusable retry helper with backoff and jitter. Current high-level client/session request path does not call this helper by default.

## `proxy/`

### `proxy/http-proxy.ts`

HTTP CONNECT tunneling utility.

### `proxy/socks.ts`

SOCKS4/SOCKS5 tunneling utility.

Current high-level session/client flow does not yet wire these modules into request execution.

## `tls/`

### `tls/node-engine.ts`

Node TLS wrapper that tunes cipher/group/sigalgs/ALPN where supported.

### `tls/stealth/*`

Raw TLS handshake logic for stronger low-level fingerprint control.

### `tls/constants.ts`

Numeric TLS protocol constants used by profile definitions and builders.

## `ws/`

### `ws/client.ts`

WebSocket client with optional browser profile impersonation for secure sockets.

### `ws/frame.ts`

RFC 6455 frame parser and encoder.

## `utils/`

Cross-cutting helpers for:

- URL handling
- Encoding/decompression
- buffer readers/writers
- logging

## `cli/`

### `cli/index.ts`

Main executable flow.

### `cli/args.ts`

Zero-dependency argument parser.

### `cli/output.ts`

Help text and response formatting.
