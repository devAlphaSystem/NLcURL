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

- `text()` for raw UTF-8 string (throws on streaming responses)
- `json()` for parsed JSON (throws on streaming responses)
- `body` — `Readable | null`; populated when `stream: true` was set; decompress stream is applied automatically
- `getAll(name)` — returns all raw header values for a given name; important for `Set-Cookie` which must not be comma-joined
- `rawHeaders` — header pairs in original transmission order with **original header name casing preserved** (e.g. `Content-Type`, not `content-type`). The `headers` map uses lowercased keys for case-insensitive lookup.

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

**HTTP/1.1 encoder** (`h1/encoder.ts`): when no `Content-Type` is set on the request, the encoder defaults based on body type:

- Plain object (`Record<string, unknown>`) → `application/json` (body serialized via `JSON.stringify`).
- String → `text/plain; charset=utf-8`.
- URLSearchParams → `application/x-www-form-urlencoded`.
- Buffer / stream → no default Content-Type set.

The HTTP/2 client (`h2/client.ts`) implements full bidirectional flow control per RFC 9113:

- **Receive side**: connection-level and per-stream receive windows are tracked; `WINDOW_UPDATE` frames are sent automatically as data is consumed.
- **Send side**: connection-level and per-stream send windows are tracked; DATA frames are chunked to respect limits; buffered data is flushed when WINDOW_UPDATE frames arrive.
- **Header priority**: request-supplied headers take precedence over profile default headers. If both the profile and the request specify the same header name, the request value wins.
- **PADDED frames**: DATA and HEADERS frames with the PADDED flag are correctly stripped of padding bytes.
- **CONTINUATION**: header blocks split across CONTINUATION frames are assembled before HPACK decoding.
- **HPACK Huffman**: encoding is enabled by default for all outgoing header values.
- **Streaming END_STREAM**: `streamRequest()` resolves immediately when the server sends HEADERS with END_STREAM (empty-body responses, e.g. 204 No Content); the body stream is ended normally.

Server `SETTINGS` frames are parsed and applied (`INITIAL_WINDOW_SIZE`, `MAX_CONCURRENT_STREAMS`, `MAX_FRAME_SIZE`). GOAWAY and connection errors automatically notify the connection pool via the `onClose` callback so dead connections are never reused.

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

Reusable retry helper with backoff and jitter. Supports retrying on:

- `ConnectionError`, `TimeoutError`
- HTTP 429 / 503 by default
- `ProtocolError` with H2 RST_STREAM error codes 1 (PROTOCOL_ERROR), 2 (INTERNAL_ERROR), 7 (REFUSED_STREAM), 11 (ENHANCE_YOUR_CALM)

`NLcURLSession.request()` automatically invokes the retry helper when `retry.count > 0` is set in the session config.

## `proxy/`

### `proxy/http-proxy.ts`

HTTP CONNECT tunneling utility.

### `proxy/socks.ts`

SOCKS4/SOCKS5 tunneling utility.

The protocol negotiator automatically tunnels through proxies when `request.proxy` is set. HTTP CONNECT and SOCKS4/5 are supported.

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

After the HTTP upgrade handshake completes, any data already buffered in the transport stream is immediately drained and processed as WebSocket frames. This ensures initial frames sent by the server inline with the 101 response are not lost.

### `ws/frame.ts`

RFC 6455 frame parser and encoder.

## `utils/`

Cross-cutting helpers for:

- URL handling
- Encoding/decompression
- Buffer readers/writers
- Logging
- Happy Eyeballs TCP connectivity

## `cli/`

### `cli/index.ts`

Main executable flow.

### `cli/args.ts`

Zero-dependency argument parser.

### `cli/output.ts`

Help text and response formatting.
