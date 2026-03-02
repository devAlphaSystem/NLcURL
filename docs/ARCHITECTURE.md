# Architecture Overview

NLcURL is organized as a layered transport and protocol stack with a strict separation between public API, request orchestration, transport negotiation, and protocol codecs.

## High-Level Layers

1. Public API layer (`src/index.ts`, `src/core/client.ts`)
2. Session orchestration layer (`src/core/session.ts`)
3. Protocol negotiation and pooling (`src/http/negotiator.ts`, `src/http/pool.ts`)
4. HTTP protocol implementations (`src/http/h1/*`, `src/http/h2/*`)
5. TLS engines (`src/tls/node-engine.ts`, `src/tls/stealth/*`)
6. Fingerprint model and profile database (`src/fingerprints/*`)
7. Cross-cutting modules (cookies, middleware, proxy, WebSocket, utils)

## Request Lifecycle

1. Caller submits `NLcURLRequest` through `request(...)` or `NLcURLSession.request(...)`.
2. Session merges defaults:

- `baseURL`, `headers`, timeout, fingerprint/profile options.
- Query params are appended to URL.
- Cookie header is injected from the session cookie jar.

3. Request interceptors run (`InterceptorChain.processRequest`).
4. Browser profile is resolved from `impersonate` if provided.
5. `ProtocolNegotiator.send(...)` acquires or creates pooled connection by origin.
6. ALPN and negotiated protocol route the request to:

- HTTP/2 client (`H2Client.streamRequest`) when `request.stream` is set and protocol is `h2`.
- HTTP/2 client (`H2Client.request`) for buffered H2 requests.
- HTTP/1.1 streaming client (`sendH1StreamingRequest`) when `request.stream` is set.
- HTTP/1.1 client (`sendH1Request`) otherwise.

7. Response body is decompressed:

- Buffered mode: `decompressBody` applied to full buffer.
- Streaming mode: `createDecompressStream` piped inline before the body `Readable` is returned.

8. If an HTTP/2 RST_STREAM or GOAWAY frame carries error code 1, 2, 7, or 11, a `ProtocolError` with `errorCode` set is thrown. The `withRetry` helper recognises these codes as retryable.
9. Session stores cookies from response headers.
10. Response interceptors run (`InterceptorChain.processResponse`).
11. Caller receives `NLcURLResponse`.

## Session and Connection Model

- A session owns one `ProtocolNegotiator` and one `ConnectionPool`.
- Pool key is origin (`scheme://host:port`).
- HTTP/1.1 entries are single-flight (`busy` flag) and reused when idle.
- HTTP/2 entries support multiplexing via stream IDs. The pool skips entries whose `H2Client.isClosed` is true.
- When an H2 connection receives GOAWAY or encounters an error, its `onClose` callback removes the pool entry automatically. H2 request failures in the negotiator also remove the pool entry (matching H1 behavior).
- Periodic idle/age eviction runs every 30 seconds.

## TLS Engine Strategy

Two engines implement `ITLSEngine`:

- `NodeTLSEngine`: uses built-in `node:tls`; supports cipher/group/sigalgs/ALPN tuning.
- `StealthTLSEngine`: raw TLS handshake path for finer ClientHello control.

Session/request options select engine via `stealth`.

## Fingerprint Architecture

`BrowserProfile` combines:

- `TLSProfile`: cipher order, extension order, supported groups, signature algorithms, ALPN, GREASE behavior.
- `H2Profile`: SETTINGS ordering, WINDOW_UPDATE, pseudo-header ordering, priority frames.
- `HeaderProfile`: ordered default headers and user-agent.

Profile database merges browser-specific maps under canonical names and aliases.

## HTTP Protocol Implementations

### HTTP/1.1

- Request serialization: `src/http/h1/encoder.ts`
- Response parser: `src/http/h1/parser.ts`
- Transport call: `src/http/h1/client.ts`

### HTTP/2

- Frame encoding/decoding: `src/http/h2/frames.ts`
- HPACK: `src/http/h2/hpack.ts`
- Stream orchestration: `src/http/h2/client.ts`

The H2 client implements RFC 9113 bidirectional flow control:

**Receive side:**

- Connection-level and per-stream receive windows are tracked.
- `WINDOW_UPDATE` frames are sent automatically when consumed data exceeds 50% of the window.

**Send side:**

- Connection-level and per-stream send windows are tracked from `SETTINGS` and `WINDOW_UPDATE` frames.
- DATA frames are chunked to respect both connection and stream send window limits.
- Buffered data is flushed automatically when WINDOW_UPDATE frames arrive.

**Frame handling:**

- DATA and HEADERS frames with the PADDED flag are correctly stripped of padding.
- Header blocks split across CONTINUATION frames are assembled before HPACK decoding.
- HPACK Huffman encoding is enabled by default for all outgoing header values.

**Connection management:**

- Server `SETTINGS` frames are parsed and applied: `INITIAL_WINDOW_SIZE` adjustments propagate to existing streams, and `MAX_CONCURRENT_STREAMS` / `MAX_FRAME_SIZE` values are recorded.
- GOAWAY frames (both graceful and error) reject in-flight streams and notify the connection pool via the `onClose` callback.

## Cookies and Middleware

- Cookie storage and matching: `src/cookies/jar.ts`
- Cookie parsing/serialization: `src/cookies/parser.ts`
- Interceptor chain: `src/middleware/interceptor.ts`
- Rate limiter: `src/middleware/rate-limiter.ts`
- Retry helper: `src/middleware/retry.ts`

## CLI Architecture

- Argument parsing: `src/cli/args.ts`
- Request execution: `src/cli/index.ts`
- Output formatting/help: `src/cli/output.ts`

CLI builds an `NLcURLRequest`, dispatches via core client, and formats output.

## Testing Architecture

- Unit tests: `test/unit/*.test.ts`
- Integration tests: `test/integration/client/tests/*`
- Integration HTTPS test server: `test/integration/server/server.js`

Integration runner starts server process, runs all suites, then tears down the server.

## Integration Notes

- **Proxy tunneling** is wired into the protocol negotiator: when `request.proxy` is set, the negotiator establishes a tunnel via HTTP CONNECT or SOCKS before performing the TLS handshake.
- **Retry middleware** is invoked by `NLcURLSession.request()` when `retry.count > 0` in the session config.
- **CLI `--cookie-jar`** loads/saves cookies in Netscape format.
- **HPACK Huffman encoding** is enabled by default for all outgoing HTTP/2 header blocks.
- **TLS certificate validation** in the stealth engine verifies X.509 chains, hostname matching, and CertificateVerify signatures.
- **HTTP/2 send-side flow control** respects both connection and stream send window limits, buffering DATA frames and flushing on WINDOW_UPDATE.
