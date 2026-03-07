# Architecture Overview

NLcURL is organized as a layered transport and protocol stack with a strict separation between public API, request orchestration, transport negotiation, and protocol codecs.

## High-Level Layers

1. Public API layer (`src/index.ts`, `src/core/client.ts`)
2. Session orchestration layer (`src/core/session.ts`)
3. Input validation (`src/core/validation.ts`)
4. Protocol negotiation and pooling (`src/http/negotiator.ts`, `src/http/pool.ts`)
5. HTTP protocol implementations (`src/http/h1/*`, `src/http/h2/*`)
6. Request body encoding, including `FormData` (`src/http/form-data.ts`, `src/http/h1/encoder.ts`)
7. TLS engines (`src/tls/node-engine.ts`, `src/tls/stealth/*`)
8. Fingerprint model and profile database (`src/fingerprints/*`)
9. Cross-cutting modules (cookies with PSL enforcement, middleware, proxy, WebSocket, utils)

## Request Lifecycle

1. Caller submits `NLcURLRequest` through `request(...)` or `NLcURLSession.request(...)`.
2. Session merges defaults:

- `baseURL`, `headers`, timeout, fingerprint/profile options, `tls` options.
- Query params are appended to URL.
- Cookie header is injected from the session cookie jar.
- **All header names and values are validated** per RFC 7230 §3.2.6 — CR/LF/NUL injection is rejected.

3. Request interceptors run (`InterceptorChain.processRequest`).
4. Browser profile is resolved from `impersonate` if provided.
5. If the request body is a `ReadableStream<Uint8Array>`, it is **pre-drained** into a `Buffer` (via `drainRequestBody()`) before encoding. `FormData` bodies are serialized via `encode()` with the correct `Content-Type` boundary.
6. `ProtocolNegotiator.send(...)` acquires or creates pooled connection by origin. TLS options (`cert`, `key`, `ca`, etc.) are forwarded to the engine.
   - When no proxy is configured, DNS resolution and TCP connection establishment use the **Happy Eyeballs algorithm (RFC 8305)**: all A and AAAA records are resolved, candidates are interleaved IPv6-first, and connection attempts are raced with a 250 ms stagger. The first socket to connect is used; all others are destroyed. A synchronous OS error (`ENETUNREACH`) on any candidate causes the next address to be tried immediately with no delay.
   - When `dnsFamily` is set, only addresses of that family are resolved, bypassing interleaving.
   - DNS resolution time is recorded separately in `timings.dns`; TCP+TLS time is recorded in `timings.connect`.
6. ALPN and negotiated protocol route the request to:

- HTTP/2 client (`H2Client.streamRequest`) when `request.stream` is set and protocol is `h2`.
- HTTP/2 client (`H2Client.request`) for buffered H2 requests.
- HTTP/1.1 streaming client (`sendH1StreamingRequest`) when `request.stream` is set.
- HTTP/1.1 client (`sendH1Request`) otherwise.

7. Response body is decompressed:

- Buffered mode: `decompressBody` applied to full buffer.
- Streaming mode: `createDecompressStream` piped inline before the body `Readable` is returned.
- Streaming H2 responses resolve correctly even when the server sends HEADERS with END_STREAM (e.g. empty-body 204 responses).

8. If redirect, session follows with RFC 7231-compliant semantics:

- 301/302 + POST: method changes to GET, body cleared, `content-type` and `content-length` stripped.
- 303: method always changes to GET, body cleared, content headers stripped.
- **307/308: method and body are preserved; `content-type` and `content-length` are not stripped.**
- `authorization` and `proxy-authorization` are stripped on cross-origin redirects.

9. If an HTTP/2 RST_STREAM or GOAWAY frame carries error code 1, 2, 7, 8, 11, or 13, a `ProtocolError` with `errorCode` set is thrown. The `withRetry` helper recognises these codes as retryable.
10. Session stores cookies from response headers.
11. Response interceptors run (`InterceptorChain.processResponse`).
12. Caller receives `NLcURLResponse`.

## Session and Connection Model

- A session owns one `ProtocolNegotiator` and one `ConnectionPool`.
- Pool key is origin (`scheme://host:port`).
- HTTP/1.1 entries are single-flight (`busy` flag) and reused when idle.
- HTTP/2 entries support multiplexing via stream IDs. The pool skips entries whose `H2Client.isClosed` is true.
- When an H2 connection receives GOAWAY or encounters an error, its `onClose` callback removes the pool entry automatically. H2 request failures in the negotiator also remove the pool entry (matching H1 behavior).
- Periodic idle/age eviction runs every 30 seconds.

## TLS Engine Strategy

Two engines implement `ITLSEngine`:

- `NodeTLSEngine`: uses built-in `node:tls`; supports cipher/group/sigalgs/ALPN tuning and mTLS client certificates (`cert`, `key`, `pfx`, `passphrase`, `ca`).
- `StealthTLSEngine`: raw TLS handshake path for finer ClientHello control.

Session/request options select engine via `stealth`.

### TLS 1.3 Key Schedule (`tls/stealth/key-schedule.ts`)

The stealth engine implements the TLS 1.3 key schedule per RFC 8446 §7.1:

- `hkdfExpandLabel` performs **HKDF-Expand-only** (not Extract+Expand) using a manual HMAC loop, producing the correct HkdfLabel-encoded output.
- `hkdfExtract` performs the HKDF-Extract step (`HMAC(salt, IKM)`).
- `deriveSecret` and `deriveHandshakeKeys` / `deriveApplicationKeys` compose these primitives to derive the full key schedule chain (early → handshake → application traffic secrets).

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
- **Request-level headers take priority over profile default headers.** When a profile supplies a default header and the request also supplies the same header name, the request value is used.
- **Streaming requests** (`streamRequest`) resolve the returned promise as soon as response headers are received, including when the server sends HEADERS with END_STREAM (empty-body responses such as 204 No Content).

**Connection management:**

- Server `SETTINGS` frames are parsed and applied: `SETTINGS_HEADER_TABLE_SIZE` updates the HPACK decoder table, `INITIAL_WINDOW_SIZE` adjustments propagate to existing streams, and `MAX_CONCURRENT_STREAMS` / `MAX_FRAME_SIZE` values are recorded.
- `INITIAL_WINDOW_SIZE` values exceeding 2³¹−1 and `MAX_FRAME_SIZE` values outside [16384, 16777215] trigger GOAWAY with PROTOCOL_ERROR per RFC 9113.
- `WINDOW_UPDATE` increments that would overflow the signed 31-bit window produce GOAWAY (connection-level) or RST_STREAM (stream-level) with FLOW_CONTROL_ERROR.
- HPACK Huffman decoded output is capped at 64 KB to prevent decompression bombs.
- GOAWAY frames (both graceful and error) reject in-flight streams and notify the connection pool via the `onClose` callback.

## Cookies and Security

- Cookie storage and matching: `src/cookies/jar.ts`
- Cookie parsing/serialization: `src/cookies/parser.ts`
- **Public Suffix List**: `src/cookies/public-suffix.ts` — trie-based lookup against the full Mozilla PSL (10,000+ rules). Prevents supercookie attacks by rejecting `Set-Cookie` headers whose `Domain` attribute is a public suffix.
- **SameSite default**: cookies without an explicit `SameSite` attribute default to `lax`.
- **Cookie prefix validation**: `__Host-` cookies must be `Secure`, have no `Domain` attribute, and use `Path=/`. `__Secure-` cookies must be `Secure`.
- PSL data is auto-generated via `npm run update-psl` and committed to the repository.

## Middleware

- Interceptor chain: `src/middleware/interceptor.ts`
- Rate limiter: `src/middleware/rate-limiter.ts`
- Retry helper: `src/middleware/retry.ts`

## Input Validation

- Header names validated per RFC 7230 §3.2.6 token grammar.
- Header values checked for forbidden CR/LF/NUL bytes.
- Validation applied in session header merging (`session.ts`) and HTTP/1.1 encoder (`h1/encoder.ts`).
- Session config, request fields, and rate limit config validated at entry points (`validation.ts`).

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

- **Happy Eyeballs (RFC 8305)** is used for all direct (non-proxy) connections. The negotiator resolves all A and AAAA records, interleaves them IPv6-first, and races TCP connection attempts with a 250 ms stagger. This eliminates hangs on hosts where IPv6 interfaces are present but non-routable.
- **Proxy tunneling** is wired into the protocol negotiator: when `request.proxy` is set, the negotiator establishes a tunnel via HTTP CONNECT or SOCKS before performing the TLS handshake. Happy Eyeballs is bypassed for proxy connections; DNS is delegated to the proxy.
- **Retry middleware** is invoked by `NLcURLSession.request()` when `retry.count > 0` in the session config. Exponential backoff factor is capped at 32× base delay.
- **CLI `--cookie-jar`** loads/saves cookies in Netscape format.
- **HPACK Huffman encoding** is enabled by default for all outgoing HTTP/2 header blocks.
- **TLS certificate validation** in the stealth engine verifies X.509 chains, hostname matching, and CertificateVerify signatures.
- **HTTP/2 send-side flow control** respects both connection and stream send window limits, buffering DATA frames and flushing on WINDOW_UPDATE.
- **FormData** builds `multipart/form-data` bodies per RFC 7578 with cryptographic boundary generation and header-injection-safe Content-Disposition escaping.
- **Proxy hardening**: SOCKS5 enforces 255-byte limits on username, password, and hostname. HTTP CONNECT responses are capped at 16 KB.
- **WebSocket frame validation**: non-zero RSV bits (without negotiated extensions), unknown opcodes, and masked server frames are rejected per RFC 6455.
