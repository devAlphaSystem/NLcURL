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

- HTTP/2 client (`H2Client.request`) when negotiated `h2`.
- HTTP/1.1 client (`sendH1Request`) otherwise.

7. Response body is decompressed if `content-encoding` is present.
8. Session stores cookies from response headers.
9. Response interceptors run (`InterceptorChain.processResponse`).
10. Caller receives `NLcURLResponse`.

## Session and Connection Model

- A session owns one `ProtocolNegotiator` and one `ConnectionPool`.
- Pool key is origin (`scheme://host:port`).
- HTTP/1.1 entries are single-flight (`busy` flag) and reused when idle.
- HTTP/2 entries support multiplexing via stream IDs.
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

## Scope Notes

The repository includes reusable proxy and retry modules. Current high-level request flow does not invoke proxy tunneling or retry helper automatically; see `README.md` and `docs/CONFIGURATION.md` for operational details.
