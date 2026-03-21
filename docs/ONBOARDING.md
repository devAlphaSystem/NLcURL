# Onboarding Guide

Get started with NLcURL — from first request to production integration.

---

## Table of Contents

- [What is NLcURL](#what-is-nlcurl)
- [Prerequisites](#prerequisites)
- [Installation](#installation)
- [Your First Request](#your-first-request)
- [Key Concepts](#key-concepts)
- [Common Patterns](#common-patterns)
- [Browser Impersonation Guide](#browser-impersonation-guide)
- [Migrating from Other Libraries](#migrating-from-other-libraries)
- [Troubleshooting](#troubleshooting)
- [Next Steps](#next-steps)

---

## What is NLcURL

NLcURL is a pure TypeScript HTTP client for Node.js that provides:

- **Full HTTP/1.1 and HTTP/2 support** with automatic protocol negotiation
- **TLS fingerprint impersonation** for 49 browser profiles (Chrome, Firefox, Safari, Edge, Tor)
- **Custom stealth TLS engine** that bypasses OpenSSL to reproduce exact browser handshakes
- **RFC-compliant** cookie management, caching, HSTS, DNS-over-HTTPS/TLS, and connection pooling
- **Zero runtime dependencies** — everything is implemented from scratch

NLcURL is suitable for any scenario where you need precise control over HTTP requests, must match browser TLS fingerprints, or require a standards-compliant HTTP client without external dependencies.

---

## Prerequisites

- **Node.js 18.17.0 or later** (required for native fetch compatibility and crypto APIs)
- **TypeScript 5.0+** (recommended; JavaScript usage is also supported after compilation)

Verify your Node.js version:

```bash
node --version
# v18.17.0 or higher
```

---

## Installation

```bash
npm install nlcurl
```

No additional system libraries or native modules are required.

---

## Your First Request

### Simple GET

```typescript
import { get } from "nlcurl";

const response = await get("https://httpbin.org/get");
console.log(response.status);  // 200
console.log(response.json());  // parsed JSON body
```

### POST with JSON

```typescript
import { post } from "nlcurl";

const response = await post("https://httpbin.org/post", {
  name: "Alice",
  role: "engineer",
});
console.log(response.json());
```

### Using a Session

```typescript
import { createSession } from "nlcurl";

const session = createSession({
  baseURL: "https://api.example.com",
  headers: { "authorization": "Bearer my-token" },
});

const users = await session.get("/users");
const user = await session.post("/users", { name: "Bob" });

// Always close when done to release connection pool resources
session.close();
```

---

## Key Concepts

### One-Shot Functions vs. Sessions

NLcURL provides two ways to make requests:

**One-shot functions** (`get`, `post`, `put`, `patch`, `del`, `head`) create a temporary session, execute one request, and close it. Use these for isolated requests.

```typescript
import { get } from "nlcurl";
await get("https://example.com");
```

**Sessions** (`createSession`) maintain persistent state: connection pool, cookie jar, cache, HSTS store, and interceptors. Use sessions when making multiple requests.

```typescript
import { createSession } from "nlcurl";
const session = createSession();
await session.get("https://example.com/a");
await session.get("https://example.com/b"); // reuses the connection
session.close();
```

### NLcURLResponse

Every request returns an `NLcURLResponse` object:

```typescript
const res = await get("https://example.com");

res.status;         // HTTP status code (number)
res.ok;             // true if status is 200-299
res.headers;        // response headers (object)
res.text();         // body as string
res.json();         // body parsed as JSON
res.rawBody;        // body as Buffer
res.contentType;    // Content-Type header value
res.timings;        // { dns, connect, tls, response, total } in ms
res.httpVersion;    // "1.1" or "2"
res.url;            // final URL (after redirects)
res.redirectUrls;   // array of redirect URLs traversed
```

### Error Handling

By default, NLcURL does not throw on non-2xx responses. Check `response.ok` or `response.status`:

```typescript
const res = await get("https://example.com/maybe-404");
if (!res.ok) {
  console.log(`Request failed: ${res.status}`);
}
```

To throw automatically on non-2xx:

```typescript
import { get, HTTPError } from "nlcurl";

try {
  await get("https://example.com/maybe-404", { throwOnError: true });
} catch (error) {
  if (error instanceof HTTPError) {
    console.log(error.statusCode);
  }
}
```

### Browser Impersonation

NLcURL can mimic the TLS and HTTP/2 fingerprints of real browsers:

```typescript
const res = await get("https://example.com", {
  impersonate: "chrome136",
});
```

Adding `stealth: true` activates the custom TLS engine for exact ClientHello reproduction:

```typescript
const res = await get("https://example.com", {
  impersonate: "chrome136",
  stealth: true,
});
```

---

## Common Patterns

### API Client with Base URL and Auth

```typescript
import { createSession } from "nlcurl";

const api = createSession({
  baseURL: "https://api.example.com/v2",
  headers: { "accept": "application/json" },
  auth: { type: "bearer", token: "eyJhbGciOi..." },
  timeout: 10000,
});

const data = await api.get("/resources");
api.close();
```

### Scraper with Fingerprint Impersonation

```typescript
import { createSession } from "nlcurl";

const session = createSession({
  impersonate: "chrome136",
  stealth: true,
  followRedirects: true,
});

const page = await session.get("https://example.com");
console.log(page.text());
session.close();
```

### Retry on Failure

```typescript
import { createSession } from "nlcurl";

const session = createSession({
  retry: { count: 3, delay: 1000, backoff: "exponential" },
});

await session.get("https://unstable-api.example.com/data");
session.close();
```

### Download a File

```typescript
import { request } from "nlcurl";
import { createWriteStream } from "node:fs";
import { pipeline } from "node:stream/promises";

const res = await request({ url: "https://example.com/file.zip", stream: true });
await pipeline(res.body!, createWriteStream("file.zip"));
```

### Using a Proxy

```typescript
import { get } from "nlcurl";

await get("https://example.com", {
  proxy: "socks5://127.0.0.1:1080",
});
```

---

## Browser Impersonation Guide

### How It Works

Real browsers produce unique TLS and HTTP/2 fingerprints based on their cipher suites, extensions, settings, and header ordering. Anti-bot systems use these fingerprints (JA3, JA4, Akamai) to distinguish automated clients from real browsers.

NLcURL ships 49 browser profiles containing exact TLS parameters, HTTP/2 settings, and header orderings. When `impersonate` is set, NLcURL configures all three layers to match the target browser.

### Standard vs. Stealth Mode

**Standard mode** (`stealth: false`, the default) uses Node.js built-in `tls.connect` with matching cipher suites and ALPN. This works for many targets but Node.js OpenSSL may produce minor fingerprint differences (extension ordering, padding).

**Stealth mode** (`stealth: true`) activates NLcURL's custom TLS engine, which constructs the ClientHello message byte-by-byte to match the target browser exactly. This produces an identical JA3 hash but uses more CPU. The stealth engine supports both TLS 1.3 and TLS 1.2 servers, including Extended Master Secret negotiation (RFC 7627), and works with both HTTPS and plain HTTP connections.

### Choosing a Profile

Use the latest version of the browser you want to impersonate:

```typescript
// Latest Chrome (recommended for general use)
{ impersonate: "chromeLatest" }

// Specific Chrome version
{ impersonate: "chrome136" }

// Firefox
{ impersonate: "firefox138" }

// Safari
{ impersonate: "safari182" }

// Tor Browser
{ impersonate: "tor_latest" }
```

Available browser families: `chrome` (99–136), `firefox` (117–138), `safari` (155–182), `edge` (122–134), `tor` (128–138).

---

## Migrating from Other Libraries

### From node-fetch / native fetch

```typescript
// Before (fetch)
const res = await fetch("https://example.com", {
  method: "POST",
  headers: { "content-type": "application/json" },
  body: JSON.stringify({ key: "value" }),
});
const data = await res.json();

// After (NLcURL)
import { post } from "nlcurl";
const res = await post("https://example.com", { key: "value" });
const data = res.json(); // synchronous — body is already buffered
```

Key differences:
- `json()` and `text()` are synchronous (body is fully buffered by default)
- Pass objects directly as body — automatic JSON serialization
- Use `{ stream: true }` for streaming bodies

### From axios

```typescript
// Before (axios)
const { data } = await axios.get("https://example.com/api");

// After (NLcURL)
import { get } from "nlcurl";
const res = await get("https://example.com/api");
const data = res.json();
```

Key differences:
- Response is `NLcURLResponse`, not auto-unwrapped
- Use `throwOnError: true` for axios-like error throwing behavior
- Session concept is similar to axios instances

---

## Troubleshooting

### Connection Refused / ECONNREFUSED

The target server is not accepting connections. Verify the URL, port, and that the server is running. If using a proxy, verify the proxy is reachable.

### TLS Handshake Failure

```
TLSError [ERR_TLS]: handshake failed
```

- If using `stealth: true`, the target server may not support the cipher suites in the chosen profile. Try a different profile or disable stealth.
- If the server only supports TLS 1.2, the stealth engine handles the downgrade automatically. Ensure you are using a profile that includes TLS 1.2 cipher suites (all built-in profiles do).
- If using client certificates (mTLS), verify the cert and key files are valid.
- If behind a corporate proxy, the proxy may be intercepting TLS. Supply the proxy's CA certificate via `tls.ca`.

### Timeout Errors

```
TimeoutError [ERR_TIMEOUT]: request timed out
```

Increase the timeout value. Use per-phase timeouts to identify where the delay occurs:

```typescript
{
  timeout: {
    connect: 10000,
    tls: 10000,
    response: 30000,
    total: 60000,
  },
}
```

### HTTP 403 / Bot Detection

If a server returns 403 despite impersonation:
- Enable stealth mode: `{ stealth: true }`
- Use a more recent browser profile
- Add realistic headers (Accept-Language, Sec-Ch-Ua, etc.)
- Check if the server requires cookies from a prior page visit — use a session for multi-step flows
- Some servers check IP reputation — consider using a proxy

### Memory Usage

For large response bodies, use streaming mode to avoid buffering the entire response in memory:

```typescript
const res = await request({ url: "https://example.com/large", stream: true });
for await (const chunk of res.body!) {
  // process chunk
}
```

---

## Next Steps

| Topic | Documentation |
|---|---|
| Complete API reference | [API.md](API.md) |
| All configuration options | [CONFIGURATION.md](CONFIGURATION.md) |
| Practical usage examples | [EXAMPLES.md](EXAMPLES.md) |
| Internal module architecture | [MODULES.md](MODULES.md) |
| Build and development setup | [SETUP.md](SETUP.md) |