# NLcURL — Usage Examples

A complete collection of usage examples for both the Node.js package API and the `nlcurl` CLI.

---

## Table of Contents

### Package Examples

1. [One-Shot Requests](#1-one-shot-requests)
2. [Sessions](#2-sessions)
3. [Browser Impersonation](#3-browser-impersonation)
4. [Request Bodies](#4-request-bodies)
5. [Headers and Query Parameters](#5-headers-and-query-parameters)
6. [Cookies and Cookie Jar](#6-cookies-and-cookie-jar)
7. [Redirects](#7-redirects)
8. [Streaming Responses](#8-streaming-responses)
9. [Proxy Support](#9-proxy-support)
10. [Retry Configuration](#10-retry-configuration)
11. [Rate Limiting](#11-rate-limiting)
12. [Interceptors](#12-interceptors)
13. [WebSocket](#13-websocket)
14. [Timeouts and Abort Signals](#14-timeouts-and-abort-signals)
15. [TLS and HTTP Version Control](#15-tls-and-http-version-control)
16. [Error Handling](#16-error-handling)
17. [Fingerprint Inspection](#17-fingerprint-inspection)
18. [Raw Headers and Timings](#18-raw-headers-and-timings)
19. [DNS Family](#19-dns-family)
20. [Header Ordering](#20-header-ordering)

### CLI Examples

21. [Basic Usage](#21-basic-usage)
22. [HTTP Methods](#22-http-methods)
23. [Headers](#23-headers)
24. [Request Body](#24-request-body)
25. [Impersonation and Stealth](#25-impersonation-and-stealth)
26. [Custom Fingerprints (JA3 / Akamai)](#26-custom-fingerprints-ja3--akamai)
27. [Proxy](#27-proxy)
28. [Cookies and Cookie Jar](#28-cookies-and-cookie-jar)
29. [Redirects](#29-redirects)
30. [Timeouts](#30-timeouts)
31. [HTTP Version](#31-http-version)
32. [Output Control](#32-output-control)
33. [TLS](#33-tls)
34. [Profile Listing](#34-profile-listing)

---

## Package Examples

### 1. One-Shot Requests

One-shot helpers do not share connections, cookies, or state. Prefer sessions for repeated requests to the same host.

```ts
import { request, get, post, put, patch, del, head } from "nlcurl";

// Basic GET
const res = await get("https://httpbin.org/get");
console.log(res.status); // 200
console.log(res.json()); // parsed JSON body

// GET with shorthand (url only)
const r = await request({ url: "https://httpbin.org/uuid" });
console.log(r.text());

// POST
const posted = await post("https://httpbin.org/post", { name: "Alice", age: 30 }); // body auto-serialized to JSON
console.log(posted.json());

// PUT
const updated = await put("https://httpbin.org/put", { id: 42, value: "updated" });

// PATCH
const patched = await patch("https://httpbin.org/patch", { field: "new-value" });

// DELETE
const deleted = await del("https://httpbin.org/delete");

// HEAD (returns headers, no body)
const checked = await head("https://httpbin.org/get");
console.log(checked.headers["content-type"]);

// OPTIONS
const opts = await request({ url: "https://httpbin.org/get", method: "OPTIONS" });
console.log(opts.headers["allow"]);
```

---

### 2. Sessions

Sessions pool connections, share cookies, and support interceptors and rate limiting.

```ts
import { createSession } from "nlcurl";

const session = createSession({
  baseURL: "https://httpbin.org",
  headers: { "X-My-Header": "hello" },
  timeout: 10_000,
  followRedirects: true,
});

// Shorthand methods
const a = await session.get("/get");
const b = await session.post("/post", { x: 1 });
const c = await session.put("/put", { x: 2 });
const d = await session.patch("/patch", { x: 3 });
const e = await session.delete("/delete");
const f = await session.head("/get");

// Full request object
const g = await session.request({
  url: "/anything",
  method: "POST",
  body: { data: true },
});

session.close();
```

#### Session with retry and rate limiting

```ts
import { createSession } from "nlcurl";

const session = createSession({
  baseURL: "https://api.example.com",
  retry: {
    count: 3,
    delay: 500,
    backoff: "exponential",
    jitter: 100,
  },
});

session.setRateLimit({ maxRequests: 10, windowMs: 1000 });

const res = await session.get("/resource");
session.close();
```

#### Chained session configuration

```ts
import { createSession } from "nlcurl";

const session = createSession({ baseURL: "https://httpbin.org" })
  .onRequest((req) => {
    req.headers ??= {};
    req.headers["X-Request-Id"] = crypto.randomUUID();
    return req;
  })
  .onResponse((res) => {
    console.log(`[${res.status}] ${res.headers["content-type"]}`);
    return res;
  })
  .setRateLimit({ maxRequests: 5, windowMs: 1000 });

const res = await session.get("/get");
session.close();
```

---

### 3. Browser Impersonation

All profile names are case-insensitive and ignore hyphens/spaces.

```ts
import { request } from "nlcurl";

// Latest Chrome (default when no profile is specified)
const chrome = await request({ url: "https://tls.browserleaks.com/json", impersonate: "chrome" });

// Specific versioned profiles
const chrome99 = await request({ url: "https://tls.browserleaks.com/json", impersonate: "chrome99" });
const chrome136 = await request({ url: "https://tls.browserleaks.com/json", impersonate: "chrome136" });

// Firefox profiles
const firefox = await request({ url: "https://tls.browserleaks.com/json", impersonate: "firefox" });
const firefox138 = await request({ url: "https://tls.browserleaks.com/json", impersonate: "firefox138" });

// Safari profiles
const safari = await request({ url: "https://tls.browserleaks.com/json", impersonate: "safari" });
const safari182 = await request({ url: "https://tls.browserleaks.com/json", impersonate: "safari182" });

// Edge profiles
const edge = await request({ url: "https://tls.browserleaks.com/json", impersonate: "edge" });
const edge136 = await request({ url: "https://tls.browserleaks.com/json", impersonate: "edge136" });

// Tor Browser profiles
const tor = await request({ url: "https://tls.browserleaks.com/json", impersonate: "tor" });
const tor145 = await request({ url: "https://tls.browserleaks.com/json", impersonate: "tor145" });
```

#### Stealth TLS engine

The stealth engine constructs the TLS ClientHello from scratch to precisely match a real browser. Use it when passive TLS fingerprinting (JA3, etc.) is actively checked.

```ts
import { request } from "nlcurl";

const res = await request({
  url: "https://tls.browserleaks.com/json",
  impersonate: "chrome136",
  stealth: true,
});

console.log(res.json());
```

#### Session-level impersonation

```ts
import { createSession } from "nlcurl";

const session = createSession({
  impersonate: "firefox138",
  stealth: true,
});

const a = await session.get("https://tls.browserleaks.com/json");
// Override impersonation on a specific request:
const b = await session.get("https://tls.browserleaks.com/json", { impersonate: "safari182" });
session.close();
```

#### Custom JA3 and Akamai fingerprints

```ts
import { request } from "nlcurl";

// Provide a raw JA3 string to override the cipher/extension/curve selections
const res = await request({
  url: "https://tls.browserleaks.com/json",
  ja3: "771,4865-4866-4867-49195-49199-49196-49200-52393-52392-49171-49172-156-157-47-53,0-23-65281-10-11-35-16-5-13-18-51-45-43-27-21,29-23-24,0",
});

// Provide an Akamai pseudo-header fingerprint to override H2 SETTINGS frames
const res2 = await request({
  url: "https://tls.browserleaks.com/json",
  impersonate: "chrome136",
  akamai: "1:65536,2:0,4:6291456,6:262144|15663105|0|m,a,s,p",
});
```

---

### 4. Request Bodies

Body type is inferred automatically — no need to set `Content-Type` manually in most cases.

```ts
import { request } from "nlcurl";

// Plain object → Content-Type: application/json
const json = await request({
  url: "https://httpbin.org/post",
  method: "POST",
  body: { username: "alice", role: "admin" },
});

// String → Content-Type: application/x-www-form-urlencoded
const form = await request({
  url: "https://httpbin.org/post",
  method: "POST",
  body: "username=alice&role=admin",
});

// URLSearchParams → form-encoded automatically
const params = new URLSearchParams({ username: "alice", role: "admin" });
const formEncoded = await request({
  url: "https://httpbin.org/post",
  method: "POST",
  body: params,
});

// Buffer → Content-Type: application/x-www-form-urlencoded
const buf = await request({
  url: "https://httpbin.org/post",
  method: "POST",
  body: Buffer.from("raw-bytes"),
});

// Override Content-Type explicitly
const custom = await request({
  url: "https://httpbin.org/post",
  method: "POST",
  headers: { "Content-Type": "text/plain" },
  body: "plain text payload",
});

// Streaming upload with ReadableStream
import { createReadStream } from "node:fs";
import { Readable } from "node:stream";

const fileStream = Readable.toWeb(createReadStream("./payload.bin")) as ReadableStream<Uint8Array>;
const streamed = await request({
  url: "https://httpbin.org/post",
  method: "POST",
  headers: { "Content-Type": "application/octet-stream" },
  body: fileStream,
});

// Null body (no body sent)
const noBody = await request({
  url: "https://httpbin.org/get",
  method: "GET",
  body: null,
});
```

---

### 5. Headers and Query Parameters

```ts
import { request } from "nlcurl";

// Custom headers
const res = await request({
  url: "https://httpbin.org/headers",
  headers: {
    Accept: "application/json",
    "X-Custom": "my-value",
    Authorization: "Bearer token123",
  },
});

// Query parameters (appended to URL)
const withParams = await request({
  url: "https://httpbin.org/get",
  params: {
    search: "typescript",
    page: 2,
    active: true,
  },
});
// Resulting URL: https://httpbin.org/get?search=typescript&page=2&active=true

// Inline query string (also works)
const inline = await request({ url: "https://httpbin.org/get?foo=bar&baz=1" });

// Session-level default headers overridden per-request
import { createSession } from "nlcurl";

const session = createSession({
  baseURL: "https://httpbin.org",
  headers: { "Accept-Language": "en-US" },
});

const r = await session.get("/headers", {
  headers: { "Accept-Language": "fr-FR" }, // overrides session default
});

session.close();
```

---

### 6. Cookies and Cookie Jar

#### Per-request cookie jar

```ts
import { request } from "nlcurl";

// Enable automatic cookie handling for this request chain
const res = await request({
  url: "https://httpbin.org/cookies/set?flavor=chocolate",
  cookieJar: true,
  followRedirects: true,
});

// The redirect target receives the Set-Cookie cookies automatically
console.log(res.json()); // { cookies: { flavor: 'chocolate' } }
```

#### Shared CookieJar instance

```ts
import { CookieJar, request } from "nlcurl";

const jar = new CookieJar();

// First request — server sets cookies
await request({
  url: "https://httpbin.org/cookies/set?session=abc123",
  cookieJar: jar,
  followRedirects: true,
});

// Second request — cookies forwarded automatically
const check = await request({
  url: "https://httpbin.org/cookies",
  cookieJar: jar,
});
console.log(check.json()); // { cookies: { session: 'abc123' } }

// Inspect stored cookies
console.log(jar.all()); // ReadonlyArray<Cookie>
console.log(jar.size); // 1

// Serialize to Netscape format
const netscape = jar.toNetscapeString();
console.log(netscape);

// Clear cookies for a specific domain
jar.clearDomain("httpbin.org");

// Clear all cookies
jar.clear();
```

#### Session-level cookie jar

```ts
import { createSession } from "nlcurl";

const session = createSession({
  baseURL: "https://httpbin.org",
  cookieJar: true, // shared jar across all session requests
});

await session.get("/cookies/set?token=xyz");
const cookies = await session.get("/cookies");
console.log(cookies.json()); // { cookies: { token: 'xyz' } }

// Read current session cookies into a CookieJar
const jar = session.getCookies();
console.log(jar?.all());

session.close();
```

#### Loading cookies from a Netscape file

```ts
import { CookieJar } from "nlcurl";
import { readFileSync } from "node:fs";

const jar = new CookieJar();
jar.loadNetscapeString(readFileSync("./cookies.txt", "utf8"));
```

---

### 7. Redirects

```ts
import { request } from "nlcurl";

// Follow redirects (default: true, up to 20)
const followed = await request({
  url: "https://httpbin.org/redirect/3",
});
console.log(followed.status); // 200

// Disable redirect following
const raw = await request({
  url: "https://httpbin.org/redirect/1",
  followRedirects: false,
});
console.log(raw.status); // 302

// Limit redirect count
const limited = await request({
  url: "https://httpbin.org/redirect/5",
  maxRedirects: 2, // throws RedirectError after 2 hops
});

// 307/308 redirects preserve the request body and Content-* headers
const preserved = await request({
  url: "https://httpbin.org/redirect-to?url=https%3A%2F%2Fhttpbin.org%2Fpost&status_code=307",
  method: "POST",
  body: { data: "important" }, // body is forwarded to the redirect target
});
console.log(preserved.json());
```

---

### 8. Streaming Responses

```ts
import { request } from "nlcurl";

// Request a streaming response
const res = await request({
  url: "https://httpbin.org/stream/10",
  stream: true,
});

if (!res.body) throw new Error("no stream");

// Pipe to stdout
const { stdout } = process;
for await (const chunk of res.body) {
  stdout.write(chunk);
}

// Or collect into a buffer
import { request as nlrequest } from "nlcurl";

const streamRes = await nlrequest({
  url: "https://httpbin.org/bytes/1024",
  stream: true,
});

const chunks: Uint8Array[] = [];
for await (const chunk of streamRes.body!) {
  chunks.push(chunk);
}
const full = Buffer.concat(chunks);
console.log(full.byteLength); // 1024

// Write streaming response directly to a file
import { createWriteStream } from "node:fs";

const fileRes = await request({
  url: "https://httpbin.org/bytes/65536",
  stream: true,
});

const out = createWriteStream("./download.bin");
fileRes.body!.pipe(out);
```

---

### 9. Proxy Support

```ts
import { request } from "nlcurl";

// HTTP proxy
const httpProxy = await request({
  url: "https://httpbin.org/get",
  proxy: "http://proxy.example.com:8080",
});

// HTTP proxy with authentication
const authProxy = await request({
  url: "https://httpbin.org/get",
  proxy: "http://proxy.example.com:8080",
  proxyAuth: ["proxyuser", "proxypass"],
});

// SOCKS5 proxy
const socks5 = await request({
  url: "https://httpbin.org/get",
  proxy: "socks5://127.0.0.1:1080",
});

// SOCKS4 proxy
const socks4 = await request({
  url: "https://httpbin.org/get",
  proxy: "socks4://127.0.0.1:1080",
});

// Session-level proxy
import { createSession } from "nlcurl";

const session = createSession({
  proxy: "socks5://127.0.0.1:9050",
  impersonate: "tor145",
});

const res = await session.get("https://check.torproject.org");
session.close();
```

---

### 10. Retry Configuration

```ts
import { createSession } from "nlcurl";

const session = createSession({
  baseURL: "https://api.example.com",
  retry: {
    count: 4, // up to 4 retries (5 total attempts)
    delay: 300, // 300 ms base delay
    backoff: "exponential", // 300 → 600 → 1200 → 2400 ms
    jitter: 150, // up to 150 ms random jitter per attempt
  },
});

const res = await session.get("/unstable-endpoint");
session.close();
```

#### Custom retry predicate

```ts
import { createSession } from "nlcurl";

const session = createSession({
  retry: {
    count: 3,
    delay: 500,
    backoff: "linear",
    jitter: 0,
    retryOn: (error, statusCode) => {
      // Only retry on 429 and 503
      return statusCode === 429 || statusCode === 503;
    },
  },
});

const res = await session.get("https://api.example.com/data");
session.close();
```

#### Linear backoff

```ts
import { createSession } from "nlcurl";

const session = createSession({
  retry: {
    count: 3,
    delay: 1000,
    backoff: "linear", // 1000 → 2000 → 3000 ms
    jitter: 0,
  },
});
```

---

### 11. Rate Limiting

```ts
import { createSession } from "nlcurl";

const session = createSession({ baseURL: "https://api.example.com" });

// Allow at most 5 requests per second
session.setRateLimit({ maxRequests: 5, windowMs: 1000 });

// These will be automatically queued if necessary
await Promise.all([
  session.get("/a"),
  session.get("/b"),
  session.get("/c"),
  session.get("/d"),
  session.get("/e"),
  session.get("/f"), // queued until the window refills
]);

session.close();
```

#### Rate limiting with chaining

```ts
import { createSession } from "nlcurl";

const session = createSession({ baseURL: "https://api.example.com" }).setRateLimit({ maxRequests: 2, windowMs: 500 });

const r = await session.get("/resource");
session.close();
```

---

### 12. Interceptors

Interceptors let you mutate every request before it is sent and every response before it is returned. Both are always called in registration order; each must return the (possibly modified) value.

```ts
import { createSession } from "nlcurl";

const session = createSession({ baseURL: "https://httpbin.org" });

// Add an Authorization header to every request
session.onRequest((req) => {
  req.headers ??= {};
  req.headers["Authorization"] = "Bearer " + getAccessToken();
  return req;
});

// Log every response
session.onResponse((res) => {
  console.log(`← ${res.status} (${res.timings.total} ms)`);
  return res;
});

const r = await session.get("/get");
session.close();

function getAccessToken() {
  return "my-token";
}
```

#### Refresh token on 401

```ts
import { createSession, NLcURLResponse } from "nlcurl";

let token = "initial-token";

const session = createSession({ baseURL: "https://api.example.com" });

session.onRequest((req) => {
  req.headers ??= {};
  req.headers["Authorization"] = `Bearer ${token}`;
  return req;
});

session.onResponse(async (res) => {
  if (res.status === 401) {
    token = await refreshToken();
    // re-issue the original request via a one-off fetch
    return session.request({ url: res.url, headers: { Authorization: `Bearer ${token}` } });
  }
  return res;
});

async function refreshToken() {
  return "new-token";
}
```

#### Signing requests

```ts
import { createSession } from "nlcurl";
import { createHmac } from "node:crypto";

const SECRET = "shared-secret";

const session = createSession({ baseURL: "https://api.example.com" });

session.onRequest((req) => {
  const ts = String(Date.now());
  const sig = createHmac("sha256", SECRET)
    .update(ts + req.url)
    .digest("hex");
  req.headers ??= {};
  req.headers["X-Timestamp"] = ts;
  req.headers["X-Signature"] = sig;
  return req;
});
```

---

### 13. WebSocket

```ts
import { WebSocketClient } from "nlcurl";

const ws = new WebSocketClient("wss://echo.websocket.org", {
  impersonate: "chrome136",
  stealth: true,
  headers: { Origin: "https://echo.websocket.org" },
  protocols: ["chat", "superchat"],
  timeout: 5000,
});

ws.on("open", () => {
  console.log("Connected");
  ws.sendText("Hello, world!");
  ws.sendBinary(Buffer.from([0x01, 0x02, 0x03]));
  ws.ping(Buffer.from("ping"));
});

ws.on("message", (data: string | Buffer) => {
  console.log("Received:", data);
});

ws.on("ping", (payload: Buffer) => {
  console.log("Ping received:", payload.toString());
  // pong is sent automatically
});

ws.on("pong", (payload: Buffer) => {
  console.log("Pong received:", payload.toString());
});

ws.on("close", (code: number, reason: string) => {
  console.log(`Closed: ${code} ${reason}`);
});

ws.on("error", (err: Error) => {
  console.error("WS error:", err.message);
});

// Close with a custom code and reason
setTimeout(() => ws.close(1000, "done"), 3000);
```

#### WebSocket with insecure TLS

```ts
import { WebSocketClient } from "nlcurl";

const ws = new WebSocketClient("wss://self-signed.example.com/ws", {
  insecure: true,
});

ws.on("open", () => ws.sendText("test"));
ws.on("message", (d) => console.log(d));
```

---

### 14. Timeouts and Abort Signals

```ts
import { request } from "nlcurl";

// Flat timeout: total milliseconds
const flat = await request({
  url: "https://httpbin.org/delay/1",
  timeout: 5000, // 5 s total
});

// Per-phase timeout
const phased = await request({
  url: "https://httpbin.org/delay/1",
  timeout: {
    connect: 2000, // TCP connect must complete within 2 s
    tls: 3000, // TLS handshake must complete within 3 s
    response: 4000, // first byte must arrive within 4 s
    total: 10_000, // entire request must finish within 10 s
  },
});

// Manual abort with AbortController
const controller = new AbortController();

setTimeout(() => controller.abort(), 2000);

const abortable = await request({
  url: "https://httpbin.org/delay/5",
  signal: controller.signal,
});
```

#### Cancelling multiple requests

```ts
import { request } from "nlcurl";

const ac = new AbortController();

const [a, b] = await Promise.allSettled([request({ url: "https://httpbin.org/delay/3", signal: ac.signal }), request({ url: "https://httpbin.org/delay/3", signal: ac.signal })]);

ac.abort(); // both requests cancelled
```

---

### 15. TLS and HTTP Version Control

```ts
import { request } from "nlcurl";

// Force HTTP/1.1
const http1 = await request({
  url: "https://httpbin.org/get",
  httpVersion: "1.1",
});

// Force HTTP/2
const http2 = await request({
  url: "https://httpbin.org/get",
  httpVersion: "2",
});

// Skip TLS certificate verification (development only)
const insecure = await request({
  url: "https://self-signed.example.com/api",
  insecure: true,
});

// Accept compressed responses (gzip, br, deflate)
const compressed = await request({
  url: "https://httpbin.org/gzip",
  acceptEncoding: "gzip, deflate, br",
});

// Session-level HTTP/2 forcing with impersonation
import { createSession } from "nlcurl";

const session = createSession({
  impersonate: "chrome136",
  httpVersion: "2",
});
const r = await session.get("https://httpbin.org/get");
session.close();
```

---

### 16. Error Handling

```ts
import { request, NLcURLError, AbortError, TimeoutError, ConnectionError, ProtocolError, ProxyError } from "nlcurl";

try {
  const res = await request({
    url: "https://httpbin.org/delay/60",
    timeout: 2000,
  });
} catch (err) {
  if (err instanceof AbortError) {
    console.error("Request was aborted");
  } else if (err instanceof TimeoutError) {
    console.error("Request timed out after", err.message);
  } else if (err instanceof ConnectionError) {
    console.error("Could not connect:", err.message);
  } else if (err instanceof ProtocolError) {
    console.error("Protocol error (H2 code:", err.errorCode, "):", err.message);
  } else if (err instanceof ProxyError) {
    console.error("Proxy connection failed:", err.message);
  } else if (err instanceof NLcURLError) {
    // Covers TLSError, HTTPError, and max-redirects exceeded (code ERR_MAX_REDIRECTS)
    console.error("Generic NLcURL error:", err.message, err.code);
  } else {
    throw err;
  }
}
```

#### Handling HTTP error status codes

```ts
import { request } from "nlcurl";

const res = await request({ url: "https://httpbin.org/status/404" });

// Status codes do NOT throw — check manually
if (res.status >= 400) {
  console.error(`HTTP ${res.status}: ${res.statusText}`);
}

if (res.status === 429) {
  const retryAfter = res.headers["retry-after"];
  console.log("Rate limited, retry after:", retryAfter);
}
```

#### Checking response body safely

```ts
import { request } from "nlcurl";

const res = await request({ url: "https://httpbin.org/get" });

// json() throws SyntaxError if body is not valid JSON
try {
  const data = res.json<{ url: string }>();
  console.log(data.url);
} catch {
  console.error("Response was not JSON:", res.text());
}
```

---

### 17. Fingerprint Inspection

```ts
import { getProfile, listProfiles, ja3Hash, ja3String, akamaiFingerprint, DEFAULT_PROFILE } from "nlcurl";

// List all registered profile keys
const profiles = listProfiles();
console.log(profiles); // ['chrome136', 'chrome_latest', 'edge136', 'edge_latest', ...]

// Look up a profile by name (case-insensitive, ignores hyphens)
const profile = getProfile("Chrome136");
// BrowserProfile has: .name, .browser, .version, .tls, .h2, .headers
console.log(profile?.name); // 'chrome136'
console.log(profile?.tls.cipherSuites); // cipher suite IDs

// DEFAULT_PROFILE is a BrowserProfile object (the latest bundled Chrome profile)
console.log(DEFAULT_PROFILE.name); // 'chrome136'
console.log(DEFAULT_PROFILE.browser); // 'chrome'

// Compute JA3 hash from a raw ClientHello buffer
// ja3Hash(helloBuffer: Buffer): string
// ja3String(helloBuffer: Buffer): string
// akamaiFingerprint(settings: Buffer): string

// These utilities require raw bytes captured from a real TLS connection;
// they are not pre-computed properties of BrowserProfile.
import { request } from "nlcurl";
```

---

### 18. Raw Headers and Timings

```ts
import { request } from "nlcurl";

const res = await request({ url: "https://httpbin.org/response-headers?X-Foo=bar" });

// Normalized (lowercase) header map — fast key lookup
console.log(res.headers["content-type"]); // 'application/json'

// Raw headers — original casing from the wire, preserves duplicates
// Array of [name, value] tuples
console.log(res.rawHeaders);
// [['Content-Type', 'application/json'], ['X-Foo', 'bar'], ...]

for (const [name, value] of res.rawHeaders) {
  console.log(`${name}: ${value}`);
}

// Access request timing breakdown (ms since request start)
const { dns, connect, tls, firstByte, total } = res.timings;
console.log(`DNS: ${dns} ms`);
console.log(`TCP: ${connect} ms`);
console.log(`TLS: ${tls} ms`);
console.log(`First byte: ${firstByte} ms`);
console.log(`Total: ${total} ms`);
```

---

### 19. DNS Family

```ts
import { request } from "nlcurl";

// Force IPv4
const v4 = await request({
  url: "https://httpbin.org/get",
  dnsFamily: 4,
});

// Force IPv6
const v6 = await request({
  url: "https://httpbin.org/get",
  dnsFamily: 6,
});
```

---

### 20. Header Ordering

Some anti-bot systems check the order of HTTP headers in a request. `headerOrder` lets you specify the exact order to emit headers.

```ts
import { request } from "nlcurl";

const res = await request({
  url: "https://httpbin.org/headers",
  headers: {
    Accept: "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
    "Accept-Language": "en-US,en;q=0.5",
    "Accept-Encoding": "gzip, deflate, br",
    DNT: "1",
  },
  headerOrder: ["Accept", "Accept-Language", "Accept-Encoding", "DNT"],
});
```

---

## CLI Examples

### 21. Basic Usage

```bash
# Simple GET request
nlcurl https://httpbin.org/get

# Pretty-print by piping to jq
nlcurl https://httpbin.org/get | jq .

# Print version
nlcurl --version

# Show help
nlcurl --help
```

---

### 22. HTTP Methods

```bash
# GET (default)
nlcurl https://httpbin.org/get

# POST
nlcurl -X POST https://httpbin.org/post

# PUT
nlcurl -X PUT https://httpbin.org/put

# PATCH
nlcurl -X PATCH https://httpbin.org/patch

# DELETE
nlcurl -X DELETE https://httpbin.org/delete

# HEAD (use -I flag)
nlcurl -I https://httpbin.org/get

# OPTIONS
nlcurl -X OPTIONS https://httpbin.org/get
```

---

### 23. Headers

```bash
# Single header
nlcurl -H "Authorization: Bearer mytoken" https://httpbin.org/headers

# Multiple headers
nlcurl \
  -H "Accept: application/json" \
  -H "X-Custom-ID: 12345" \
  -H "Authorization: Bearer mytoken" \
  https://httpbin.org/headers

# Custom User-Agent
nlcurl -A "MyBot/1.0" https://httpbin.org/user-agent

# Include response headers in output
nlcurl -i https://httpbin.org/get

# Include response headers only (HEAD)
nlcurl -I https://httpbin.org/get
```

---

### 24. Request Body

```bash
# POST JSON body
nlcurl -X POST \
  -H "Content-Type: application/json" \
  -d '{"username":"alice","password":"secret"}' \
  https://httpbin.org/post

# POST form-encoded body
nlcurl -X POST \
  -d "username=alice&password=secret" \
  https://httpbin.org/post

# Raw body (no URL-encoding)
nlcurl -X POST \
  --data-raw '{"raw":"value"}' \
  https://httpbin.org/post

# PUT with body
nlcurl -X PUT \
  -H "Content-Type: application/json" \
  -d '{"id":1,"value":"updated"}' \
  https://httpbin.org/put

# PATCH with body
nlcurl -X PATCH \
  -H "Content-Type: application/json" \
  -d '{"field":"new"}' \
  https://httpbin.org/patch
```

---

### 25. Impersonation and Stealth

```bash
# Impersonate latest Chrome (TLS fingerprint + headers + H2 settings)
nlcurl --impersonate chrome https://tls.browserleaks.com/json

# Specific Chrome version
nlcurl --impersonate chrome136 https://tls.browserleaks.com/json

# Firefox
nlcurl --impersonate firefox138 https://tls.browserleaks.com/json

# Safari
nlcurl --impersonate safari182 https://tls.browserleaks.com/json

# Edge
nlcurl --impersonate edge136 https://tls.browserleaks.com/json

# Tor Browser
nlcurl --impersonate tor145 https://tls.browserleaks.com/json

# Impersonate + stealth TLS engine (constructs ClientHello from scratch)
nlcurl --impersonate chrome136 --stealth https://tls.browserleaks.com/json

# Request compressed response with impersonation
nlcurl --impersonate firefox138 --compressed https://httpbin.org/gzip
```

---

### 26. Custom Fingerprints (JA3 / Akamai)

```bash
# Override JA3 fingerprint
nlcurl --ja3 "771,4865-4866-4867-49195-49199-49196-49200-52393-52392-49171-49172-156-157-47-53,0-23-65281-10-11-35-16-5-13-18-51-45-43-27-21,29-23-24,0" \
  https://tls.browserleaks.com/json

# Override Akamai H2 fingerprint
nlcurl \
  --impersonate chrome136 \
  --akamai "1:65536,2:0,4:6291456,6:262144|15663105|0|m,a,s,p" \
  https://tls.browserleaks.com/json

# Combine both custom fingerprints
nlcurl \
  --ja3 "771,4865-4866-4867-49195-49199-49196-49200-52393-52392-49171-49172-156-157-47-53,0-23-65281-10-11-35-16-5-13-18-51-45-43-27-21,29-23-24,0" \
  --akamai "1:65536,2:0,4:6291456,6:262144|15663105|0|m,a,s,p" \
  https://tls.browserleaks.com/json
```

---

### 27. Proxy

```bash
# HTTP proxy
nlcurl -x http://proxy.example.com:8080 https://httpbin.org/get

# HTTP proxy with credentials (inline)
nlcurl -x http://proxy.example.com:8080 -U "proxyuser:proxypass" https://httpbin.org/get

# SOCKS5 proxy
nlcurl -x socks5://127.0.0.1:1080 https://httpbin.org/get

# SOCKS4 proxy
nlcurl -x socks4://127.0.0.1:1080 https://httpbin.org/get

# Tor (SOCKS5) with Tor Browser impersonation
nlcurl -x socks5://127.0.0.1:9050 --impersonate tor145 https://check.torproject.org

# Proxy with TLS skip
nlcurl -x http://proxy.example.com:8080 -k https://self-signed.internal/api
```

---

### 28. Cookies and Cookie Jar

```bash
# Send a raw cookie string
nlcurl -b "session=abc123; token=xyz" https://httpbin.org/cookies

# Load cookies from and save to a Netscape-format file
nlcurl -c ./cookies.txt https://httpbin.org/cookies/set?flavor=chocolate -L

# Use an existing cookie file (read-only) as a cookie source
nlcurl -b ./cookies.txt https://httpbin.org/cookies

# Load from file and save back (combined -b/-c)
nlcurl -b ./cookies.txt -c ./cookies.txt https://httpbin.org/cookies/set?key=val -L
```

---

### 29. Redirects

```bash
# Follow redirects (default behavior; -L is a no-op but explicit for clarity)
nlcurl -L https://httpbin.org/redirect/3

# Disable redirect following
nlcurl --no-location https://httpbin.org/redirect/1

# Limit redirect count
nlcurl -L --max-redirs 2 https://httpbin.org/redirect/5
```

---

### 30. Timeouts

```bash
# Set total timeout in seconds
nlcurl -m 5 https://httpbin.org/delay/1

# 2-second timeout (will error on a slow endpoint)
nlcurl -m 2 https://httpbin.org/delay/10

# Combined with impersonation
nlcurl -m 10 --impersonate chrome136 https://tls.browserleaks.com/json
```

---

### 31. HTTP Version

```bash
# Force HTTP/1.1
nlcurl --http1.1 https://httpbin.org/get

# Force HTTP/2
nlcurl --http2 https://httpbin.org/get

# Force HTTP/2 with impersonation
nlcurl --http2 --impersonate chrome136 https://httpbin.org/get
```

---

### 32. Output Control

```bash
# Write response body to a file
nlcurl -o ./response.json https://httpbin.org/get

# Download a binary file
nlcurl -o ./image.png https://httpbin.org/image/png

# Silent mode (suppress all non-body output)
nlcurl -s https://httpbin.org/get

# Verbose mode (show request + response headers and timings)
nlcurl -v https://httpbin.org/get

# Verbose + write body to file
nlcurl -v -o ./out.json https://httpbin.org/get

# Include response headers in stdout output
nlcurl -i https://httpbin.org/get

# Request gzip compression and decompress
nlcurl --compressed https://httpbin.org/gzip

# Combine: impersonate + compressed + verbose + output file
nlcurl --impersonate chrome136 --compressed -v -o ./data.json https://httpbin.org/get
```

---

### 33. TLS

```bash
# Skip TLS certificate verification
nlcurl -k https://self-signed.example.com/api

# Skip TLS verification with impersonation
nlcurl -k --impersonate chrome136 https://self-signed.example.com/api

# Skip TLS verification with stealth
nlcurl -k --stealth --impersonate chrome136 https://self-signed.example.com/api
```

---

### 34. Profile Listing

```bash
# List all built-in browser profiles
nlcurl --list-profiles
```

Example output:

```
chrome
chrome99
chrome101
chrome112
chrome116
chrome120
chrome124
chrome128
chrome131
chrome133
chrome136
chrome_latest
edge
edge99
edge101
edge126
edge131
edge136
edge_latest
firefox
firefox133
firefox135
firefox136
firefox137
firefox138
firefox_latest
safari
safari153
safari161
safari173
safari180
safari182
safari_latest
tor
tor133
tor140
tor145
tor_latest
```

---

## Advanced Combinations

### Session with impersonation, proxy, retries, and interceptors

```ts
import { createSession } from "nlcurl";

const session = createSession({
  baseURL: "https://api.example.com",
  impersonate: "chrome136",
  stealth: true,
  proxy: "socks5://127.0.0.1:1080",
  cookieJar: true,
  retry: { count: 3, delay: 500, backoff: "exponential", jitter: 100 },
  timeout: { connect: 5000, tls: 5000, total: 30_000 },
  dnsFamily: 4,
})
  .onRequest((req) => {
    req.headers ??= {};
    req.headers["X-Request-Id"] = crypto.randomUUID();
    return req;
  })
  .onResponse((res) => {
    console.log(`[${res.status}] ${res.timings.total} ms`);
    return res;
  })
  .setRateLimit({ maxRequests: 10, windowMs: 1000 });

const res = await session.post("/login", { username: "alice", password: "secret" });

const profile = await session.get("/profile");
console.log(profile.json());

session.close();
```

### CLI pipeline: scrape + parse

```bash
# Fetch a JSON API, extract a field with jq
nlcurl --impersonate chrome136 --compressed -s https://api.example.com/data \
  | jq '.results[].name'

# Download and verify content
nlcurl -o ./data.json --impersonate firefox138 -L https://api.example.com/export
echo "Downloaded $(wc -c < ./data.json) bytes"

# POST login, save cookies, then fetch protected endpoint
nlcurl -X POST \
  -H "Content-Type: application/json" \
  -d '{"user":"alice","pass":"secret"}' \
  -c ./session.txt \
  -L \
  https://api.example.com/login

nlcurl -b ./session.txt https://api.example.com/protected
```
