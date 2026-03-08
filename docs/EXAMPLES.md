# Examples

Practical usage patterns for NLcURL. All examples use ES module imports.

---

## Table of Contents

- [Basic Requests](#basic-requests)
- [Browser Impersonation](#browser-impersonation)
- [Sessions and Connection Reuse](#sessions-and-connection-reuse)
- [Authentication](#authentication)
- [Streaming](#streaming)
- [Server-Sent Events](#server-sent-events)
- [WebSocket](#websocket)
- [File Upload](#file-upload)
- [Proxy Usage](#proxy-usage)
- [TLS Configuration](#tls-configuration)
- [Cookie Management](#cookie-management)
- [Caching](#caching)
- [HSTS](#hsts)
- [DNS Configuration](#dns-configuration)
- [Retry and Rate Limiting](#retry-and-rate-limiting)
- [Interceptors](#interceptors)
- [Progress Tracking](#progress-tracking)
- [Error Handling](#error-handling)
- [Logging](#logging)
- [Timeouts and Abort](#timeouts-and-abort)
- [Request Body Compression](#request-body-compression)
- [Fingerprint Inspection](#fingerprint-inspection)
- [CLI Usage](#cli-usage)

---

## Basic Requests

### GET Request

```typescript
import { get } from "nlcurl";

const response = await get("https://httpbin.org/get");
console.log(response.status);       // 200
console.log(response.ok);           // true
console.log(response.json());       // parsed JSON body
console.log(response.text());       // raw text body
console.log(response.contentType);  // "application/json"
```

### POST with JSON Body

```typescript
import { post } from "nlcurl";

const response = await post("https://httpbin.org/post", {
  name: "Alice",
  age: 30,
});
// Content-Type is automatically set to application/json
```

### POST with Form Data

```typescript
import { post } from "nlcurl";

const response = await post("https://httpbin.org/post",
  new URLSearchParams({ username: "alice", password: "secret" }),
);
// Content-Type: application/x-www-form-urlencoded
```

### PUT, PATCH, DELETE, HEAD

```typescript
import { put, patch, del, head } from "nlcurl";

await put("https://httpbin.org/put", { key: "value" });
await patch("https://httpbin.org/patch", { key: "updated" });
await del("https://httpbin.org/delete");
const headRes = await head("https://httpbin.org/get");
console.log(headRes.headers["content-length"]);
```

### Custom Headers

```typescript
import { get } from "nlcurl";

const response = await get("https://httpbin.org/headers", {
  headers: {
    "x-custom-header": "custom-value",
    "accept": "application/json",
  },
});
```

### Query Parameters

```typescript
import { get } from "nlcurl";

const response = await get("https://httpbin.org/get", {
  params: {
    search: "nlcurl",
    page: 1,
    active: true,
  },
});
// URL becomes: https://httpbin.org/get?search=nlcurl&page=1&active=true
```

---

## Browser Impersonation

### Impersonate Chrome

```typescript
import { get } from "nlcurl";

const response = await get("https://tls.browserleaks.com/json", {
  impersonate: "chrome136",
});
```

### Impersonate with Stealth TLS Engine

```typescript
import { get } from "nlcurl";

// Uses NLcURL's custom TLS engine for exactClientHello reproduction
const response = await get("https://example.com", {
  impersonate: "firefox138",
  stealth: true,
});
```

### List Available Profiles

```typescript
import { listProfiles, getProfile } from "nlcurl";

console.log(listProfiles());
// ["chrome99", "chrome100", ..., "tor_latest"]

const profile = getProfile("chrome136");
console.log(profile?.browser);    // "chrome"
console.log(profile?.version);    // "136"
```

### Impersonate Safari Through a Session

```typescript
import { createSession } from "nlcurl";

const session = createSession({
  impersonate: "safari182",
  stealth: true,
});

const res1 = await session.get("https://example.com/page1");
const res2 = await session.get("https://example.com/page2");
session.close();
```

---

## Sessions and Connection Reuse

### Persistent Session

```typescript
import { createSession } from "nlcurl";

const session = createSession({
  baseURL: "https://api.example.com/v2",
  headers: {
    "authorization": "Bearer my-token",
    "accept": "application/json",
  },
  timeout: 15000,
});

const users = await session.get("/users");
const user = await session.post("/users", { name: "Bob" });
const updated = await session.patch("/users/1", { name: "Robert" });
await session.delete("/users/2");

session.close();
```

### Base URL with Relative Paths

```typescript
import { createSession } from "nlcurl";

const session = createSession({
  baseURL: "https://api.github.com",
  headers: { "accept": "application/vnd.github.v3+json" },
});

// Resolved: https://api.github.com/repos/nodejs/node
const repo = await session.get("/repos/nodejs/node");
session.close();
```

---

## Authentication

### Basic Auth

```typescript
import { get } from "nlcurl";

const response = await get("https://httpbin.org/basic-auth/user/pass", {
  auth: { type: "basic", username: "user", password: "pass" },
});
```

### Bearer Token

```typescript
import { get } from "nlcurl";

const response = await get("https://api.example.com/protected", {
  auth: { type: "bearer", token: "eyJhbGciOiJIUzI1NiIsInR..." },
});
```

---

## Streaming

### Streaming Response

```typescript
import { request } from "nlcurl";

const response = await request({
  url: "https://example.com/large-file.zip",
  stream: true,
});

// response.body is a Readable stream
for await (const chunk of response.body!) {
  process.stdout.write(chunk);
}
```

### Stream to File

```typescript
import { request } from "nlcurl";
import { createWriteStream } from "node:fs";
import { pipeline } from "node:stream/promises";

const response = await request({
  url: "https://example.com/archive.tar.gz",
  stream: true,
});

await pipeline(response.body!, createWriteStream("archive.tar.gz"));
```

---

## Server-Sent Events

### Async Generator

```typescript
import { request } from "nlcurl";
import { parseSSEStream } from "nlcurl";

const response = await request({
  url: "https://example.com/events",
  stream: true,
  headers: { "accept": "text/event-stream" },
});

for await (const event of parseSSEStream(response.body!)) {
  console.log(`Event: ${event.event}`);
  console.log(`Data: ${event.data}`);
  console.log(`ID: ${event.id}`);
}
```

### Manual SSE Parsing

```typescript
import { SSEParser } from "nlcurl";

const parser = new SSEParser();
parser.feed("event: update\ndata: {\"value\":42}\n\n");

let event;
while ((event = parser.pull()) !== null) {
  console.log(event.event);  // "update"
  console.log(event.data);   // '{"value":42}'
}
```

---

## WebSocket

### Basic WebSocket

```typescript
import { WebSocketClient } from "nlcurl";

const ws = new WebSocketClient("wss://echo.websocket.events");

ws.on("open", () => {
  console.log("Connected");
  ws.sendText("Hello, WebSocket!");
});

ws.on("message", (data, isBinary) => {
  console.log("Received:", isBinary ? data : data.toString());
});

ws.on("close", (code, reason) => {
  console.log(`Closed: ${code} ${reason}`);
});

ws.on("error", (error) => {
  console.error("Error:", error.message);
});
```

### WebSocket with Impersonation and Compression

```typescript
import { WebSocketClient } from "nlcurl";

const ws = new WebSocketClient("wss://example.com/ws", {
  impersonate: "chrome136",
  stealth: true,
  compress: true,       // permessage-deflate
  protocols: ["graphql-ws"],
  headers: {
    "authorization": "Bearer token",
  },
});

ws.on("open", () => {
  ws.sendText(JSON.stringify({
    type: "connection_init",
    payload: {},
  }));
});
```

---

## File Upload

### Multipart Form Data

```typescript
import { post } from "nlcurl";
import { FormData } from "nlcurl";
import { readFileSync } from "node:fs";

const form = new FormData();
form.append("field", "value");
form.append("file", {
  data: readFileSync("photo.jpg"),
  filename: "photo.jpg",
  contentType: "image/jpeg",
});

const response = await post("https://httpbin.org/post", form);
```

### Resumable Upload

```typescript
import {
  buildUploadCreationHeaders,
  buildUploadResumeHeaders,
  splitIntoChunks,
  parseUploadUrl,
  parseUploadOffset,
  isUploadComplete,
} from "nlcurl";
import { post, patch } from "nlcurl";

const fileData = Buffer.alloc(10 * 1024 * 1024); // 10 MB

// Step 1: Create the upload
const createHeaders = buildUploadCreationHeaders(fileData.length, "application/octet-stream");
const createRes = await post("https://example.com/uploads", null, {
  headers: createHeaders,
});
const uploadUrl = parseUploadUrl(createRes.headers, "https://example.com/uploads")!;

// Step 2: Upload in chunks
const chunks = splitIntoChunks(fileData);
for (const [offset, chunk] of chunks) {
  const isLast = offset + chunk.length >= fileData.length;
  const headers = buildUploadResumeHeaders(offset, chunk.length, isLast);
  await patch(uploadUrl, chunk, { headers });
}
```

---

## Proxy Usage

### HTTP Proxy

```typescript
import { get } from "nlcurl";

const response = await get("https://example.com", {
  proxy: "http://proxy.company.com:8080",
});
```

### SOCKS5 Proxy

```typescript
import { get } from "nlcurl";

const response = await get("https://example.com", {
  proxy: "socks5://127.0.0.1:1080",
});
```

### SOCKS5 with Authentication

```typescript
import { get } from "nlcurl";

const response = await get("https://example.com", {
  proxy: "socks5://proxy.example.com:1080",
  proxyAuth: ["username", "password"],
});
```

### HTTPS Proxy

```typescript
import { get } from "nlcurl";

const response = await get("https://example.com", {
  proxy: "https://secure-proxy.example.com:443",
});
```

### Environment Variable Proxies

```bash
export HTTPS_PROXY=http://proxy.company.com:8080
export NO_PROXY=localhost,127.0.0.1,.internal.corp
```

```typescript
import { get } from "nlcurl";

// Proxy is automatically resolved from environment variables
const response = await get("https://example.com");
```

---

## TLS Configuration

### Client Certificates (mTLS)

```typescript
import { get } from "nlcurl";
import { readFileSync } from "node:fs";

const response = await get("https://mtls.example.com/api", {
  tls: {
    cert: readFileSync("client.crt"),
    key: readFileSync("client.key"),
    passphrase: "key-passphrase",
  },
});
```

### Custom CA Certificate

```typescript
import { get } from "nlcurl";
import { readFileSync } from "node:fs";

const response = await get("https://internal.example.com", {
  tls: {
    ca: readFileSync("internal-ca.pem"),
  },
});
```

### Certificate Pinning

```typescript
import { get } from "nlcurl";

const response = await get("https://example.com", {
  tls: {
    pinnedPublicKey: "sha256//YLh1dUR9y6Kja30RrAn7JKnbQG/uEtLMkBgFF2Fuihg=",
  },
});
```

### TLS Keylogging (Wireshark Decryption)

```typescript
import { setKeylogFile } from "nlcurl";

setKeylogFile("/tmp/tls-keys.log");
// All subsequent TLS sessions log key material in NSS format
```

Or via environment variable:

```bash
export SSLKEYLOGFILE=/tmp/tls-keys.log
```

---

## Cookie Management

### Automatic Cookie Handling

```typescript
import { createSession } from "nlcurl";

const session = createSession();

// Cookies from Set-Cookie headers are automatically stored
await session.get("https://httpbin.org/cookies/set/session/abc123");

// Subsequent requests include stored cookies
const response = await session.get("https://httpbin.org/cookies");
console.log(response.json()); // { cookies: { session: "abc123" } }

session.close();
```

### Shared Cookie Jar

```typescript
import { createSession, CookieJar } from "nlcurl";

const jar = new CookieJar({ maxCookies: 5000 });

const session1 = createSession({ cookieJar: jar });
const session2 = createSession({ cookieJar: jar });

// Both sessions share the same cookie storage
```

### Export/Import Cookies (Netscape Format)

```typescript
import { CookieJar } from "nlcurl";
import { writeFileSync, readFileSync } from "node:fs";

const jar = new CookieJar();

// Export to Netscape cookie file
writeFileSync("cookies.txt", jar.toNetscapeString());

// Import from Netscape cookie file
const jar2 = new CookieJar();
jar2.loadNetscapeString(readFileSync("cookies.txt", "utf-8"));
```

### Disable Cookies

```typescript
import { createSession } from "nlcurl";

const session = createSession({ cookieJar: false });
```

---

## Caching

### Enable Caching

```typescript
import { createSession } from "nlcurl";

const session = createSession({
  cacheConfig: {
    maxEntries: 500,
    maxSize: 25 * 1024 * 1024,    // 25 MB
  },
});

// First request: fetched from server and cached
await session.get("https://example.com/data");

// Second request: served from cache if fresh
await session.get("https://example.com/data");

session.close();
```

### Cache Modes

```typescript
import { createSession } from "nlcurl";

const session = createSession({
  cacheConfig: { maxEntries: 1000 },
});

// Force bypass cache
await session.get("https://example.com/data", { cache: "no-store" });

// Always revalidate
await session.get("https://example.com/data", { cache: "no-cache" });

// Serve stale if available
await session.get("https://example.com/data", { cache: "force-cache" });

// Cache-only, 504 if not cached
await session.get("https://example.com/data", { cache: "only-if-cached" });

session.close();
```

### Inspect Cache Store

```typescript
const cache = session.getCache();
if (cache) {
  console.log(`Entries: ${cache.size}`);
  console.log(`Total size: ${cache.totalSize} bytes`);
  cache.delete("GET", "https://example.com/stale");
  cache.clear();
}
```

---

## HSTS

### Enable HSTS

```typescript
import { createSession } from "nlcurl";

const session = createSession({
  hsts: {
    enabled: true,
    preload: [
      { host: "example.com", includeSubDomains: true },
    ],
  },
});

// This http:// URL is automatically upgraded to https://
await session.get("http://example.com/api");

session.close();
```

---

## DNS Configuration

### DNS-over-HTTPS

```typescript
import { createSession } from "nlcurl";

const session = createSession({
  dns: {
    doh: {
      server: "https://1.1.1.1/dns-query",
      method: "POST",
      timeout: 3000,
    },
  },
});

await session.get("https://example.com");
session.close();
```

### DNS-over-TLS

```typescript
import { DoTResolver, DOT_SERVERS } from "nlcurl";

const resolver = new DoTResolver({
  server: DOT_SERVERS.google.host,
  servername: DOT_SERVERS.google.servername,
  keepAlive: true,
});

const ipv4 = await resolver.resolve4("example.com");
const ipv6 = await resolver.resolve6("example.com");

resolver.close();
```

### Force IPv4 or IPv6

```typescript
import { get } from "nlcurl";

const ipv4 = await get("https://example.com", { dnsFamily: 4 });
const ipv6 = await get("https://example.com", { dnsFamily: 6 });
```

---

## Retry and Rate Limiting

### Automatic Retry

```typescript
import { createSession } from "nlcurl";

const session = createSession({
  retry: {
    count: 5,
    delay: 2000,
    backoff: "exponential",
    jitter: 500,
  },
});

// Retries on 429, 500, 502, 503, 504, and connection errors
await session.get("https://unstable-api.example.com/data");
session.close();
```

### Custom Retry Predicate

```typescript
import { createSession } from "nlcurl";

const session = createSession({
  retry: {
    count: 3,
    delay: 1000,
    backoff: "linear",
    retryOn: (error, statusCode) => {
      if (statusCode === 429) return true;
      if (error?.message.includes("ECONNRESET")) return true;
      return false;
    },
  },
});
```

### Rate Limiting

```typescript
import { createSession } from "nlcurl";

const session = createSession();

session.setRateLimit({
  maxRequests: 10,
  windowMs: 1000,      // 10 requests per second
});

// Requests exceeding the rate are automatically queued
const promises = Array.from({ length: 50 }, (_, i) =>
  session.get(`https://api.example.com/items/${i}`)
);

await Promise.all(promises);
session.close();
```

---

## Interceptors

### Request Interceptor

```typescript
import { createSession } from "nlcurl";

const session = createSession();

session.onRequest((req) => {
  // Add a timestamp header to every request
  return {
    ...req,
    headers: {
      ...req.headers,
      "x-request-time": new Date().toISOString(),
    },
  };
});

await session.get("https://example.com");
session.close();
```

### Response Interceptor

```typescript
import { createSession } from "nlcurl";

const session = createSession();

session.onResponse((response) => {
  console.log(`${response.request.method} ${response.url} → ${response.status} (${response.timings.total}ms)`);
  return response;
});

await session.get("https://example.com");
session.close();
```

### Async Interceptors

```typescript
import { createSession } from "nlcurl";

const session = createSession();

session.onRequest(async (req) => {
  // Fetch a dynamic token before each request
  const tokenRes = await fetch("https://auth.example.com/token");
  const { token } = await tokenRes.json();
  return {
    ...req,
    headers: { ...req.headers, authorization: `Bearer ${token}` },
  };
});
```

---

## Progress Tracking

### Download Progress

```typescript
import { get } from "nlcurl";

const response = await get("https://example.com/large-file", {
  onDownloadProgress: (event) => {
    console.log(`Downloaded: ${event.bytes}/${event.totalBytes} (${event.percent.toFixed(1)}%)`);
  },
});
```

### Upload Progress

```typescript
import { post } from "nlcurl";

const response = await post("https://example.com/upload", largeBuffer, {
  onUploadProgress: (event) => {
    console.log(`Uploaded: ${event.percent.toFixed(1)}%`);
  },
});
```

---

## Error Handling

### Error Types

```typescript
import { get, NLcURLError, HTTPError, TimeoutError, TLSError, ConnectionError } from "nlcurl";

try {
  await get("https://example.com/not-found", { throwOnError: true });
} catch (error) {
  if (error instanceof HTTPError) {
    console.log(`HTTP ${error.statusCode}: ${error.message}`);
    console.log(`Code: ${error.code}`);  // "ERR_HTTP"
  } else if (error instanceof TimeoutError) {
    console.log(`Timeout in ${error.phase} phase`);
  } else if (error instanceof TLSError) {
    console.log(`TLS error (alert ${error.alertCode}): ${error.message}`);
  } else if (error instanceof ConnectionError) {
    console.log(`Connection failed: ${error.message}`);
  } else if (error instanceof NLcURLError) {
    console.log(`Error [${error.code}]: ${error.message}`);
  }
}
```

### Throw on Non-2xx

```typescript
import { createSession } from "nlcurl";

const session = createSession({ throwOnError: true });

// Throws HTTPError for status codes outside 200-299
try {
  await session.get("https://httpbin.org/status/500");
} catch (error) {
  console.log(error.statusCode);  // 500
}

session.close();
```

### JSON Error Serialization

```typescript
import { NLcURLError } from "nlcurl";

try {
  // ...
} catch (error) {
  if (error instanceof NLcURLError) {
    console.log(JSON.stringify(error.toJSON(), null, 2));
    // { name, code, message, stack, cause? }
  }
}
```

---

## Logging

### Debug Logging

```typescript
import { createSession, ConsoleLogger } from "nlcurl";

const session = createSession({
  logger: new ConsoleLogger("debug"),
});

// Outputs to stderr: [nlcurl:debug] request GET https://...
// Outputs to stderr: [nlcurl:debug] response GET https://... 200 45ms
await session.get("https://example.com");
session.close();
```

### JSON Structured Logging

```typescript
import { createSession, JsonLogger } from "nlcurl";

const session = createSession({
  logger: new JsonLogger("info", "my-api-client"),
});
```

### Set Global Default Logger

```typescript
import { setDefaultLogger, ConsoleLogger } from "nlcurl";

// All sessions created without an explicit logger will use this
setDefaultLogger(new ConsoleLogger("debug"));
```

---

## Timeouts and Abort

### Simple Timeout

```typescript
import { get } from "nlcurl";

const response = await get("https://slow-api.example.com", {
  timeout: 5000,   // 5 seconds for everything
});
```

### Per-Phase Timeouts

```typescript
import { get } from "nlcurl";

const response = await get("https://example.com", {
  timeout: {
    connect: 5000,
    tls: 5000,
    response: 10000,
    total: 30000,
  },
});
```

### AbortController

```typescript
import { get } from "nlcurl";

const controller = new AbortController();

setTimeout(() => controller.abort(), 5000);

try {
  const response = await get("https://example.com", {
    signal: controller.signal,
  });
} catch (error) {
  if (error.code === "ERR_ABORTED") {
    console.log("Request was aborted");
  }
}
```

---

## Request Body Compression

```typescript
import { post } from "nlcurl";

const largePayload = JSON.stringify({ data: "x".repeat(10000) });

const response = await post("https://example.com/api", largePayload, {
  compressBody: "gzip",
  headers: { "content-type": "application/json" },
});
// Content-Encoding: gzip is automatically set
// Body is compressed before sending (only for bodies ≥ 1024 bytes)
```

---

## Fingerprint Inspection

### Compute JA3 Hash

```typescript
import { getProfile, ja3Hash, ja3String } from "nlcurl";

const profile = getProfile("chrome136")!;
console.log(ja3String(profile.tls));
console.log(ja3Hash(profile.tls));
```

### Compute JA4 Fingerprint

```typescript
import { getProfile, ja4Fingerprint } from "nlcurl";

const profile = getProfile("firefox138")!;
console.log(ja4Fingerprint(profile.tls));
```

### Compute Akamai HTTP/2 Fingerprint

```typescript
import { getProfile, akamaiFingerprint } from "nlcurl";

const profile = getProfile("chrome136")!;
console.log(akamaiFingerprint(profile.h2));
```

---

## CLI Usage

### Basic GET

```bash
nlcurl https://httpbin.org/get
```

### POST with JSON

```bash
nlcurl -X POST \
  -H "Content-Type: application/json" \
  -d '{"name": "Alice"}' \
  https://httpbin.org/post
```

### Browser Impersonation

```bash
nlcurl --impersonate chrome136 --stealth https://tls.browserleaks.com/json
```

### Verbose Output

```bash
nlcurl -v https://example.com
```

Output:
```
> GET / HTTP/1.1
> host: example.com
> accept: */*
>
< HTTP/2 200 OK
< content-type: text/html
< content-length: 1256
<
<!doctype html>...
```

### Save Output to File

```bash
nlcurl -o page.html https://example.com
```

### With Proxy and Cookies

```bash
nlcurl -x socks5://127.0.0.1:1080 \
  -c cookies.txt \
  https://example.com
```

### Force HTTP Version

```bash
nlcurl --http2 https://example.com
nlcurl --http1.1 https://example.com
```

### List Profiles

```bash
nlcurl --list-profiles
```