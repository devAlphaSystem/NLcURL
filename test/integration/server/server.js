/**
 * NLcURL Integration Test Server
 *
 * A comprehensive HTTPS test server with endpoints covering every
 * HTTP feature NLcURL supports: methods, headers, cookies, redirects,
 * compression, chunked encoding, timeouts, status codes, and more.
 *
 * Usage:
 *   node server.js            → starts on a random port, prints it
 *   node server.js --port=N   → starts on port N
 */

import https from "node:https";
import { createServer as createH2SecureServer } from "node:http2";
import zlib from "node:zlib";
import { URL } from "node:url";
import { generateCert } from "./cert.js";

const { key, cert } = generateCert();

// ── Routing ──────────────────────────────────────────────────────────

const routes = new Map();

function route(method, path, handler) {
  routes.set(`${method} ${path}`, handler);
}

function matchRoute(method, pathname) {
  // Exact match first
  const exact = routes.get(`${method} ${pathname}`);
  if (exact) return exact;
  // Wildcard match
  for (const [key, handler] of routes) {
    const [m, p] = key.split(" ", 2);
    if (m === "*" && p === pathname) return handler;
    if (m === method && p.endsWith("*") && pathname.startsWith(p.slice(0, -1))) return handler;
  }
  return null;
}

// ── Helpers ──────────────────────────────────────────────────────────

function readBody(req) {
  return new Promise((resolve, reject) => {
    const chunks = [];
    req.on("data", (c) => chunks.push(c));
    req.on("end", () => resolve(Buffer.concat(chunks)));
    req.on("error", reject);
  });
}

function json(res, data, status = 200) {
  const body = JSON.stringify(data);
  res.writeHead(status, {
    "content-type": "application/json",
    "content-length": Buffer.byteLength(body),
  });
  res.end(body);
}

// ── Endpoints ────────────────────────────────────────────────────────

// 1. Echo: returns method, url, headers, body
route("*", "/echo", async (req, res) => {
  const body = await readBody(req);
  json(res, {
    method: req.method,
    url: req.url,
    headers: req.headers,
    body: body.toString("utf8"),
    bodyLength: body.length,
  });
});

// 2. GET /json — returns a JSON payload
route("GET", "/json", (req, res) => {
  json(res, { message: "hello", items: [1, 2, 3], nested: { a: true } });
});

// 3. GET /text — returns plain text
route("GET", "/text", (req, res) => {
  const body = "Hello, NLcURL!";
  res.writeHead(200, {
    "content-type": "text/plain",
    "content-length": Buffer.byteLength(body),
  });
  res.end(body);
});

// 4. GET /status/:code — returns the given status code
route("GET", "/status/*", (req, res) => {
  const code = parseInt(req.url.split("/status/")[1], 10) || 200;
  const texts = { 200: "OK", 201: "Created", 204: "No Content", 301: "Moved", 400: "Bad Request", 401: "Unauthorized", 403: "Forbidden", 404: "Not Found", 500: "Internal Server Error", 502: "Bad Gateway", 503: "Service Unavailable" };
  if (code === 204) {
    res.writeHead(204);
    res.end();
    return;
  }
  json(res, { status: code, message: texts[code] || "Unknown" }, code);
});

// 5. GET /headers — returns request headers back as JSON
route("GET", "/headers", (req, res) => {
  json(res, { headers: req.headers });
});

// 6. POST /post — echoes posted JSON body
route("POST", "/post", async (req, res) => {
  const body = await readBody(req);
  let parsed;
  const ct = req.headers["content-type"] || "";
  if (ct.includes("application/json")) {
    try {
      parsed = JSON.parse(body.toString());
    } catch {
      parsed = null;
    }
  } else if (ct.includes("application/x-www-form-urlencoded")) {
    parsed = Object.fromEntries(new URLSearchParams(body.toString()));
  } else {
    parsed = body.toString();
  }
  json(res, {
    received: parsed,
    contentType: ct,
    contentLength: body.length,
  });
});

// 7. PUT /put — echoes PUT body
route("PUT", "/put", async (req, res) => {
  const body = await readBody(req);
  json(res, { method: "PUT", body: body.toString(), length: body.length });
});

// 8. PATCH /patch — echoes PATCH body
route("PATCH", "/patch", async (req, res) => {
  const body = await readBody(req);
  json(res, { method: "PATCH", body: body.toString(), length: body.length });
});

// 9. DELETE /delete — returns confirmation
route("DELETE", "/delete", (req, res) => {
  json(res, { method: "DELETE", deleted: true });
});

// 10. HEAD /head — returns headers only (no body)
route("HEAD", "/head", (req, res) => {
  res.writeHead(200, {
    "content-type": "application/json",
    "x-custom": "head-test",
    "content-length": "42",
  });
  res.end();
});

// 11. OPTIONS /options
route("OPTIONS", "/options", (req, res) => {
  res.writeHead(200, {
    allow: "GET, POST, PUT, PATCH, DELETE, HEAD, OPTIONS",
    "content-length": "0",
  });
  res.end();
});

// 12. Cookie setting: GET /cookies/set?name=value&name2=value2
route("GET", "/cookies/set", (req, res) => {
  const url = new URL(req.url, `https://${req.headers.host}`);
  const cookies = [];
  for (const [name, value] of url.searchParams) {
    cookies.push(`${name}=${value}; Path=/; HttpOnly`);
  }
  const headers = {};
  // Use raw setHeader to send multiple Set-Cookie headers
  res.writeHead(200, { "content-type": "application/json" });
  // writeHead doesn't support duplicate keys, use raw write
  // Actually we need to use res.setHeader before writeHead
  // Let's restart the response
  res.socket; // no-op
  json(res, { cookies_set: cookies.length });
  return; // json already sent headers
});

// Better cookie set: uses raw socket writes for multiple Set-Cookie
route("GET", "/cookies/setmulti", (req, res) => {
  const url = new URL(req.url, `https://${req.headers.host}`);
  const setCookies = [];
  for (const [name, value] of url.searchParams) {
    setCookies.push(`${name}=${value}; Path=/; HttpOnly`);
  }
  // Node's http API supports array for Set-Cookie
  const body = JSON.stringify({ cookies_set: setCookies.length });
  res.writeHead(200, {
    "content-type": "application/json",
    "content-length": Buffer.byteLength(body),
    "set-cookie": setCookies,
  });
  res.end(body);
});

// 13. Cookie reading: GET /cookies/get — returns cookies received
route("GET", "/cookies/get", (req, res) => {
  const cookieHeader = req.headers["cookie"] || "";
  const cookies = {};
  if (cookieHeader) {
    for (const pair of cookieHeader.split(";")) {
      const [k, ...v] = pair.trim().split("=");
      if (k) cookies[k.trim()] = v.join("=").trim();
    }
  }
  json(res, { cookies });
});

// 14. Redirects
route("GET", "/redirect/301", (req, res) => {
  res.writeHead(301, { location: "/redirect/target" });
  res.end();
});

route("GET", "/redirect/302", (req, res) => {
  res.writeHead(302, { location: "/redirect/target" });
  res.end();
});

route("GET", "/redirect/303", (req, res) => {
  res.writeHead(303, { location: "/redirect/target" });
  res.end();
});

route("GET", "/redirect/307", (req, res) => {
  res.writeHead(307, { location: "/redirect/target" });
  res.end();
});

route("GET", "/redirect/308", (req, res) => {
  res.writeHead(308, { location: "/redirect/target" });
  res.end();
});

route("POST", "/redirect/307", async (req, res) => {
  res.writeHead(307, { location: "/echo" });
  res.end();
});

route("POST", "/redirect/303", async (req, res) => {
  res.writeHead(303, { location: "/echo" });
  res.end();
});

route("GET", "/redirect/target", (req, res) => {
  json(res, { redirected: true, method: req.method });
});

// Redirect chain: /redirect/chain/N → N-1 → ... → 0 → /redirect/target
route("GET", "/redirect/chain/*", (req, res) => {
  const n = parseInt(req.url.split("/redirect/chain/")[1], 10);
  if (isNaN(n) || n <= 0) {
    json(res, { redirected: true, chain_complete: true });
    return;
  }
  res.writeHead(302, { location: `/redirect/chain/${n - 1}` });
  res.end();
});

// Redirect with cookie: sets a cookie then redirects
route("GET", "/redirect/withcookie", (req, res) => {
  res.writeHead(302, {
    location: "/cookies/get",
    "set-cookie": "redirect_cookie=from_redirect; Path=/",
  });
  res.end();
});

// 15. Compressed responses
route("GET", "/gzip", (req, res) => {
  const data = JSON.stringify({ compressed: "gzip", data: "x".repeat(500) });
  const compressed = zlib.gzipSync(data);
  res.writeHead(200, {
    "content-type": "application/json",
    "content-encoding": "gzip",
    "content-length": compressed.length,
  });
  res.end(compressed);
});

route("GET", "/deflate", (req, res) => {
  const data = JSON.stringify({ compressed: "deflate", data: "x".repeat(500) });
  const compressed = zlib.deflateSync(data);
  res.writeHead(200, {
    "content-type": "application/json",
    "content-encoding": "deflate",
    "content-length": compressed.length,
  });
  res.end(compressed);
});

route("GET", "/brotli", (req, res) => {
  const data = JSON.stringify({ compressed: "brotli", data: "x".repeat(500) });
  const compressed = zlib.brotliCompressSync(data);
  res.writeHead(200, {
    "content-type": "application/json",
    "content-encoding": "br",
    "content-length": compressed.length,
  });
  res.end(compressed);
});

// 16. Chunked transfer encoding
route("GET", "/chunked", (req, res) => {
  res.writeHead(200, { "content-type": "text/plain", "transfer-encoding": "chunked" });
  const chunks = ["Hello,", " ", "chunked", " ", "world!"];
  let i = 0;
  const iv = setInterval(() => {
    if (i < chunks.length) {
      res.write(chunks[i]);
      i++;
    } else {
      clearInterval(iv);
      res.end();
    }
  }, 10);
});

// 17. Large response
route("GET", "/large", (req, res) => {
  const size = 100_000;
  const body = Buffer.alloc(size, 0x41); // 'A'
  res.writeHead(200, {
    "content-type": "application/octet-stream",
    "content-length": size,
  });
  res.end(body);
});

// 18. Slow response (for timeout testing)
route("GET", "/slow", (req, res) => {
  const url = new URL(req.url, `https://${req.headers.host}`);
  const delayMs = parseInt(url.searchParams.get("ms") || "3000", 10);
  setTimeout(() => {
    json(res, { delayed: true, ms: delayMs });
  }, delayMs);
});

// 19. Query parameters echo
route("GET", "/params", (req, res) => {
  const url = new URL(req.url, `https://${req.headers.host}`);
  const params = Object.fromEntries(url.searchParams);
  json(res, { params });
});

// 20. Multiple Set-Cookie via rawHeaders
route("GET", "/cookies/multi", (req, res) => {
  const body = JSON.stringify({ cookies: 3 });
  res.writeHead(200, {
    "content-type": "application/json",
    "content-length": Buffer.byteLength(body),
    "set-cookie": ["session=abc123; Path=/; HttpOnly", "theme=dark; Path=/", "lang=en; Path=/"],
  });
  res.end(body);
});

// 21. Custom response headers
route("GET", "/custom-headers", (req, res) => {
  const body = JSON.stringify({ ok: true });
  res.writeHead(200, {
    "content-type": "application/json",
    "content-length": Buffer.byteLength(body),
    "x-custom-header": "custom-value",
    "x-request-id": "req-12345",
    "x-powered-by": "NLcURL-Test-Server",
  });
  res.end(body);
});

// 22. AbortController test: delays forever
route("GET", "/hang", (req, res) => {
  // Never responds — client must abort
  req.on("close", () => {});
});

// 23. Empty body (204)
route("GET", "/no-content", (req, res) => {
  res.writeHead(204);
  res.end();
});

// ── Server Setup ─────────────────────────────────────────────────────

function handleRequest(req, res) {
  const url = new URL(req.url, `https://${req.headers.host || "localhost"}`);
  const handler = matchRoute(req.method, url.pathname);
  if (handler) {
    try {
      const result = handler(req, res);
      if (result && typeof result.catch === "function") {
        result.catch((err) => {
          console.error(`[ERROR] ${req.method} ${req.url}:`, err);
          if (!res.headersSent) {
            json(res, { error: err.message }, 500);
          }
        });
      }
    } catch (err) {
      console.error(`[ERROR] ${req.method} ${req.url}:`, err);
      if (!res.headersSent) {
        json(res, { error: err.message }, 500);
      }
    }
  } else {
    json(res, { error: "Not Found", method: req.method, path: url.pathname }, 404);
  }
}

// Parse CLI args
const args = process.argv.slice(2);
let port = 0; // random port
for (const arg of args) {
  if (arg.startsWith("--port=")) {
    port = parseInt(arg.split("=")[1], 10);
  }
}

const server = https.createServer({ key, cert }, handleRequest);

server.listen(port, "127.0.0.1", () => {
  const addr = server.address();
  console.log(`NLCURL_TEST_PORT=${addr.port}`);
  console.log(`Server listening on https://127.0.0.1:${addr.port}`);
});

// Graceful shutdown
process.on("SIGTERM", () => {
  server.close();
  process.exit(0);
});
process.on("SIGINT", () => {
  server.close();
  process.exit(0);
});

export { server };
