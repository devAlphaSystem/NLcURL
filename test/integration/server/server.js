import https from "node:https";
import { createServer as createH2SecureServer } from "node:http2";
import zlib from "node:zlib";
import { URL } from "node:url";
import { generateCert } from "./cert.js";

const { key, cert } = generateCert();

const routes = new Map();

function route(method, path, handler) {
  routes.set(`${method} ${path}`, handler);
}

function matchRoute(method, pathname) {
  const exact = routes.get(`${method} ${pathname}`);
  if (exact) return exact;
  for (const [key, handler] of routes) {
    const [m, p] = key.split(" ", 2);
    if (m === "*" && p === pathname) return handler;
    if (m === method && p.endsWith("*") && pathname.startsWith(p.slice(0, -1))) return handler;
  }
  return null;
}

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

route("GET", "/json", (req, res) => {
  json(res, { message: "hello", items: [1, 2, 3], nested: { a: true } });
});

route("GET", "/text", (req, res) => {
  const body = "Hello, NLcURL!";
  res.writeHead(200, {
    "content-type": "text/plain",
    "content-length": Buffer.byteLength(body),
  });
  res.end(body);
});

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

route("GET", "/headers", (req, res) => {
  json(res, { headers: req.headers });
});

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

route("PUT", "/put", async (req, res) => {
  const body = await readBody(req);
  json(res, { method: "PUT", body: body.toString(), length: body.length });
});

route("PATCH", "/patch", async (req, res) => {
  const body = await readBody(req);
  json(res, { method: "PATCH", body: body.toString(), length: body.length });
});

route("DELETE", "/delete", (req, res) => {
  json(res, { method: "DELETE", deleted: true });
});

route("HEAD", "/head", (req, res) => {
  res.writeHead(200, {
    "content-type": "application/json",
    "x-custom": "head-test",
    "content-length": "42",
  });
  res.end();
});

route("OPTIONS", "/options", (req, res) => {
  res.writeHead(200, {
    allow: "GET, POST, PUT, PATCH, DELETE, HEAD, OPTIONS",
    "content-length": "0",
  });
  res.end();
});

route("GET", "/cookies/set", (req, res) => {
  const url = new URL(req.url, `https://${req.headers.host}`);
  const cookies = [];
  for (const [name, value] of url.searchParams) {
    cookies.push(`${name}=${value}; Path=/; HttpOnly`);
  }
  const headers = {};
  res.writeHead(200, { "content-type": "application/json" });
  res.socket;
  json(res, { cookies_set: cookies.length });
  return;
});

route("GET", "/cookies/setmulti", (req, res) => {
  const url = new URL(req.url, `https://${req.headers.host}`);
  const setCookies = [];
  for (const [name, value] of url.searchParams) {
    setCookies.push(`${name}=${value}; Path=/; HttpOnly`);
  }
  const body = JSON.stringify({ cookies_set: setCookies.length });
  res.writeHead(200, {
    "content-type": "application/json",
    "content-length": Buffer.byteLength(body),
    "set-cookie": setCookies,
  });
  res.end(body);
});

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

route("POST", "/redirect/308", async (req, res) => {
  res.writeHead(308, { location: "/echo" });
  res.end();
});

route("POST", "/redirect/303", async (req, res) => {
  res.writeHead(303, { location: "/echo" });
  res.end();
});

route("GET", "/redirect/target", (req, res) => {
  json(res, { redirected: true, method: req.method });
});

route("GET", "/redirect/chain/*", (req, res) => {
  const n = parseInt(req.url.split("/redirect/chain/")[1], 10);
  if (isNaN(n) || n <= 0) {
    json(res, { redirected: true, chain_complete: true });
    return;
  }
  res.writeHead(302, { location: `/redirect/chain/${n - 1}` });
  res.end();
});

route("GET", "/redirect/withcookie", (req, res) => {
  res.writeHead(302, {
    location: "/cookies/get",
    "set-cookie": "redirect_cookie=from_redirect; Path=/",
  });
  res.end();
});

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

route("GET", "/large", (req, res) => {
  const size = 100_000;
  const body = Buffer.alloc(size, 0x41);
  res.writeHead(200, {
    "content-type": "application/octet-stream",
    "content-length": size,
  });
  res.end(body);
});

route("GET", "/slow", (req, res) => {
  const url = new URL(req.url, `https://${req.headers.host}`);
  const delayMs = parseInt(url.searchParams.get("ms") || "3000", 10);
  setTimeout(() => {
    json(res, { delayed: true, ms: delayMs });
  }, delayMs);
});

route("GET", "/params", (req, res) => {
  const url = new URL(req.url, `https://${req.headers.host}`);
  const params = Object.fromEntries(url.searchParams);
  json(res, { params });
});

route("GET", "/cookies/multi", (req, res) => {
  const body = JSON.stringify({ cookies: 3 });
  res.writeHead(200, {
    "content-type": "application/json",
    "content-length": Buffer.byteLength(body),
    "set-cookie": ["session=abc123; Path=/; HttpOnly", "theme=dark; Path=/", "lang=en; Path=/"],
  });
  res.end(body);
});

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

route("GET", "/hang", (req, res) => {
  req.on("close", () => {});
});

route("GET", "/no-content", (req, res) => {
  res.writeHead(204);
  res.end();
});

route("GET", "/redirect/loop-a", (req, res) => {
  res.writeHead(302, { location: "/redirect/loop-b" });
  res.end();
});

route("GET", "/redirect/loop-b", (req, res) => {
  res.writeHead(302, { location: "/redirect/loop-a" });
  res.end();
});

route("GET", "/redirect/self", (req, res) => {
  res.writeHead(302, { location: "/redirect/self" });
  res.end();
});

route("GET", "/cookies/many", (req, res) => {
  const cookies = [];
  for (let i = 0; i < 100; i++) {
    cookies.push(`cookie${i}=value${i}; Path=/`);
  }
  const body = JSON.stringify({ cookies_sent: cookies.length });
  res.writeHead(200, {
    "content-type": "application/json",
    "content-length": Buffer.byteLength(body),
    "set-cookie": cookies,
  });
  res.end(body);
});

route("GET", "/cookies/maxage", (req, res) => {
  const body = JSON.stringify({ ok: true });
  res.writeHead(200, {
    "content-type": "application/json",
    "content-length": Buffer.byteLength(body),
    "set-cookie": ["short=ok; Path=/; Max-Age=3600", "huge=capped; Path=/; Max-Age=999999999"],
  });
  res.end(body);
});

route("GET", "/headers/many", (req, res) => {
  const body = JSON.stringify({ ok: true });
  const headers = { "content-type": "application/json", "content-length": Buffer.byteLength(body).toString() };
  for (let i = 0; i < 100; i++) {
    headers[`x-test-${i}`] = `value-${i}`;
  }
  res.writeHead(200, headers);
  res.end(body);
});

route("GET", "/redirect/downgrade-headers", (req, res) => {
  json(res, { headers: req.headers });
});

route("GET", "/redirect/with-referrer-policy", (req, res) => {
  res.writeHead(302, {
    location: "/echo",
    "referrer-policy": "no-referrer",
  });
  res.end();
});

route("GET", "/redirect/dual-location", (req, res) => {
  res.setHeader("content-length", "0");
  res.writeHead(302);
  res.socket.write("HTTP/1.1 302 Found\r\n" + "Location: /echo\r\n" + "Location: /json\r\n" + "Content-Length: 0\r\n" + "\r\n");
  res.detachSocket(res.socket);
});

route("GET", "/cookies/xsrf", (req, res) => {
  const body = JSON.stringify({ ok: true });
  res.writeHead(200, {
    "content-type": "application/json",
    "content-length": Buffer.byteLength(body),
    "set-cookie": "XSRF-TOKEN=abc123xsrf; Path=/; Secure",
  });
  res.end(body);
});

route("GET", "/cookies/check-xsrf", (req, res) => {
  json(res, {
    xsrfHeader: req.headers["x-xsrf-token"] || null,
    cookie: req.headers["cookie"] || null,
  });
});

route("GET", "/integrity/sha256", (req, res) => {
  const body = "Hello, integrity!";
  res.writeHead(200, {
    "content-type": "text/plain",
    "content-length": Buffer.byteLength(body),
  });
  res.end(body);
});

route("GET", "/max-body", (req, res) => {
  const buf = Buffer.alloc(10000, 0x41);
  res.writeHead(200, {
    "content-type": "application/octet-stream",
    "content-length": buf.length,
  });
  res.end(buf);
});

route("GET", "/sse/stream", (req, res) => {
  res.writeHead(200, {
    "content-type": "text/event-stream",
    "cache-control": "no-cache",
    connection: "keep-alive",
  });
  let count = 0;
  const iv = setInterval(() => {
    count++;
    res.write(`id: ${count}\nevent: message\ndata: event-${count}\n\n`);
    if (count >= 3) {
      clearInterval(iv);
      res.end();
    }
  }, 50);
});

route("GET", "/cookies/httponly", (req, res) => {
  const body = JSON.stringify({ ok: true });
  res.writeHead(200, {
    "content-type": "application/json",
    "content-length": Buffer.byteLength(body),
    "set-cookie": ["visible=yes; Path=/", "secret=hidden; Path=/; HttpOnly"],
  });
  res.end(body);
});

route("GET", "/early-hints-test", (req, res) => {
  json(res, { earlyHints: true });
});

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

const args = process.argv.slice(2);
let port = 0;
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

process.on("SIGTERM", () => {
  server.close();
  process.exit(0);
});
process.on("SIGINT", () => {
  server.close();
  process.exit(0);
});

export { server };
