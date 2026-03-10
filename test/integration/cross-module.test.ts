import { describe, it } from "node:test";
import { strict as assert } from "node:assert";

import { HSTSStore } from "../../src/hsts/store.js";
import { CookieJar } from "../../src/cookies/jar.js";
import { CacheStore, parseCacheControl } from "../../src/cache/store.js";
import { AltSvcStore } from "../../src/http/alt-svc.js";
import { InterceptorChain } from "../../src/middleware/interceptor.js";
import { CircuitBreaker } from "../../src/middleware/circuit-breaker.js";
import { RateLimiter } from "../../src/middleware/rate-limiter.js";
import { DNSCache } from "../../src/dns/cache.js";
import { parseRetryAfter } from "../../src/middleware/retry-after.js";
import { computeReferrer, parseReferrerPolicy } from "../../src/http/referrer-policy.js";
import { resolveURL, appendParams, originOf } from "../../src/utils/url.js";
import { validateUrlSafety, validateHeaderName, validateHeaderValue } from "../../src/core/validation.js";
import { SSEParser } from "../../src/sse/parser.js";
import { ConsoleLogger, SILENT_LOGGER } from "../../src/utils/logger.js";
import { isPublicSuffix, getRegistrableDomain } from "../../src/cookies/public-suffix.js";
import { verifyIntegrity } from "../../src/utils/integrity.js";
import { compressBody } from "../../src/utils/compression.js";
import { FormData } from "../../src/http/form-data.js";
import type { NLcURLRequest } from "../../src/core/request.js";

describe("Integration: HSTS + URL handling", () => {
  it("upgrades URL then resolves relative path against upgraded base", () => {
    const hsts = new HSTSStore();
    hsts.parseHeader("api.example.com", "max-age=31536000; includeSubDomains", true);

    const upgraded = hsts.upgradeURL("http://api.example.com/v1/");
    assert.ok(upgraded.startsWith("https://"));

    const resolved = resolveURL(upgraded, "./users?page=1");
    const parsed = new URL(resolved);
    assert.equal(parsed.protocol, "https:");
    assert.equal(parsed.hostname, "api.example.com");
    assert.equal(parsed.pathname, "/v1/users");
    assert.equal(parsed.searchParams.get("page"), "1");
  });

  it("HSTS + appendParams integration preserves scheme upgrade through param addition", () => {
    const hsts = new HSTSStore();
    hsts.parseHeader("cdn.example.com", "max-age=86400", true);

    const upgraded = hsts.upgradeURL("http://cdn.example.com/assets");
    const withParams = appendParams(upgraded, { v: "2.0", format: "webp" });

    const parsed = new URL(withParams);
    assert.equal(parsed.protocol, "https:");
    assert.equal(parsed.searchParams.get("v"), "2.0");
    assert.equal(parsed.searchParams.get("format"), "webp");
  });
});

describe("Integration: Cookies + Public Suffix + HSTS", () => {
  it("rejects cookies for public suffixes then accepts for registrable domain", () => {
    assert.equal(isPublicSuffix("com"), true);
    assert.equal(isPublicSuffix("co.uk"), true);

    const jar = new CookieJar();
    const reqUrl = new URL("https://shop.example.co.uk/cart");

    jar.setCookies({ "set-cookie": "sid=abc; Domain=co.uk; Path=/" }, reqUrl);
    assert.equal(jar.getCookieHeader(reqUrl), "");

    jar.setCookies({ "set-cookie": "sid=abc; Domain=example.co.uk; Path=/" }, reqUrl);
    assert.notEqual(jar.getCookieHeader(reqUrl), "");

    assert.equal(getRegistrableDomain("shop.example.co.uk"), "example.co.uk");
  });

  it("HSTS-upgraded URL carries cookies correctly", () => {
    const hsts = new HSTSStore();
    hsts.parseHeader("secure.example.com", "max-age=31536000", true);

    const jar = new CookieJar();
    const secureUrl = new URL("https://secure.example.com/");
    jar.setCookies({ "set-cookie": "token=xyz; Path=/; Secure" }, secureUrl);

    const upgraded = hsts.upgradeURL("http://secure.example.com/api");
    const requestUrl = new URL(upgraded);
    const header = jar.getCookieHeader(requestUrl);
    assert.ok(header.includes("token=xyz"));
  });
});

describe("Integration: Cache + Referrer Policy", () => {
  it("referrer policy affects cross-origin cache key behavior", () => {
    const policy = parseReferrerPolicy("strict-origin-when-cross-origin");
    assert.equal(policy, "strict-origin-when-cross-origin");

    const sameOriginRef = computeReferrer(new URL("https://example.com/page/1"), new URL("https://example.com/page/2"), policy);
    assert.ok(sameOriginRef.includes("/page/1"));

    const crossOriginRef = computeReferrer(new URL("https://example.com/secret/page"), new URL("https://other.com/api"), policy);
    assert.equal(crossOriginRef, "https://example.com/");

    const downgradeRef = computeReferrer(new URL("https://example.com/page"), new URL("http://insecure.com/api"), policy);
    assert.equal(downgradeRef, "");

    const key1 = CacheStore.cacheKey("GET", "https://example.com/page/2");
    const key2 = CacheStore.cacheKey("GET", "https://other.com/api");
    assert.notEqual(key1, key2);
  });
});

describe("Integration: Circuit Breaker + Rate Limiter", () => {
  it("rate limiter and circuit breaker work together for origin protection", async () => {
    const limiter = new RateLimiter({ maxRequests: 5, windowMs: 10000 });
    const breaker = new CircuitBreaker({
      failureThreshold: 3,
      resetTimeoutMs: 5000,
    });
    const origin = "https://api.example.com:443";

    for (let i = 0; i < 3; i++) {
      await limiter.acquire();
      breaker.recordResponse(origin, 503);
    }

    assert.throws(() => breaker.allowRequest(origin), /circuit/i);

    await limiter.acquire();
    assert.throws(() => breaker.allowRequest(origin), /circuit/i);
  });
});

describe("Integration: Interceptor + URL + Validation", () => {
  it("interceptors can modify request URL with validated headers", async () => {
    const chain = new InterceptorChain();

    chain.addRequestInterceptor((req) => {
      const url = appendParams(req.url, { api_key: "test123" });
      validateHeaderName("x-request-id");
      validateHeaderValue("x-request-id", "req-001");
      return {
        ...req,
        url,
        headers: { ...req.headers, "x-request-id": "req-001" },
      };
    });

    chain.addRequestInterceptor((req) => {
      validateUrlSafety(req.url, {
        allowPrivateIPs: false,
        allowDangerousPorts: false,
      });
      return req;
    });

    const req: NLcURLRequest = {
      url: "https://api.example.com/data",
      method: "GET",
      headers: {},
    };

    const processed = await chain.processRequest(req);
    const parsed = new URL(processed.url);
    assert.equal(parsed.searchParams.get("api_key"), "test123");
    assert.equal(processed.headers!["x-request-id"], "req-001");
  });

  it("interceptor chain rejects requests to private IPs", async () => {
    const chain = new InterceptorChain();
    chain.addRequestInterceptor((req) => {
      validateUrlSafety(req.url, { allowPrivateIPs: false });
      return req;
    });

    const req: NLcURLRequest = {
      url: "http://192.168.1.1/admin",
      method: "GET",
    };

    await assert.rejects(async () => {
      await chain.processRequest(req);
    });
  });
});

describe("Integration: DNS Cache + Origin extraction", () => {
  it("DNS cache entries align with URL origin extraction", () => {
    const cache = new DNSCache({ maxEntries: 100 });

    cache.set("api.example.com", "A", [{ name: "api.example.com", type: 1, ttl: 300, data: Buffer.from([93, 184, 216, 34]) }]);

    const records = cache.get("API.EXAMPLE.COM", "A");
    assert.ok(records);
    assert.equal(records!.length, 1);

    const origin = originOf("https://api.example.com/path");
    assert.equal(origin, "https://api.example.com:443");
  });
});

describe("Integration: Alt-Svc + HSTS + Origin", () => {
  it("Alt-Svc entries stored per origin align with HSTS-upgraded origins", () => {
    const hsts = new HSTSStore();
    hsts.parseHeader("cdn.example.com", "max-age=31536000", true);

    const altSvc = new AltSvcStore();
    const origin = originOf("https://cdn.example.com/");
    altSvc.parseHeader(origin, 'h2="cdn.example.com:443"; ma=86400');

    const entry = altSvc.lookup(origin);
    assert.ok(entry);
    assert.equal(entry!.alpn, "h2");

    const upgraded = hsts.upgradeURL("http://cdn.example.com/asset.js");
    const upgradedOrigin = originOf(upgraded);
    assert.equal(upgradedOrigin, origin);

    const sameEntry = altSvc.lookup(upgradedOrigin);
    assert.ok(sameEntry);
  });
});

describe("Integration: SSE + Retry-After", () => {
  it("SSE retry field and Retry-After header parsing produce compatible values", () => {
    const parser = new SSEParser();
    parser.feed("retry: 5000\ndata: reconnect\n\n");
    const event = parser.pull();
    assert.equal(event!.retry, 5000);

    const retryAfter = parseRetryAfter("5");
    assert.equal(retryAfter, 5000);

    assert.equal(event!.retry, retryAfter);
  });
});

describe("Integration: Compression + Integrity", () => {
  it("compressed data can be verified after decompression with SRI hash", async () => {
    const original = Buffer.from("The quick brown fox jumps over the lazy dog");
    const compressed = await compressBody(original, "gzip");

    assert.notEqual(compressed.toString("hex"), original.toString("hex"));

    const crypto = await import("node:crypto");
    const hash = crypto.createHash("sha256").update(original).digest("base64");
    const integrity = `sha256-${hash}`;

    assert.equal(verifyIntegrity(original, integrity), true);
    assert.equal(verifyIntegrity(compressed, integrity), false);
  });
});

describe("Integration: FormData + Validation", () => {
  it("FormData fields pass header validation", () => {
    const form = new FormData();
    form.append("username", "testuser");
    form.append("avatar", {
      data: Buffer.from([0x89, 0x50, 0x4e, 0x47]),
      filename: "avatar.png",
      contentType: "image/png",
    });

    const contentType = form.contentType;
    assert.ok(contentType.startsWith("multipart/form-data; boundary="));

    validateHeaderValue("content-type", contentType);
    validateHeaderName("content-type");
  });
});

describe("Integration: Cookie persistence across HSTS upgrade cycle", () => {
  it("cookies set on HTTPS survive HSTS upgrade of HTTP URLs", () => {
    const hsts = new HSTSStore();
    const jar = new CookieJar();

    hsts.parseHeader("app.example.com", "max-age=31536000; includeSubDomains", true);
    const secureUrl = new URL("https://app.example.com/");
    jar.setCookies({ "set-cookie": "session=abc123; Path=/; Secure; HttpOnly" }, secureUrl);

    const httpUrl = "http://app.example.com/dashboard";
    const upgraded = hsts.upgradeURL(httpUrl);
    assert.ok(upgraded.startsWith("https://"));

    const cookieHeader = jar.getCookieHeader(new URL(upgraded));
    assert.ok(cookieHeader.includes("session=abc123"));

    const subUpgraded = hsts.upgradeURL("http://sub.app.example.com/");
    assert.ok(subUpgraded.startsWith("https://"));
  });
});

describe("Integration: Cache-Control + Retry-After", () => {
  it("cache directives and retry-after work together for stale responses", () => {
    const directives = parseCacheControl("max-age=0, must-revalidate, stale-while-revalidate=60");
    assert.equal(directives.maxAge, 0);
    assert.equal(directives.mustRevalidate, true);
    assert.equal(directives.staleWhileRevalidate, 60);

    const retryDelayMs = parseRetryAfter("30");
    assert.equal(retryDelayMs, 30000);

    assert.ok(retryDelayMs! / 1000 <= directives.staleWhileRevalidate!);
  });
});

describe("Integration: Logger + Validation errors", () => {
  it("SILENT_LOGGER can be used without side effects during validation", () => {
    SILENT_LOGGER.debug("validating...");
    SILENT_LOGGER.error("validation failed");

    assert.throws(() => {
      validateUrlSafety("http://10.0.0.1/api", { allowPrivateIPs: false });
    });
  });

  it("ConsoleLogger child logger maintains context through validation flow", () => {
    const captured: string[] = [];
    const origWrite = process.stderr.write;
    process.stderr.write = ((chunk: string | Uint8Array) => {
      captured.push(typeof chunk === "string" ? chunk : Buffer.from(chunk).toString());
      return true;
    }) as typeof process.stderr.write;

    try {
      const logger = new ConsoleLogger("debug", "validation");
      const child = logger.child({ component: "url-safety" });
      child.debug("checking URL safety");

      assert.equal(captured.length, 1);
      assert.ok(captured[0]!.includes("validation:url-safety"));

      validateUrlSafety("https://example.com/api", { allowPrivateIPs: false });
    } finally {
      process.stderr.write = origWrite;
    }
  });
});
