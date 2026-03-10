/**
 * Unit tests for src/core/validation.ts
 * SSRF protection per WHATWG fetch §2.9 "bad port" blocklist.
 * Private IP detection per RFC 1918, RFC 4193, RFC 4291 (loopback, link-local).
 * Header validation per RFC 7230 §3.2 token syntax.
 */
import { describe, it } from "node:test";
import { strict as assert } from "node:assert";
import { NLcURLError } from "../../src/core/errors.js";
import { validateUrlSafety, validateHeaderName, validateHeaderValue, assertNonEmptyString, assertPositiveNumber, assertNonNegativeInt, assertEnum, assertPlainObject, validateUrl, validateTimeout, validateRequest, validateRetryConfig, validateRateLimitConfig } from "../../src/core/validation.js";

describe("validateUrlSafety", () => {
  it("allows standard HTTPS URLs", () => {
    assert.doesNotThrow(() => validateUrlSafety("https://example.com/api"));
  });

  it("allows standard HTTP URLs", () => {
    assert.doesNotThrow(() => validateUrlSafety("http://example.com/api"));
  });

  it("blocks port 22 (SSH) in the WHATWG dangerous port list", () => {
    assert.throws(() => validateUrlSafety("https://example.com:22/"), NLcURLError);
  });

  it("blocks port 25 (SMTP) in the dangerous port list", () => {
    assert.throws(() => validateUrlSafety("https://example.com:25/"), NLcURLError);
  });

  it("blocks port 21 (FTP control)", () => {
    assert.throws(() => validateUrlSafety("http://example.com:21/"), NLcURLError);
  });

  it("blocks port 6667 (IRC)", () => {
    assert.throws(() => validateUrlSafety("http://example.com:6667/"), NLcURLError);
  });

  it("allows dangerous ports when allowDangerousPorts is true", () => {
    assert.doesNotThrow(() => validateUrlSafety("https://example.com:22/", { allowDangerousPorts: true }));
  });

  it("blocks RFC 1918 10.x.x.x private IPs", () => {
    assert.throws(() => validateUrlSafety("http://10.0.0.1/"), NLcURLError);
  });

  it("blocks RFC 1918 172.16.x.x private IPs", () => {
    assert.throws(() => validateUrlSafety("http://172.16.0.1/"), NLcURLError);
  });

  it("blocks RFC 1918 192.168.x.x private IPs", () => {
    assert.throws(() => validateUrlSafety("http://192.168.1.1/"), NLcURLError);
  });

  it("blocks loopback 127.0.0.1 (RFC 1122)", () => {
    assert.throws(() => validateUrlSafety("http://127.0.0.1/"), NLcURLError);
  });

  it("blocks link-local 169.254.x.x (RFC 3927)", () => {
    assert.throws(() => validateUrlSafety("http://169.254.1.1/"), NLcURLError);
  });

  it("blocks IPv6 loopback ::1 (RFC 4291 §2.5.3)", () => {
    assert.throws(() => validateUrlSafety("http://[::1]/"), NLcURLError);
  });

  it("blocks IPv6 link-local fe80:: (RFC 4291 §2.5.6)", () => {
    assert.throws(() => validateUrlSafety("http://[fe80::1]/"), NLcURLError);
  });

  it("blocks IPv6 unique-local fc00::/fd00:: (RFC 4193)", () => {
    assert.throws(() => validateUrlSafety("http://[fd12::1]/"), NLcURLError);
  });

  it("allows private IPs when allowPrivateIPs is true", () => {
    assert.doesNotThrow(() => validateUrlSafety("http://192.168.1.1/", { allowPrivateIPs: true }));
  });

  it("blocks URLs exceeding 65535 characters", () => {
    const longUrl = "https://example.com/" + "a".repeat(65535);
    assert.throws(() => validateUrlSafety(longUrl), NLcURLError);
  });

  it("throws on invalid URL format", () => {
    assert.throws(() => validateUrlSafety("not-a-url"), NLcURLError);
  });

  it("blocks CGN 100.64.x.x (RFC 6598)", () => {
    assert.throws(() => validateUrlSafety("http://100.64.0.1/"), NLcURLError);
  });

  it("blocks multicast 224.0.0.1 (RFC 5771)", () => {
    assert.throws(() => validateUrlSafety("http://224.0.0.1/"), NLcURLError);
  });

  it("blocks broadcast 255.255.255.255", () => {
    assert.throws(() => validateUrlSafety("http://255.255.255.255/"), NLcURLError);
  });

  it("does not block public IP addresses", () => {
    assert.doesNotThrow(() => validateUrlSafety("http://8.8.8.8/"));
    assert.doesNotThrow(() => validateUrlSafety("http://1.1.1.1/"));
  });
});

describe("validateHeaderName", () => {
  it("accepts valid header names", () => {
    assert.doesNotThrow(() => validateHeaderName("Content-Type"));
    assert.doesNotThrow(() => validateHeaderName("x-custom-header"));
    assert.doesNotThrow(() => validateHeaderName("X-Request-Id"));
    assert.doesNotThrow(() => validateHeaderName("accept"));
  });

  it("rejects empty header name", () => {
    assert.throws(() => validateHeaderName(""), NLcURLError);
  });

  it("rejects header name with spaces", () => {
    assert.throws(() => validateHeaderName("Content Type"), NLcURLError);
  });

  it("rejects header name with control characters", () => {
    assert.throws(() => validateHeaderName("Header\x00Name"), NLcURLError);
  });

  it("rejects header name with colon", () => {
    assert.throws(() => validateHeaderName("Header:Name"), NLcURLError);
  });
});

describe("validateHeaderValue", () => {
  it("accepts normal header values", () => {
    assert.doesNotThrow(() => validateHeaderValue("Content-Type", "application/json"));
  });

  it("rejects values with null byte", () => {
    assert.throws(() => validateHeaderValue("X-Test", "value\x00evil"), NLcURLError);
  });

  it("rejects values with newline (HTTP response splitting)", () => {
    assert.throws(() => validateHeaderValue("X-Test", "value\nevil"), NLcURLError);
  });

  it("rejects values with carriage return", () => {
    assert.throws(() => validateHeaderValue("X-Test", "value\revil"), NLcURLError);
  });
});

describe("assertNonEmptyString", () => {
  it("passes for non-empty string", () => {
    assert.doesNotThrow(() => assertNonEmptyString("hello", "test"));
  });

  it("throws for empty string", () => {
    assert.throws(() => assertNonEmptyString("", "test"), NLcURLError);
  });

  it("throws for non-string types", () => {
    assert.throws(() => assertNonEmptyString(42, "test"), NLcURLError);
    assert.throws(() => assertNonEmptyString(null, "test"), NLcURLError);
    assert.throws(() => assertNonEmptyString(undefined, "test"), NLcURLError);
    assert.throws(() => assertNonEmptyString(true, "test"), NLcURLError);
  });
});

describe("assertPositiveNumber", () => {
  it("passes for positive finite number", () => {
    assert.doesNotThrow(() => assertPositiveNumber(1, "test"));
    assert.doesNotThrow(() => assertPositiveNumber(0.001, "test"));
    assert.doesNotThrow(() => assertPositiveNumber(Number.MAX_SAFE_INTEGER, "test"));
  });

  it("throws for zero", () => {
    assert.throws(() => assertPositiveNumber(0, "test"), NLcURLError);
  });

  it("throws for negative numbers", () => {
    assert.throws(() => assertPositiveNumber(-1, "test"), NLcURLError);
  });

  it("throws for NaN", () => {
    assert.throws(() => assertPositiveNumber(NaN, "test"), NLcURLError);
  });

  it("throws for Infinity", () => {
    assert.throws(() => assertPositiveNumber(Infinity, "test"), NLcURLError);
  });

  it("throws for non-number types", () => {
    assert.throws(() => assertPositiveNumber("5", "test"), NLcURLError);
    assert.throws(() => assertPositiveNumber(null, "test"), NLcURLError);
  });
});

describe("assertNonNegativeInt", () => {
  it("passes for 0 and positive integers", () => {
    assert.doesNotThrow(() => assertNonNegativeInt(0, "test"));
    assert.doesNotThrow(() => assertNonNegativeInt(1, "test"));
    assert.doesNotThrow(() => assertNonNegativeInt(100, "test"));
  });

  it("throws for negative integers", () => {
    assert.throws(() => assertNonNegativeInt(-1, "test"), NLcURLError);
  });

  it("throws for floating point numbers", () => {
    assert.throws(() => assertNonNegativeInt(1.5, "test"), NLcURLError);
  });

  it("throws for NaN and Infinity", () => {
    assert.throws(() => assertNonNegativeInt(NaN, "test"), NLcURLError);
    assert.throws(() => assertNonNegativeInt(Infinity, "test"), NLcURLError);
  });
});

describe("assertEnum", () => {
  const allowed = new Set(["GET", "POST", "PUT"]);

  it("passes for values in the allowed set", () => {
    assert.doesNotThrow(() => assertEnum("GET", allowed, "method"));
    assert.doesNotThrow(() => assertEnum("POST", allowed, "method"));
  });

  it("throws for values not in the allowed set", () => {
    assert.throws(() => assertEnum("PATCH", allowed, "method"), NLcURLError);
    assert.throws(() => assertEnum("", allowed, "method"), NLcURLError);
  });
});

describe("assertPlainObject", () => {
  it("passes for plain objects", () => {
    assert.doesNotThrow(() => assertPlainObject({}, "test"));
    assert.doesNotThrow(() => assertPlainObject({ key: "value" }, "test"));
  });

  it("throws for null", () => {
    assert.throws(() => assertPlainObject(null, "test"), NLcURLError);
  });

  it("throws for arrays", () => {
    assert.throws(() => assertPlainObject([], "test"), NLcURLError);
  });

  it("throws for non-objects", () => {
    assert.throws(() => assertPlainObject("string", "test"), NLcURLError);
    assert.throws(() => assertPlainObject(42, "test"), NLcURLError);
  });

  it("rejects objects with __proto__ key", () => {
    const obj = Object.create(null);
    obj["__proto__"] = {};
    assert.throws(() => assertPlainObject(obj, "test"), NLcURLError);
  });

  it("rejects objects with constructor key", () => {
    const obj = Object.create(null);
    obj["constructor"] = "malicious";
    assert.throws(() => assertPlainObject(obj, "test"), NLcURLError);
  });

  it("rejects objects with prototype key", () => {
    const obj = Object.create(null);
    obj["prototype"] = {};
    assert.throws(() => assertPlainObject(obj, "test"), NLcURLError);
  });
});

describe("validateUrl", () => {
  it("accepts http and https URLs by default", () => {
    assert.doesNotThrow(() => validateUrl("http://example.com"));
    assert.doesNotThrow(() => validateUrl("https://example.com"));
  });

  it("rejects non-http/https schemes", () => {
    assert.throws(() => validateUrl("ftp://example.com"), NLcURLError);
    assert.throws(() => validateUrl("file:///etc/passwd"), NLcURLError);
  });

  it("accepts custom allowed schemes", () => {
    assert.doesNotThrow(() => validateUrl("ws://example.com", new Set(["ws:", "wss:"])));
  });

  it("rejects empty string", () => {
    assert.throws(() => validateUrl(""), NLcURLError);
  });

  it("rejects URLs with embedded credentials", () => {
    assert.throws(() => validateUrl("https://user:pass@example.com"), NLcURLError);
  });

  it("rejects invalid URL syntax", () => {
    assert.throws(() => validateUrl("not a url"), NLcURLError);
  });
});

describe("validateTimeout", () => {
  it("allows undefined and null", () => {
    assert.doesNotThrow(() => validateTimeout(undefined));
    assert.doesNotThrow(() => validateTimeout(null));
  });

  it("allows positive finite numbers", () => {
    assert.doesNotThrow(() => validateTimeout(5000));
    assert.doesNotThrow(() => validateTimeout(0.5));
  });

  it("rejects zero, negative, NaN, Infinity", () => {
    assert.throws(() => validateTimeout(0), NLcURLError);
    assert.throws(() => validateTimeout(-1), NLcURLError);
    assert.throws(() => validateTimeout(NaN), NLcURLError);
    assert.throws(() => validateTimeout(Infinity), NLcURLError);
  });

  it("accepts TimeoutConfig object with valid fields", () => {
    assert.doesNotThrow(() => validateTimeout({ connect: 5000, tls: 3000 }));
  });

  it("rejects TimeoutConfig with invalid field values", () => {
    assert.throws(() => validateTimeout({ connect: -1 }), NLcURLError);
    assert.throws(() => validateTimeout({ total: 0 }), NLcURLError);
  });

  it("rejects arrays and strings", () => {
    assert.throws(() => validateTimeout([5000]), NLcURLError);
    assert.throws(() => validateTimeout("5000"), NLcURLError);
  });
});

describe("validateRetryConfig", () => {
  it("accepts valid retry config", () => {
    assert.doesNotThrow(() => validateRetryConfig({ count: 3, delay: 1000, backoff: "exponential" }));
  });

  it("rejects negative count", () => {
    assert.throws(() => validateRetryConfig({ count: -1 }), NLcURLError);
  });

  it("rejects non-integer count", () => {
    assert.throws(() => validateRetryConfig({ count: 1.5 }), NLcURLError);
  });

  it("rejects non-positive delay", () => {
    assert.throws(() => validateRetryConfig({ delay: 0 }), NLcURLError);
    assert.throws(() => validateRetryConfig({ delay: -100 }), NLcURLError);
  });

  it("rejects invalid backoff strategy", () => {
    assert.throws(() => validateRetryConfig({ backoff: "invalid" }), NLcURLError);
  });

  it("rejects negative jitter", () => {
    assert.throws(() => validateRetryConfig({ jitter: -1 }), NLcURLError);
  });
});

describe("validateRateLimitConfig", () => {
  it("accepts valid rate limit config", () => {
    assert.doesNotThrow(() => validateRateLimitConfig({ maxRequests: 100, windowMs: 60000 }));
  });

  it("rejects non-positive maxRequests", () => {
    assert.throws(() => validateRateLimitConfig({ maxRequests: 0, windowMs: 1000 }), NLcURLError);
  });

  it("rejects non-integer maxRequests", () => {
    assert.throws(() => validateRateLimitConfig({ maxRequests: 1.5, windowMs: 1000 }), NLcURLError);
  });

  it("rejects non-positive windowMs", () => {
    assert.throws(() => validateRateLimitConfig({ maxRequests: 10, windowMs: 0 }), NLcURLError);
  });
});
