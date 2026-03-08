import { describe, it, beforeEach, afterEach } from "node:test";
import assert from "node:assert/strict";
import { resolveEnvProxy } from "../../src/proxy/env-proxy.js";

describe("resolveEnvProxy", () => {
  const saved: Record<string, string | undefined> = {};
  const envKeys = ["http_proxy", "HTTP_PROXY", "https_proxy", "HTTPS_PROXY", "no_proxy", "NO_PROXY", "all_proxy", "ALL_PROXY"];

  beforeEach(() => {
    for (const k of envKeys) {
      saved[k] = process.env[k];
      delete process.env[k];
    }
  });

  afterEach(() => {
    for (const k of envKeys) {
      if (saved[k] !== undefined) process.env[k] = saved[k];
      else delete process.env[k];
    }
  });

  it("returns undefined when no proxy env vars are set", () => {
    assert.equal(resolveEnvProxy("https://example.com"), undefined);
  });

  it("resolves HTTP_PROXY for http URLs", () => {
    process.env["HTTP_PROXY"] = "http://proxy:8080";
    assert.equal(resolveEnvProxy("http://example.com/path"), "http://proxy:8080");
  });

  it("resolves HTTPS_PROXY for https URLs", () => {
    process.env["HTTPS_PROXY"] = "http://secure-proxy:8080";
    assert.equal(resolveEnvProxy("https://example.com"), "http://secure-proxy:8080");
  });

  it("prefers lowercase env vars over uppercase", () => {
    process.env["http_proxy"] = "http://lower:8080";
    assert.equal(resolveEnvProxy("http://example.com"), "http://lower:8080");
  });

  it("falls back to ALL_PROXY", () => {
    process.env["ALL_PROXY"] = "http://all:8080";
    assert.equal(resolveEnvProxy("http://example.com"), "http://all:8080");
    assert.equal(resolveEnvProxy("https://example.com"), "http://all:8080");
  });

  it("bypasses proxy when host matches NO_PROXY", () => {
    process.env["HTTP_PROXY"] = "http://proxy:8080";
    process.env["NO_PROXY"] = "example.com,localhost";
    assert.equal(resolveEnvProxy("http://example.com"), undefined);
    assert.equal(resolveEnvProxy("http://localhost:3000"), undefined);
  });

  it("supports NO_PROXY wildcard *", () => {
    process.env["HTTP_PROXY"] = "http://proxy:8080";
    process.env["NO_PROXY"] = "*";
    assert.equal(resolveEnvProxy("http://anything.com"), undefined);
  });

  it("supports NO_PROXY domain suffix matching", () => {
    process.env["HTTP_PROXY"] = "http://proxy:8080";
    process.env["NO_PROXY"] = ".example.com";
    assert.equal(resolveEnvProxy("http://foo.example.com"), undefined);
    assert.equal(resolveEnvProxy("http://example.com"), undefined);
    assert.notEqual(resolveEnvProxy("http://notexample.com"), undefined);
  });

  it("supports NO_PROXY suffix matching without leading dot", () => {
    process.env["HTTP_PROXY"] = "http://proxy:8080";
    process.env["NO_PROXY"] = "example.com";
    assert.equal(resolveEnvProxy("http://sub.example.com"), undefined);
  });

  it("returns undefined for invalid URL", () => {
    assert.equal(resolveEnvProxy("not-a-url"), undefined);
  });
});
