/**
 * Live DNS resolution tests.
 *
 * Tests real DNS-over-HTTPS (DoH) queries against Cloudflare and Google
 * public resolvers, validating A/AAAA record resolution, caching, and
 * the full wire-format encode/decode pipeline against real authoritative data.
 */
import { describe, it } from "node:test";
import { strict as assert } from "node:assert";
import { DoHResolver, DNSCache } from "../../src/index.js";
import { parseARecord, parseAAAARecord } from "../../src/dns/codec.js";
import { LIVE_TIMEOUT } from "./helpers.js";

describe("DNS-over-HTTPS with Cloudflare (1.1.1.1)", { timeout: LIVE_TIMEOUT }, () => {
  const resolver = new DoHResolver({
    server: "https://cloudflare-dns.com/dns-query",
    method: "POST",
    timeout: 10_000,
  });

  it("resolves A record for google.com", async () => {
    const records = await resolver.query("google.com", "A");
    assert.ok(records.length > 0, "Expected at least one A record");
    for (const rec of records) {
      assert.equal(rec.type, 1, "Expected A record type");
      assert.equal(rec.data.length, 4, "A record should be 4 bytes");
      const ip = parseARecord(rec.data);
      assert.ok(/^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$/.test(ip), `Invalid IPv4: ${ip}`);
    }
  });

  it("resolves AAAA record for google.com", async () => {
    const records = await resolver.query("google.com", "AAAA");
    assert.ok(records.length > 0, "Expected at least one AAAA record");
    for (const rec of records) {
      assert.equal(rec.type, 28, "Expected AAAA record type");
      assert.equal(rec.data.length, 16, "AAAA record should be 16 bytes");
      const ip = parseAAAARecord(rec.data);
      assert.ok(ip.includes(":"), `Expected IPv6 address, got: ${ip}`);
    }
  });

  it("resolves A record for cloudflare.com", async () => {
    const records = await resolver.query("cloudflare.com", "A");
    assert.ok(records.length > 0);
    const ips = records.map((r) => parseARecord(r.data));
    assert.ok(
      ips.some((ip) => ip.startsWith("104.")),
      `Expected Cloudflare IP, got: ${ips.join(", ")}`,
    );
  });

  it("resolves A record for github.com", async () => {
    const records = await resolver.query("github.com", "A");
    assert.ok(records.length > 0);
    const ip = parseARecord(records[0]!.data);
    assert.ok(/^\d+\.\d+\.\d+\.\d+$/.test(ip));
  });

  it("caches DNS responses", async () => {
    await resolver.query("example.com", "A");

    const cache = resolver.getCache();
    const cached = cache.get("example.com", "A");
    assert.ok(cached, "Expected cached entry for example.com");
    assert.ok(cached.length > 0, "Cached entry should have records");
  });
});

describe("DNS-over-HTTPS with Google (8.8.8.8)", { timeout: LIVE_TIMEOUT }, () => {
  const resolver = new DoHResolver({
    server: "https://dns.google/dns-query",
    method: "POST",
    timeout: 10_000,
  });

  it("resolves A record for example.com", async () => {
    const records = await resolver.query("example.com", "A");
    assert.ok(records.length > 0);
    const ip = parseARecord(records[0]!.data);
    assert.ok(/^\d+\.\d+\.\d+\.\d+$/.test(ip), `Invalid IP: ${ip}`);
  });

  it("resolves AAAA record for example.com", async () => {
    const records = await resolver.query("example.com", "AAAA");
    assert.ok(records.length > 0);
    const ip = parseAAAARecord(records[0]!.data);
    assert.ok(ip.includes(":"), `Expected IPv6, got: ${ip}`);
  });
});

describe("DNS-over-HTTPS with GET method", { timeout: LIVE_TIMEOUT }, () => {
  const resolver = new DoHResolver({
    server: "https://cloudflare-dns.com/dns-query",
    method: "GET",
    timeout: 10_000,
  });

  it("resolves A record using GET", async () => {
    const records = await resolver.query("www.google.com", "A");
    assert.ok(records.length > 0);
    const ip = parseARecord(records[0]!.data);
    assert.ok(/^\d+\.\d+\.\d+\.\d+$/.test(ip));
  });
});

describe("DNS resolution of various well-known domains", { timeout: LIVE_TIMEOUT }, () => {
  const resolver = new DoHResolver({
    server: "https://cloudflare-dns.com/dns-query",
    method: "POST",
    timeout: 10_000,
  });

  const domains = ["www.google.com", "www.amazon.com", "www.facebook.com", "www.microsoft.com", "www.apple.com", "github.com", "stackoverflow.com", "www.wikipedia.org"];

  for (const domain of domains) {
    it(`resolves ${domain}`, async () => {
      const records = await resolver.query(domain, "A");
      assert.ok(records.length > 0, `No A records for ${domain}`);
    });
  }
});

describe("DNS HTTPS records (SVCB)", { timeout: LIVE_TIMEOUT }, () => {
  const resolver = new DoHResolver({
    server: "https://cloudflare-dns.com/dns-query",
    method: "POST",
    timeout: 10_000,
  });

  it("resolves HTTPS record for cloudflare.com", async () => {
    const records = await resolver.query("cloudflare.com", "HTTPS");
    assert.ok(Array.isArray(records), "Expected array of records");
  });
});

describe("DNSCache standalone", () => {
  it("respects TTL eviction", async () => {
    const cache = new DNSCache({ maxEntries: 100, minTTL: 1 });
    const record = { name: "test.com", type: 1, ttl: 1, data: Buffer.from([1, 2, 3, 4]) };
    cache.set("test.com", "A", [record]);

    assert.ok(cache.get("test.com", "A"), "Should be cached initially");

    await new Promise((r) => setTimeout(r, 1200));
    assert.equal(cache.get("test.com", "A"), undefined, "Should be evicted after TTL");
  });
});
