import { describe, it } from "node:test";
import assert from "node:assert/strict";
import { ja3String, ja3Hash, ja3nString, ja3nHash } from "../../src/fingerprints/ja3.js";
import { getProfile } from "../../src/fingerprints/database.js";

describe("ja3String", () => {
  it("returns comma-separated fields", () => {
    const profile = getProfile("chrome");
    assert.ok(profile, "chrome profile should exist");

    const ja3 = ja3String(profile.tls);
    const parts = ja3.split(",");
    assert.equal(parts.length, 5, "JA3 string should have 5 comma-separated sections");
  });

  it("excludes GREASE values", () => {
    const profile = getProfile("chrome");
    assert.ok(profile);

    const ja3 = ja3String(profile.tls);
    const parts = ja3.split(",");
    for (const part of parts) {
      const values = part.split("-").filter(Boolean).map(Number);
      for (const v of values) {
        const isGrease = (v & 0x0f0f) === 0x0a0a && v >= 0x0a0a;
        assert.ok(!isGrease, `GREASE value ${v} (0x${v.toString(16)}) should be filtered`);
      }
    }
  });

  it("first field is the client version", () => {
    const profile = getProfile("chrome");
    assert.ok(profile);
    const ja3 = ja3String(profile.tls);
    const version = parseInt(ja3.split(",")[0]!, 10);
    assert.ok(version >= 0x0301, "Version should be at least TLS 1.0");
  });
});

describe("ja3Hash", () => {
  it("returns 32-char hex MD5 hash", () => {
    const profile = getProfile("chrome");
    assert.ok(profile);

    const hash = ja3Hash(profile.tls);
    assert.equal(hash.length, 32);
    assert.match(hash, /^[0-9a-f]{32}$/);
  });

  it("is deterministic", () => {
    const profile = getProfile("chrome");
    assert.ok(profile);
    assert.equal(ja3Hash(profile.tls), ja3Hash(profile.tls));
  });

  it("differs between browsers", () => {
    const chrome = getProfile("chrome");
    const firefox = getProfile("firefox");
    assert.ok(chrome);
    assert.ok(firefox);
    assert.notEqual(ja3Hash(chrome.tls), ja3Hash(firefox.tls));
  });
});

describe("ja3nString", () => {
  it("returns sorted cipher suites and extensions", () => {
    const profile = getProfile("chrome");
    assert.ok(profile);

    const ja3n = ja3nString(profile.tls);
    const parts = ja3n.split(",");
    assert.equal(parts.length, 5);

    const ciphers = parts[1]!.split("-").filter(Boolean).map(Number);
    for (let i = 1; i < ciphers.length; i++) {
      assert.ok(ciphers[i]! >= ciphers[i - 1]!, "Ciphers should be sorted in JA3N");
    }

    const extensions = parts[2]!.split("-").filter(Boolean).map(Number);
    for (let i = 1; i < extensions.length; i++) {
      assert.ok(extensions[i]! >= extensions[i - 1]!, "Extensions should be sorted in JA3N");
    }
  });
});

describe("ja3nHash", () => {
  it("returns 32-char hex MD5 hash", () => {
    const profile = getProfile("firefox");
    assert.ok(profile);
    const hash = ja3nHash(profile.tls);
    assert.equal(hash.length, 32);
    assert.match(hash, /^[0-9a-f]{32}$/);
  });
});
