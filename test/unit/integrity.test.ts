/**
 * Unit tests for src/utils/integrity.ts
 * W3C Subresource Integrity (SRI) specification: https://www.w3.org/TR/SRI/
 * Expected hash values independently computed using Node.js crypto.
 */
import { describe, it } from "node:test";
import { strict as assert } from "node:assert";
import { createHash } from "node:crypto";
import { verifyIntegrity } from "../../src/utils/integrity.js";

function computeSRI(body: Buffer, algo: string): string {
  return `${algo}-${createHash(algo).update(body).digest("base64")}`;
}

describe("verifyIntegrity", () => {
  const body = Buffer.from("Hello, World!");

  const sha256Hash = computeSRI(body, "sha256");
  const sha384Hash = computeSRI(body, "sha384");
  const sha512Hash = computeSRI(body, "sha512");

  it("verifies sha256 integrity successfully", () => {
    assert.equal(verifyIntegrity(body, sha256Hash), true);
  });

  it("verifies sha384 integrity successfully", () => {
    assert.equal(verifyIntegrity(body, sha384Hash), true);
  });

  it("verifies sha512 integrity successfully", () => {
    assert.equal(verifyIntegrity(body, sha512Hash), true);
  });

  it("returns false for mismatched hash", () => {
    assert.equal(verifyIntegrity(body, "sha256-AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="), false);
  });

  it("returns true if any hash in a multi-hash string matches (per W3C SRI §3.3)", () => {
    const integrity = `sha256-wronghash ${sha384Hash}`;
    assert.equal(verifyIntegrity(body, integrity), true);
  });

  it("returns false when no hash matches in multi-hash string", () => {
    assert.equal(verifyIntegrity(body, "sha256-AAAA sha384-BBBB"), false);
  });

  it("returns false for empty integrity string", () => {
    assert.equal(verifyIntegrity(body, ""), false);
  });

  it("returns false for invalid format (no algorithm prefix)", () => {
    assert.equal(verifyIntegrity(body, "not-a-valid-sri"), false);
  });

  it("returns false for unsupported algorithm", () => {
    assert.equal(verifyIntegrity(body, "md5-somehash"), false);
  });

  it("verifies empty body with correct hash", () => {
    const emptyBody = Buffer.alloc(0);
    const emptyHash = computeSRI(emptyBody, "sha256");
    assert.equal(verifyIntegrity(emptyBody, emptyHash), true);
  });

  it("handles whitespace trimming in integrity string", () => {
    assert.equal(verifyIntegrity(body, `  ${sha256Hash}  `), true);
  });

  it("handles multiple spaces between hash entries", () => {
    assert.equal(verifyIntegrity(body, `sha256-wrong   ${sha256Hash}`), true);
  });

  it("verifies integrity for binary content", () => {
    const binaryBody = Buffer.from([0x00, 0xff, 0x80, 0x7f, 0xde, 0xad, 0xbe, 0xef]);
    const binaryHash = computeSRI(binaryBody, "sha256");
    assert.equal(verifyIntegrity(binaryBody, binaryHash), true);
  });

  it("verifies integrity for unicode content", () => {
    const unicodeBody = Buffer.from("日本語テスト", "utf-8");
    const unicodeHash = computeSRI(unicodeBody, "sha256");
    assert.equal(verifyIntegrity(unicodeBody, unicodeHash), true);
  });
});
