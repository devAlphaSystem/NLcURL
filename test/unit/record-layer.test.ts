/**
 * Unit tests for src/tls/stealth/record-layer.ts
 *
 * Validates TLS record parsing, AEAD encryption/decryption round-trips,
 * nonce construction, and the wrap/unwrap functions that form the core
 * of encrypted TLS 1.3 communication.
 */
import { describe, it } from "node:test";
import { strict as assert } from "node:assert";
import { randomBytes } from "node:crypto";
import { readRecord, writeRecord, buildNonce, buildAdditionalData, encryptRecord, decryptRecord, wrapEncryptedRecord, unwrapEncryptedRecord, aeadFromCipher, type AEADAlgorithm } from "../../src/tls/stealth/record-layer.js";
import { RecordType, ProtocolVersion } from "../../src/tls/constants.js";

describe("readRecord", () => {
  it("parses a valid TLS record", () => {
    const payload = Buffer.from("hello");
    const record = Buffer.alloc(5 + payload.length);
    record[0] = RecordType.HANDSHAKE;
    record.writeUInt16BE(ProtocolVersion.TLS_1_2, 1);
    record.writeUInt16BE(payload.length, 3);
    payload.copy(record, 5);

    const result = readRecord(record, 0);
    assert.ok(result);
    assert.equal(result.record.type, RecordType.HANDSHAKE);
    assert.equal(result.record.version, ProtocolVersion.TLS_1_2);
    assert.deepStrictEqual(result.record.fragment, payload);
    assert.equal(result.bytesRead, 5 + payload.length);
  });

  it("returns null for incomplete header", () => {
    assert.equal(readRecord(Buffer.alloc(4), 0), null);
  });

  it("returns null for incomplete payload", () => {
    const buf = Buffer.alloc(5);
    buf[0] = RecordType.HANDSHAKE;
    buf.writeUInt16BE(ProtocolVersion.TLS_1_2, 1);
    buf.writeUInt16BE(100, 3);
    assert.equal(readRecord(buf, 0), null);
  });

  it("parses at given offset", () => {
    const prefix = Buffer.alloc(10, 0xff);
    const payload = Buffer.from("test");
    const record = Buffer.alloc(5 + payload.length);
    record[0] = RecordType.APPLICATION_DATA;
    record.writeUInt16BE(ProtocolVersion.TLS_1_2, 1);
    record.writeUInt16BE(payload.length, 3);
    payload.copy(record, 5);

    const combined = Buffer.concat([prefix, record]);
    const result = readRecord(combined, 10);
    assert.ok(result);
    assert.equal(result.record.type, RecordType.APPLICATION_DATA);
    assert.deepStrictEqual(result.record.fragment, payload);
  });

  it("handles empty payload", () => {
    const record = Buffer.alloc(5);
    record[0] = RecordType.CHANGE_CIPHER_SPEC;
    record.writeUInt16BE(ProtocolVersion.TLS_1_2, 1);
    record.writeUInt16BE(0, 3);
    const result = readRecord(record, 0);
    assert.ok(result);
    assert.equal(result.record.fragment.length, 0);
    assert.equal(result.bytesRead, 5);
  });

  it("parses multiple records sequentially", () => {
    const r1 = writeRecord(RecordType.HANDSHAKE, ProtocolVersion.TLS_1_2, Buffer.from("abc"));
    const r2 = writeRecord(RecordType.APPLICATION_DATA, ProtocolVersion.TLS_1_2, Buffer.from("def"));
    const combined = Buffer.concat([r1, r2]);

    const res1 = readRecord(combined, 0);
    assert.ok(res1);
    assert.equal(res1.record.type, RecordType.HANDSHAKE);

    const res2 = readRecord(combined, res1.bytesRead);
    assert.ok(res2);
    assert.equal(res2.record.type, RecordType.APPLICATION_DATA);
  });
});

describe("writeRecord", () => {
  it("creates correct 5-byte header followed by payload", () => {
    const payload = Buffer.from([0x01, 0x02, 0x03]);
    const record = writeRecord(RecordType.HANDSHAKE, ProtocolVersion.TLS_1_2, payload);

    assert.equal(record.length, 8);
    assert.equal(record[0], RecordType.HANDSHAKE);
    assert.equal(record.readUInt16BE(1), ProtocolVersion.TLS_1_2);
    assert.equal(record.readUInt16BE(3), 3);
    assert.deepStrictEqual(record.subarray(5), payload);
  });

  it("round-trips with readRecord", () => {
    const payload = randomBytes(100);
    const written = writeRecord(RecordType.APPLICATION_DATA, ProtocolVersion.TLS_1_0, payload);
    const parsed = readRecord(written, 0);
    assert.ok(parsed);
    assert.equal(parsed.record.type, RecordType.APPLICATION_DATA);
    assert.equal(parsed.record.version, ProtocolVersion.TLS_1_0);
    assert.deepStrictEqual(Buffer.from(parsed.record.fragment), payload);
  });
});

describe("buildNonce", () => {
  it("XORs sequence number into last 8 bytes of 12-byte IV", () => {
    const iv = Buffer.alloc(12, 0);
    const nonce = buildNonce(iv, 42n);
    assert.equal(nonce.readBigUInt64BE(4), 42n);
  });

  it("preserves first 4 bytes of IV", () => {
    const iv = Buffer.from("aabbccdd00000000000000ff", "hex");
    const nonce = buildNonce(iv, 0n);
    assert.equal(nonce.readUInt32BE(0), 0xaabbccdd);
  });

  it("XORs correctly (not overwrites) the IV", () => {
    const iv = Buffer.from("000000000000000000000001", "hex");
    const nonce = buildNonce(iv, 1n);
    assert.equal(nonce[11], 0x00);
  });

  it("does not mutate the original IV", () => {
    const iv = Buffer.from("aabbccddeeff001122334455", "hex");
    const originalHex = iv.toString("hex");
    buildNonce(iv, 99n);
    assert.equal(iv.toString("hex"), originalHex);
  });
});

describe("buildAdditionalData", () => {
  it("builds 5-byte AAD: ApplicationData + TLS 1.2 + length", () => {
    const aad = buildAdditionalData(1234);
    assert.equal(aad.length, 5);
    assert.equal(aad[0], RecordType.APPLICATION_DATA);
    assert.equal(aad.readUInt16BE(1), ProtocolVersion.TLS_1_2);
    assert.equal(aad.readUInt16BE(3), 1234);
  });
});

describe("AEAD encrypt/decrypt round-trip", () => {
  const algorithms: AEADAlgorithm[] = ["aes-128-gcm", "aes-256-gcm", "chacha20-poly1305"];

  for (const alg of algorithms) {
    const keyLen = alg === "aes-128-gcm" ? 16 : 32;

    it(`round-trips ${alg} encryption`, () => {
      const key = randomBytes(keyLen);
      const nonce = randomBytes(12);
      const plaintext = Buffer.from("hello TLS world");
      const aad = buildAdditionalData(plaintext.length + 1 + 16);

      const ciphertext = encryptRecord(alg, key, nonce, plaintext, aad);
      assert.equal(ciphertext.length, plaintext.length + 16);

      const decrypted = decryptRecord(alg, key, nonce, ciphertext, aad);
      assert.deepStrictEqual(decrypted, plaintext);
    });

    it(`${alg} rejects tampered ciphertext`, () => {
      const key = randomBytes(keyLen);
      const nonce = randomBytes(12);
      const plaintext = Buffer.from("sensitive data");
      const aad = buildAdditionalData(plaintext.length + 1 + 16);

      const ciphertext = encryptRecord(alg, key, nonce, plaintext, aad);
      ciphertext[0]! ^= 0xff;
      assert.throws(() => decryptRecord(alg, key, nonce, ciphertext, aad));
    });

    it(`${alg} rejects wrong key`, () => {
      const key = randomBytes(keyLen);
      const wrongKey = randomBytes(keyLen);
      const nonce = randomBytes(12);
      const plaintext = Buffer.from("test");
      const aad = buildAdditionalData(plaintext.length + 1 + 16);

      const ciphertext = encryptRecord(alg, key, nonce, plaintext, aad);
      assert.throws(() => decryptRecord(alg, wrongKey, nonce, ciphertext, aad));
    });
  }
});

describe("wrapEncryptedRecord / unwrapEncryptedRecord", () => {
  it("round-trips a TLS 1.3 APPLICATION_DATA record", () => {
    const key = randomBytes(16);
    const iv = randomBytes(12);
    const plaintext = Buffer.from("HTTP/2 data here");

    const wrapped = wrapEncryptedRecord("aes-128-gcm", key, iv, 0n, RecordType.APPLICATION_DATA, plaintext);

    assert.equal(wrapped[0], RecordType.APPLICATION_DATA);

    const parsed = readRecord(wrapped, 0);
    assert.ok(parsed);

    const result = unwrapEncryptedRecord("aes-128-gcm", key, iv, 0n, parsed.record);
    assert.equal(result.contentType, RecordType.APPLICATION_DATA);
    assert.deepStrictEqual(result.plaintext, plaintext);
  });

  it("round-trips a HANDSHAKE content type (encrypted Finished etc.)", () => {
    const key = randomBytes(16);
    const iv = randomBytes(12);
    const handshakeMsg = Buffer.from([20, 0, 0, 32, ...randomBytes(32)]);

    const wrapped = wrapEncryptedRecord("aes-128-gcm", key, iv, 0n, RecordType.HANDSHAKE, handshakeMsg);
    const parsed = readRecord(wrapped, 0);
    assert.ok(parsed);

    const result = unwrapEncryptedRecord("aes-128-gcm", key, iv, 0n, parsed.record);
    assert.equal(result.contentType, RecordType.HANDSHAKE);
    assert.deepStrictEqual(result.plaintext, handshakeMsg);
  });

  it("sequence numbers produce different ciphertexts for same plaintext", () => {
    const key = randomBytes(16);
    const iv = randomBytes(12);
    const plaintext = Buffer.from("same data");

    const w0 = wrapEncryptedRecord("aes-128-gcm", key, iv, 0n, RecordType.APPLICATION_DATA, plaintext);
    const w1 = wrapEncryptedRecord("aes-128-gcm", key, iv, 1n, RecordType.APPLICATION_DATA, plaintext);

    assert.notDeepStrictEqual(w0, w1);

    const p0 = readRecord(w0, 0)!;
    const p1 = readRecord(w1, 0)!;
    const r0 = unwrapEncryptedRecord("aes-128-gcm", key, iv, 0n, p0.record);
    const r1 = unwrapEncryptedRecord("aes-128-gcm", key, iv, 1n, p1.record);
    assert.deepStrictEqual(r0.plaintext, plaintext);
    assert.deepStrictEqual(r1.plaintext, plaintext);
  });

  it("wrong sequence number fails decryption", () => {
    const key = randomBytes(16);
    const iv = randomBytes(12);
    const plaintext = Buffer.from("test");

    const wrapped = wrapEncryptedRecord("aes-128-gcm", key, iv, 5n, RecordType.APPLICATION_DATA, plaintext);
    const parsed = readRecord(wrapped, 0)!;

    assert.throws(() => unwrapEncryptedRecord("aes-128-gcm", key, iv, 6n, parsed.record));
  });
});

describe("aeadFromCipher", () => {
  it("maps TLS cipher suite names to AEAD algorithms", () => {
    assert.equal(aeadFromCipher("TLS_AES_128_GCM_SHA256"), "aes-128-gcm");
    assert.equal(aeadFromCipher("TLS_AES_256_GCM_SHA384"), "aes-256-gcm");
    assert.equal(aeadFromCipher("TLS_CHACHA20_POLY1305_SHA256"), "chacha20-poly1305");
  });

  it("throws for unsupported ciphers", () => {
    assert.throws(() => aeadFromCipher("TLS_NULL_WITH_NULL_NULL"));
  });
});
