import { describe, it } from "node:test";
import assert from "node:assert/strict";
import { readRecord, writeRecord, buildNonce, aeadFromCipher, encryptRecord, decryptRecord } from "../../src/tls/stealth/record-layer.js";
import { RecordType, ProtocolVersion } from "../../src/tls/constants.js";

describe("readRecord", () => {
  it("reads a complete TLS record", () => {
    const payload = Buffer.from("hello");
    const buf = Buffer.alloc(5 + payload.length);
    buf[0] = RecordType.HANDSHAKE;
    buf.writeUInt16BE(ProtocolVersion.TLS_1_2, 1);
    buf.writeUInt16BE(payload.length, 3);
    payload.copy(buf, 5);

    const result = readRecord(buf, 0);
    assert.ok(result);
    assert.equal(result.record.type, RecordType.HANDSHAKE);
    assert.equal(result.record.version, ProtocolVersion.TLS_1_2);
    assert.deepEqual([...result.record.fragment], [...payload]);
    assert.equal(result.bytesRead, 5 + payload.length);
  });

  it("returns null for incomplete header", () => {
    const buf = Buffer.from([0x16, 0x03, 0x03]);
    assert.equal(readRecord(buf, 0), null);
  });

  it("returns null for incomplete payload", () => {
    const buf = Buffer.alloc(5 + 2);
    buf[0] = RecordType.HANDSHAKE;
    buf.writeUInt16BE(ProtocolVersion.TLS_1_2, 1);
    buf.writeUInt16BE(10, 3);
    assert.equal(readRecord(buf, 0), null);
  });

  it("respects offset parameter", () => {
    const prefix = Buffer.from([0x00, 0x00, 0x00]);
    const payload = Buffer.from([0xaa]);
    const record = Buffer.alloc(5 + payload.length);
    record[0] = RecordType.APPLICATION_DATA;
    record.writeUInt16BE(ProtocolVersion.TLS_1_2, 1);
    record.writeUInt16BE(1, 3);
    record[5] = 0xaa;

    const buf = Buffer.concat([prefix, record]);
    const result = readRecord(buf, 3);
    assert.ok(result);
    assert.equal(result.record.type, RecordType.APPLICATION_DATA);
    assert.equal(result.record.fragment[0], 0xaa);
  });
});

describe("writeRecord", () => {
  it("creates a valid TLS record", () => {
    const payload = Buffer.from([0x01, 0x02, 0x03]);
    const record = writeRecord(RecordType.HANDSHAKE, ProtocolVersion.TLS_1_2, payload);

    assert.equal(record[0], RecordType.HANDSHAKE);
    assert.equal(record.readUInt16BE(1), ProtocolVersion.TLS_1_2);
    assert.equal(record.readUInt16BE(3), 3);
    assert.deepEqual([...record.subarray(5)], [0x01, 0x02, 0x03]);
  });

  it("roundtrips with readRecord", () => {
    const payload = Buffer.from("test data");
    const written = writeRecord(RecordType.ALERT, ProtocolVersion.TLS_1_3, payload);
    const result = readRecord(written, 0);
    assert.ok(result);
    assert.equal(result.record.type, RecordType.ALERT);
    assert.equal(result.record.version, ProtocolVersion.TLS_1_3);
    assert.deepEqual(result.record.fragment.toString(), "test data");
  });
});

describe("buildNonce", () => {
  it("XORs sequence number with IV", () => {
    const iv = Buffer.alloc(12, 0);
    const nonce = buildNonce(iv, 0n);
    assert.deepEqual([...nonce], Array(12).fill(0));
  });

  it("XORs correctly for non-zero sequence", () => {
    const iv = Buffer.alloc(12, 0);
    const nonce = buildNonce(iv, 1n);
    assert.equal(nonce[11], 1);
    assert.equal(nonce[10], 0);
  });

  it("does not modify original IV", () => {
    const iv = Buffer.alloc(12, 0xff);
    const original = Buffer.from(iv);
    buildNonce(iv, 42n);
    assert.deepEqual([...iv], [...original]);
  });
});

describe("aeadFromCipher", () => {
  it("AES-128-GCM", () => {
    assert.equal(aeadFromCipher("TLS_AES_128_GCM_SHA256"), "aes-128-gcm");
  });

  it("AES-256-GCM", () => {
    assert.equal(aeadFromCipher("TLS_AES_256_GCM_SHA384"), "aes-256-gcm");
  });

  it("ChaCha20-Poly1305", () => {
    assert.equal(aeadFromCipher("TLS_CHACHA20_POLY1305_SHA256"), "chacha20-poly1305");
  });

  it("throws for unsupported cipher", () => {
    assert.throws(() => aeadFromCipher("TLS_NULL_NULL"));
  });
});

describe("encryptRecord / decryptRecord roundtrip", () => {
  it("AES-128-GCM roundtrip", () => {
    const key = Buffer.alloc(16, 0x42);
    const nonce = Buffer.alloc(12, 0x01);
    const plaintext = Buffer.from("secret data");
    const aad = Buffer.from([0x17, 0x03, 0x03, 0x00, 0x00]);

    const encrypted = encryptRecord("aes-128-gcm", key, nonce, plaintext, aad);
    assert.ok(encrypted.length > plaintext.length);

    const decrypted = decryptRecord("aes-128-gcm", key, nonce, encrypted, aad);
    assert.deepEqual(decrypted.toString(), "secret data");
  });

  it("AES-256-GCM roundtrip", () => {
    const key = Buffer.alloc(32, 0xaa);
    const nonce = Buffer.alloc(12, 0x02);
    const plaintext = Buffer.from("more secret data");
    const aad = Buffer.from([0x17, 0x03, 0x03, 0x00, 0x00]);

    const encrypted = encryptRecord("aes-256-gcm", key, nonce, plaintext, aad);
    const decrypted = decryptRecord("aes-256-gcm", key, nonce, encrypted, aad);
    assert.deepEqual(decrypted.toString(), "more secret data");
  });

  it("fails with wrong key", () => {
    const key = Buffer.alloc(16, 0x42);
    const wrongKey = Buffer.alloc(16, 0x43);
    const nonce = Buffer.alloc(12, 0x01);
    const plaintext = Buffer.from("data");
    const aad = Buffer.from([0x17, 0x03, 0x03, 0x00, 0x00]);

    const encrypted = encryptRecord("aes-128-gcm", key, nonce, plaintext, aad);
    assert.throws(() => decryptRecord("aes-128-gcm", wrongKey, nonce, encrypted, aad));
  });

  it("fails with wrong AAD", () => {
    const key = Buffer.alloc(16, 0x42);
    const nonce = Buffer.alloc(12, 0x01);
    const plaintext = Buffer.from("data");
    const aad = Buffer.from([0x17, 0x03, 0x03, 0x00, 0x04]);
    const wrongAad = Buffer.from([0x17, 0x03, 0x03, 0x00, 0x05]);

    const encrypted = encryptRecord("aes-128-gcm", key, nonce, plaintext, aad);
    assert.throws(() => decryptRecord("aes-128-gcm", key, nonce, encrypted, wrongAad));
  });
});
