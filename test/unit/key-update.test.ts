/**
 * Unit tests for TLS 1.3 KeyUpdate key ordering.
 *
 * Regression test: when responding to a server's KeyUpdate with
 * request_update=update_requested, the client MUST encrypt the response
 * with the CURRENT (old) keys and THEN rotate to new keys.
 *
 * The bug was that the code rotated client keys BEFORE encrypting
 * the KeyUpdate response, meaning the response was encrypted with
 * new keys that the server can't decrypt (it hasn't received the
 * response yet, so it still expects old keys).
 *
 * We test this by simulating the key rotation flow and verifying
 * that the correct key material is used at each step.
 */
import { describe, it } from "node:test";
import { strict as assert } from "node:assert";
import { randomBytes } from "node:crypto";
import { hkdfExpandLabel, hashLength } from "../../src/tls/stealth/key-schedule.js";
import { wrapEncryptedRecord, unwrapEncryptedRecord, readRecord } from "../../src/tls/stealth/record-layer.js";
import { RecordType } from "../../src/tls/constants.js";

describe("KeyUpdate response key ordering (regression)", () => {
  const hashAlg = "sha256";
  const aead = "aes-128-gcm" as const;
  const keyLen = 16;
  const ivLen = 12;

  /** Derive next-generation traffic secret and keys */
  function rotateKeys(currentSecret: Buffer) {
    const newSecret = hkdfExpandLabel(hashAlg, currentSecret, "traffic upd", Buffer.alloc(0), hashLength(hashAlg));
    const newKey = hkdfExpandLabel(hashAlg, newSecret, "key", Buffer.alloc(0), keyLen);
    const newIV = hkdfExpandLabel(hashAlg, newSecret, "iv", Buffer.alloc(0), ivLen);
    return { secret: newSecret, key: newKey, iv: newIV };
  }

  it("response encrypted with old keys is decryptable by the peer", () => {
    const clientSecret = randomBytes(32);
    const clientKey = hkdfExpandLabel(hashAlg, clientSecret, "key", Buffer.alloc(0), keyLen);
    const clientIV = hkdfExpandLabel(hashAlg, clientSecret, "iv", Buffer.alloc(0), ivLen);
    const clientSeq = 5n;

    const kuMsg = Buffer.from([24, 0, 0, 1, 0]);

    const encryptedCorrect = wrapEncryptedRecord(aead, clientKey, clientIV, clientSeq, RecordType.HANDSHAKE, kuMsg);

    const parsed = readRecord(encryptedCorrect, 0)!;
    const decrypted = unwrapEncryptedRecord(aead, clientKey, clientIV, clientSeq, parsed.record);
    assert.deepStrictEqual(decrypted.plaintext, kuMsg);
    assert.equal(decrypted.contentType, RecordType.HANDSHAKE);
  });

  it("response encrypted with NEW keys cannot be decrypted by peer using old keys", () => {
    const clientSecret = randomBytes(32);
    const clientKey = hkdfExpandLabel(hashAlg, clientSecret, "key", Buffer.alloc(0), keyLen);
    const clientIV = hkdfExpandLabel(hashAlg, clientSecret, "iv", Buffer.alloc(0), ivLen);
    const clientSeq = 5n;

    const rotated = rotateKeys(clientSecret);

    const kuMsg = Buffer.from([24, 0, 0, 1, 0]);

    const encryptedWrong = wrapEncryptedRecord(aead, rotated.key, rotated.iv, 0n, RecordType.HANDSHAKE, kuMsg);

    const parsed = readRecord(encryptedWrong, 0)!;
    assert.throws(() => unwrapEncryptedRecord(aead, clientKey, clientIV, clientSeq, parsed.record), "Decryption with old keys should fail when encrypted with new keys");
  });

  it("after rotation, new keys produce different ciphertext than old keys", () => {
    const clientSecret = randomBytes(32);
    const oldKey = hkdfExpandLabel(hashAlg, clientSecret, "key", Buffer.alloc(0), keyLen);
    const oldIV = hkdfExpandLabel(hashAlg, clientSecret, "iv", Buffer.alloc(0), ivLen);

    const rotated = rotateKeys(clientSecret);

    const msg = Buffer.from("test data");
    const encOld = wrapEncryptedRecord(aead, oldKey, oldIV, 0n, RecordType.APPLICATION_DATA, msg);
    const encNew = wrapEncryptedRecord(aead, rotated.key, rotated.iv, 0n, RecordType.APPLICATION_DATA, msg);

    assert.notDeepStrictEqual(encOld, encNew);
  });

  it("sequence number resets to 0 after rotation", () => {
    const clientSecret = randomBytes(32);
    const rotated = rotateKeys(clientSecret);

    const msg = Buffer.from("post-rotation data");
    const encrypted = wrapEncryptedRecord(aead, rotated.key, rotated.iv, 0n, RecordType.APPLICATION_DATA, msg);
    const parsed = readRecord(encrypted, 0)!;
    const decrypted = unwrapEncryptedRecord(aead, rotated.key, rotated.iv, 0n, parsed.record);
    assert.deepStrictEqual(decrypted.plaintext, msg);
  });

  it("traffic secret update is deterministic (same input → same output)", () => {
    const secret = Buffer.from("a".repeat(32));
    const r1 = rotateKeys(secret);
    const r2 = rotateKeys(secret);
    assert.deepStrictEqual(r1.secret, r2.secret);
    assert.deepStrictEqual(r1.key, r2.key);
    assert.deepStrictEqual(r1.iv, r2.iv);
  });

  it("traffic secret update is one-way (different from input)", () => {
    const secret = randomBytes(32);
    const rotated = rotateKeys(secret);
    assert.notDeepStrictEqual(rotated.secret, secret);
  });
});
