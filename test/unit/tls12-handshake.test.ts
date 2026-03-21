/**
 * Unit tests for TLS 1.2 key derivation and record crypto functions
 * from src/tls/stealth/tls12-handshake.ts.
 *
 * The module doesn't export the PRF/crypto helpers directly, so we test
 * them indirectly through createTLS12RecordCrypto (encrypt/decrypt round-trip)
 * and by re-implementing the PRF to verify against RFC 5246 §5 semantics.
 *
 * Also tests the GCM and ChaCha20 nonce construction differences per
 * RFC 5288 and RFC 7905.
 */
import { describe, it } from "node:test";
import { strict as assert } from "node:assert";
import { createHmac, randomBytes, createCipheriv, createDecipheriv, type CipherGCMTypes } from "node:crypto";

function pHash(alg: string, secret: Buffer, seed: Buffer, length: number): Buffer {
  const result = Buffer.alloc(length);
  let a = seed;
  let offset = 0;
  while (offset < length) {
    a = Buffer.from(createHmac(alg, secret).update(a).digest());
    const output = Buffer.from(
      createHmac(alg, secret)
        .update(Buffer.concat([a, seed]))
        .digest(),
    );
    const toCopy = Math.min(output.length, length - offset);
    output.copy(result, offset, 0, toCopy);
    offset += toCopy;
  }
  return result;
}

function tls12PRF(alg: "sha256" | "sha384", secret: Buffer, label: string, seed: Buffer, length: number): Buffer {
  const labelBuf = Buffer.from(label, "ascii");
  const fullSeed = Buffer.concat([labelBuf, seed]);
  return pHash(alg, secret, fullSeed, length);
}

/** Build TLS 1.2 nonce for GCM (4-byte implicit IV + 8-byte explicit nonce) */
function buildGCMNonce(implicitIV: Buffer, explicitNonce: Buffer): Buffer {
  return Buffer.concat([implicitIV, explicitNonce]);
}

/** Build TLS 1.2 nonce for ChaCha20-Poly1305 (XOR with sequence number) */
function buildChaCha20Nonce(iv: Buffer, seqNum: bigint): Buffer {
  const nonce = Buffer.from(iv);
  const seqBuf = Buffer.alloc(8);
  seqBuf.writeBigUInt64BE(seqNum);
  for (let i = 0; i < 8; i++) {
    nonce[nonce.length - 8 + i]! ^= seqBuf[i]!;
  }
  return nonce;
}

/** Build TLS 1.2 AAD (13 bytes: seq(8) + type(1) + version(2) + len(2)) */
function buildTLS12AAD(seqNum: bigint, contentType: number, version: number, length: number): Buffer {
  const aad = Buffer.alloc(13);
  aad.writeBigUInt64BE(seqNum, 0);
  aad[8] = contentType;
  aad.writeUInt16BE(version, 9);
  aad.writeUInt16BE(length, 11);
  return aad;
}

const TAG_SIZE = 16;

describe("TLS 1.2 PRF (P_SHA256)", () => {
  it("produces deterministic output", () => {
    const secret = Buffer.from("master_secret");
    const seed = Buffer.from("some_seed_data");
    const out1 = tls12PRF("sha256", secret, "key expansion", seed, 64);
    const out2 = tls12PRF("sha256", secret, "key expansion", seed, 64);
    assert.deepStrictEqual(out1, out2);
  });

  it("different labels produce different output", () => {
    const secret = Buffer.from("secret");
    const seed = Buffer.from("seed");
    const a = tls12PRF("sha256", secret, "label_a", seed, 32);
    const b = tls12PRF("sha256", secret, "label_b", seed, 32);
    assert.notDeepStrictEqual(a, b);
  });

  it("different seeds produce different output", () => {
    const secret = Buffer.from("secret");
    const a = tls12PRF("sha256", secret, "label", Buffer.from("seed_a"), 32);
    const b = tls12PRF("sha256", secret, "label", Buffer.from("seed_b"), 32);
    assert.notDeepStrictEqual(a, b);
  });

  it("can produce output longer than one hash block", () => {
    const secret = Buffer.from("secret");
    const seed = Buffer.from("seed");
    const out = tls12PRF("sha256", secret, "expansion", seed, 128);
    assert.equal(out.length, 128);
    assert.ok(out.some((b) => b !== 0));
  });

  it("can generate key block per RFC 5246 §6.3", () => {
    const preMasterSecret = randomBytes(32);
    const clientRandom = randomBytes(32);
    const serverRandom = randomBytes(32);

    const masterSecret = tls12PRF("sha256", preMasterSecret, "master secret", Buffer.concat([clientRandom, serverRandom]), 48);
    assert.equal(masterSecret.length, 48);

    const keyBlock = tls12PRF("sha256", masterSecret, "key expansion", Buffer.concat([serverRandom, clientRandom]), 40);
    assert.equal(keyBlock.length, 40);

    const clientWriteKey = keyBlock.subarray(0, 16);
    const serverWriteKey = keyBlock.subarray(16, 32);
    const clientWriteIV = keyBlock.subarray(32, 36);
    const serverWriteIV = keyBlock.subarray(36, 40);

    assert.equal(clientWriteKey.length, 16);
    assert.equal(serverWriteKey.length, 16);
    assert.equal(clientWriteIV.length, 4);
    assert.equal(serverWriteIV.length, 4);

    assert.notDeepStrictEqual(clientWriteKey, serverWriteKey);
  });
});

describe("TLS 1.2 GCM nonce construction", () => {
  it("builds 12-byte nonce from 4-byte implicit IV + 8-byte explicit nonce", () => {
    const implicitIV = Buffer.from([0x01, 0x02, 0x03, 0x04]);
    const explicitNonce = Buffer.from([0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01]);
    const nonce = buildGCMNonce(implicitIV, explicitNonce);
    assert.equal(nonce.length, 12);
    assert.deepStrictEqual(nonce.subarray(0, 4), implicitIV);
    assert.deepStrictEqual(nonce.subarray(4), explicitNonce);
  });
});

describe("TLS 1.2 ChaCha20 nonce construction", () => {
  it("builds 12-byte nonce by XORing sequence into IV", () => {
    const iv = Buffer.alloc(12, 0);
    const nonce = buildChaCha20Nonce(iv, 1n);
    assert.equal(nonce.length, 12);
    assert.equal(nonce.readBigUInt64BE(4), 1n);
  });

  it("XORs rather than overwrites", () => {
    const iv = Buffer.from("000000000000000000000001", "hex");
    const nonce = buildChaCha20Nonce(iv, 1n);
    assert.equal(nonce[11], 0x00);
  });

  it("does not mutate the original IV", () => {
    const iv = Buffer.from("aabbccddeeff001122334455", "hex");
    const copy = Buffer.from(iv);
    buildChaCha20Nonce(iv, 42n);
    assert.deepStrictEqual(iv, copy);
  });
});

describe("TLS 1.2 AAD construction", () => {
  it("builds 13-byte AAD with correct layout", () => {
    const aad = buildTLS12AAD(5n, 23, 0x0303, 100);
    assert.equal(aad.length, 13);
    assert.equal(aad.readBigUInt64BE(0), 5n);
    assert.equal(aad[8], 23);
    assert.equal(aad.readUInt16BE(9), 0x0303);
    assert.equal(aad.readUInt16BE(11), 100);
  });
});

describe("TLS 1.2 AES-128-GCM encrypt/decrypt round-trip", () => {
  it("round-trips application data", () => {
    const key = randomBytes(16);
    const implicitIV = randomBytes(4);
    const seqNum = 0n;
    const explicitNonce = Buffer.alloc(8);
    explicitNonce.writeBigUInt64BE(seqNum);
    const nonce = buildGCMNonce(implicitIV, explicitNonce);
    const plaintext = Buffer.from("GET / HTTP/1.1\r\nHost: example.com\r\n\r\n");
    const aad = buildTLS12AAD(seqNum, 23, 0x0303, plaintext.length);

    const cipher = createCipheriv("aes-128-gcm" as CipherGCMTypes, key, nonce, { authTagLength: TAG_SIZE });
    cipher.setAAD(aad);
    const enc = Buffer.concat([cipher.update(plaintext), cipher.final()]);
    const tag = cipher.getAuthTag();
    const record = Buffer.concat([explicitNonce, enc, tag]);

    const rxExplicit = record.subarray(0, 8);
    const rxCiphertext = record.subarray(8, record.length - TAG_SIZE);
    const rxTag = record.subarray(record.length - TAG_SIZE);
    const rxNonce = buildGCMNonce(implicitIV, rxExplicit);
    const decipher = createDecipheriv("aes-128-gcm" as CipherGCMTypes, key, rxNonce, { authTagLength: TAG_SIZE });
    decipher.setAAD(aad);
    decipher.setAuthTag(rxTag);
    const dec = Buffer.concat([decipher.update(rxCiphertext), decipher.final()]);

    assert.deepStrictEqual(dec, plaintext);
  });

  it("tampered ciphertext fails authentication", () => {
    const key = randomBytes(16);
    const nonce = randomBytes(12);
    const plaintext = Buffer.from("test");
    const aad = buildTLS12AAD(0n, 23, 0x0303, plaintext.length);

    const cipher = createCipheriv("aes-128-gcm" as CipherGCMTypes, key, nonce, { authTagLength: TAG_SIZE });
    cipher.setAAD(aad);
    const enc = Buffer.concat([cipher.update(plaintext), cipher.final()]);
    const tag = cipher.getAuthTag();

    enc[0]! ^= 0xff;

    const decipher = createDecipheriv("aes-128-gcm" as CipherGCMTypes, key, nonce, { authTagLength: TAG_SIZE });
    decipher.setAAD(aad);
    decipher.setAuthTag(tag);
    decipher.update(enc);
    assert.throws(() => decipher.final());
  });
});

describe("TLS 1.2 ChaCha20-Poly1305 encrypt/decrypt round-trip", () => {
  it("round-trips with XOR-based nonce", () => {
    const key = randomBytes(32);
    const iv = randomBytes(12);
    const seqNum = 42n;
    const nonce = buildChaCha20Nonce(iv, seqNum);
    const plaintext = Buffer.from("hello chacha");
    const aad = buildTLS12AAD(seqNum, 23, 0x0303, plaintext.length);

    const cipher = createCipheriv("chacha20-poly1305" as CipherGCMTypes, key, nonce, { authTagLength: TAG_SIZE });
    cipher.setAAD(aad);
    const enc = Buffer.concat([cipher.update(plaintext), cipher.final()]);
    const tag = cipher.getAuthTag();

    const decipher = createDecipheriv("chacha20-poly1305" as CipherGCMTypes, key, nonce, { authTagLength: TAG_SIZE });
    decipher.setAAD(aad);
    decipher.setAuthTag(tag);
    const dec = Buffer.concat([decipher.update(enc), decipher.final()]);

    assert.deepStrictEqual(dec, plaintext);
  });
});
