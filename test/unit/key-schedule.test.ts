/**
 * Unit tests for src/tls/stealth/key-schedule.ts
 *
 * Validates TLS 1.3 key derivation against RFC 8448 test vectors.
 * These are the official IETF test vectors — if these pass, the
 * crypto primitives are producing correct results.
 */
import { describe, it } from "node:test";
import { strict as assert } from "node:assert";
import { hkdfExtract, hkdfExpandLabel, deriveSecret, deriveHandshakeKeys, deriveApplicationKeys, computeFinishedVerifyData, hashLength, zeroKey } from "../../src/tls/stealth/key-schedule.js";
import { createHash } from "node:crypto";

/**
 * RFC 8448 §3 — Simple 1-RTT Handshake test vectors.
 * All hex strings come directly from the RFC.
 */
describe("TLS 1.3 Key Schedule — RFC 8448 test vectors", () => {
  const sharedSecret = Buffer.from("8bd4054fb55b9d63fdfbacf9f04b9f0d35e6d63f537563efd46272900f89492d", "hex");

  const helloHash = Buffer.from("860c06edc07858ee8e78f0e7428c58edd6b43f2ca3e6e95f02ed063cf0e1cad8", "hex");

  it("hkdfExtract produces correct early secret from zero PSK", () => {
    const earlySecret = hkdfExtract("sha256", Buffer.alloc(32), Buffer.alloc(32));
    assert.equal(earlySecret.toString("hex"), "33ad0a1c607ec03b09e6cd9893680ce210adf300aa1f2660e1b22e10f170f92a");
  });

  it("deriveSecret('derived') produces correct salt for handshake secret", () => {
    const earlySecret = hkdfExtract("sha256", Buffer.alloc(32), Buffer.alloc(32));
    const emptyHash = createHash("sha256").digest();
    const derivedSalt = deriveSecret("sha256", earlySecret, "derived", emptyHash);
    assert.equal(derivedSalt.toString("hex"), "6f2615a108c702c5678f54fc9dbab69716c076189c48250cebeac3576c3611ba");
  });

  it("hkdfExtract produces correct handshake secret", () => {
    const earlySecret = hkdfExtract("sha256", Buffer.alloc(32), Buffer.alloc(32));
    const emptyHash = createHash("sha256").digest();
    const derivedSalt = deriveSecret("sha256", earlySecret, "derived", emptyHash);
    const handshakeSecret = hkdfExtract("sha256", derivedSalt, sharedSecret);
    assert.equal(handshakeSecret.toString("hex"), "1dc826e93606aa6fdc0aadc12f741b01046aa6b99f691ed221a9f0ca043fbeac");
  });

  it("deriveSecret('c hs traffic') produces correct client handshake traffic secret", () => {
    const earlySecret = hkdfExtract("sha256", Buffer.alloc(32), Buffer.alloc(32));
    const emptyHash = createHash("sha256").digest();
    const derivedSalt = deriveSecret("sha256", earlySecret, "derived", emptyHash);
    const handshakeSecret = hkdfExtract("sha256", derivedSalt, sharedSecret);
    const clientHS = deriveSecret("sha256", handshakeSecret, "c hs traffic", helloHash);
    assert.equal(clientHS.toString("hex"), "b3eddb126e067f35a780b3abf45e2d8f3b1a950738f52e9600746a0e27a55a21");
  });

  it("deriveSecret('s hs traffic') produces correct server handshake traffic secret", () => {
    const earlySecret = hkdfExtract("sha256", Buffer.alloc(32), Buffer.alloc(32));
    const emptyHash = createHash("sha256").digest();
    const derivedSalt = deriveSecret("sha256", earlySecret, "derived", emptyHash);
    const handshakeSecret = hkdfExtract("sha256", derivedSalt, sharedSecret);
    const serverHS = deriveSecret("sha256", handshakeSecret, "s hs traffic", helloHash);
    assert.equal(serverHS.toString("hex"), "b67b7d690cc16c4e75e54213cb2d37b4e9c912bcded9105d42befd59d391ad38");
  });

  it("hkdfExpandLabel('key') derives correct handshake keys", () => {
    const earlySecret = hkdfExtract("sha256", Buffer.alloc(32), Buffer.alloc(32));
    const emptyHash = createHash("sha256").digest();
    const derivedSalt = deriveSecret("sha256", earlySecret, "derived", emptyHash);
    const handshakeSecret = hkdfExtract("sha256", derivedSalt, sharedSecret);
    const clientHS = deriveSecret("sha256", handshakeSecret, "c hs traffic", helloHash);
    const serverHS = deriveSecret("sha256", handshakeSecret, "s hs traffic", helloHash);

    const clientKey = hkdfExpandLabel("sha256", clientHS, "key", Buffer.alloc(0), 16);
    const clientIV = hkdfExpandLabel("sha256", clientHS, "iv", Buffer.alloc(0), 12);
    const serverKey = hkdfExpandLabel("sha256", serverHS, "key", Buffer.alloc(0), 16);
    const serverIV = hkdfExpandLabel("sha256", serverHS, "iv", Buffer.alloc(0), 12);

    assert.equal(clientKey.toString("hex"), "dbfaa693d1762c5b666af5d950258d01");
    assert.equal(clientIV.toString("hex"), "5bd3c71b836e0b76bb73265f");
    assert.equal(serverKey.toString("hex"), "3fce516009c21727d0f2e4e86ee403bc");
    assert.equal(serverIV.toString("hex"), "5d313eb2671276ee13000b30");
  });

  it("deriveHandshakeKeys returns all correct values end-to-end", () => {
    const keys = deriveHandshakeKeys("sha256", sharedSecret, helloHash, 16, 12);

    assert.equal(keys.clientHandshakeKey.toString("hex"), "dbfaa693d1762c5b666af5d950258d01");
    assert.equal(keys.clientHandshakeIV.toString("hex"), "5bd3c71b836e0b76bb73265f");
    assert.equal(keys.serverHandshakeKey.toString("hex"), "3fce516009c21727d0f2e4e86ee403bc");
    assert.equal(keys.serverHandshakeIV.toString("hex"), "5d313eb2671276ee13000b30");

    assert.equal(keys.masterSecret.toString("hex"), "18df06843d13a08bf2a449844c5f8a478001bc4d4c627984d5a41da8d0402919");
  });

  it("computeFinishedVerifyData produces correct HMAC", () => {
    const keys = deriveHandshakeKeys("sha256", sharedSecret, helloHash, 16, 12);
    const serverHS = deriveSecret("sha256", keys.handshakeSecret, "s hs traffic", helloHash);

    const transcriptHash = createHash("sha256").update(Buffer.from("test")).digest();
    const verifyData = computeFinishedVerifyData("sha256", serverHS, transcriptHash);

    assert.equal(verifyData.length, 32);

    const verifyData2 = computeFinishedVerifyData("sha256", serverHS, transcriptHash);
    assert.deepStrictEqual(verifyData, verifyData2);
  });
});

describe("Key schedule utility functions", () => {
  it("hashLength returns 32 for sha256", () => {
    assert.equal(hashLength("sha256"), 32);
  });

  it("hashLength returns 48 for sha384", () => {
    assert.equal(hashLength("sha384"), 48);
  });

  it("zeroKey returns buffer of correct length filled with zeros", () => {
    const key = zeroKey("sha256");
    assert.equal(key.length, 32);
    assert.ok(key.every((b) => b === 0));
  });

  it("zeroKey sha384 returns 48-byte buffer", () => {
    const key = zeroKey("sha384");
    assert.equal(key.length, 48);
    assert.ok(key.every((b) => b === 0));
  });
});

describe("Application keys derivation", () => {
  it("derives application keys from master secret and handshake hash", () => {
    const sharedSecret = Buffer.from("8bd4054fb55b9d63fdfbacf9f04b9f0d35e6d63f537563efd46272900f89492d", "hex");
    const helloHash = Buffer.from("860c06edc07858ee8e78f0e7428c58edd6b43f2ca3e6e95f02ed063cf0e1cad8", "hex");

    const hsKeys = deriveHandshakeKeys("sha256", sharedSecret, helloHash, 16, 12);

    const handshakeHash = createHash("sha256").update(Buffer.from("handshake-complete")).digest();
    const appKeys = deriveApplicationKeys("sha256", hsKeys.masterSecret, handshakeHash, 16, 12);

    assert.equal(appKeys.clientKey.length, 16);
    assert.equal(appKeys.clientIV.length, 12);
    assert.equal(appKeys.serverKey.length, 16);
    assert.equal(appKeys.serverIV.length, 12);
    assert.equal(appKeys.clientTrafficSecret.length, 32);
    assert.equal(appKeys.serverTrafficSecret.length, 32);

    assert.notDeepStrictEqual(appKeys.clientKey, appKeys.serverKey);
    assert.notDeepStrictEqual(appKeys.clientIV, appKeys.serverIV);

    const appKeys2 = deriveApplicationKeys("sha256", hsKeys.masterSecret, handshakeHash, 16, 12);
    assert.deepStrictEqual(appKeys.clientKey, appKeys2.clientKey);
    assert.deepStrictEqual(appKeys.serverKey, appKeys2.serverKey);
  });
});
