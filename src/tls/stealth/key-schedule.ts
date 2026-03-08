import { createHmac, createHash as _createHash } from "node:crypto";

/** Hash algorithm identifiers used in the TLS 1.3 key schedule. */
export type HashAlgorithm = "sha256" | "sha384";

/**
 * Return the digest output length for the given hash algorithm.
 *
 * @param {HashAlgorithm} alg - Hash algorithm.
 * @returns {number} Length in bytes.
 */
export function hashLength(alg: HashAlgorithm): number {
  return alg === "sha256" ? 32 : 48;
}

/**
 * HKDF-Extract as defined in RFC 5869.
 *
 * @param {HashAlgorithm} alg - Hash algorithm.
 * @param {Buffer} salt - Salt value.
 * @param {Buffer} ikm - Input keying material.
 * @returns {Buffer} Pseudorandom key.
 */
export function hkdfExtract(alg: HashAlgorithm, salt: Buffer, ikm: Buffer): Buffer {
  return Buffer.from(createHmac(alg, salt).update(ikm).digest());
}

/**
 * HKDF-Expand-Label as defined in TLS 1.3 (RFC 8446 §7.1).
 *
 * @param {HashAlgorithm} alg - Hash algorithm.
 * @param {Buffer} secret - Input secret.
 * @param {string} label - Label string (without the "tls13 " prefix).
 * @param {Buffer} context - Context hash.
 * @param {number} length - Desired output length in bytes.
 * @returns {Buffer} Derived key material.
 */
export function hkdfExpandLabel(alg: HashAlgorithm, secret: Buffer, label: string, context: Buffer, length: number): Buffer {
  const fullLabel = Buffer.from("tls13 " + label, "ascii");
  const hkdfLabel = Buffer.alloc(2 + 1 + fullLabel.length + 1 + context.length);
  let offset = 0;
  hkdfLabel.writeUInt16BE(length, offset);
  offset += 2;
  hkdfLabel[offset++] = fullLabel.length;
  fullLabel.copy(hkdfLabel, offset);
  offset += fullLabel.length;
  hkdfLabel[offset++] = context.length;
  context.copy(hkdfLabel, offset);

  return hkdfExpand(alg, secret, hkdfLabel, length);
}

function hkdfExpand(alg: HashAlgorithm, prk: Buffer, info: Buffer, length: number): Buffer {
  const hashLen = hashLength(alg);
  const n = Math.ceil(length / hashLen);
  const okm = Buffer.alloc(n * hashLen);
  let t = Buffer.alloc(0);
  for (let i = 1; i <= n; i++) {
    const hmac = createHmac(alg, prk);
    hmac.update(t);
    hmac.update(info);
    hmac.update(Buffer.from([i]));
    t = Buffer.from(hmac.digest());
    t.copy(okm, (i - 1) * hashLen);
  }
  return okm.subarray(0, length);
}

/**
 * Derive a TLS 1.3 secret from an intermediate secret and transcript hash.
 *
 * @param {HashAlgorithm} alg - Hash algorithm.
 * @param {Buffer} secret - Base secret.
 * @param {string} label - Derivation label.
 * @param {Buffer} transcriptHash - Current transcript hash.
 * @returns {Buffer} Derived secret.
 */
export function deriveSecret(alg: HashAlgorithm, secret: Buffer, label: string, transcriptHash: Buffer): Buffer {
  return hkdfExpandLabel(alg, secret, label, transcriptHash, hashLength(alg));
}

export { _createHash as createHash };

/**
 * Return an all-zero key of the hash's digest length.
 *
 * @param {HashAlgorithm} alg - Hash algorithm.
 * @returns {Buffer} Zero-filled buffer.
 */
export function zeroKey(alg: HashAlgorithm): Buffer {
  return Buffer.alloc(hashLength(alg));
}

/** Derived TLS 1.3 handshake traffic keys and intermediate secrets. */
export interface HandshakeKeys {
  /** Client handshake traffic encryption key. */
  clientHandshakeKey: Buffer;
  /** Client handshake traffic IV. */
  clientHandshakeIV: Buffer;
  /** Server handshake traffic encryption key. */
  serverHandshakeKey: Buffer;
  /** Server handshake traffic IV. */
  serverHandshakeIV: Buffer;
  /** Handshake secret for further derivation. */
  handshakeSecret: Buffer;
  /** Master secret for application key derivation. */
  masterSecret: Buffer;
}

/** Derived TLS 1.3 application traffic encryption keys. */
export interface ApplicationKeys {
  /** Client application traffic key. */
  clientKey: Buffer;
  /** Client application traffic IV. */
  clientIV: Buffer;
  /** Server application traffic key. */
  serverKey: Buffer;
  /** Server application traffic IV. */
  serverIV: Buffer;
}

/**
 * Determine key and IV lengths for a TLS cipher suite.
 *
 * @param {string} cipherName - Cipher suite name string.
 * @returns {{ keyLen: number; ivLen: number }} Key and IV lengths in bytes.
 */
export function keyIVLengths(cipherName: string): { keyLen: number; ivLen: number } {
  if (cipherName.includes("AES_128")) {
    return { keyLen: 16, ivLen: 12 };
  }
  if (cipherName.includes("AES_256") || cipherName.includes("CHACHA20")) {
    return { keyLen: 32, ivLen: 12 };
  }
  return { keyLen: 16, ivLen: 12 };
}

/**
 * Derive TLS 1.3 handshake traffic keys from the shared secret.
 *
 * @param {HashAlgorithm} alg - Hash algorithm.
 * @param {Buffer} sharedSecret - ECDHE shared secret.
 * @param {Buffer} helloHash - Transcript hash up to and including ServerHello.
 * @param {number} keyLen - Desired key length in bytes.
 * @param {number} ivLen - Desired IV length in bytes.
 * @returns {HandshakeKeys} Handshake keys and intermediate secrets.
 */
export function deriveHandshakeKeys(alg: HashAlgorithm, sharedSecret: Buffer, helloHash: Buffer, keyLen: number, ivLen: number): HandshakeKeys {
  const earlySecret = hkdfExtract(alg, Buffer.alloc(hashLength(alg)), zeroKey(alg));

  const derivedSalt = deriveSecret(alg, earlySecret, "derived", emptyHash(alg));

  const handshakeSecret = hkdfExtract(alg, derivedSalt, sharedSecret);

  const clientSecret = deriveSecret(alg, handshakeSecret, "c hs traffic", helloHash);
  const serverSecret = deriveSecret(alg, handshakeSecret, "s hs traffic", helloHash);

  const clientHandshakeKey = hkdfExpandLabel(alg, clientSecret, "key", Buffer.alloc(0), keyLen);
  const clientHandshakeIV = hkdfExpandLabel(alg, clientSecret, "iv", Buffer.alloc(0), ivLen);
  const serverHandshakeKey = hkdfExpandLabel(alg, serverSecret, "key", Buffer.alloc(0), keyLen);
  const serverHandshakeIV = hkdfExpandLabel(alg, serverSecret, "iv", Buffer.alloc(0), ivLen);

  const derivedMasterSalt = deriveSecret(alg, handshakeSecret, "derived", emptyHash(alg));
  const masterSecret = hkdfExtract(alg, derivedMasterSalt, zeroKey(alg));

  return {
    clientHandshakeKey,
    clientHandshakeIV,
    serverHandshakeKey,
    serverHandshakeIV,
    handshakeSecret,
    masterSecret,
  };
}

/**
 * Derive TLS 1.3 application traffic keys from the master secret.
 *
 * @param {HashAlgorithm} alg - Hash algorithm.
 * @param {Buffer} masterSecret - Master secret from the key schedule.
 * @param {Buffer} handshakeHash - Transcript hash up to and including server Finished.
 * @param {number} keyLen - Desired key length in bytes.
 * @param {number} ivLen - Desired IV length in bytes.
 * @returns {ApplicationKeys} Application traffic encryption keys.
 */
export function deriveApplicationKeys(alg: HashAlgorithm, masterSecret: Buffer, handshakeHash: Buffer, keyLen: number, ivLen: number): ApplicationKeys {
  const clientSecret = deriveSecret(alg, masterSecret, "c ap traffic", handshakeHash);
  const serverSecret = deriveSecret(alg, masterSecret, "s ap traffic", handshakeHash);

  return {
    clientKey: hkdfExpandLabel(alg, clientSecret, "key", Buffer.alloc(0), keyLen),
    clientIV: hkdfExpandLabel(alg, clientSecret, "iv", Buffer.alloc(0), ivLen),
    serverKey: hkdfExpandLabel(alg, serverSecret, "key", Buffer.alloc(0), keyLen),
    serverIV: hkdfExpandLabel(alg, serverSecret, "iv", Buffer.alloc(0), ivLen),
  };
}

function emptyHash(alg: HashAlgorithm): Buffer {
  return _createHash(alg).digest();
}

/**
 * Compute the Finished verify_data for the TLS 1.3 handshake.
 *
 * @param {HashAlgorithm} alg - Hash algorithm.
 * @param {Buffer} baseSecret - Handshake traffic secret.
 * @param {Buffer} transcriptHash - Current transcript hash.
 * @returns {Buffer} HMAC verify data bytes.
 */
export function computeFinishedVerifyData(alg: HashAlgorithm, baseSecret: Buffer, transcriptHash: Buffer): Buffer {
  const finishedKey = hkdfExpandLabel(alg, baseSecret, "finished", Buffer.alloc(0), hashLength(alg));
  return Buffer.from(createHmac(alg, finishedKey).update(transcriptHash).digest());
}
