import { createHmac, createHash as _createHash } from "node:crypto";

/**
 * Hash algorithm identifiers supported by the TLS 1.3 key schedule.
 *
 * @typedef {'sha256'|'sha384'} HashAlgorithm
 */
export type HashAlgorithm = "sha256" | "sha384";

/**
 * Returns the output length in bytes for the given hash algorithm.
 *
 * @param {HashAlgorithm} alg - Hash algorithm identifier.
 * @returns {number} Output length: `32` for `sha256`, `48` for `sha384`.
 */
export function hashLength(alg: HashAlgorithm): number {
  return alg === "sha256" ? 32 : 48;
}

/**
 * Performs the HKDF-Extract step (RFC 5869 §2.2): computes `HMAC-Hash(salt, IKM)`.
 *
 * @param {HashAlgorithm} alg  - Hash algorithm for the HMAC computation.
 * @param {Buffer}        salt - Salt value (used as HMAC key).
 * @param {Buffer}        ikm  - Input keying material.
 * @returns {Buffer} Pseudorandom key (PRK) of length `hashLength(alg)`.
 */
export function hkdfExtract(alg: HashAlgorithm, salt: Buffer, ikm: Buffer): Buffer {
  return Buffer.from(createHmac(alg, salt).update(ikm).digest());
}

/**
 * Performs the TLS 1.3 HKDF-Expand-Label operation (RFC 8446 §7.1),
 * deriving a key of `length` bytes from `secret` using the given label
 * and context hash.
 *
 * @param {HashAlgorithm} alg     - Hash algorithm for HKDF.
 * @param {Buffer}        secret  - Input secret (PRK from HKDF-Extract).
 * @param {string}        label   - TLS 1.3 label string (without the `"tls13 "` prefix).
 * @param {Buffer}        context - Transcript hash, or empty buffer for simple derivations.
 * @param {number}        length  - Desired output length in bytes.
 * @returns {Buffer} Derived key material of the specified length.
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
 * Derives a secret with a transcript hash context using HKDF-Expand-Label
 * (RFC 8446 §7.1). This is the canonical `Derive-Secret` function of the
 * TLS 1.3 key schedule.
 *
 * @param {HashAlgorithm} alg            - Hash algorithm for HKDF.
 * @param {Buffer}        secret         - Input PRK.
 * @param {string}        label          - TLS 1.3 label string.
 * @param {Buffer}        transcriptHash - Current transcript hash value.
 * @returns {Buffer} Derived secret of length `hashLength(alg)`.
 */
export function deriveSecret(alg: HashAlgorithm, secret: Buffer, label: string, transcriptHash: Buffer): Buffer {
  return hkdfExpandLabel(alg, secret, label, transcriptHash, hashLength(alg));
}

export { _createHash as createHash };

/**
 * Returns a zero-filled `Buffer` whose length equals the output size of
 * `alg` — used as the IKM or salt argument in HKDF-Extract calls that
 * require a zero-length secret at the start of the TLS 1.3 key schedule.
 *
 * @param {HashAlgorithm} alg - Hash algorithm that determines buffer length.
 * @returns {Buffer} Zero-filled buffer of `hashLength(alg)` bytes.
 */
export function zeroKey(alg: HashAlgorithm): Buffer {
  return Buffer.alloc(hashLength(alg));
}

/**
 * Key material derived during the handshake phase of TLS 1.3 key schedule,
 * used to decrypt EncryptedExtensions, Certificate, CertificateVerify, and
 * Finished messages from the server.
 *
 * @typedef  {Object} HandshakeKeys
 * @property {Buffer}  clientHandshakeKey - Client handshake traffic key.
 * @property {Buffer}  clientHandshakeIV  - Client handshake traffic IV.
 * @property {Buffer}  serverHandshakeKey - Server handshake traffic key.
 * @property {Buffer}  serverHandshakeIV  - Server handshake traffic IV.
 * @property {Buffer}  handshakeSecret    - TLS 1.3 handshake secret (intermediate key schedule value).
 * @property {Buffer}  masterSecret       - TLS 1.3 master secret used to derive application keys.
 */
export interface HandshakeKeys {
  clientHandshakeKey: Buffer;
  clientHandshakeIV: Buffer;
  serverHandshakeKey: Buffer;
  serverHandshakeIV: Buffer;
  handshakeSecret: Buffer;
  masterSecret: Buffer;
}

/**
 * Application traffic key material derived after handshake completion,
 * used to encrypt and decrypt application data records.
 *
 * @typedef  {Object} ApplicationKeys
 * @property {Buffer}  clientKey - Client application traffic key.
 * @property {Buffer}  clientIV  - Client application traffic IV.
 * @property {Buffer}  serverKey - Server application traffic key.
 * @property {Buffer}  serverIV  - Server application traffic IV.
 */
export interface ApplicationKeys {
  clientKey: Buffer;
  clientIV: Buffer;
  serverKey: Buffer;
  serverIV: Buffer;
}

/**
 * Returns the key and IV byte lengths for the given AEAD cipher name.
 *
 * @param {string} cipherName - AEAD cipher name (e.g. `"TLS_AES_128_GCM_SHA256"`).
 * @returns {{ keyLen: number; ivLen: number }} Key length and IV length in bytes.
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
 * Derives TLS 1.3 handshake traffic keys from the ECDH shared secret and
 * the transcript hash of the ClientHello and ServerHello messages
 * (RFC 8446 §7.1).
 *
 * @param {HashAlgorithm} alg          - Hash algorithm specified by the negotiated cipher suite.
 * @param {Buffer}        sharedSecret - ECDH shared secret from key exchange.
 * @param {Buffer}        helloHash    - Transcript hash over ClientHello..ServerHello.
 * @param {number}        keyLen       - Required key byte length.
 * @param {number}        ivLen        - Required IV byte length.
 * @returns {HandshakeKeys} Derived handshake keys and intermediate secrets.
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
 * Derives TLS 1.3 application traffic keys from the master secret and the
 * full handshake transcript hash (RFC 8446 §7.1). These keys are used to
 * encrypt and decrypt all application data after the handshake completes.
 *
 * @param {HashAlgorithm} alg           - Hash algorithm specified by the negotiated cipher suite.
 * @param {Buffer}        masterSecret  - TLS 1.3 master secret from {@link deriveHandshakeKeys}.
 * @param {Buffer}        handshakeHash - Transcript hash over the complete handshake.
 * @param {number}        keyLen        - Required key byte length.
 * @param {number}        ivLen         - Required IV byte length.
 * @returns {ApplicationKeys} Derived application traffic keys.
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
 * Computes the `verify_data` for a TLS 1.3 Finished message (RFC 8446 §4.4.4)
 * as `HMAC(finished_key, transcript_hash)`, where `finished_key` is derived
 * from the base traffic secret using HKDF-Expand-Label.
 *
 * @param {HashAlgorithm} alg            - Hash algorithm for HMAC.
 * @param {Buffer}        baseSecret     - Base traffic secret (client or server handshake secret).
 * @param {Buffer}        transcriptHash - Current transcript hash at the point of Finished.
 * @returns {Buffer} The `verify_data` bytes to include in or validate against the Finished message.
 */
export function computeFinishedVerifyData(alg: HashAlgorithm, baseSecret: Buffer, transcriptHash: Buffer): Buffer {
  const finishedKey = hkdfExpandLabel(alg, baseSecret, "finished", Buffer.alloc(0), hashLength(alg));
  return Buffer.from(createHmac(alg, finishedKey).update(transcriptHash).digest());
}
