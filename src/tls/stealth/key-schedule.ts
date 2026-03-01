/**
 * TLS 1.3 key schedule.
 *
 * Implements the HKDF-based key derivation defined in RFC 8446 section 7.
 * Uses only `node:crypto` -- zero external dependencies.
 */

import { createHmac, hkdfSync } from 'node:crypto';

export type HashAlgorithm = 'sha256' | 'sha384';

/** Hash output length in bytes. */
export function hashLength(alg: HashAlgorithm): number {
  return alg === 'sha256' ? 32 : 48;
}

/**
 * HKDF-Extract (RFC 5869 section 2.2).
 *
 * Returns a pseudo-random key of `hashLength(alg)` bytes.
 */
export function hkdfExtract(
  alg: HashAlgorithm,
  salt: Buffer,
  ikm: Buffer,
): Buffer {
  return Buffer.from(createHmac(alg, salt).update(ikm).digest());
}

/**
 * HKDF-Expand-Label (RFC 8446 section 7.1).
 *
 *   HKDF-Expand-Label(Secret, Label, Context, Length) =
 *     HKDF-Expand(Secret, HkdfLabel, Length)
 *
 *   struct {
 *     uint16 length = Length;
 *     opaque label<7..255> = "tls13 " + Label;
 *     opaque context<0..255> = Context;
 *   } HkdfLabel;
 */
export function hkdfExpandLabel(
  alg: HashAlgorithm,
  secret: Buffer,
  label: string,
  context: Buffer,
  length: number,
): Buffer {
  const fullLabel = Buffer.from('tls13 ' + label, 'ascii');
  const hkdfLabel = Buffer.alloc(2 + 1 + fullLabel.length + 1 + context.length);
  let offset = 0;
  hkdfLabel.writeUInt16BE(length, offset);
  offset += 2;
  hkdfLabel[offset++] = fullLabel.length;
  fullLabel.copy(hkdfLabel, offset);
  offset += fullLabel.length;
  hkdfLabel[offset++] = context.length;
  context.copy(hkdfLabel, offset);

  return Buffer.from(
    hkdfSync(alg, secret, hkdfLabel, Buffer.alloc(0), length),
  );
}

/**
 * Derive-Secret (RFC 8446 section 7.1).
 *
 *   Derive-Secret(Secret, Label, Messages) =
 *     HKDF-Expand-Label(Secret, Label, Transcript-Hash(Messages), Hash.length)
 */
export function deriveSecret(
  alg: HashAlgorithm,
  secret: Buffer,
  label: string,
  transcriptHash: Buffer,
): Buffer {
  return hkdfExpandLabel(alg, secret, label, transcriptHash, hashLength(alg));
}

/**
 * Compute transcript hash incrementally.
 */
export { createHash } from 'node:crypto';

/**
 * Zero-length secret for the initial extract stage.
 */
export function zeroKey(alg: HashAlgorithm): Buffer {
  return Buffer.alloc(hashLength(alg));
}

// ---- Full key schedule ----

export interface HandshakeKeys {
  clientHandshakeKey: Buffer;
  clientHandshakeIV: Buffer;
  serverHandshakeKey: Buffer;
  serverHandshakeIV: Buffer;
  handshakeSecret: Buffer;
  /** Master secret (used to derive application keys after Finished). */
  masterSecret: Buffer;
}

export interface ApplicationKeys {
  clientKey: Buffer;
  clientIV: Buffer;
  serverKey: Buffer;
  serverIV: Buffer;
}

/**
 * Key and IV length for a cipher suite.
 */
export function keyIVLengths(cipherName: string): { keyLen: number; ivLen: number } {
  if (cipherName.includes('AES_128')) {
    return { keyLen: 16, ivLen: 12 };
  }
  if (cipherName.includes('AES_256') || cipherName.includes('CHACHA20')) {
    return { keyLen: 32, ivLen: 12 };
  }
  return { keyLen: 16, ivLen: 12 };
}

/**
 * Derive handshake traffic keys from the shared secret and transcript hash.
 *
 * This implements the Early Secret -> Handshake Secret portion of the
 * RFC 8446 key schedule.
 */
export function deriveHandshakeKeys(
  alg: HashAlgorithm,
  sharedSecret: Buffer,
  helloHash: Buffer,
  keyLen: number,
  ivLen: number,
): HandshakeKeys {
  // 1. Early secret = HKDF-Extract(salt=0, IKM=0)
  const earlySecret = hkdfExtract(alg, Buffer.alloc(hashLength(alg)), zeroKey(alg));

  // 2. Derive salt for handshake secret
  const derivedSalt = deriveSecret(alg, earlySecret, 'derived', emptyHash(alg));

  // 3. Handshake secret = HKDF-Extract(salt=derived, IKM=shared_secret)
  const handshakeSecret = hkdfExtract(alg, derivedSalt, sharedSecret);

  // 4. Client/server handshake traffic secrets
  const clientSecret = deriveSecret(alg, handshakeSecret, 'c hs traffic', helloHash);
  const serverSecret = deriveSecret(alg, handshakeSecret, 's hs traffic', helloHash);

  // 5. Traffic keys
  const clientHandshakeKey = hkdfExpandLabel(alg, clientSecret, 'key', Buffer.alloc(0), keyLen);
  const clientHandshakeIV = hkdfExpandLabel(alg, clientSecret, 'iv', Buffer.alloc(0), ivLen);
  const serverHandshakeKey = hkdfExpandLabel(alg, serverSecret, 'key', Buffer.alloc(0), keyLen);
  const serverHandshakeIV = hkdfExpandLabel(alg, serverSecret, 'iv', Buffer.alloc(0), ivLen);

  // 6. Master secret derivation
  const derivedMasterSalt = deriveSecret(alg, handshakeSecret, 'derived', emptyHash(alg));
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
 * Derive application traffic keys from the master secret and the
 * full handshake transcript hash.
 */
export function deriveApplicationKeys(
  alg: HashAlgorithm,
  masterSecret: Buffer,
  handshakeHash: Buffer,
  keyLen: number,
  ivLen: number,
): ApplicationKeys {
  const clientSecret = deriveSecret(alg, masterSecret, 'c ap traffic', handshakeHash);
  const serverSecret = deriveSecret(alg, masterSecret, 's ap traffic', handshakeHash);

  return {
    clientKey: hkdfExpandLabel(alg, clientSecret, 'key', Buffer.alloc(0), keyLen),
    clientIV: hkdfExpandLabel(alg, clientSecret, 'iv', Buffer.alloc(0), ivLen),
    serverKey: hkdfExpandLabel(alg, serverSecret, 'key', Buffer.alloc(0), keyLen),
    serverIV: hkdfExpandLabel(alg, serverSecret, 'iv', Buffer.alloc(0), ivLen),
  };
}

/**
 * Hash of empty string -- used for the Derive-Secret("derived", "")
 * step in the key schedule.
 */
function emptyHash(alg: HashAlgorithm): Buffer {
  const { createHash } = require('node:crypto');
  return createHash(alg).digest();
}

/**
 * Build the Finished verify_data.
 *
 *   finished_key = HKDF-Expand-Label(BaseKey, "finished", "", Hash.length)
 *   verify_data  = HMAC(finished_key, Transcript-Hash(Handshake Context))
 */
export function computeFinishedVerifyData(
  alg: HashAlgorithm,
  baseSecret: Buffer,
  transcriptHash: Buffer,
): Buffer {
  const finishedKey = hkdfExpandLabel(
    alg,
    baseSecret,
    'finished',
    Buffer.alloc(0),
    hashLength(alg),
  );
  return Buffer.from(createHmac(alg, finishedKey).update(transcriptHash).digest());
}
