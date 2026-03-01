/**
 * TLS record layer.
 *
 * Handles framing, encryption, and decryption of TLS records.
 * Operates on raw TCP byte streams.
 */

import {
  createCipheriv,
  createDecipheriv,
  type CipherGCMTypes,
} from 'node:crypto';
import { BufferReader } from '../../utils/buffer-reader.js';
import { BufferWriter } from '../../utils/buffer-writer.js';
import { RecordType, ProtocolVersion } from '../constants.js';
import { TLSError } from '../../core/errors.js';

/** Maximum TLS record payload (2^14 = 16384). */
const MAX_RECORD_PAYLOAD = 16384;

/** Maximum ciphertext overhead (tag + content type byte). */
const MAX_CIPHERTEXT_OVERHEAD = 256;

// ---- Record types ----

export interface TLSRecord {
  type: number;
  version: number;
  fragment: Buffer;
}

// ---- Record reading ----

/**
 * Read a single TLS record from a buffer.
 *
 * Returns the record and the number of bytes consumed, or `null` if
 * the buffer does not contain a complete record.
 */
export function readRecord(data: Buffer, offset: number): { record: TLSRecord; bytesRead: number } | null {
  if (data.length - offset < 5) return null;

  const type = data[offset]!;
  const version = data.readUInt16BE(offset + 1);
  const length = data.readUInt16BE(offset + 3);

  if (data.length - offset - 5 < length) return null;

  const fragment = data.subarray(offset + 5, offset + 5 + length);

  return {
    record: { type, version, fragment },
    bytesRead: 5 + length,
  };
}

/**
 * Write a TLS record (unencrypted) to a buffer.
 */
export function writeRecord(type: number, version: number, payload: Buffer): Buffer {
  const w = new BufferWriter(5 + payload.length);
  w.writeUInt8(type);
  w.writeUInt16(version);
  w.writeUInt16(payload.length);
  w.writeBytes(payload);
  return w.toBuffer();
}

// ---- AEAD encryption/decryption ----

export type AEADAlgorithm = 'aes-128-gcm' | 'aes-256-gcm' | 'chacha20-poly1305';

/**
 * Determine AEAD algorithm from cipher suite name.
 */
export function aeadFromCipher(cipherName: string): AEADAlgorithm {
  if (cipherName.includes('AES_128_GCM') || cipherName.includes('aes-128-gcm')) {
    return 'aes-128-gcm';
  }
  if (cipherName.includes('AES_256_GCM') || cipherName.includes('aes-256-gcm')) {
    return 'aes-256-gcm';
  }
  if (cipherName.includes('CHACHA20') || cipherName.includes('chacha20')) {
    return 'chacha20-poly1305';
  }
  throw new TLSError(`Unsupported cipher: ${cipherName}`);
}

/** Tag size for all supported AEAD algorithms. */
const TAG_SIZE = 16;

/**
 * Build the per-record nonce by XORing the IV with the 64-bit
 * sequence number (zero-padded on the left).
 */
export function buildNonce(iv: Buffer, sequenceNumber: bigint): Buffer {
  const nonce = Buffer.from(iv);
  const seqBuf = Buffer.alloc(8);
  seqBuf.writeBigUInt64BE(sequenceNumber);
  // XOR the last 8 bytes of IV with the sequence number
  for (let i = 0; i < 8; i++) {
    nonce[nonce.length - 8 + i]! ^= seqBuf[i]!;
  }
  return nonce;
}

/**
 * Encrypt a TLS 1.3 record.
 *
 * The plaintext is the handshake/application data followed by the
 * content type byte.  The additional data is the record header of the
 * outer (opaque) application_data record.
 */
export function encryptRecord(
  algorithm: AEADAlgorithm,
  key: Buffer,
  nonce: Buffer,
  plaintext: Buffer,
  additionalData: Buffer,
): Buffer {
  const cipher = createCipheriv(
    algorithm as CipherGCMTypes,
    key,
    nonce,
    { authTagLength: TAG_SIZE },
  );
  cipher.setAAD(additionalData);
  const encrypted = cipher.update(plaintext);
  const final = cipher.final();
  const tag = cipher.getAuthTag();
  return Buffer.concat([encrypted, final, tag]);
}

/**
 * Decrypt a TLS 1.3 record.
 *
 * Returns the decrypted plaintext including the trailing content type
 * byte.  The caller must strip the content type.
 */
export function decryptRecord(
  algorithm: AEADAlgorithm,
  key: Buffer,
  nonce: Buffer,
  ciphertext: Buffer,
  additionalData: Buffer,
): Buffer {
  if (ciphertext.length < TAG_SIZE) {
    throw new TLSError('Record too short for AEAD tag');
  }
  const encryptedData = ciphertext.subarray(0, ciphertext.length - TAG_SIZE);
  const tag = ciphertext.subarray(ciphertext.length - TAG_SIZE);

  const decipher = createDecipheriv(
    algorithm as CipherGCMTypes,
    key,
    nonce,
    { authTagLength: TAG_SIZE },
  );
  decipher.setAAD(additionalData);
  decipher.setAuthTag(tag);

  try {
    const decrypted = decipher.update(encryptedData);
    const final = decipher.final();
    return Buffer.concat([decrypted, final]);
  } catch {
    throw new TLSError('AEAD decryption failed');
  }
}

/**
 * Build the additional data for a TLS 1.3 encrypted record.
 *
 * For TLS 1.3: the 5-byte record header of the *outer* record
 * (type=application_data, version=0x0303, length).
 */
export function buildAdditionalData(ciphertextLength: number): Buffer {
  const w = new BufferWriter(5);
  w.writeUInt8(RecordType.APPLICATION_DATA);
  w.writeUInt16(ProtocolVersion.TLS_1_2); // TLS 1.3 records use 0x0303 in the header
  w.writeUInt16(ciphertextLength);
  return w.toBuffer();
}

/**
 * Wrap plaintext into an encrypted TLS 1.3 record.
 *
 * Appends the real content type byte to the plaintext, encrypts with
 * AEAD, and wraps in a record with type=application_data.
 */
export function wrapEncryptedRecord(
  algorithm: AEADAlgorithm,
  key: Buffer,
  iv: Buffer,
  sequenceNumber: bigint,
  contentType: number,
  plaintext: Buffer,
): Buffer {
  // Build inner plaintext: data + content_type byte
  const inner = Buffer.alloc(plaintext.length + 1);
  plaintext.copy(inner);
  inner[plaintext.length] = contentType;

  const nonce = buildNonce(iv, sequenceNumber);
  const ciphertextLength = inner.length + TAG_SIZE;
  const aad = buildAdditionalData(ciphertextLength);
  const ciphertext = encryptRecord(algorithm, key, nonce, inner, aad);

  return writeRecord(RecordType.APPLICATION_DATA, ProtocolVersion.TLS_1_2, ciphertext);
}

/**
 * Unwrap an encrypted TLS 1.3 record.
 *
 * Returns the decrypted plaintext and the real content type.
 */
export function unwrapEncryptedRecord(
  algorithm: AEADAlgorithm,
  key: Buffer,
  iv: Buffer,
  sequenceNumber: bigint,
  record: TLSRecord,
): { contentType: number; plaintext: Buffer } {
  const nonce = buildNonce(iv, sequenceNumber);
  const aad = buildAdditionalData(record.fragment.length);
  const inner = decryptRecord(algorithm, key, nonce, record.fragment, aad);

  // Strip trailing zeros and find the real content type
  let i = inner.length - 1;
  while (i >= 0 && inner[i] === 0) i--;
  if (i < 0) {
    throw new TLSError('Empty decrypted record');
  }

  const contentType = inner[i]!;
  const plaintext = inner.subarray(0, i);

  return { contentType, plaintext };
}
