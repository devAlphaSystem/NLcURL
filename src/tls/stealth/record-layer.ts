import { createCipheriv, createDecipheriv, type CipherGCMTypes } from "node:crypto";
import { BufferWriter } from "../../utils/buffer-writer.js";
import { RecordType, ProtocolVersion } from "../constants.js";
import { TLSError } from "../../core/errors.js";

/** Parsed TLS record with type, version, and payload fragment. */
export interface TLSRecord {
  /** Record content type. */
  type: number;
  /** Protocol version from the record header. */
  version: number;
  /** Record payload bytes. */
  fragment: Buffer;
}

/**
 * Read a single TLS record from a buffer at the given offset.
 *
 * @param {Buffer} data - Buffer containing one or more TLS records.
 * @param {number} offset - Byte offset to start reading from.
 * @returns {{ record: TLSRecord; bytesRead: number } | null} Parsed record and bytes consumed, or `null` if incomplete.
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
 * Write a TLS record with the given type, version, and payload.
 *
 * @param {number} type - Record content type.
 * @param {number} version - Protocol version.
 * @param {Buffer} payload - Record payload.
 * @returns {Buffer} Serialized TLS record buffer.
 */
export function writeRecord(type: number, version: number, payload: Buffer): Buffer {
  const w = new BufferWriter(5 + payload.length);
  w.writeUInt8(type);
  w.writeUInt16(version);
  w.writeUInt16(payload.length);
  w.writeBytes(payload);
  return w.toBuffer();
}

/** AEAD algorithm identifiers for TLS record encryption. */
export type AEADAlgorithm = "aes-128-gcm" | "aes-256-gcm" | "chacha20-poly1305";

/**
 * Determine the AEAD algorithm from a cipher suite name.
 *
 * @param {string} cipherName - Cipher suite or algorithm name.
 * @returns {AEADAlgorithm} Corresponding AEAD algorithm identifier.
 */
export function aeadFromCipher(cipherName: string): AEADAlgorithm {
  if (cipherName.includes("AES_128_GCM") || cipherName.includes("aes-128-gcm")) {
    return "aes-128-gcm";
  }
  if (cipherName.includes("AES_256_GCM") || cipherName.includes("aes-256-gcm")) {
    return "aes-256-gcm";
  }
  if (cipherName.includes("CHACHA20") || cipherName.includes("chacha20")) {
    return "chacha20-poly1305";
  }
  throw new TLSError(`Unsupported cipher: ${cipherName}`);
}

const TAG_SIZE = 16;

/**
 * Build a per-record nonce by XORing the IV with a sequence number.
 *
 * @param {Buffer} iv - Base initialization vector.
 * @param {bigint} sequenceNumber - Record sequence number.
 * @returns {Buffer} Nonce buffer for AEAD encryption.
 */
export function buildNonce(iv: Buffer, sequenceNumber: bigint): Buffer {
  const nonce = Buffer.from(iv);
  const seqBuf = Buffer.alloc(8);
  seqBuf.writeBigUInt64BE(sequenceNumber);
  for (let i = 0; i < 8; i++) {
    nonce[nonce.length - 8 + i]! ^= seqBuf[i]!;
  }
  return nonce;
}

/**
 * Encrypt a TLS record payload using AEAD.
 *
 * @param {AEADAlgorithm} algorithm - AEAD algorithm.
 * @param {Buffer} key - Encryption key.
 * @param {Buffer} nonce - Per-record nonce.
 * @param {Buffer} plaintext - Plaintext payload.
 * @param {Buffer} additionalData - Associated data for authentication.
 * @returns {Buffer} Ciphertext with appended authentication tag.
 */
export function encryptRecord(algorithm: AEADAlgorithm, key: Buffer, nonce: Buffer, plaintext: Buffer, additionalData: Buffer): Buffer {
  const cipher = createCipheriv(algorithm as CipherGCMTypes, key, nonce, { authTagLength: TAG_SIZE });
  cipher.setAAD(additionalData);
  const encrypted = cipher.update(plaintext);
  const final = cipher.final();
  const tag = cipher.getAuthTag();
  return Buffer.concat([encrypted, final, tag]);
}

/**
 * Decrypt a TLS record payload using AEAD.
 *
 * @param {AEADAlgorithm} algorithm - AEAD algorithm.
 * @param {Buffer} key - Decryption key.
 * @param {Buffer} nonce - Per-record nonce.
 * @param {Buffer} ciphertext - Ciphertext with authentication tag.
 * @param {Buffer} additionalData - Associated data for verification.
 * @returns {Buffer} Decrypted plaintext.
 */
export function decryptRecord(algorithm: AEADAlgorithm, key: Buffer, nonce: Buffer, ciphertext: Buffer, additionalData: Buffer): Buffer {
  if (ciphertext.length < TAG_SIZE) {
    throw new TLSError("Record too short for AEAD tag");
  }
  const encryptedData = ciphertext.subarray(0, ciphertext.length - TAG_SIZE);
  const tag = ciphertext.subarray(ciphertext.length - TAG_SIZE);

  const decipher = createDecipheriv(algorithm as CipherGCMTypes, key, nonce, { authTagLength: TAG_SIZE });
  decipher.setAAD(additionalData);
  decipher.setAuthTag(tag);

  try {
    const decrypted = decipher.update(encryptedData);
    const final = decipher.final();
    return Buffer.concat([decrypted, final]);
  } catch {
    throw new TLSError("AEAD decryption failed");
  }
}

/**
 * Build the additional authenticated data (AAD) for a TLS 1.3 record.
 *
 * @param {number} ciphertextLength - Length of the ciphertext including the tag.
 * @returns {Buffer} 5-byte AAD buffer.
 */
export function buildAdditionalData(ciphertextLength: number): Buffer {
  const w = new BufferWriter(5);
  w.writeUInt8(RecordType.APPLICATION_DATA);
  w.writeUInt16(ProtocolVersion.TLS_1_2);
  w.writeUInt16(ciphertextLength);
  return w.toBuffer();
}

/**
 * Encrypt and wrap a plaintext payload into a TLS 1.3 application data record.
 *
 * @param {AEADAlgorithm} algorithm - AEAD algorithm.
 * @param {Buffer} key - Client write key.
 * @param {Buffer} iv - Client write IV.
 * @param {bigint} sequenceNumber - Current sequence number.
 * @param {number} contentType - Inner record content type.
 * @param {Buffer} plaintext - Plaintext payload.
 * @returns {Buffer} Serialized encrypted TLS record.
 */
export function wrapEncryptedRecord(algorithm: AEADAlgorithm, key: Buffer, iv: Buffer, sequenceNumber: bigint, contentType: number, plaintext: Buffer): Buffer {
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
 * Decrypt and unwrap a TLS 1.3 encrypted record.
 *
 * @param {AEADAlgorithm} algorithm - AEAD algorithm.
 * @param {Buffer} key - Server write key.
 * @param {Buffer} iv - Server write IV.
 * @param {bigint} sequenceNumber - Current sequence number.
 * @param {TLSRecord} record - Encrypted TLS record.
 * @returns {{ contentType: number; plaintext: Buffer }} Decrypted content type and plaintext.
 */
export function unwrapEncryptedRecord(algorithm: AEADAlgorithm, key: Buffer, iv: Buffer, sequenceNumber: bigint, record: TLSRecord): { contentType: number; plaintext: Buffer } {
  const nonce = buildNonce(iv, sequenceNumber);
  const aad = buildAdditionalData(record.fragment.length);
  const inner = decryptRecord(algorithm, key, nonce, record.fragment, aad);

  let i = inner.length - 1;
  while (i >= 0 && inner[i] === 0) i--;
  if (i < 0) {
    throw new TLSError("Empty decrypted record");
  }

  const contentType = inner[i]!;
  const plaintext = inner.subarray(0, i);

  return { contentType, plaintext };
}
