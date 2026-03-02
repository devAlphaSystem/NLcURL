
import {
  createCipheriv,
  createDecipheriv,
  type CipherGCMTypes,
} from 'node:crypto';
import { BufferReader } from '../../utils/buffer-reader.js';
import { BufferWriter } from '../../utils/buffer-writer.js';
import { RecordType, ProtocolVersion } from '../constants.js';
import { TLSError } from '../../core/errors.js';

const MAX_RECORD_PAYLOAD = 16384;

const MAX_CIPHERTEXT_OVERHEAD = 256;

/**
 * A single parsed TLS record as defined in RFC 8446 ¥5.1.
 *
 * @typedef  {Object} TLSRecord
 * @property {number} type     - Content type byte (see {@link RecordType}).
 * @property {number} version  - Legacy record version (e.g. `0x0303` for TLS 1.2 compatibility).
 * @property {Buffer} fragment - Raw payload bytes of the record.
 */
export interface TLSRecord {
  type: number;
  version: number;
  fragment: Buffer;
}

/**
 * Attempts to parse a single TLS record from `data` beginning at `offset`.
 * Returns `null` without consuming the buffer if fewer than 5 bytes are
 * available or the payload has not been fully received yet.
 *
 * @param {Buffer} data   - Buffer containing one or more TLS records.
 * @param {number} offset - Byte offset within `data` to begin parsing.
 * @returns {{ record: TLSRecord; bytesRead: number } | null} Parsed record and byte count, or `null` if more data is needed.
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
 * Serializes a TLS record into its 5-byte header plus payload binary form.
 *
 * @param {number} type    - TLS content type byte.
 * @param {number} version - TLS record version (e.g. `0x0303`).
 * @param {Buffer} payload - Record payload bytes.
 * @returns {Buffer} The complete serialized TLS record.
 */
export function writeRecord(type: number, version: number, payload: Buffer): Buffer {
  const w = new BufferWriter(5 + payload.length);
  w.writeUInt8(type);
  w.writeUInt16(version);
  w.writeUInt16(payload.length);
  w.writeBytes(payload);
  return w.toBuffer();
}

/**
 * AEAD algorithm identifiers supported by the record layer. Corresponds to
 * the TLS 1.3 mandatory cipher suites.
 *
 * @typedef {'aes-128-gcm'|'aes-256-gcm'|'chacha20-poly1305'} AEADAlgorithm
 */
export type AEADAlgorithm = 'aes-128-gcm' | 'aes-256-gcm' | 'chacha20-poly1305';

/**
 * Maps a cipher suite name string to the corresponding AEAD algorithm
 * identifier used by the record layer.
 *
 * @param {string} cipherName - Cipher suite name from {@link TLSConnectionInfo} (e.g. `"TLS_AES_128_GCM_SHA256"`).
 * @returns {AEADAlgorithm} The corresponding AEAD algorithm identifier.
 * @throws {TLSError} If the cipher name does not correspond to a supported AEAD algorithm.
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

const TAG_SIZE = 16;

/**
 * Constructs the per-record nonce by XOR-ing the static IV with the
 * big-endian 64-bit sequence number (RFC 8446 ¥5.3).
 *
 * @param {Buffer} iv             - Static IV of length matching the AEAD algorithm.
 * @param {bigint} sequenceNumber - Record sequence number (starts at 0, increments by 1).
 * @returns {Buffer} The per-record nonce.
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
 * Encrypts `plaintext` using the specified AEAD algorithm and returns the
 * ciphertext with an appended 16-byte authentication tag.
 *
 * @param {AEADAlgorithm} algorithm      - AEAD algorithm identifier.
 * @param {Buffer}        key            - Encryption key.
 * @param {Buffer}        nonce          - Per-record nonce.
 * @param {Buffer}        plaintext      - Data to encrypt.
 * @param {Buffer}        additionalData - Additional authenticated data (AAD).
 * @returns {Buffer} Ciphertext followed by the 16-byte authentication tag.
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
 * Decrypts and authenticates `ciphertext` using the specified AEAD algorithm.
 * The last 16 bytes of `ciphertext` are treated as the authentication tag.
 *
 * @param {AEADAlgorithm} algorithm      - AEAD algorithm identifier.
 * @param {Buffer}        key            - Decryption key.
 * @param {Buffer}        nonce          - Per-record nonce.
 * @param {Buffer}        ciphertext     - Ciphertext including the 16-byte authentication tag.
 * @param {Buffer}        additionalData - Additional authenticated data (AAD) for tag verification.
 * @returns {Buffer} Decrypted plaintext bytes.
 * @throws {TLSError} If the ciphertext is too short or authentication fails.
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
 * Builds the additional authenticated data (AAD) for a TLS 1.3 application
 * data record, encoded as a 5-byte pseudo-record header per RFC 8446 ¥5.2.
 *
 * @param {number} ciphertextLength - Total length of the ciphertext including the AEAD tag.
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
 * Encodes a TLS 1.3 inner plaintext (content bytes + content type byte) and
 * wraps it in an encrypted TLS record with the appropriate AAD, following
 * RFC 8446 ¥5.2.
 *
 * @param {AEADAlgorithm} algorithm     - AEAD algorithm identifier.
 * @param {Buffer}        key           - Application traffic key.
 * @param {Buffer}        iv            - Application traffic IV.
 * @param {bigint}        sequenceNumber - Sequence number for nonce derivation.
 * @param {number}        contentType   - True content type byte to embed in the inner plaintext.
 * @param {Buffer}        plaintext     - Application data to encrypt.
 * @returns {Buffer} The complete TLS application_data record ready to send.
 */
export function wrapEncryptedRecord(
  algorithm: AEADAlgorithm,
  key: Buffer,
  iv: Buffer,
  sequenceNumber: bigint,
  contentType: number,
  plaintext: Buffer,
): Buffer {
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
 * Decrypts a TLS 1.3 application_data record, strips the zero-padding, and
 * recovers the true content type embedded as the last non-zero byte of the
 * inner plaintext (RFC 8446 ¥5.2).
 *
 * @param {AEADAlgorithm} algorithm     - AEAD algorithm identifier.
 * @param {Buffer}        key           - Application traffic key.
 * @param {Buffer}        iv            - Application traffic IV.
 * @param {bigint}        sequenceNumber - Sequence number for nonce derivation.
 * @param {TLSRecord}     record        - Encrypted TLS record received from the remote party.
 * @returns {{ contentType: number; plaintext: Buffer }} Recovered content type and decrypted payload.
 * @throws {TLSError} If decryption or authentication fails, or the record is empty after unpadding.
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

  let i = inner.length - 1;
  while (i >= 0 && inner[i] === 0) i--;
  if (i < 0) {
    throw new TLSError('Empty decrypted record');
  }

  const contentType = inner[i]!;
  const plaintext = inner.subarray(0, i);

  return { contentType, plaintext };
}
