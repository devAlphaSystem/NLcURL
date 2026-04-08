import { randomBytes, createHmac, createCipheriv, generateKeyPairSync, diffieHellman, createPrivateKey, createPublicKey, type CipherGCMTypes } from "node:crypto";

/** Parsed individual Encrypted Client Hello configuration entry. */
export interface ECHConfig {
  /** ECH config version identifier. */
  version: number;
  /** Length of the configuration contents. */
  length: number;
  /** Raw configuration content bytes. */
  contents: Buffer;
  /** Public name (outer SNI) extracted from the config. */
  publicName: string;
}

/** Complete parsed ECH configuration list with outer SNI. */
export interface ECHParameters {
  /** Raw serialized ECHConfigList buffer. */
  echConfigList: Buffer;
  /** Outer SNI derived from the first config's public name. */
  outerSNI: string;
  /** Individual ECH configuration entries. */
  configs: ECHConfig[];
}

/** User-facing options for Encrypted Client Hello. */
export interface ECHOptions {
  /** Enable ECH support. */
  enabled?: boolean;
  /** Base64 or binary ECHConfigList. */
  echConfigList?: string | Buffer;
  /** Send a GREASE ECH extension when no real config is available. */
  grease?: boolean;
  /** Maximum number of ECH retry attempts. */
  maxRetries?: number;
}

/**
 * Parse a serialized ECHConfigList into structured parameters.
 *
 * @param {Buffer} data - Raw ECHConfigList buffer.
 * @returns {ECHParameters|null} Parsed parameters, or `null` if the data is invalid.
 */
export function parseECHConfigList(data: Buffer): ECHParameters | null {
  if (data.length < 4) return null;

  const totalLength = data.readUInt16BE(0);
  if (totalLength + 2 > data.length) return null;

  const configs: ECHConfig[] = [];
  let offset = 2;

  while (offset + 4 <= 2 + totalLength) {
    const version = data.readUInt16BE(offset);
    offset += 2;
    const configLength = data.readUInt16BE(offset);
    offset += 2;

    if (offset + configLength > 2 + totalLength) break;

    const contents = data.subarray(offset, offset + configLength);

    const publicName = extractPublicName(contents);

    configs.push({
      version,
      length: configLength,
      contents,
      publicName,
    });

    offset += configLength;
  }

  if (configs.length === 0) return null;

  const outerSNI = configs[0]!.publicName;

  return {
    echConfigList: data,
    outerSNI,
    configs,
  };
}

function extractPublicName(contents: Buffer): string {
  if (contents.length < 7) return "";

  let offset = 0;

  offset += 1;
  offset += 2;
  if (offset + 2 > contents.length) return "";
  const pkLen = contents.readUInt16BE(offset);
  offset += 2 + pkLen;

  if (offset + 2 > contents.length) return "";
  const csLen = contents.readUInt16BE(offset);
  offset += 2 + csLen;

  if (offset >= contents.length) return "";
  offset += 1;

  if (offset >= contents.length) return "";
  const nameLen = contents[offset]!;
  offset += 1;

  if (offset + nameLen > contents.length) return "";
  return contents.subarray(offset, offset + nameLen).toString("ascii");
}

/**
 * Generate a GREASE Encrypted Client Hello extension payload.
 *
 * @returns {Buffer} Random GREASE ECH extension data.
 */
export function generateGreaseECH(): Buffer {
  const payloadLen = 128 + Math.floor(Math.random() * 64);
  const buf = Buffer.alloc(1 + 4 + 1 + 2 + 32 + 2 + payloadLen);
  let offset = 0;

  buf[offset++] = 0x00;

  buf.writeUInt16BE(0x0001, offset);
  offset += 2;
  buf.writeUInt16BE(0x0001, offset);
  offset += 2;

  buf[offset++] = randomBytes(1)[0]!;

  const enc = randomBytes(32);
  buf.writeUInt16BE(32, offset);
  offset += 2;
  enc.copy(buf, offset);
  offset += 32;

  const payload = randomBytes(payloadLen);
  buf.writeUInt16BE(payloadLen, offset);
  offset += 2;
  payload.copy(buf, offset);

  return buf;
}

/** Parsed HPKE key configuration from an ECHConfig entry. */
export interface HpkeKeyConfig {
  /** Configuration identifier byte. */
  configId: number;
  /** Key Encapsulation Mechanism identifier. */
  kemId: number;
  /** Receiver's public key bytes. */
  publicKey: Buffer;
  /** Supported KDF and AEAD cipher suite pairs. */
  cipherSuites: Array<{ kdfId: number; aeadId: number }>;
}

/**
 * Parse the HPKE key configuration from ECHConfig contents.
 *
 * @param {Buffer} contents - Raw contents buffer of an ECHConfig entry.
 * @returns {HpkeKeyConfig|null} Parsed HPKE key config, or `null` if malformed.
 */
export function parseHpkeKeyConfig(contents: Buffer): HpkeKeyConfig | null {
  if (contents.length < 7) return null;

  let offset = 0;
  const configId = contents[offset]!;
  offset += 1;

  const kemId = contents.readUInt16BE(offset);
  offset += 2;

  if (offset + 2 > contents.length) return null;
  const pkLen = contents.readUInt16BE(offset);
  offset += 2;

  if (offset + pkLen > contents.length) return null;
  const publicKey = Buffer.from(contents.subarray(offset, offset + pkLen));
  offset += pkLen;

  if (offset + 2 > contents.length) return null;
  const csLen = contents.readUInt16BE(offset);
  offset += 2;

  const cipherSuites: Array<{ kdfId: number; aeadId: number }> = [];
  const csEnd = offset + csLen;
  while (offset + 4 <= csEnd) {
    const kdfId = contents.readUInt16BE(offset);
    offset += 2;
    const aeadId = contents.readUInt16BE(offset);
    offset += 2;
    cipherSuites.push({ kdfId, aeadId });
  }

  return { configId, kemId, publicKey, cipherSuites };
}

/**
 * Extract the maximum name length field from ECHConfig contents.
 *
 * @param {Buffer} contents - Raw ECHConfig contents.
 * @returns {number} Maximum name length, or `0` if unparseable.
 */
export function getMaxNameLength(contents: Buffer): number {
  if (contents.length < 7) return 0;

  let offset = 0;
  offset += 1;
  offset += 2;

  if (offset + 2 > contents.length) return 0;
  const pkLen = contents.readUInt16BE(offset);
  offset += 2 + pkLen;

  if (offset + 2 > contents.length) return 0;
  const csLen = contents.readUInt16BE(offset);
  offset += 2 + csLen;

  if (offset >= contents.length) return 0;
  return contents[offset]!;
}

function hpkeHkdfExtract(salt: Buffer, ikm: Buffer): Buffer {
  const s = salt.length === 0 ? Buffer.alloc(32) : salt;
  return Buffer.from(createHmac("sha256", s).update(ikm).digest());
}

function hpkeHkdfExpand(prk: Buffer, info: Buffer, length: number): Buffer {
  const N = Math.ceil(length / 32);
  const okm = Buffer.alloc(N * 32);
  let T = Buffer.alloc(0);
  for (let i = 1; i <= N; i++) {
    const hmac = createHmac("sha256", prk);
    hmac.update(T);
    hmac.update(info);
    hmac.update(Buffer.from([i]));
    T = Buffer.from(hmac.digest());
    T.copy(okm, (i - 1) * 32);
  }
  return okm.subarray(0, length);
}

function labeledExtract(suiteId: Buffer, salt: Buffer, label: string, ikm: Buffer): Buffer {
  const hpkeV1 = Buffer.from("HPKE-v1", "ascii");
  const labelBuf = Buffer.from(label, "ascii");
  const labeledIkm = Buffer.concat([hpkeV1, suiteId, labelBuf, ikm]);
  return hpkeHkdfExtract(salt, labeledIkm);
}

function labeledExpand(suiteId: Buffer, prk: Buffer, label: string, info: Buffer, length: number): Buffer {
  const hpkeV1 = Buffer.from("HPKE-v1", "ascii");
  const labelBuf = Buffer.from(label, "ascii");
  const lenBuf = Buffer.alloc(2);
  lenBuf.writeUInt16BE(length);
  const labeledInfo = Buffer.concat([lenBuf, hpkeV1, suiteId, labelBuf, info]);
  return hpkeHkdfExpand(prk, labeledInfo, length);
}

function buildX25519PKCS8(raw: Buffer): Buffer {
  return Buffer.concat([Buffer.from([0x30, 0x2e, 0x02, 0x01, 0x00, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x6e, 0x04, 0x22, 0x04, 0x20]), raw]);
}

function buildX25519SPKI(raw: Buffer): Buffer {
  return Buffer.concat([Buffer.from([0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x6e, 0x03, 0x21, 0x00]), raw]);
}

function dhkemX25519Encap(pkR: Buffer): { sharedSecret: Buffer; enc: Buffer } {
  const kp = generateKeyPairSync("x25519");
  const pkEDer = Buffer.from(kp.publicKey.export({ type: "spki", format: "der" }));
  const skEDer = Buffer.from(kp.privateKey.export({ type: "pkcs8", format: "der" }));
  const pkE = Buffer.from(pkEDer.subarray(pkEDer.length - 32));
  const skE = Buffer.from(skEDer.subarray(skEDer.length - 32));

  const privKey = createPrivateKey({ key: buildX25519PKCS8(skE), format: "der", type: "pkcs8" });
  const pubKey = createPublicKey({ key: buildX25519SPKI(pkR), format: "der", type: "spki" });
  const dh = Buffer.from(diffieHellman({ privateKey: privKey, publicKey: pubKey }));

  const enc = Buffer.from(pkE);
  const kemContext = Buffer.concat([enc, pkR]);

  const kemSuiteId = Buffer.from([0x4b, 0x45, 0x4d, 0x00, 0x20]);

  const prk = labeledExtract(kemSuiteId, Buffer.alloc(0), "shared_secret", dh);
  const sharedSecret = labeledExpand(kemSuiteId, prk, "shared_secret", kemContext, 32);

  return { sharedSecret, enc };
}

function aeadParams(aeadId: number): { Nk: number; Nn: number } {
  switch (aeadId) {
    case 0x0001:
      return { Nk: 16, Nn: 12 };
    case 0x0002:
      return { Nk: 32, Nn: 12 };
    case 0x0003:
      return { Nk: 32, Nn: 12 };
    default:
      throw new Error(`Unsupported HPKE AEAD: 0x${aeadId.toString(16)}`);
  }
}

function aeadAlgorithm(aeadId: number): string {
  switch (aeadId) {
    case 0x0001:
      return "aes-128-gcm";
    case 0x0002:
      return "aes-256-gcm";
    case 0x0003:
      return "chacha20-poly1305";
    default:
      throw new Error(`Unsupported HPKE AEAD: 0x${aeadId.toString(16)}`);
  }
}

function hpkeKeyScheduleS(kemId: number, kdfId: number, aeadId: number, sharedSecret: Buffer, info: Buffer): { key: Buffer; baseNonce: Buffer } {
  const suiteId = Buffer.alloc(10);
  suiteId.write("HPKE", 0, "ascii");
  suiteId.writeUInt16BE(kemId, 4);
  suiteId.writeUInt16BE(kdfId, 6);
  suiteId.writeUInt16BE(aeadId, 8);

  const { Nk, Nn } = aeadParams(aeadId);

  const pskIdHash = labeledExtract(suiteId, Buffer.alloc(0), "psk_id_hash", Buffer.alloc(0));
  const infoHash = labeledExtract(suiteId, Buffer.alloc(0), "info_hash", info);

  const ksContext = Buffer.concat([Buffer.from([0x00]), pskIdHash, infoHash]);

  const secret = labeledExtract(suiteId, sharedSecret, "secret", Buffer.alloc(0));

  const key = labeledExpand(suiteId, secret, "key", ksContext, Nk);
  const baseNonce = labeledExpand(suiteId, secret, "base_nonce", ksContext, Nn);

  return { key, baseNonce };
}

function hpkeSeal(key: Buffer, baseNonce: Buffer, aad: Buffer, plaintext: Buffer, aeadId: number): Buffer {
  const alg = aeadAlgorithm(aeadId);
  const cipher = createCipheriv(alg as CipherGCMTypes, key, baseNonce, { authTagLength: 16 });
  cipher.setAAD(aad);
  const encrypted = cipher.update(plaintext);
  const final = cipher.final();
  const tag = cipher.getAuthTag();
  return Buffer.concat([encrypted, final, tag]);
}

/**
 * Build the outer ECH extension data for a ClientHello.
 *
 * @param {number} kdfId - KDF identifier.
 * @param {number} aeadId - AEAD identifier.
 * @param {number} configId - ECH config ID.
 * @param {Buffer} enc - HPKE encapsulated key.
 * @param {Buffer} payload - Encrypted inner ClientHello payload.
 * @returns {Buffer} Serialized ECH outer extension bytes.
 */
export function buildECHOuterExtData(kdfId: number, aeadId: number, configId: number, enc: Buffer, payload: Buffer): Buffer {
  const len = 1 + 2 + 2 + 1 + 2 + enc.length + 2 + payload.length;
  const buf = Buffer.alloc(len);
  let off = 0;
  buf[off++] = 0x00;
  buf.writeUInt16BE(kdfId, off);
  off += 2;
  buf.writeUInt16BE(aeadId, off);
  off += 2;
  buf[off++] = configId;
  buf.writeUInt16BE(enc.length, off);
  off += 2;
  enc.copy(buf, off);
  off += enc.length;
  buf.writeUInt16BE(payload.length, off);
  off += 2;
  payload.copy(buf, off);
  return buf;
}

/** Parameters required to encrypt an inner ClientHello with ECH. */
export interface ECHEncryptionParams {
  /** Selected ECH configuration entry. */
  config: ECHConfig;
  /** Raw bytes of the selected configuration (including version and length). */
  configRaw: Buffer;
}

/**
 * Extract the first raw ECHConfig entry from a serialized ECHConfigList.
 *
 * @param {Buffer} echConfigList - Full serialized ECHConfigList buffer.
 * @returns {Buffer | null} Raw config bytes, or `null` if the list is too short.
 */
export function extractFirstECHConfigRaw(echConfigList: Buffer): Buffer | null {
  if (echConfigList.length < 6) return null;
  const totalLength = echConfigList.readUInt16BE(0);
  if (totalLength + 2 > echConfigList.length) return null;

  const configLength = echConfigList.readUInt16BE(4);
  if (6 + configLength > echConfigList.length) return null;

  return Buffer.from(echConfigList.subarray(2, 6 + configLength));
}

/**
 * Encrypt an inner ClientHello body using HPKE for Encrypted Client Hello.
 *
 * @param {Buffer} innerCHBody - Serialized inner ClientHello body.
 * @param {Buffer} outerCHAAD - Additional authenticated data from the outer ClientHello.
 * @param {ECHConfig} config - Parsed ECH configuration entry.
 * @param {Buffer} configRaw - Raw bytes of the ECH configuration.
 * @returns {{ extensionData: Buffer; enc: Buffer; kdfId: number; aeadId: number; configId: number }} Extension data, encapsulated key, and algorithm identifiers.
 */
export function echEncryptInner(innerCHBody: Buffer, outerCHAAD: Buffer, config: ECHConfig, configRaw: Buffer): { extensionData: Buffer; enc: Buffer; kdfId: number; aeadId: number; configId: number } {
  const hpkeConfig = parseHpkeKeyConfig(config.contents);
  if (!hpkeConfig) throw new Error("Invalid ECHConfig: cannot parse HPKE key config");

  if (hpkeConfig.kemId !== 0x0020) {
    throw new Error(`Unsupported KEM: 0x${hpkeConfig.kemId.toString(16)} (only DHKEM(X25519, HKDF-SHA256) = 0x0020)`);
  }

  const suite = hpkeConfig.cipherSuites.find((cs) => cs.kdfId === 0x0001 && (cs.aeadId === 0x0001 || cs.aeadId === 0x0003));
  if (!suite) throw new Error("No supported HPKE cipher suite in ECHConfig");

  const hpkeInfo = Buffer.concat([Buffer.from("tls ech\x00", "ascii"), configRaw]);

  const { sharedSecret, enc } = dhkemX25519Encap(hpkeConfig.publicKey);
  const { key, baseNonce } = hpkeKeyScheduleS(hpkeConfig.kemId, suite.kdfId, suite.aeadId, sharedSecret, hpkeInfo);

  const payload = hpkeSeal(key, baseNonce, outerCHAAD, innerCHBody, suite.aeadId);

  const extensionData = buildECHOuterExtData(suite.kdfId, suite.aeadId, hpkeConfig.configId, enc, payload);

  return { extensionData, enc, kdfId: suite.kdfId, aeadId: suite.aeadId, configId: hpkeConfig.configId };
}

/**
 * Parse ECH retry configuration from a server's EncryptedExtensions.
 *
 * @param {Buffer} data - Serialized ECHConfigList from the retry_configs extension.
 * @returns {ECHParameters | null} Parsed retry parameters, or `null` if invalid.
 */
export function parseECHRetryConfigs(data: Buffer): ECHParameters | null {
  return parseECHConfigList(data);
}

/**
 * Determine whether an ECH retry should be attempted.
 *
 * @param {number} retryCount - Number of retries already attempted.
 * @param {number} maxRetries - Maximum allowed retries.
 * @param {ECHParameters | null} retryConfigs - Retry ECH configs from the server.
 * @returns {boolean} `true` if another retry is warranted.
 */
export function shouldRetryECH(retryCount: number, maxRetries: number, retryConfigs: ECHParameters | null): boolean {
  if (retryCount >= maxRetries) return false;
  if (!retryConfigs || retryConfigs.configs.length === 0) return false;
  return true;
}
