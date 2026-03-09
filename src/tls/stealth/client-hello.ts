import { randomBytes, createECDH, generateKeyPairSync } from "node:crypto";
import { BufferWriter } from "../../utils/buffer-writer.js";
import { RecordType, HandshakeType, ExtensionType, GREASE_VALUES, NamedGroup } from "../constants.js";
import type { BrowserProfile, TLSExtensionDef } from "../../fingerprints/types.js";
import type { ECHEncryptionParams } from "../ech.js";
import { echEncryptInner, buildECHOuterExtData, parseHpkeKeyConfig, getMaxNameLength } from "../ech.js";

function randomGrease(): number {
  return GREASE_VALUES[Math.floor(Math.random() * GREASE_VALUES.length)]!;
}

/** Key exchange entry containing the group identifier and key material. */
export interface KeyShareEntry {
  /** Named group identifier. */
  group: number;
  /** Public key bytes. */
  publicKey: Buffer;
  /** Private key bytes. */
  privateKey: Buffer;
}

/**
 * Generate a key pair for the specified TLS named group.
 *
 * @param {number} group - Named group identifier (e.g. X25519, SECP256R1).
 * @returns {KeyShareEntry} Key share entry with public and private key material.
 */
export function generateKeyShare(group: number): KeyShareEntry | null {
  switch (group) {
    case NamedGroup.X25519: {
      const kp = generateKeyPairSync("x25519");
      const pub = kp.publicKey.export({ type: "spki", format: "der" });
      const priv = kp.privateKey.export({ type: "pkcs8", format: "der" });
      const publicKey = Buffer.from(pub.subarray(pub.length - 32));
      const privateKey = Buffer.from(priv.subarray(priv.length - 32));
      return { group, publicKey, privateKey };
    }
    case NamedGroup.SECP256R1:
    case NamedGroup.SECP384R1:
    case NamedGroup.SECP521R1: {
      const curveName = group === NamedGroup.SECP256R1 ? "prime256v1" : group === NamedGroup.SECP384R1 ? "secp384r1" : "secp521r1";
      const ecdh = createECDH(curveName);
      ecdh.generateKeys();
      return {
        group,
        publicKey: Buffer.from(ecdh.getPublicKey()),
        privateKey: Buffer.from(ecdh.getPrivateKey()),
      };
    }
    default:
      return null;
  }
}

function buildKeyShareExtensionData(keyShares: KeyShareEntry[]): Buffer {
  const w = new BufferWriter(256);
  const lenReserve = w.reserve(2);
  const startPos = w.position;

  for (const ks of keyShares) {
    w.writeUInt16(ks.group);
    w.writeUInt16(ks.publicKey.length);
    w.writeBytes(ks.publicKey);
  }

  w.patchUInt16(lenReserve, w.position - startPos);
  return w.toBuffer();
}

/** Result of building a TLS ClientHello message. */
export interface ClientHelloResult {
  /** Complete TLS record containing the ClientHello. */
  record: Buffer;
  /** Generated key share entries. */
  keyShares: KeyShareEntry[];
  /** Client random bytes. */
  clientRandom: Buffer;
  /** Session ID bytes (may be empty). */
  sessionId: Buffer;
  /** Raw handshake message (without record layer). */
  handshakeMessage: Buffer;
}

/**
 * Build a TLS ClientHello record matching a browser fingerprint profile.
 *
 * @param {BrowserProfile} profile - Browser profile with TLS extension ordering and cipher suites.
 * @param {string} hostname - Server hostname for SNI.
 * @returns {ClientHelloResult} ClientHello result with record bytes and key material.
 */
export function buildClientHello(profile: BrowserProfile, hostname: string): ClientHelloResult {
  const tlsProfile = profile.tls;

  const clientRandom = randomBytes(32);
  const sessionId = tlsProfile.randomSessionId ? randomBytes(32) : Buffer.alloc(0);
  const keyShares = tlsProfile.keyShareGroups.map(generateKeyShare).filter((ks): ks is KeyShareEntry => ks !== null);

  const greaseCipher = tlsProfile.grease ? randomGrease() : 0;
  const greaseExt = tlsProfile.grease ? randomGrease() : 0;
  const greaseGroup = tlsProfile.grease ? randomGrease() : 0;
  const greaseVersion = tlsProfile.grease ? randomGrease() : 0;

  const body = new BufferWriter(4096);

  body.writeUInt16(tlsProfile.clientVersion);

  body.writeBytes(clientRandom);

  body.writeUInt8(sessionId.length);
  if (sessionId.length > 0) body.writeBytes(sessionId);

  const ciphers = tlsProfile.grease ? [greaseCipher, ...tlsProfile.cipherSuites] : [...tlsProfile.cipherSuites];
  body.writeUInt16(ciphers.length * 2);
  for (const c of ciphers) body.writeUInt16(c);

  body.writeUInt8(tlsProfile.compressionMethods.length);
  for (const m of tlsProfile.compressionMethods) body.writeUInt8(m);

  const extWriter = new BufferWriter(4096);

  if (tlsProfile.grease) {
    extWriter.writeUInt16(greaseExt);
    extWriter.writeUInt16(1);
    extWriter.writeUInt8(0);
  }

  for (const extDef of tlsProfile.extensions) {
    writeExtension(extWriter, extDef, hostname, keyShares, tlsProfile, {
      greaseGroup,
      greaseVersion,
    });
  }

  if (tlsProfile.grease) {
    const lastGrease = randomGrease();
    extWriter.writeUInt16(lastGrease);
    extWriter.writeUInt16(1);
    extWriter.writeUInt8(0);
  }

  const extBytes = extWriter.toBuffer();
  body.writeUInt16(extBytes.length);
  body.writeBytes(extBytes);

  const clientHelloBody = body.toBuffer();

  const handshake = new BufferWriter(4 + clientHelloBody.length);
  handshake.writeUInt8(HandshakeType.CLIENT_HELLO);
  handshake.writeUInt24(clientHelloBody.length);
  handshake.writeBytes(clientHelloBody);
  const handshakeMessage = handshake.toBuffer();

  const record = new BufferWriter(5 + handshakeMessage.length);
  record.writeUInt8(RecordType.HANDSHAKE);
  record.writeUInt16(tlsProfile.recordVersion);
  record.writeUInt16(handshakeMessage.length);
  record.writeBytes(handshakeMessage);

  return {
    record: record.toBuffer(),
    keyShares,
    clientRandom,
    sessionId,
    handshakeMessage,
  };
}

function writeExtension(w: BufferWriter, extDef: TLSExtensionDef, hostname: string, keyShares: KeyShareEntry[], tlsProfile: import("../../fingerprints/types.js").TLSProfile, grease: { greaseGroup: number; greaseVersion: number }): void {
  if (extDef.type === ExtensionType.KEY_SHARE) {
    const data = buildKeyShareExtensionData(keyShares);
    w.writeUInt16(ExtensionType.KEY_SHARE);
    w.writeUInt16(data.length);
    w.writeBytes(data);
    return;
  }

  if (extDef.type === ExtensionType.SUPPORTED_GROUPS && tlsProfile.grease) {
    const groups = [grease.greaseGroup, ...tlsProfile.supportedGroups];
    const inner = new BufferWriter(2 + groups.length * 2);
    inner.writeUInt16(groups.length * 2);
    for (const g of groups) inner.writeUInt16(g);
    const data = inner.toBuffer();
    w.writeUInt16(ExtensionType.SUPPORTED_GROUPS);
    w.writeUInt16(data.length);
    w.writeBytes(data);
    return;
  }

  if (extDef.type === ExtensionType.SUPPORTED_VERSIONS && tlsProfile.grease) {
    const versions = [grease.greaseVersion, ...tlsProfile.supportedVersions];
    const inner = new BufferWriter(1 + versions.length * 2);
    inner.writeUInt8(versions.length * 2);
    for (const v of versions) inner.writeUInt16(v);
    const data = inner.toBuffer();
    w.writeUInt16(ExtensionType.SUPPORTED_VERSIONS);
    w.writeUInt16(data.length);
    w.writeBytes(data);
    return;
  }

  w.writeUInt16(extDef.type);
  if (extDef.data) {
    const data = extDef.data(hostname);
    w.writeUInt16(data.length);
    if (data.length > 0) w.writeBytes(data);
  } else {
    w.writeUInt16(0);
  }
}

/** Extended ClientHello result with Encrypted Client Hello inner message. */
export interface ClientHelloECHResult extends ClientHelloResult {
  /** Raw inner ClientHello handshake message before encryption. */
  innerHandshakeMessage: Buffer;
  /** Client random used in the inner ClientHello. */
  innerRandom: Buffer;
}

/**
 * Build a TLS ClientHello with Encrypted Client Hello (ECH) wrapping.
 *
 * @param {BrowserProfile} profile - Browser fingerprint profile.
 * @param {string} hostname - True server hostname (encrypted in the inner ClientHello).
 * @param {ECHEncryptionParams} echParams - ECH encryption parameters.
 * @returns {ClientHelloECHResult} Extended result with both outer and inner handshake data.
 */
export function buildClientHelloWithECH(profile: BrowserProfile, hostname: string, echParams: ECHEncryptionParams): ClientHelloECHResult {
  const tlsProfile = profile.tls;

  const innerRandom = randomBytes(32);
  const outerRandom = randomBytes(32);
  const outerSessionId = tlsProfile.randomSessionId ? randomBytes(32) : Buffer.alloc(0);
  const keyShares = tlsProfile.keyShareGroups.map(generateKeyShare).filter((ks): ks is KeyShareEntry => ks !== null);

  const greaseCipher = tlsProfile.grease ? randomGrease() : 0;
  const greaseExt = tlsProfile.grease ? randomGrease() : 0;
  const greaseGroup = tlsProfile.grease ? randomGrease() : 0;
  const greaseVersion = tlsProfile.grease ? randomGrease() : 0;
  const lastGreaseInner = tlsProfile.grease ? randomGrease() : 0;
  const lastGreaseOuter = tlsProfile.grease ? randomGrease() : 0;

  const greaseVals = { greaseGroup, greaseVersion };

  const hpkeConfig = parseHpkeKeyConfig(echParams.config.contents);
  if (!hpkeConfig || hpkeConfig.kemId !== 0x0020) {
    throw new Error("Unsupported ECH config: requires DHKEM(X25519, HKDF-SHA256)");
  }
  const suite = hpkeConfig.cipherSuites.find((cs) => cs.kdfId === 0x0001 && (cs.aeadId === 0x0001 || cs.aeadId === 0x0003));
  if (!suite) throw new Error("No supported HPKE cipher suite in ECH config");

  const innerCHBody = buildCHBodyCore(tlsProfile, hostname, innerRandom, Buffer.alloc(0), keyShares, greaseCipher, greaseExt, lastGreaseInner, greaseVals, Buffer.from([0x01]));

  const innerHSMsg = wrapHandshakeMessage(innerCHBody);

  const maxNameLen = getMaxNameLength(echParams.config.contents);
  const hostLen = Buffer.byteLength(hostname, "ascii");
  const paddingLen = Math.max(0, maxNameLen - hostLen);
  const paddedInner = paddingLen > 0 ? Buffer.concat([innerCHBody, Buffer.alloc(paddingLen)]) : innerCHBody;

  const expectedPayloadLen = paddedInner.length + 16;

  const zeroEchExt = buildECHOuterExtData(suite.kdfId, suite.aeadId, hpkeConfig.configId, Buffer.alloc(32), Buffer.alloc(expectedPayloadLen));

  const buildOuter = (echExtData: Buffer): Buffer => buildCHBodyCore(tlsProfile, echParams.config.publicName, outerRandom, outerSessionId, keyShares, greaseCipher, greaseExt, lastGreaseOuter, greaseVals, echExtData);

  const outerBodyZero = buildOuter(zeroEchExt);
  const outerAAD = wrapHandshakeMessage(outerBodyZero);

  const echResult = echEncryptInner(paddedInner, outerAAD, echParams.config, echParams.configRaw);

  const finalOuterBody = buildOuter(echResult.extensionData);
  const finalHandshakeMessage = wrapHandshakeMessage(finalOuterBody);

  const record = new BufferWriter(5 + finalHandshakeMessage.length);
  record.writeUInt8(RecordType.HANDSHAKE);
  record.writeUInt16(tlsProfile.recordVersion);
  record.writeUInt16(finalHandshakeMessage.length);
  record.writeBytes(finalHandshakeMessage);

  return {
    record: record.toBuffer(),
    keyShares,
    clientRandom: outerRandom,
    sessionId: outerSessionId,
    handshakeMessage: finalHandshakeMessage,
    innerHandshakeMessage: innerHSMsg,
    innerRandom,
  };
}

function buildCHBodyCore(tlsProfile: import("../../fingerprints/types.js").TLSProfile, hostname: string, clientRandom: Buffer, sessionId: Buffer, keyShares: KeyShareEntry[], greaseCipher: number, greaseExt: number, lastGrease: number, grease: { greaseGroup: number; greaseVersion: number }, echExtData?: Buffer): Buffer {
  const body = new BufferWriter(4096);

  body.writeUInt16(tlsProfile.clientVersion);
  body.writeBytes(clientRandom);

  body.writeUInt8(sessionId.length);
  if (sessionId.length > 0) body.writeBytes(sessionId);

  const ciphers = tlsProfile.grease ? [greaseCipher, ...tlsProfile.cipherSuites] : [...tlsProfile.cipherSuites];
  body.writeUInt16(ciphers.length * 2);
  for (const c of ciphers) body.writeUInt16(c);

  body.writeUInt8(tlsProfile.compressionMethods.length);
  for (const m of tlsProfile.compressionMethods) body.writeUInt8(m);

  const extWriter = new BufferWriter(4096);

  if (tlsProfile.grease) {
    extWriter.writeUInt16(greaseExt);
    extWriter.writeUInt16(1);
    extWriter.writeUInt8(0);
  }

  for (const extDef of tlsProfile.extensions) {
    if (extDef.type === ExtensionType.ENCRYPTED_CLIENT_HELLO && echExtData) {
      extWriter.writeUInt16(ExtensionType.ENCRYPTED_CLIENT_HELLO);
      extWriter.writeUInt16(echExtData.length);
      extWriter.writeBytes(echExtData);
      continue;
    }

    writeExtension(extWriter, extDef, hostname, keyShares, tlsProfile, grease);
  }

  if (tlsProfile.grease) {
    extWriter.writeUInt16(lastGrease);
    extWriter.writeUInt16(1);
    extWriter.writeUInt8(0);
  }

  const extBytes = extWriter.toBuffer();
  body.writeUInt16(extBytes.length);
  body.writeBytes(extBytes);

  return body.toBuffer();
}

function wrapHandshakeMessage(chBody: Buffer): Buffer {
  const w = new BufferWriter(4 + chBody.length);
  w.writeUInt8(HandshakeType.CLIENT_HELLO);
  w.writeUInt24(chBody.length);
  w.writeBytes(chBody);
  return w.toBuffer();
}
