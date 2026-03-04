import { randomBytes, createECDH, generateKeyPairSync } from "node:crypto";
import { BufferWriter } from "../../utils/buffer-writer.js";
import { RecordType, HandshakeType, ExtensionType, GREASE_VALUES, NamedGroup } from "../constants.js";
import type { BrowserProfile, TLSExtensionDef } from "../../fingerprints/types.js";

function randomGrease(): number {
  return GREASE_VALUES[Math.floor(Math.random() * GREASE_VALUES.length)]!;
}

/**
 * An ephemeral key share generated for a specific named group, used during
 * TLS 1.3 key exchange. Contains both the public key to advertise in the
 * ClientHello and the private key required to compute the shared secret.
 *
 * @typedef  {Object} KeyShareEntry
 * @property {number} group      - Named group code (e.g. `NamedGroup.X25519`).
 * @property {Buffer} publicKey  - Raw public key bytes to include in the key_share extension.
 * @property {Buffer} privateKey - Raw private key bytes used for ECDH computation.
 */
export interface KeyShareEntry {
  group: number;
  publicKey: Buffer;
  privateKey: Buffer;
}

/**
 * Generates an ephemeral key pair for the specified named group. Supports
 * X25519, SECP256R1, SECP384R1, and SECP521R1.
 *
 * @param {number} group - Named group code from the {@link NamedGroup} enum.
 * @returns {KeyShareEntry} The generated key pair with group identifier.
 * @throws {Error} If the specified group is not supported.
 */
export function generateKeyShare(group: number): KeyShareEntry {
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
      throw new Error(`Unsupported key share group: 0x${group.toString(16)}`);
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

/**
 * Carries the outputs of {@link buildClientHello} that must be retained
 * for subsequent handshake processing.
 *
 * @typedef  {Object}           ClientHelloResult
 * @property {Buffer}           record            - The complete TLS record containing the ClientHello.
 * @property {KeyShareEntry[]}  keyShares          - Generated key shares (private keys needed for key derivation).
 * @property {Buffer}           clientRandom       - 32-byte client random included in the ClientHello body.
 * @property {Buffer}           sessionId          - Legacy session ID bytes (may be empty).
 * @property {Buffer}           handshakeMessage   - The raw handshake message body (used for transcript hashing).
 */
export interface ClientHelloResult {
  record: Buffer;
  keyShares: KeyShareEntry[];
  clientRandom: Buffer;
  sessionId: Buffer;
  handshakeMessage: Buffer;
}

/**
 * Constructs a binary TLS 1.3 ClientHello record that mirrors the exact byte
 * structure produced by the given browser profile, including GREASE injection,
 * key share generation, and extension ordering.
 *
 * @param {BrowserProfile} profile  - The browser profile whose TLS fingerprint to replicate.
 * @param {string}         hostname - The SNI hostname to include in the server_name extension.
 * @returns {ClientHelloResult} The encoded record alongside key material needed for the handshake.
 */
export function buildClientHello(profile: BrowserProfile, hostname: string): ClientHelloResult {
  const tlsProfile = profile.tls;

  const clientRandom = randomBytes(32);
  const sessionId = tlsProfile.randomSessionId ? randomBytes(32) : Buffer.alloc(0);
  const keyShares = tlsProfile.keyShareGroups.map(generateKeyShare);

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
