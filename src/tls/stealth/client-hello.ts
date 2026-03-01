/**
 * ClientHello builder.
 *
 * Constructs a TLS ClientHello message byte-by-byte, giving full
 * control over extension ordering, GREASE placement, cipher suite
 * order, and every other field that contributes to the JA3 fingerprint.
 *
 * The output is a complete TLS record (record header + handshake
 * header + ClientHello body) ready to send over a TCP socket.
 */

import { randomBytes, createECDH, generateKeyPairSync } from 'node:crypto';
import { BufferWriter } from '../../utils/buffer-writer.js';
import {
  RecordType,
  HandshakeType,
  ExtensionType,
  GREASE_VALUES,
  NamedGroup,
} from '../constants.js';
import type { BrowserProfile, TLSExtensionDef } from '../../fingerprints/types.js';

// ---- GREASE ----

/** Pick a random GREASE value. */
function randomGrease(): number {
  return GREASE_VALUES[Math.floor(Math.random() * GREASE_VALUES.length)]!;
}

// ---- Key share generation ----

export interface KeyShareEntry {
  group: number;
  publicKey: Buffer;
  privateKey: Buffer;
}

/**
 * Generate a key share for the given named group.
 */
export function generateKeyShare(group: number): KeyShareEntry {
  switch (group) {
    case NamedGroup.X25519: {
      const kp = generateKeyPairSync('x25519');
      const pub = kp.publicKey.export({ type: 'spki', format: 'der' });
      const priv = kp.privateKey.export({ type: 'pkcs8', format: 'der' });
      // X25519 public key is the last 32 bytes of the SPKI DER
      const publicKey = Buffer.from(pub.subarray(pub.length - 32));
      // X25519 private key is the last 32 bytes of the PKCS8 DER
      const privateKey = Buffer.from(priv.subarray(priv.length - 32));
      return { group, publicKey, privateKey };
    }
    case NamedGroup.SECP256R1:
    case NamedGroup.SECP384R1:
    case NamedGroup.SECP521R1: {
      const curveName =
        group === NamedGroup.SECP256R1
          ? 'prime256v1'
          : group === NamedGroup.SECP384R1
            ? 'secp384r1'
            : 'secp521r1';
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

// ---- Key share extension data builder ----

function buildKeyShareExtensionData(keyShares: KeyShareEntry[]): Buffer {
  const w = new BufferWriter(256);
  // client_shares length placeholder
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

// ---- ClientHello construction ----

export interface ClientHelloResult {
  /** Complete TLS record bytes to send. */
  record: Buffer;
  /** Generated key shares for use in key exchange. */
  keyShares: KeyShareEntry[];
  /** The client_random value (32 bytes). */
  clientRandom: Buffer;
  /** Session ID (may be empty or 32 bytes). */
  sessionId: Buffer;
  /** The raw ClientHello handshake message (without record header) for
   *  transcript hashing. */
  handshakeMessage: Buffer;
}

/**
 * Build a complete ClientHello record from a browser profile.
 */
export function buildClientHello(
  profile: BrowserProfile,
  hostname: string,
): ClientHelloResult {
  const tlsProfile = profile.tls;

  // Generate cryptographic material
  const clientRandom = randomBytes(32);
  const sessionId = tlsProfile.randomSessionId ? randomBytes(32) : Buffer.alloc(0);
  const keyShares = tlsProfile.keyShareGroups.map(generateKeyShare);

  // Pick GREASE values (reuse same value per category for consistency)
  const greaseCipher = tlsProfile.grease ? randomGrease() : 0;
  const greaseExt = tlsProfile.grease ? randomGrease() : 0;
  const greaseGroup = tlsProfile.grease ? randomGrease() : 0;
  const greaseVersion = tlsProfile.grease ? randomGrease() : 0;

  // ---- Build ClientHello body ----

  const body = new BufferWriter(4096);

  // client_version
  body.writeUInt16(tlsProfile.clientVersion);

  // random (32 bytes)
  body.writeBytes(clientRandom);

  // session_id
  body.writeUInt8(sessionId.length);
  if (sessionId.length > 0) body.writeBytes(sessionId);

  // cipher_suites
  const ciphers = tlsProfile.grease
    ? [greaseCipher, ...tlsProfile.cipherSuites]
    : [...tlsProfile.cipherSuites];
  body.writeUInt16(ciphers.length * 2);
  for (const c of ciphers) body.writeUInt16(c);

  // compression_methods
  body.writeUInt8(tlsProfile.compressionMethods.length);
  for (const m of tlsProfile.compressionMethods) body.writeUInt8(m);

  // ---- Extensions ----

  const extWriter = new BufferWriter(4096);

  // If GREASE is enabled, prepend a GREASE extension
  if (tlsProfile.grease) {
    extWriter.writeUInt16(greaseExt);
    extWriter.writeUInt16(1);
    extWriter.writeUInt8(0);
  }

  // Write each extension from the profile in exact order
  for (const extDef of tlsProfile.extensions) {
    writeExtension(extWriter, extDef, hostname, keyShares, tlsProfile, {
      greaseGroup,
      greaseVersion,
    });
  }

  // If GREASE is enabled, append a GREASE extension at end
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

  // ---- Wrap in handshake header ----

  const handshake = new BufferWriter(4 + clientHelloBody.length);
  handshake.writeUInt8(HandshakeType.CLIENT_HELLO);
  handshake.writeUInt24(clientHelloBody.length);
  handshake.writeBytes(clientHelloBody);
  const handshakeMessage = handshake.toBuffer();

  // ---- Wrap in record ----

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

// ---- Extension writer ----

function writeExtension(
  w: BufferWriter,
  extDef: TLSExtensionDef,
  hostname: string,
  keyShares: KeyShareEntry[],
  tlsProfile: import('../../fingerprints/types.js').TLSProfile,
  grease: { greaseGroup: number; greaseVersion: number },
): void {
  // Special handling for key_share -- inject actual key material
  if (extDef.type === ExtensionType.KEY_SHARE) {
    const data = buildKeyShareExtensionData(keyShares);
    w.writeUInt16(ExtensionType.KEY_SHARE);
    w.writeUInt16(data.length);
    w.writeBytes(data);
    return;
  }

  // Special handling for supported_groups with GREASE
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

  // Special handling for supported_versions with GREASE
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

  // General case
  w.writeUInt16(extDef.type);
  if (extDef.data) {
    const data = extDef.data(hostname);
    w.writeUInt16(data.length);
    if (data.length > 0) w.writeBytes(data);
  } else {
    w.writeUInt16(0);
  }
}
