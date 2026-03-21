/**
 * Unit tests for src/tls/stealth/client-hello.ts
 *
 * Validates the structure of generated ClientHello messages:
 * - TLS record framing (5-byte header)
 * - Handshake message framing (type + uint24 length)
 * - Client random, session ID, cipher suites, compression, extensions
 * - Padding to 512 bytes for messages in the 256–511 range
 * - GREASE injection in proper positions
 * - Key share extension encoding
 */
import { describe, it } from "node:test";
import { strict as assert } from "node:assert";
import { buildClientHello, generateKeyShare, type ClientHelloResult } from "../../src/tls/stealth/client-hello.js";
import { RecordType, HandshakeType, ProtocolVersion, CipherSuite, ExtensionType, NamedGroup, GREASE_VALUES, SignatureScheme, ECPointFormat, PskKeyExchangeMode, CertCompressAlg } from "../../src/tls/constants.js";
import * as ext from "../../src/fingerprints/extensions.js";
import type { BrowserProfile, TLSExtensionDef } from "../../src/fingerprints/types.js";

/** Build a minimal Chrome-like profile that produces a short ClientHello */
function minimalProfile(overrides?: Partial<BrowserProfile["tls"]>): BrowserProfile {
  const tls = {
    recordVersion: ProtocolVersion.TLS_1_0,
    clientVersion: ProtocolVersion.TLS_1_2,
    cipherSuites: [CipherSuite.TLS_AES_128_GCM_SHA256],
    compressionMethods: [0],
    extensions: [{ type: ExtensionType.SERVER_NAME, data: ext.sniData }, { type: ExtensionType.SUPPORTED_VERSIONS, data: () => ext.supportedVersionsData([ProtocolVersion.TLS_1_3, ProtocolVersion.TLS_1_2]) }, { type: ExtensionType.SUPPORTED_GROUPS, data: () => ext.supportedGroupsData([NamedGroup.X25519]) }, { type: ExtensionType.KEY_SHARE }, { type: ExtensionType.SIGNATURE_ALGORITHMS, data: () => ext.signatureAlgorithmsData([SignatureScheme.ECDSA_SECP256R1_SHA256]) }] satisfies TLSExtensionDef[],
    supportedGroups: [NamedGroup.X25519],
    signatureAlgorithms: [SignatureScheme.ECDSA_SECP256R1_SHA256],
    alpnProtocols: ["h2"],
    grease: false,
    randomSessionId: true,
    keyShareGroups: [NamedGroup.X25519],
    supportedVersions: [ProtocolVersion.TLS_1_3, ProtocolVersion.TLS_1_2],
    ...overrides,
  };
  return {
    name: "test-minimal",
    engine: "chromium",
    tls,
    h2: { settings: [], windowUpdate: 0, pseudoHeaderOrder: [] },
    headers: { headers: [], userAgent: "test" },
  } as unknown as BrowserProfile;
}

/** Build a larger Chrome-like profile that will hit the 256–511 range for padding */
function paddingProfile(): BrowserProfile {
  const extensions: TLSExtensionDef[] = [
    { type: ExtensionType.SERVER_NAME, data: ext.sniData },
    { type: ExtensionType.EXTENDED_MASTER_SECRET, data: () => Buffer.alloc(0) },
    { type: ExtensionType.RENEGOTIATION_INFO, data: () => ext.renegotiationInfoData() },
    { type: ExtensionType.SUPPORTED_GROUPS, data: () => ext.supportedGroupsData([NamedGroup.X25519, NamedGroup.SECP256R1, NamedGroup.SECP384R1]) },
    { type: ExtensionType.EC_POINT_FORMATS, data: () => ext.ecPointFormatsData([ECPointFormat.UNCOMPRESSED]) },
    { type: ExtensionType.SESSION_TICKET, data: () => ext.sessionTicketData() },
    { type: ExtensionType.APPLICATION_LAYER_PROTOCOL_NEGOTIATION, data: () => ext.alpnData(["h2", "http/1.1"]) },
    { type: ExtensionType.STATUS_REQUEST, data: () => ext.statusRequestData() },
    { type: ExtensionType.SIGNATURE_ALGORITHMS, data: () => ext.signatureAlgorithmsData([SignatureScheme.ECDSA_SECP256R1_SHA256, SignatureScheme.RSA_PSS_RSAE_SHA256, SignatureScheme.RSA_PKCS1_SHA256, SignatureScheme.ECDSA_SECP384R1_SHA384, SignatureScheme.RSA_PSS_RSAE_SHA384, SignatureScheme.RSA_PKCS1_SHA384, SignatureScheme.RSA_PSS_RSAE_SHA512, SignatureScheme.RSA_PKCS1_SHA512]) },
    { type: ExtensionType.SIGNED_CERTIFICATE_TIMESTAMP },
    { type: ExtensionType.KEY_SHARE },
    { type: ExtensionType.PSK_KEY_EXCHANGE_MODES, data: () => ext.pskKeyExchangeModesData([PskKeyExchangeMode.PSK_DHE_KE]) },
    { type: ExtensionType.SUPPORTED_VERSIONS, data: () => ext.supportedVersionsData([ProtocolVersion.TLS_1_3, ProtocolVersion.TLS_1_2]) },
    { type: ExtensionType.COMPRESS_CERTIFICATE, data: () => ext.compressCertData([CertCompressAlg.BROTLI]) },
    { type: ExtensionType.APPLICATION_SETTINGS, data: () => ext.applicationSettingsData(["h2"]) },
    { type: ExtensionType.DELEGATED_CREDENTIALS, data: () => ext.delegatedCredentialsData([SignatureScheme.ECDSA_SECP256R1_SHA256, SignatureScheme.RSA_PSS_RSAE_SHA256, SignatureScheme.RSA_PSS_RSAE_SHA384, SignatureScheme.RSA_PSS_RSAE_SHA512]) },
    { type: ExtensionType.PADDING },
  ];

  const tls = {
    recordVersion: ProtocolVersion.TLS_1_0,
    clientVersion: ProtocolVersion.TLS_1_2,
    cipherSuites: [CipherSuite.TLS_AES_128_GCM_SHA256, CipherSuite.TLS_AES_256_GCM_SHA384, CipherSuite.TLS_CHACHA20_POLY1305_SHA256, CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256, CipherSuite.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256, CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384, CipherSuite.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384, CipherSuite.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256, CipherSuite.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256, CipherSuite.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA, CipherSuite.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA, CipherSuite.TLS_RSA_WITH_AES_128_GCM_SHA256, CipherSuite.TLS_RSA_WITH_AES_256_GCM_SHA384, CipherSuite.TLS_RSA_WITH_AES_128_CBC_SHA, CipherSuite.TLS_RSA_WITH_AES_256_CBC_SHA],
    compressionMethods: [0],
    extensions,
    supportedGroups: [NamedGroup.X25519, NamedGroup.SECP256R1, NamedGroup.SECP384R1],
    signatureAlgorithms: [SignatureScheme.ECDSA_SECP256R1_SHA256, SignatureScheme.RSA_PSS_RSAE_SHA256, SignatureScheme.RSA_PKCS1_SHA256, SignatureScheme.ECDSA_SECP384R1_SHA384, SignatureScheme.RSA_PSS_RSAE_SHA384, SignatureScheme.RSA_PKCS1_SHA384, SignatureScheme.RSA_PSS_RSAE_SHA512, SignatureScheme.RSA_PKCS1_SHA512],
    alpnProtocols: ["h2", "http/1.1"],
    grease: false,
    randomSessionId: true,
    keyShareGroups: [NamedGroup.X25519],
    supportedVersions: [ProtocolVersion.TLS_1_3, ProtocolVersion.TLS_1_2],
    certCompressAlgorithms: [CertCompressAlg.BROTLI],
    pskKeyExchangeModes: [PskKeyExchangeMode.PSK_DHE_KE],
    ecPointFormats: [ECPointFormat.UNCOMPRESSED],
    applicationSettings: ["h2"],
    delegatedCredentials: [SignatureScheme.ECDSA_SECP256R1_SHA256, SignatureScheme.RSA_PSS_RSAE_SHA256, SignatureScheme.RSA_PSS_RSAE_SHA384, SignatureScheme.RSA_PSS_RSAE_SHA512],
  };

  return {
    name: "test-padding",
    engine: "chromium",
    tls,
    h2: { settings: [], windowUpdate: 0, pseudoHeaderOrder: [] },
    headers: { headers: [], userAgent: "test" },
  } as unknown as BrowserProfile;
}

/** Read uint24 from buffer at offset */
function readUint24(buf: Buffer, off: number): number {
  return (buf[off]! << 16) | (buf[off + 1]! << 8) | buf[off + 2]!;
}

function isGrease(value: number): boolean {
  return (GREASE_VALUES as readonly number[]).includes(value);
}

/** Parse ClientHello extensions from the raw handshake body, returning extension types */
function parseExtensionTypes(handshake: Buffer): number[] {
  let offset = 4;
  offset += 2;
  offset += 32;
  const sessionIdLen = handshake[offset]!;
  offset += 1 + sessionIdLen;
  const csLen = handshake.readUInt16BE(offset);
  offset += 2 + csLen;
  const compLen = handshake[offset]!;
  offset += 1 + compLen;
  const extLen = handshake.readUInt16BE(offset);
  offset += 2;
  const extEnd = offset + extLen;

  const types: number[] = [];
  while (offset < extEnd) {
    const type = handshake.readUInt16BE(offset);
    offset += 2;
    const dataLen = handshake.readUInt16BE(offset);
    offset += 2 + dataLen;
    types.push(type);
  }
  return types;
}

describe("generateKeyShare", () => {
  it("generates X25519 key pair with 32-byte keys", () => {
    const ks = generateKeyShare(NamedGroup.X25519);
    assert.ok(ks);
    assert.equal(ks.group, NamedGroup.X25519);
    assert.equal(ks.publicKey.length, 32);
    assert.equal(ks.privateKey.length, 32);
  });

  it("generates SECP256R1 key pair", () => {
    const ks = generateKeyShare(NamedGroup.SECP256R1);
    assert.ok(ks);
    assert.equal(ks.group, NamedGroup.SECP256R1);
    assert.equal(ks.publicKey.length, 65);
  });

  it("generates SECP384R1 key pair", () => {
    const ks = generateKeyShare(NamedGroup.SECP384R1);
    assert.ok(ks);
    assert.equal(ks.group, NamedGroup.SECP384R1);
    assert.equal(ks.publicKey.length, 97);
  });

  it("returns null for unknown groups", () => {
    assert.equal(generateKeyShare(0xffff), null);
  });
});

describe("buildClientHello structure", () => {
  it("produces a valid TLS record with correct header", () => {
    const profile = minimalProfile();
    const result = buildClientHello(profile, "example.com");

    assert.equal(result.record[0], RecordType.HANDSHAKE);
    const recordVersion = result.record.readUInt16BE(1);
    assert.equal(recordVersion, ProtocolVersion.TLS_1_0);
    const recordLen = result.record.readUInt16BE(3);
    assert.equal(recordLen, result.record.length - 5);
  });

  it("handshake message starts with CLIENT_HELLO type and uint24 length", () => {
    const profile = minimalProfile();
    const result = buildClientHello(profile, "example.com");
    const hs = result.handshakeMessage;

    assert.equal(hs[0], HandshakeType.CLIENT_HELLO);
    const bodyLen = readUint24(hs, 1);
    assert.equal(bodyLen, hs.length - 4);
  });

  it("handshake contains correct client version and 32-byte random", () => {
    const profile = minimalProfile();
    const result = buildClientHello(profile, "example.com");
    const hs = result.handshakeMessage;

    const clientVersion = hs.readUInt16BE(4);
    assert.equal(clientVersion, ProtocolVersion.TLS_1_2);

    const random = hs.subarray(6, 38);
    assert.equal(random.length, 32);
    assert.deepStrictEqual(random, result.clientRandom);
  });

  it("session ID matches the returned sessionId", () => {
    const profile = minimalProfile({ randomSessionId: true });
    const result = buildClientHello(profile, "example.com");
    const hs = result.handshakeMessage;

    const sidLen = hs[38]!;
    assert.equal(sidLen, 32);
    const sid = hs.subarray(39, 39 + sidLen);
    assert.deepStrictEqual(sid, result.sessionId);
  });

  it("session ID is empty when randomSessionId is false", () => {
    const profile = minimalProfile({ randomSessionId: false });
    const result = buildClientHello(profile, "example.com");
    assert.equal(result.sessionId.length, 0);
    assert.equal(result.handshakeMessage[38], 0);
  });

  it("cipher suites are encoded correctly", () => {
    const profile = minimalProfile({
      cipherSuites: [CipherSuite.TLS_AES_128_GCM_SHA256, CipherSuite.TLS_AES_256_GCM_SHA384],
    });
    const result = buildClientHello(profile, "example.com");
    const hs = result.handshakeMessage;

    const sidLen = hs[38]!;
    let offset = 39 + sidLen;
    const csLen = hs.readUInt16BE(offset);
    assert.equal(csLen, 4);
    offset += 2;
    assert.equal(hs.readUInt16BE(offset), CipherSuite.TLS_AES_128_GCM_SHA256);
    assert.equal(hs.readUInt16BE(offset + 2), CipherSuite.TLS_AES_256_GCM_SHA384);
  });

  it("compression methods are encoded correctly", () => {
    const profile = minimalProfile();
    const result = buildClientHello(profile, "example.com");
    const hs = result.handshakeMessage;

    const sidLen = hs[38]!;
    let offset = 39 + sidLen;
    const csLen = hs.readUInt16BE(offset);
    offset += 2 + csLen;
    const compLen = hs[offset]!;
    assert.equal(compLen, 1);
    assert.equal(hs[offset + 1], 0);
  });

  it("key shares are returned and non-empty", () => {
    const profile = minimalProfile();
    const result = buildClientHello(profile, "example.com");
    assert.ok(result.keyShares.length > 0);
    assert.equal(result.keyShares[0]!.group, NamedGroup.X25519);
    assert.equal(result.keyShares[0]!.publicKey.length, 32);
  });

  it("record bytes equals 5 + handshakeMessage length", () => {
    const profile = minimalProfile();
    const result = buildClientHello(profile, "example.com");
    assert.equal(result.record.length, 5 + result.handshakeMessage.length);
    assert.deepStrictEqual(result.record.subarray(5), result.handshakeMessage);
  });
});

describe("ClientHello GREASE", () => {
  it("injects GREASE cipher suite as first entry when grease=true", () => {
    const profile = minimalProfile({ grease: true });
    const result = buildClientHello(profile, "example.com");
    const hs = result.handshakeMessage;

    const sidLen = hs[38]!;
    let offset = 39 + sidLen;
    offset += 2;
    const firstCipher = hs.readUInt16BE(offset);
    assert.ok(isGrease(firstCipher), `Expected first cipher to be GREASE, got 0x${firstCipher.toString(16)}`);
  });

  it("injects GREASE extension at start and end", () => {
    const profile = minimalProfile({ grease: true });
    const result = buildClientHello(profile, "example.com");
    const types = parseExtensionTypes(result.handshakeMessage);

    assert.ok(isGrease(types[0]!), `Expected first ext to be GREASE, got 0x${types[0]!.toString(16)}`);
    assert.ok(isGrease(types[types.length - 1]!), `Expected last ext to be GREASE, got 0x${types[types.length - 1]!.toString(16)}`);
  });
});

describe("ClientHello padding (regression)", () => {
  it("pads handshake to 512 bytes when in the 256–511 range", () => {
    const profile = paddingProfile();
    const result = buildClientHello(profile, "example.com");
    const hsLen = result.handshakeMessage.length;

    assert.equal(hsLen, 512, `Expected handshake padded to 512 bytes, got ${hsLen}`);
  });

  it("padding extension contains all zeros", () => {
    const profile = paddingProfile();
    const result = buildClientHello(profile, "example.com");
    const types = parseExtensionTypes(result.handshakeMessage);

    assert.ok(types.includes(ExtensionType.PADDING), "Padding extension not found");

    const hs = result.handshakeMessage;
    let offset = 4 + 2 + 32;
    const sidLen = hs[offset]!;
    offset += 1 + sidLen;
    const csLen = hs.readUInt16BE(offset);
    offset += 2 + csLen;
    const compLen = hs[offset]!;
    offset += 1 + compLen;
    const extTotalLen = hs.readUInt16BE(offset);
    offset += 2;
    const extEnd = offset + extTotalLen;

    while (offset < extEnd) {
      const type = hs.readUInt16BE(offset);
      offset += 2;
      const dataLen = hs.readUInt16BE(offset);
      offset += 2;
      if (type === ExtensionType.PADDING) {
        const paddingBytes = hs.subarray(offset, offset + dataLen);
        for (let i = 0; i < paddingBytes.length; i++) {
          assert.equal(paddingBytes[i], 0, `Padding byte at index ${i} is not zero`);
        }
        break;
      }
      offset += dataLen;
    }
  });

  it("does not pad when message is below 256 bytes", () => {
    const profile = minimalProfile({ randomSessionId: false });
    const result = buildClientHello(profile, "x.co");
    assert.ok(result.handshakeMessage.length < 256, `Expected <256 bytes, got ${result.handshakeMessage.length}`);
  });
});

describe("buildClientHello determinism", () => {
  it("produces different client randoms on each call", () => {
    const profile = minimalProfile();
    const r1 = buildClientHello(profile, "example.com");
    const r2 = buildClientHello(profile, "example.com");
    assert.notDeepStrictEqual(r1.clientRandom, r2.clientRandom);
  });

  it("produces different session IDs on each call", () => {
    const profile = minimalProfile({ randomSessionId: true });
    const r1 = buildClientHello(profile, "example.com");
    const r2 = buildClientHello(profile, "example.com");
    assert.notDeepStrictEqual(r1.sessionId, r2.sessionId);
  });
});
