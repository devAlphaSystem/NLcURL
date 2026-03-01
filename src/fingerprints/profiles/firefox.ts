/**
 * Firefox browser fingerprint profiles.
 */

import type {
  BrowserProfile,
  TLSProfile,
  H2Profile,
  HeaderProfile,
  TLSExtensionDef,
} from '../types.js';
import {
  CipherSuite,
  ExtensionType,
  NamedGroup,
  SignatureScheme,
  ECPointFormat,
  PskKeyExchangeMode,
  ProtocolVersion,
} from '../../tls/constants.js';
import * as ext from '../extensions.js';

// ---- Firefox cipher suites ----

const FF_CIPHER_SUITES: number[] = [
  CipherSuite.TLS_AES_128_GCM_SHA256,
  CipherSuite.TLS_CHACHA20_POLY1305_SHA256,
  CipherSuite.TLS_AES_256_GCM_SHA384,
  CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
  CipherSuite.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
  CipherSuite.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,
  CipherSuite.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
  CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
  CipherSuite.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
  CipherSuite.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,
  CipherSuite.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,
  CipherSuite.TLS_RSA_WITH_AES_128_GCM_SHA256,
  CipherSuite.TLS_RSA_WITH_AES_256_GCM_SHA384,
  CipherSuite.TLS_RSA_WITH_AES_128_CBC_SHA,
  CipherSuite.TLS_RSA_WITH_AES_256_CBC_SHA,
];

const FF_GROUPS: number[] = [
  NamedGroup.X25519,
  NamedGroup.SECP256R1,
  NamedGroup.SECP384R1,
  NamedGroup.SECP521R1,
  NamedGroup.FFDHE2048,
  NamedGroup.FFDHE3072,
];

const FF_SIGALGS: number[] = [
  SignatureScheme.ECDSA_SECP256R1_SHA256,
  SignatureScheme.ECDSA_SECP384R1_SHA384,
  SignatureScheme.ECDSA_SECP521R1_SHA512,
  SignatureScheme.RSA_PSS_RSAE_SHA256,
  SignatureScheme.RSA_PSS_RSAE_SHA384,
  SignatureScheme.RSA_PSS_RSAE_SHA512,
  SignatureScheme.RSA_PKCS1_SHA256,
  SignatureScheme.RSA_PKCS1_SHA384,
  SignatureScheme.RSA_PKCS1_SHA512,
];

const FF_SUPPORTED_VERSIONS: number[] = [
  ProtocolVersion.TLS_1_3,
  ProtocolVersion.TLS_1_2,
];

// ---- Extension ordering (Firefox) ----

function firefoxExtensions(): TLSExtensionDef[] {
  return [
    { type: ExtensionType.SERVER_NAME, data: ext.sniData },
    { type: ExtensionType.EXTENDED_MASTER_SECRET, data: () => ext.extendedMasterSecretData() },
    { type: ExtensionType.RENEGOTIATION_INFO, data: () => ext.renegotiationInfoData() },
    { type: ExtensionType.SUPPORTED_GROUPS, data: () => ext.supportedGroupsData(FF_GROUPS) },
    { type: ExtensionType.EC_POINT_FORMATS, data: () => ext.ecPointFormatsData([ECPointFormat.UNCOMPRESSED]) },
    { type: ExtensionType.SESSION_TICKET, data: () => ext.sessionTicketData() },
    { type: ExtensionType.APPLICATION_LAYER_PROTOCOL_NEGOTIATION, data: () => ext.alpnData(['h2', 'http/1.1']) },
    { type: ExtensionType.STATUS_REQUEST, data: () => ext.statusRequestData() },
    { type: ExtensionType.DELEGATED_CREDENTIALS, data: () => ext.delegatedCredentialsData([
      SignatureScheme.ECDSA_SECP256R1_SHA256,
      SignatureScheme.ECDSA_SECP384R1_SHA384,
      SignatureScheme.ECDSA_SECP521R1_SHA512,
      SignatureScheme.RSA_PSS_RSAE_SHA256,
      SignatureScheme.RSA_PSS_RSAE_SHA384,
      SignatureScheme.RSA_PSS_RSAE_SHA512,
    ]) },
    { type: ExtensionType.KEY_SHARE, data: () => ext.keySharePlaceholder([NamedGroup.X25519, NamedGroup.SECP256R1]) },
    { type: ExtensionType.SUPPORTED_VERSIONS, data: () => ext.supportedVersionsData(FF_SUPPORTED_VERSIONS) },
    { type: ExtensionType.SIGNATURE_ALGORITHMS, data: () => ext.signatureAlgorithmsData(FF_SIGALGS) },
    { type: ExtensionType.PSK_KEY_EXCHANGE_MODES, data: () => ext.pskKeyExchangeModesData([PskKeyExchangeMode.PSK_DHE_KE]) },
    { type: ExtensionType.RECORD_SIZE_LIMIT, data: () => ext.recordSizeLimitData(16385) },
  ];
}

// ---- HTTP/2 ----

const FF_H2: H2Profile = {
  settings: [
    { id: 1, value: 65536 },   // HEADER_TABLE_SIZE
    { id: 2, value: 0 },        // ENABLE_PUSH
    { id: 4, value: 131072 },   // INITIAL_WINDOW_SIZE
    { id: 5, value: 16384 },    // MAX_FRAME_SIZE
  ],
  windowUpdate: 12517377,
  pseudoHeaderOrder: [':method', ':path', ':authority', ':scheme'],
  priorityFrames: [],
};

// ---- Header template ----

function firefoxHeaders(version: string): HeaderProfile {
  const major = version.split('.')[0];
  const ua = `Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:${major}.0) Gecko/20100101 Firefox/${major}.0`;
  return {
    userAgent: ua,
    headers: [
      ['user-agent', ua],
      ['accept', 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8'],
      ['accept-language', 'en-US,en;q=0.5'],
      ['accept-encoding', 'gzip, deflate, br, zstd'],
      ['sec-fetch-dest', 'document'],
      ['sec-fetch-mode', 'navigate'],
      ['sec-fetch-site', 'none'],
      ['sec-fetch-user', '?1'],
      ['priority', 'u=0, i'],
    ],
  };
}

// ---- TLS template ----

function firefoxTLS(): TLSProfile {
  return {
    recordVersion: ProtocolVersion.TLS_1_0,
    clientVersion: ProtocolVersion.TLS_1_2,
    cipherSuites: FF_CIPHER_SUITES,
    compressionMethods: [0],
    extensions: firefoxExtensions(),
    supportedGroups: FF_GROUPS,
    signatureAlgorithms: FF_SIGALGS,
    alpnProtocols: ['h2', 'http/1.1'],
    grease: false,
    randomSessionId: true,
    keyShareGroups: [NamedGroup.X25519, NamedGroup.SECP256R1],
    pskKeyExchangeModes: [PskKeyExchangeMode.PSK_DHE_KE],
    supportedVersions: FF_SUPPORTED_VERSIONS,
    ecPointFormats: [ECPointFormat.UNCOMPRESSED],
    recordSizeLimit: 16385,
    delegatedCredentials: [
      SignatureScheme.ECDSA_SECP256R1_SHA256,
      SignatureScheme.ECDSA_SECP384R1_SHA384,
      SignatureScheme.ECDSA_SECP521R1_SHA512,
      SignatureScheme.RSA_PSS_RSAE_SHA256,
      SignatureScheme.RSA_PSS_RSAE_SHA384,
      SignatureScheme.RSA_PSS_RSAE_SHA512,
    ],
  };
}

// ---- Profile factory ----

function firefoxProfile(name: string, version: string): BrowserProfile {
  return {
    name,
    browser: 'firefox',
    version,
    tls: firefoxTLS(),
    h2: FF_H2,
    headers: firefoxHeaders(version),
  };
}

// ---- Exported profiles ----

export const firefox133 = firefoxProfile('firefox133', '133.0');
export const firefox134 = firefoxProfile('firefox134', '134.0');
export const firefox135 = firefoxProfile('firefox135', '135.0');
export const firefox136 = firefoxProfile('firefox136', '136.0');
export const firefox137 = firefoxProfile('firefox137', '137.0');
export const firefox138 = firefoxProfile('firefox138', '138.0');

export const firefoxLatest = firefox138;

export const firefoxProfiles: ReadonlyMap<string, BrowserProfile> = new Map([
  ['firefox133', firefox133],
  ['firefox134', firefox134],
  ['firefox135', firefox135],
  ['firefox136', firefox136],
  ['firefox137', firefox137],
  ['firefox138', firefox138],
  ['firefox_latest', firefox138],
]);
