/**
 * Tor Browser fingerprint profiles.
 *
 * Tor Browser is based on Firefox ESR with specific privacy hardening.
 * It uses a narrower set of cipher suites and extensions to reduce
 * fingerprint uniqueness across Tor users.
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

// ---- Tor cipher suites (same as Firefox but no_padding removed) ----

const TOR_CIPHER_SUITES: number[] = [
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

const TOR_GROUPS: number[] = [
  NamedGroup.X25519,
  NamedGroup.SECP256R1,
  NamedGroup.SECP384R1,
  NamedGroup.SECP521R1,
  NamedGroup.FFDHE2048,
  NamedGroup.FFDHE3072,
];

const TOR_SIGALGS: number[] = [
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

// ---- Extensions ----

function torExtensions(): TLSExtensionDef[] {
  return [
    { type: ExtensionType.SERVER_NAME, data: ext.sniData },
    { type: ExtensionType.EXTENDED_MASTER_SECRET, data: () => ext.extendedMasterSecretData() },
    { type: ExtensionType.RENEGOTIATION_INFO, data: () => ext.renegotiationInfoData() },
    { type: ExtensionType.SUPPORTED_GROUPS, data: () => ext.supportedGroupsData(TOR_GROUPS) },
    { type: ExtensionType.EC_POINT_FORMATS, data: () => ext.ecPointFormatsData([ECPointFormat.UNCOMPRESSED]) },
    { type: ExtensionType.SESSION_TICKET, data: () => ext.sessionTicketData() },
    { type: ExtensionType.APPLICATION_LAYER_PROTOCOL_NEGOTIATION, data: () => ext.alpnData(['h2', 'http/1.1']) },
    { type: ExtensionType.STATUS_REQUEST, data: () => ext.statusRequestData() },
    { type: ExtensionType.KEY_SHARE, data: () => ext.keySharePlaceholder([NamedGroup.X25519, NamedGroup.SECP256R1]) },
    { type: ExtensionType.SUPPORTED_VERSIONS, data: () => ext.supportedVersionsData([ProtocolVersion.TLS_1_3, ProtocolVersion.TLS_1_2]) },
    { type: ExtensionType.SIGNATURE_ALGORITHMS, data: () => ext.signatureAlgorithmsData(TOR_SIGALGS) },
    { type: ExtensionType.PSK_KEY_EXCHANGE_MODES, data: () => ext.pskKeyExchangeModesData([PskKeyExchangeMode.PSK_DHE_KE]) },
    { type: ExtensionType.RECORD_SIZE_LIMIT, data: () => ext.recordSizeLimitData(16385) },
  ];
}

// ---- HTTP/2 ----

const TOR_H2: H2Profile = {
  settings: [
    { id: 1, value: 65536 },
    { id: 2, value: 0 },
    { id: 4, value: 131072 },
    { id: 5, value: 16384 },
  ],
  windowUpdate: 12517377,
  pseudoHeaderOrder: [':method', ':path', ':authority', ':scheme'],
  priorityFrames: [],
};

// ---- Headers ----

function torHeaders(ffVersion: string): HeaderProfile {
  const ua = `Mozilla/5.0 (Windows NT 10.0; rv:${ffVersion}) Gecko/20100101 Firefox/${ffVersion}`;
  return {
    userAgent: ua,
    headers: [
      ['user-agent', ua],
      ['accept', 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8'],
      ['accept-language', 'en-US,en;q=0.5'],
      ['accept-encoding', 'gzip, deflate, br'],
      ['sec-fetch-dest', 'document'],
      ['sec-fetch-mode', 'navigate'],
      ['sec-fetch-site', 'none'],
      ['sec-fetch-user', '?1'],
    ],
  };
}

// ---- TLS template ----

function torTLS(): TLSProfile {
  return {
    recordVersion: ProtocolVersion.TLS_1_0,
    clientVersion: ProtocolVersion.TLS_1_2,
    cipherSuites: TOR_CIPHER_SUITES,
    compressionMethods: [0],
    extensions: torExtensions(),
    supportedGroups: TOR_GROUPS,
    signatureAlgorithms: TOR_SIGALGS,
    alpnProtocols: ['h2', 'http/1.1'],
    grease: false,
    randomSessionId: true,
    keyShareGroups: [NamedGroup.X25519, NamedGroup.SECP256R1],
    pskKeyExchangeModes: [PskKeyExchangeMode.PSK_DHE_KE],
    supportedVersions: [ProtocolVersion.TLS_1_3, ProtocolVersion.TLS_1_2],
    ecPointFormats: [ECPointFormat.UNCOMPRESSED],
    recordSizeLimit: 16385,
  };
}

// ---- Profile factory ----

function torProfile(name: string, ffVersion: string): BrowserProfile {
  return {
    name,
    browser: 'tor',
    version: ffVersion,
    tls: torTLS(),
    h2: TOR_H2,
    headers: torHeaders(ffVersion),
  };
}

// ---- Exported profiles ----

export const tor133 = torProfile('tor133', '128.0');
export const tor140 = torProfile('tor140', '128.0');
export const tor145 = torProfile('tor145', '128.0');

export const torLatest = tor145;

export const torProfiles: ReadonlyMap<string, BrowserProfile> = new Map([
  ['tor133', tor133],
  ['tor140', tor140],
  ['tor145', tor145],
  ['tor_latest', tor145],
]);
