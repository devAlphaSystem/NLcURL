/**
 * Safari browser fingerprint profiles.
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

// ---- Safari cipher suites ----
// Safari has a distinctive cipher order, placing CHACHA20 earlier

const SAFARI_CIPHER_SUITES: number[] = [
  CipherSuite.TLS_AES_128_GCM_SHA256,
  CipherSuite.TLS_AES_256_GCM_SHA384,
  CipherSuite.TLS_CHACHA20_POLY1305_SHA256,
  CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
  CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
  CipherSuite.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,
  CipherSuite.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
  CipherSuite.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
  CipherSuite.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
  CipherSuite.TLS_RSA_WITH_AES_256_GCM_SHA384,
  CipherSuite.TLS_RSA_WITH_AES_128_GCM_SHA256,
  CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA,
  CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA,
  CipherSuite.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,
  CipherSuite.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,
  CipherSuite.TLS_RSA_WITH_AES_256_CBC_SHA,
  CipherSuite.TLS_RSA_WITH_AES_128_CBC_SHA,
];

const SAFARI_GROUPS: number[] = [
  NamedGroup.X25519,
  NamedGroup.SECP256R1,
  NamedGroup.SECP384R1,
  NamedGroup.SECP521R1,
];

const SAFARI_SIGALGS: number[] = [
  SignatureScheme.ECDSA_SECP256R1_SHA256,
  SignatureScheme.RSA_PSS_RSAE_SHA256,
  SignatureScheme.RSA_PKCS1_SHA256,
  SignatureScheme.ECDSA_SECP384R1_SHA384,
  SignatureScheme.ECDSA_SECP521R1_SHA512,
  SignatureScheme.RSA_PSS_RSAE_SHA384,
  SignatureScheme.RSA_PSS_RSAE_SHA512,
  SignatureScheme.RSA_PKCS1_SHA384,
  SignatureScheme.RSA_PKCS1_SHA512,
];

// ---- Extensions ----

function safariExtensions(): TLSExtensionDef[] {
  return [
    { type: ExtensionType.SERVER_NAME, data: ext.sniData },
    { type: ExtensionType.EXTENDED_MASTER_SECRET, data: () => ext.extendedMasterSecretData() },
    { type: ExtensionType.RENEGOTIATION_INFO, data: () => ext.renegotiationInfoData() },
    { type: ExtensionType.SUPPORTED_GROUPS, data: () => ext.supportedGroupsData(SAFARI_GROUPS) },
    { type: ExtensionType.EC_POINT_FORMATS, data: () => ext.ecPointFormatsData([ECPointFormat.UNCOMPRESSED]) },
    { type: ExtensionType.APPLICATION_LAYER_PROTOCOL_NEGOTIATION, data: () => ext.alpnData(['h2', 'http/1.1']) },
    { type: ExtensionType.STATUS_REQUEST, data: () => ext.statusRequestData() },
    { type: ExtensionType.SIGNATURE_ALGORITHMS, data: () => ext.signatureAlgorithmsData(SAFARI_SIGALGS) },
    { type: ExtensionType.SIGNED_CERTIFICATE_TIMESTAMP },
    { type: ExtensionType.KEY_SHARE, data: () => ext.keySharePlaceholder([NamedGroup.X25519]) },
    { type: ExtensionType.PSK_KEY_EXCHANGE_MODES, data: () => ext.pskKeyExchangeModesData([PskKeyExchangeMode.PSK_DHE_KE]) },
    { type: ExtensionType.SUPPORTED_VERSIONS, data: () => ext.supportedVersionsData([ProtocolVersion.TLS_1_3, ProtocolVersion.TLS_1_2]) },
  ];
}

// ---- HTTP/2 ----

const SAFARI_H2: H2Profile = {
  settings: [
    { id: 4, value: 4194304 },   // INITIAL_WINDOW_SIZE
    { id: 3, value: 100 },       // MAX_CONCURRENT_STREAMS
  ],
  windowUpdate: 10485760,
  pseudoHeaderOrder: [':method', ':scheme', ':path', ':authority'],
  priorityFrames: [],
};

// ---- Headers ----

function safariHeaders(version: string, webkitBuild: string): HeaderProfile {
  const ua = `Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/${webkitBuild} (KHTML, like Gecko) Version/${version} Safari/${webkitBuild}`;
  return {
    userAgent: ua,
    headers: [
      ['user-agent', ua],
      ['accept', 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8'],
      ['accept-language', 'en-US,en;q=0.9'],
      ['accept-encoding', 'gzip, deflate, br'],
      ['sec-fetch-dest', 'document'],
      ['sec-fetch-mode', 'navigate'],
      ['sec-fetch-site', 'none'],
    ],
  };
}

// ---- TLS template ----

function safariTLS(): TLSProfile {
  return {
    recordVersion: ProtocolVersion.TLS_1_0,
    clientVersion: ProtocolVersion.TLS_1_2,
    cipherSuites: SAFARI_CIPHER_SUITES,
    compressionMethods: [0],
    extensions: safariExtensions(),
    supportedGroups: SAFARI_GROUPS,
    signatureAlgorithms: SAFARI_SIGALGS,
    alpnProtocols: ['h2', 'http/1.1'],
    grease: true,
    randomSessionId: true,
    keyShareGroups: [NamedGroup.X25519],
    pskKeyExchangeModes: [PskKeyExchangeMode.PSK_DHE_KE],
    supportedVersions: [ProtocolVersion.TLS_1_3, ProtocolVersion.TLS_1_2],
    ecPointFormats: [ECPointFormat.UNCOMPRESSED],
  };
}

// ---- Profile factory ----

function safariProfile(
  name: string,
  version: string,
  webkitBuild: string,
): BrowserProfile {
  return {
    name,
    browser: 'safari',
    version,
    tls: safariTLS(),
    h2: SAFARI_H2,
    headers: safariHeaders(version, webkitBuild),
  };
}

// ---- Exported profiles ----

export const safari153 = safariProfile('safari153', '15.3', '605.1.15');
export const safari155 = safariProfile('safari155', '15.5', '605.1.15');
export const safari160 = safariProfile('safari160', '16.0', '605.1.15');
export const safari165 = safariProfile('safari165', '16.5', '605.1.15');
export const safari170 = safariProfile('safari170', '17.0', '605.1.15');
export const safari174 = safariProfile('safari174', '17.4', '605.1.15');
export const safari175 = safariProfile('safari175', '17.5', '605.1.15');
export const safari180 = safariProfile('safari180', '18.0', '605.1.15');
export const safari182 = safariProfile('safari182', '18.2', '605.1.15');

export const safariLatest = safari182;

export const safariProfiles: ReadonlyMap<string, BrowserProfile> = new Map([
  ['safari153', safari153],
  ['safari155', safari155],
  ['safari160', safari160],
  ['safari165', safari165],
  ['safari170', safari170],
  ['safari174', safari174],
  ['safari175', safari175],
  ['safari180', safari180],
  ['safari182', safari182],
  ['safari_latest', safari182],
]);
