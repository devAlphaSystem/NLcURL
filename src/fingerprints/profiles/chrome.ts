import type { BrowserProfile, TLSProfile, H2Profile, HeaderProfile, TLSExtensionDef, H2Setting } from "../types.js";
import { CipherSuite, ExtensionType, NamedGroup, SignatureScheme, ECPointFormat, PskKeyExchangeMode, CertCompressAlg, ProtocolVersion } from "../../tls/constants.js";
import * as ext from "../extensions.js";

const CHROME_CIPHER_SUITES: number[] = [CipherSuite.TLS_AES_128_GCM_SHA256, CipherSuite.TLS_AES_256_GCM_SHA384, CipherSuite.TLS_CHACHA20_POLY1305_SHA256, CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256, CipherSuite.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256, CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384, CipherSuite.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384, CipherSuite.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256, CipherSuite.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256, CipherSuite.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA, CipherSuite.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA, CipherSuite.TLS_RSA_WITH_AES_128_GCM_SHA256, CipherSuite.TLS_RSA_WITH_AES_256_GCM_SHA384, CipherSuite.TLS_RSA_WITH_AES_128_CBC_SHA, CipherSuite.TLS_RSA_WITH_AES_256_CBC_SHA];

const CHROME_GROUPS: number[] = [NamedGroup.X25519, NamedGroup.SECP256R1, NamedGroup.SECP384R1];

const CHROME_GROUPS_PQ: number[] = [NamedGroup.X25519_MLKEM768, NamedGroup.X25519, NamedGroup.SECP256R1, NamedGroup.SECP384R1];

const CHROME_SIGALGS: number[] = [SignatureScheme.ECDSA_SECP256R1_SHA256, SignatureScheme.RSA_PSS_RSAE_SHA256, SignatureScheme.RSA_PKCS1_SHA256, SignatureScheme.ECDSA_SECP384R1_SHA384, SignatureScheme.RSA_PSS_RSAE_SHA384, SignatureScheme.RSA_PKCS1_SHA384, SignatureScheme.RSA_PSS_RSAE_SHA512, SignatureScheme.RSA_PKCS1_SHA512];

const CHROME_SUPPORTED_VERSIONS: number[] = [ProtocolVersion.TLS_1_3, ProtocolVersion.TLS_1_2];

const CHROME_KEY_SHARE_GROUPS: number[] = [NamedGroup.X25519];

const CHROME_KEY_SHARE_GROUPS_PQ: number[] = [NamedGroup.X25519_MLKEM768, NamedGroup.X25519];

const CHROME_CERT_COMPRESS: number[] = [CertCompressAlg.BROTLI];

const CHROME_DELEGATED_CREDS: number[] = [SignatureScheme.ECDSA_SECP256R1_SHA256, SignatureScheme.RSA_PSS_RSAE_SHA256, SignatureScheme.RSA_PSS_RSAE_SHA384, SignatureScheme.RSA_PSS_RSAE_SHA512];

function chromeExtensions(opts: { ech?: boolean; alps?: boolean; pq?: boolean }): TLSExtensionDef[] {
  const groups = opts.pq ? CHROME_GROUPS_PQ : CHROME_GROUPS;
  const keyShareGroups = opts.pq ? CHROME_KEY_SHARE_GROUPS_PQ : CHROME_KEY_SHARE_GROUPS;
  const list: TLSExtensionDef[] = [
    { type: ExtensionType.SERVER_NAME, data: ext.sniData },
    { type: ExtensionType.EXTENDED_MASTER_SECRET, data: () => ext.extendedMasterSecretData() },
    { type: ExtensionType.RENEGOTIATION_INFO, data: () => ext.renegotiationInfoData() },
    { type: ExtensionType.SUPPORTED_GROUPS, data: () => ext.supportedGroupsData(groups) },
    { type: ExtensionType.EC_POINT_FORMATS, data: () => ext.ecPointFormatsData([ECPointFormat.UNCOMPRESSED]) },
    { type: ExtensionType.SESSION_TICKET, data: () => ext.sessionTicketData() },
    { type: ExtensionType.APPLICATION_LAYER_PROTOCOL_NEGOTIATION, data: () => ext.alpnData(["h2", "http/1.1"]) },
    { type: ExtensionType.STATUS_REQUEST, data: () => ext.statusRequestData() },
    { type: ExtensionType.SIGNATURE_ALGORITHMS, data: () => ext.signatureAlgorithmsData(CHROME_SIGALGS) },
    { type: ExtensionType.SIGNED_CERTIFICATE_TIMESTAMP },
    { type: ExtensionType.KEY_SHARE, data: () => ext.keySharePlaceholder(keyShareGroups) },
    { type: ExtensionType.PSK_KEY_EXCHANGE_MODES, data: () => ext.pskKeyExchangeModesData([PskKeyExchangeMode.PSK_DHE_KE]) },
    { type: ExtensionType.SUPPORTED_VERSIONS, data: () => ext.supportedVersionsData(CHROME_SUPPORTED_VERSIONS) },
    { type: ExtensionType.COMPRESS_CERTIFICATE, data: () => ext.compressCertData(CHROME_CERT_COMPRESS) },
    { type: ExtensionType.PADDING },
  ];

  if (opts.alps) {
    list.push({
      type: ExtensionType.APPLICATION_SETTINGS,
      data: () => ext.applicationSettingsData(["h2"]),
    });
  }

  if (opts.ech) {
    list.push({
      type: ExtensionType.ENCRYPTED_CLIENT_HELLO,
      data: () => ext.echGreaseData(),
    });
  }

  list.push({
    type: ExtensionType.DELEGATED_CREDENTIALS,
    data: () => ext.delegatedCredentialsData(CHROME_DELEGATED_CREDS),
  });

  return list;
}

const CHROME_H2_SETTINGS: H2Setting[] = [
  { id: 1, value: 65536 },
  { id: 2, value: 0 },
  { id: 4, value: 6291456 },
  { id: 6, value: 262144 },
];

const CHROME_H2: H2Profile = {
  settings: CHROME_H2_SETTINGS,
  windowUpdate: 15663105,
  pseudoHeaderOrder: [":method", ":authority", ":scheme", ":path"],
  priorityFrames: [],
};

function chromeHeaders(version: string): HeaderProfile {
  const ua = `Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/${version} Safari/537.36`;
  return {
    userAgent: ua,
    headers: [
      ["sec-ch-ua-platform", '"Windows"'],
      ["user-agent", ua],
      ["sec-ch-ua", `"Chromium";v="${version.split(".")[0]}", "Not=A?Brand";v="8", "Google Chrome";v="${version.split(".")[0]}"`],
      ["sec-ch-ua-mobile", "?0"],
      ["accept", "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7"],
      ["sec-fetch-site", "none"],
      ["sec-fetch-mode", "navigate"],
      ["sec-fetch-user", "?1"],
      ["sec-fetch-dest", "document"],
      ["accept-encoding", "gzip, deflate, br, zstd"],
      ["accept-language", "en-US,en;q=0.9"],
    ],
  };
}

function chromeTLS(opts: { ech?: boolean; alps?: boolean; pq?: boolean } = {}): TLSProfile {
  const groups = opts.pq ? CHROME_GROUPS_PQ : CHROME_GROUPS;
  const keyShareGroups = opts.pq ? CHROME_KEY_SHARE_GROUPS_PQ : CHROME_KEY_SHARE_GROUPS;
  return {
    recordVersion: ProtocolVersion.TLS_1_0,
    clientVersion: ProtocolVersion.TLS_1_2,
    cipherSuites: CHROME_CIPHER_SUITES,
    compressionMethods: [0],
    extensions: chromeExtensions(opts),
    supportedGroups: groups,
    signatureAlgorithms: CHROME_SIGALGS,
    alpnProtocols: ["h2", "http/1.1"],
    grease: true,
    randomSessionId: true,
    certCompressAlgorithms: CHROME_CERT_COMPRESS,
    keyShareGroups: keyShareGroups,
    pskKeyExchangeModes: [PskKeyExchangeMode.PSK_DHE_KE],
    supportedVersions: CHROME_SUPPORTED_VERSIONS,
    ecPointFormats: [ECPointFormat.UNCOMPRESSED],
    delegatedCredentials: CHROME_DELEGATED_CREDS,
    applicationSettings: opts.alps ? ["h2"] : undefined,
  };
}

function chromeProfile(name: string, version: string, opts: { ech?: boolean; alps?: boolean; pq?: boolean } = {}): BrowserProfile {
  return {
    name,
    browser: "chrome",
    version,
    tls: chromeTLS(opts),
    h2: CHROME_H2,
    headers: chromeHeaders(version),
  };
}

/** Chrome 99 browser fingerprint profile. */
export const chrome99 = chromeProfile("chrome99", "99.0.4844.51");
/** Chrome 100 browser fingerprint profile. */
export const chrome100 = chromeProfile("chrome100", "100.0.4896.75");
/** Chrome 101 browser fingerprint profile. */
export const chrome101 = chromeProfile("chrome101", "101.0.4951.67");
/** Chrome 104 browser fingerprint profile. */
export const chrome104 = chromeProfile("chrome104", "104.0.5112.81");
/** Chrome 107 browser fingerprint profile. */
export const chrome107 = chromeProfile("chrome107", "107.0.5304.107");
/** Chrome 110 browser fingerprint profile. */
export const chrome110 = chromeProfile("chrome110", "110.0.5481.177");
/** Chrome 116 browser fingerprint profile. */
export const chrome116 = chromeProfile("chrome116", "116.0.5845.96", { alps: true });
/** Chrome 119 browser fingerprint profile. */
export const chrome119 = chromeProfile("chrome119", "119.0.6045.105", { alps: true });
/** Chrome 120 browser fingerprint profile. */
export const chrome120 = chromeProfile("chrome120", "120.0.6099.109", { alps: true, ech: true });
/** Chrome 123 browser fingerprint profile. */
export const chrome123 = chromeProfile("chrome123", "123.0.6312.86", { alps: true, ech: true });
/** Chrome 124 browser fingerprint profile. */
export const chrome124 = chromeProfile("chrome124", "124.0.6367.60", { alps: true, ech: true, pq: true });
/** Chrome 126 browser fingerprint profile. */
export const chrome126 = chromeProfile("chrome126", "126.0.6478.55", { alps: true, ech: true, pq: true });
/** Chrome 127 browser fingerprint profile. */
export const chrome127 = chromeProfile("chrome127", "127.0.6533.72", { alps: true, ech: true, pq: true });
/** Chrome 131 browser fingerprint profile. */
export const chrome131 = chromeProfile("chrome131", "131.0.6778.86", { alps: true, ech: true, pq: true });
/** Chrome 133 browser fingerprint profile. */
export const chrome133 = chromeProfile("chrome133", "133.0.6943.53", { alps: true, ech: true, pq: true });
/** Chrome 136 browser fingerprint profile. */
export const chrome136 = chromeProfile("chrome136", "136.0.7103.92", { alps: true, ech: true, pq: true });

/** Alias for the most recent Chrome profile. */
export const chromeLatest = chrome136;

/** Map of all available Chrome profiles keyed by name. */
export const chromeProfiles: ReadonlyMap<string, BrowserProfile> = new Map([
  ["chrome99", chrome99],
  ["chrome100", chrome100],
  ["chrome101", chrome101],
  ["chrome104", chrome104],
  ["chrome107", chrome107],
  ["chrome110", chrome110],
  ["chrome116", chrome116],
  ["chrome119", chrome119],
  ["chrome120", chrome120],
  ["chrome123", chrome123],
  ["chrome124", chrome124],
  ["chrome126", chrome126],
  ["chrome127", chrome127],
  ["chrome131", chrome131],
  ["chrome133", chrome133],
  ["chrome136", chrome136],
  ["chrome_latest", chrome136],
]);
