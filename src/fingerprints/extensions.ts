import { BufferWriter } from "../utils/buffer-writer.js";
import { CipherSuite, ExtensionType, NamedGroup, SignatureScheme, ECPointFormat, PskKeyExchangeMode, CertCompressAlg, ProtocolVersion } from "../tls/constants.js";

/**
 * Builds the SNI (Server Name Indication) extension payload for the given
 * hostname, encoded as a TLS `HostName` name list structure per RFC 6066.
 *
 * @param {string} hostname - The ASCII server name to advertise.
 * @returns {Buffer} Encoded SNI extension data.
 */
export function sniData(hostname: string): Buffer {
  const host = Buffer.from(hostname, "ascii");
  const w = new BufferWriter(host.length + 16);
  w.writeUInt16(host.length + 3 + 2);
  w.writeUInt16(host.length + 3);
  w.writeUInt8(0);
  w.writeUInt16(host.length);
  w.writeBytes(host);
  return w.toBuffer();
}

/**
 * Builds the `supported_versions` extension payload listing the given TLS
 * version codes in the order provided.
 *
 * @param {number[]} versions - Ordered TLS version codes (e.g. `[0x0304, 0x0303]`).
 * @returns {Buffer} Encoded supported_versions extension data.
 */
export function supportedVersionsData(versions: number[]): Buffer {
  const w = new BufferWriter(1 + versions.length * 2);
  w.writeUInt8(versions.length * 2);
  for (const v of versions) w.writeUInt16(v);
  return w.toBuffer();
}

/**
 * Builds the `supported_groups` extension payload listing the given named
 * group codes (elliptic curves and finite-field groups).
 *
 * @param {number[]} groups - Ordered named group codes (e.g. `[0x001d, 0x0017]`).
 * @returns {Buffer} Encoded supported_groups extension data.
 */
export function supportedGroupsData(groups: number[]): Buffer {
  const w = new BufferWriter(2 + groups.length * 2);
  w.writeUInt16(groups.length * 2);
  for (const g of groups) w.writeUInt16(g);
  return w.toBuffer();
}

/**
 * Builds the `ec_point_formats` extension payload specifying the supported
 * EC point encoding formats.
 *
 * @param {number[]} formats - EC point format codes (e.g. `[0]` for uncompressed).
 * @returns {Buffer} Encoded ec_point_formats extension data.
 */
export function ecPointFormatsData(formats: number[]): Buffer {
  const w = new BufferWriter(1 + formats.length);
  w.writeUInt8(formats.length);
  for (const f of formats) w.writeUInt8(f);
  return w.toBuffer();
}

/**
 * Builds the `signature_algorithms` extension payload listing the supported
 * signature scheme codes in the order provided.
 *
 * @param {number[]} algs - Ordered signature scheme codes (e.g. `[0x0403, 0x0804]`).
 * @returns {Buffer} Encoded signature_algorithms extension data.
 */
export function signatureAlgorithmsData(algs: number[]): Buffer {
  const w = new BufferWriter(2 + algs.length * 2);
  w.writeUInt16(algs.length * 2);
  for (const a of algs) w.writeUInt16(a);
  return w.toBuffer();
}

/**
 * Builds the ALPN (Application-Layer Protocol Negotiation) extension payload
 * advertising the given protocol name strings in preference order.
 *
 * @param {string[]} protocols - Protocol names in preference order (e.g. `['h2', 'http/1.1']`).
 * @returns {Buffer} Encoded ALPN extension data.
 */
export function alpnData(protocols: string[]): Buffer {
  let totalLen = 0;
  const bufs = protocols.map((p) => {
    const b = Buffer.from(p, "ascii");
    totalLen += 1 + b.length;
    return b;
  });
  const w = new BufferWriter(2 + totalLen);
  w.writeUInt16(totalLen);
  for (const b of bufs) {
    w.writeUInt8(b.length);
    w.writeBytes(b);
  }
  return w.toBuffer();
}

/**
 * Builds the `compress_certificate` extension payload listing the supported
 * certificate compression algorithm codes (RFC 8879).
 *
 * @param {number[]} algorithms - Compression algorithm codes (e.g. `[2]` for brotli).
 * @returns {Buffer} Encoded compress_certificate extension data.
 */
export function compressCertData(algorithms: number[]): Buffer {
  const w = new BufferWriter(1 + algorithms.length * 2);
  w.writeUInt8(algorithms.length * 2);
  for (const a of algorithms) w.writeUInt16(a);
  return w.toBuffer();
}

/**
 * Builds the `psk_key_exchange_modes` extension payload specifying the
 * supported PSK key exchange mode codes.
 *
 * @param {number[]} modes - PSK key exchange mode codes (e.g. `[1]` for psk_dhe_ke).
 * @returns {Buffer} Encoded psk_key_exchange_modes extension data.
 */
export function pskKeyExchangeModesData(modes: number[]): Buffer {
  const w = new BufferWriter(1 + modes.length);
  w.writeUInt8(modes.length);
  for (const m of modes) w.writeUInt8(m);
  return w.toBuffer();
}

/**
 * Returns an empty buffer as a placeholder for the `key_share` extension.
 * The actual key share data is computed and injected at ClientHello build time
 * by the handshake engine, which needs the private keys to complete the DH.
 *
 * @param {number[]} groups - Named group codes for which key shares will be generated.
 * @returns {Buffer} Empty placeholder buffer.
 */
export function keySharePlaceholder(groups: number[]): Buffer {
  return Buffer.alloc(0);
}

/**
 * Builds the `status_request` extension payload requesting OCSP stapling
 * from the server (RFC 6066 §8).
 *
 * @returns {Buffer} Encoded status_request extension data.
 */
export function statusRequestData(): Buffer {
  const w = new BufferWriter(5);
  w.writeUInt8(1);
  w.writeUInt16(0);
  w.writeUInt16(0);
  return w.toBuffer();
}

/**
 * Returns an empty buffer for the `session_ticket` extension, signalling
 * that the client supports TLS session tickets but has none to present.
 *
 * @returns {Buffer} Empty session_ticket extension payload.
 */
export function sessionTicketData(): Buffer {
  return Buffer.alloc(0);
}

/**
 * Returns an empty buffer for the `extended_master_secret` extension (RFC 7627),
 * which signals support for the extended master secret computation.
 *
 * @returns {Buffer} Empty extended_master_secret extension payload.
 */
export function extendedMasterSecretData(): Buffer {
  return Buffer.alloc(0);
}

/**
 * Builds the `renegotiation_info` extension payload with an empty renegotiated
 * connection field, indicating that this is an initial TLS handshake (RFC 5746).
 *
 * @returns {Buffer} Encoded renegotiation_info extension data (`[0x00]`).
 */
export function renegotiationInfoData(): Buffer {
  return Buffer.from([0]);
}

/**
 * Returns an empty buffer for the `signed_certificate_timestamp` extension
 * (RFC 6962), signalling SCT support without providing any timestamps.
 *
 * @returns {Buffer} Empty SCT extension payload.
 */
export function sctData(): Buffer {
  return Buffer.alloc(0);
}

/**
 * Builds the `record_size_limit` extension payload (RFC 8449) specifying the
 * maximum plaintext record size the client is willing to receive.
 *
 * @param {number} limit - Maximum record size in bytes (typically 16384 for browsers).
 * @returns {Buffer} Encoded record_size_limit extension data.
 */
export function recordSizeLimitData(limit: number): Buffer {
  const w = new BufferWriter(2);
  w.writeUInt16(limit);
  return w.toBuffer();
}

/**
 * Builds the `delegated_credentials` extension payload (RFC 9345) listing
 * the signature algorithms acceptable for use with delegated credentials.
 *
 * @param {number[]} sigAlgs - Signature algorithm codes acceptable for delegated credentials.
 * @returns {Buffer} Encoded delegated_credentials extension data.
 */
export function delegatedCredentialsData(sigAlgs: number[]): Buffer {
  const w = new BufferWriter(2 + sigAlgs.length * 2);
  w.writeUInt16(sigAlgs.length * 2);
  for (const a of sigAlgs) w.writeUInt16(a);
  return w.toBuffer();
}

/**
 * Builds the `application_settings` (ALPS) extension payload for the given
 * protocol names, a Chrome-specific extension that negotiates application-level
 * settings over TLS.
 *
 * @param {string[]} protocols - ALPN protocol names to include in the ALPS extension.
 * @returns {Buffer} Encoded application_settings extension data.
 */
export function applicationSettingsData(protocols: string[]): Buffer {
  let totalLen = 0;
  const bufs = protocols.map((p) => {
    const b = Buffer.from(p, "ascii");
    totalLen += 2 + b.length;
    return b;
  });
  const w = new BufferWriter(2 + totalLen);
  w.writeUInt16(totalLen);
  for (const b of bufs) {
    w.writeUInt16(b.length);
    w.writeBytes(b);
  }
  return w.toBuffer();
}

/**
 * Builds a synthetic Encrypted Client Hello (ECH) GREASE extension payload
 * (draft-ietf-tls-esni). This does not perform real ECH; it emits a
 * deterministic fake payload that matches the extension structure browsers send
 * when the server does not advertise real ECH support.
 *
 * @returns {Buffer} Encoded ECH GREASE extension data.
 */
export function echGreaseData(): Buffer {
  const w = new BufferWriter(8 + 32);
  w.writeUInt8(0);
  w.writeUInt16(0x0020);
  w.writeUInt16(0x0001);
  w.writeUInt16(0x0001);
  w.writeUInt8(0);
  w.writeUInt16(32);
  const enc = Buffer.alloc(32);
  for (let i = 0; i < 32; i++) enc[i] = (i * 37 + 7) & 0xff;
  w.writeBytes(enc);
  w.writeUInt16(16);
  const payload = Buffer.alloc(16);
  for (let i = 0; i < 16; i++) payload[i] = (i * 53 + 13) & 0xff;
  w.writeBytes(payload);
  return w.toBuffer();
}
