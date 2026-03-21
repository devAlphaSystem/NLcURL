import { BufferWriter } from "../utils/buffer-writer.js";

/**
 * Build Server Name Indication extension data.
 *
 * @param {string} hostname - Target server hostname.
 * @returns {Buffer} Encoded SNI extension payload.
 */
export function sniData(hostname: string): Buffer {
  const host = Buffer.from(hostname, "ascii");
  const w = new BufferWriter(host.length + 16);
  w.writeUInt16(host.length + 3);
  w.writeUInt8(0);
  w.writeUInt16(host.length);
  w.writeBytes(host);
  return w.toBuffer();
}

/**
 * Build supported_versions extension data.
 *
 * @param {number[]} versions - TLS version code points.
 * @returns {Buffer} Encoded extension payload.
 */
export function supportedVersionsData(versions: number[]): Buffer {
  const w = new BufferWriter(1 + versions.length * 2);
  w.writeUInt8(versions.length * 2);
  for (const v of versions) w.writeUInt16(v);
  return w.toBuffer();
}

/**
 * Build supported_groups (named curves) extension data.
 *
 * @param {number[]} groups - Named group code points.
 * @returns {Buffer} Encoded extension payload.
 */
export function supportedGroupsData(groups: number[]): Buffer {
  const w = new BufferWriter(2 + groups.length * 2);
  w.writeUInt16(groups.length * 2);
  for (const g of groups) w.writeUInt16(g);
  return w.toBuffer();
}

/**
 * Build ec_point_formats extension data.
 *
 * @param {number[]} formats - EC point format identifiers.
 * @returns {Buffer} Encoded extension payload.
 */
export function ecPointFormatsData(formats: number[]): Buffer {
  const w = new BufferWriter(1 + formats.length);
  w.writeUInt8(formats.length);
  for (const f of formats) w.writeUInt8(f);
  return w.toBuffer();
}

/**
 * Build signature_algorithms extension data.
 *
 * @param {number[]} algs - Signature algorithm code points.
 * @returns {Buffer} Encoded extension payload.
 */
export function signatureAlgorithmsData(algs: number[]): Buffer {
  const w = new BufferWriter(2 + algs.length * 2);
  w.writeUInt16(algs.length * 2);
  for (const a of algs) w.writeUInt16(a);
  return w.toBuffer();
}

/**
 * Build Application-Layer Protocol Negotiation extension data.
 *
 * @param {string[]} protocols - ALPN protocol identifier strings.
 * @returns {Buffer} Encoded extension payload.
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
 * Build compress_certificate extension data.
 *
 * @param {number[]} algorithms - Certificate compression algorithm identifiers.
 * @returns {Buffer} Encoded extension payload.
 */
export function compressCertData(algorithms: number[]): Buffer {
  const w = new BufferWriter(1 + algorithms.length * 2);
  w.writeUInt8(algorithms.length * 2);
  for (const a of algorithms) w.writeUInt16(a);
  return w.toBuffer();
}

/**
 * Build psk_key_exchange_modes extension data.
 *
 * @param {number[]} modes - PSK key exchange mode identifiers.
 * @returns {Buffer} Encoded extension payload.
 */
export function pskKeyExchangeModesData(modes: number[]): Buffer {
  const w = new BufferWriter(1 + modes.length);
  w.writeUInt8(modes.length);
  for (const m of modes) w.writeUInt8(m);
  return w.toBuffer();
}

/**
 * Build a key_share extension placeholder (populated later during handshake).
 *
 * @param {number[]} groups - Named groups to reserve key share entries for.
 * @returns {Buffer} Empty buffer placeholder.
 */
export function keySharePlaceholder(_groups: number[]): Buffer {
  return Buffer.alloc(0);
}

/**
 * Build status_request (OCSP stapling) extension data.
 *
 * @returns {Buffer} Encoded extension payload.
 */
export function statusRequestData(): Buffer {
  const w = new BufferWriter(5);
  w.writeUInt8(1);
  w.writeUInt16(0);
  w.writeUInt16(0);
  return w.toBuffer();
}

/**
 * Build an empty session_ticket extension.
 *
 * @returns {Buffer} Empty buffer for session ticket extension.
 */
export function sessionTicketData(): Buffer {
  return Buffer.alloc(0);
}

/**
 * Build an empty extended_master_secret extension.
 *
 * @returns {Buffer} Empty buffer signaling extended master secret support.
 */
export function extendedMasterSecretData(): Buffer {
  return Buffer.alloc(0);
}

/**
 * Build renegotiation_info extension data.
 *
 * @returns {Buffer} Encoded renegotiation info with zero-length field.
 */
export function renegotiationInfoData(): Buffer {
  return Buffer.from([0]);
}

/**
 * Build an empty signed_certificate_timestamp extension.
 *
 * @returns {Buffer} Empty buffer requesting SCT data.
 */
export function sctData(): Buffer {
  return Buffer.alloc(0);
}

/**
 * Build record_size_limit extension data.
 *
 * @param {number} limit - Maximum record fragment size.
 * @returns {Buffer} Encoded extension payload.
 */
export function recordSizeLimitData(limit: number): Buffer {
  const w = new BufferWriter(2);
  w.writeUInt16(limit);
  return w.toBuffer();
}

/**
 * Build delegated_credentials extension data.
 *
 * @param {number[]} sigAlgs - Signature algorithm code points accepted for delegated credentials.
 * @returns {Buffer} Encoded extension payload.
 */
export function delegatedCredentialsData(sigAlgs: number[]): Buffer {
  const w = new BufferWriter(2 + sigAlgs.length * 2);
  w.writeUInt16(sigAlgs.length * 2);
  for (const a of sigAlgs) w.writeUInt16(a);
  return w.toBuffer();
}

/**
 * Build application_settings (ALPS) extension data.
 *
 * @param {string[]} protocols - Protocol identifier strings for application settings.
 * @returns {Buffer} Encoded extension payload.
 */
export function applicationSettingsData(protocols: string[]): Buffer {
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
 * Build an Encrypted Client Hello GREASE extension.
 *
 * @returns {Buffer} Deterministic ECH GREASE payload for fingerprint consistency.
 */
export function echGreaseData(): Buffer {
  const w = new BufferWriter(8 + 32 + 2 + 16);
  w.writeUInt8(0);
  w.writeUInt16(0x0020);
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

/**
 * Build a padding extension of the specified length.
 *
 * @param {number} paddingLength - Number of zero bytes to include.
 * @returns {Buffer} Zero-filled buffer of the requested length.
 */
export function paddingData(paddingLength: number): Buffer {
  return Buffer.alloc(Math.max(0, paddingLength));
}
