/**
 * Extension data builders.
 *
 * These helpers produce raw extension_data bytes for various TLS
 * extensions.  They are used by browser profiles to populate the
 * extensions array in a declarative manner.
 */

import { BufferWriter } from '../utils/buffer-writer.js';
import {
  CipherSuite,
  ExtensionType,
  NamedGroup,
  SignatureScheme,
  ECPointFormat,
  PskKeyExchangeMode,
  CertCompressAlg,
  ProtocolVersion,
} from '../tls/constants.js';

// ---- helpers ----

/** Build SNI extension data.  RFC 6066 section 3. */
export function sniData(hostname: string): Buffer {
  const host = Buffer.from(hostname, 'ascii');
  const w = new BufferWriter(host.length + 16);
  // ServerNameList length (2 bytes)
  w.writeUInt16(host.length + 3 + 2);
  // list length
  w.writeUInt16(host.length + 3);
  // name_type = host_name (0)
  w.writeUInt8(0);
  // host name length + data
  w.writeUInt16(host.length);
  w.writeBytes(host);
  return w.toBuffer();
}

/** Build supported_versions extension data (for ClientHello). */
export function supportedVersionsData(versions: number[]): Buffer {
  const w = new BufferWriter(1 + versions.length * 2);
  w.writeUInt8(versions.length * 2);
  for (const v of versions) w.writeUInt16(v);
  return w.toBuffer();
}

/** Build supported_groups extension data. */
export function supportedGroupsData(groups: number[]): Buffer {
  const w = new BufferWriter(2 + groups.length * 2);
  w.writeUInt16(groups.length * 2);
  for (const g of groups) w.writeUInt16(g);
  return w.toBuffer();
}

/** Build ec_point_formats extension data. */
export function ecPointFormatsData(formats: number[]): Buffer {
  const w = new BufferWriter(1 + formats.length);
  w.writeUInt8(formats.length);
  for (const f of formats) w.writeUInt8(f);
  return w.toBuffer();
}

/** Build signature_algorithms extension data. */
export function signatureAlgorithmsData(algs: number[]): Buffer {
  const w = new BufferWriter(2 + algs.length * 2);
  w.writeUInt16(algs.length * 2);
  for (const a of algs) w.writeUInt16(a);
  return w.toBuffer();
}

/** Build ALPN extension data. */
export function alpnData(protocols: string[]): Buffer {
  let totalLen = 0;
  const bufs = protocols.map((p) => {
    const b = Buffer.from(p, 'ascii');
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

/** Build compress_certificate extension data. */
export function compressCertData(algorithms: number[]): Buffer {
  const w = new BufferWriter(1 + algorithms.length * 2);
  w.writeUInt8(algorithms.length * 2);
  for (const a of algorithms) w.writeUInt16(a);
  return w.toBuffer();
}

/** Build psk_key_exchange_modes extension data. */
export function pskKeyExchangeModesData(modes: number[]): Buffer {
  const w = new BufferWriter(1 + modes.length);
  w.writeUInt8(modes.length);
  for (const m of modes) w.writeUInt8(m);
  return w.toBuffer();
}

/** Build key_share extension data.  Actual key material is filled at
 *  handshake time; this returns a placeholder structure with the
 *  correct groups. */
export function keySharePlaceholder(groups: number[]): Buffer {
  // We will compute real key shares at handshake time.
  // For fingerprinting purposes this is not hashed into JA3.
  return Buffer.alloc(0);
}

/** Status request (OCSP) extension data -- single responder, no IDs,
 *  no extensions (the common case). */
export function statusRequestData(): Buffer {
  const w = new BufferWriter(5);
  w.writeUInt8(1); // status_type = ocsp
  w.writeUInt16(0); // responder_id_list length
  w.writeUInt16(0); // request_extensions length
  return w.toBuffer();
}

/** Session ticket extension data (empty, requests new ticket). */
export function sessionTicketData(): Buffer {
  return Buffer.alloc(0);
}

/** Extended master secret extension (empty data). */
export function extendedMasterSecretData(): Buffer {
  return Buffer.alloc(0);
}

/** Renegotiation info extension (initial handshake -- single 0 byte). */
export function renegotiationInfoData(): Buffer {
  return Buffer.from([0]);
}

/** Signed certificate timestamp extension (empty request). */
export function sctData(): Buffer {
  return Buffer.alloc(0);
}

/** Record size limit extension data. */
export function recordSizeLimitData(limit: number): Buffer {
  const w = new BufferWriter(2);
  w.writeUInt16(limit);
  return w.toBuffer();
}

/** Delegated credentials extension data. */
export function delegatedCredentialsData(sigAlgs: number[]): Buffer {
  const w = new BufferWriter(2 + sigAlgs.length * 2);
  w.writeUInt16(sigAlgs.length * 2);
  for (const a of sigAlgs) w.writeUInt16(a);
  return w.toBuffer();
}

/** Application settings (ALPS) extension data. */
export function applicationSettingsData(protocols: string[]): Buffer {
  let totalLen = 0;
  const bufs = protocols.map((p) => {
    const b = Buffer.from(p, 'ascii');
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

/** Encrypted client hello (ECH) -- outer extension with a GREASE
 *  payload so the extension shows in the fingerprint but does not
 *  require real ECH config. */
export function echGreaseData(): Buffer {
  // Type = outer (0), followed by a random GREASE cipher suite and
  // dummy payload.  This mirrors Chrome's GREASE ECH behavior.
  const w = new BufferWriter(8 + 32);
  w.writeUInt8(0); // ECHClientHelloType = outer
  // HpkeCipherSuite
  w.writeUInt16(0x0020); // KEM: DHKEM(X25519, HKDF-SHA256)
  w.writeUInt16(0x0001); // KDF: HKDF-SHA256
  w.writeUInt16(0x0001); // AEAD: AES-128-GCM
  w.writeUInt8(0); // config_id
  w.writeUInt16(32); // enc length
  const enc = Buffer.alloc(32);
  // Fill with random-looking but deterministic bytes for GREASE
  for (let i = 0; i < 32; i++) enc[i] = (i * 37 + 7) & 0xff;
  w.writeBytes(enc);
  w.writeUInt16(16); // payload length
  const payload = Buffer.alloc(16);
  for (let i = 0; i < 16; i++) payload[i] = (i * 53 + 13) & 0xff;
  w.writeBytes(payload);
  return w.toBuffer();
}
