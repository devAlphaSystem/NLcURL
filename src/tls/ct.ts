/** Hash algorithms used in Signed Certificate Timestamps. */
export enum SCTHashAlgorithm {
  NONE = 0,
  MD5 = 1,
  SHA1 = 2,
  SHA224 = 3,
  SHA256 = 4,
  SHA384 = 5,
  SHA512 = 6,
}

/** Digital signature algorithms used in Signed Certificate Timestamps. */
export enum SCTSignatureAlgorithm {
  ANONYMOUS = 0,
  RSA = 1,
  DSA = 2,
  ECDSA = 3,
}

/** Signed Certificate Timestamp version identifiers. */
export enum SCTVersion {
  V1 = 0,
}

/** Parsed Signed Certificate Timestamp (RFC 6962). */
export interface SCT {
  /** SCT structure version. */
  version: SCTVersion;
  /** Log ID (SHA-256 hash of the log's public key). */
  logId: Buffer;
  /** Timestamp when the SCT was issued. */
  timestamp: Date;
  /** SCT extensions data. */
  extensions: Buffer;
  /** Hash algorithm used in the signature. */
  hashAlgorithm: SCTHashAlgorithm;
  /** Signature algorithm used. */
  signatureAlgorithm: SCTSignatureAlgorithm;
  /** Digital signature bytes. */
  signature: Buffer;
}

/** Result of validating SCTs for Certificate Transparency compliance. */
export interface SCTValidationResult {
  /** Whether the certificate meets CT compliance requirements. */
  compliant: boolean;
  /** Number of unique SCTs found. */
  sctCount: number;
  /** Deduplicated SCT entries. */
  scts: SCT[];
  /** Source from which the SCTs were obtained. */
  source?: "embedded" | "tls-extension" | "ocsp";
}

/**
 * Parse a serialized SCT list into individual SCT entries.
 *
 * @param {Buffer} data - TLS-encoded SCT list buffer.
 * @returns {SCT[]} Array of parsed {@link SCT} objects.
 */
export function parseSCTList(data: Buffer): SCT[] {
  if (data.length < 2) return [];

  const listLength = data.readUInt16BE(0);
  if (listLength + 2 > data.length) return [];

  const scts: SCT[] = [];
  let offset = 2;
  const end = 2 + listLength;

  while (offset + 2 <= end) {
    const sctLength = data.readUInt16BE(offset);
    offset += 2;

    if (offset + sctLength > end) break;

    const sct = parseSingleSCT(data.subarray(offset, offset + sctLength));
    if (sct) scts.push(sct);
    offset += sctLength;
  }

  return scts;
}

function parseSingleSCT(data: Buffer): SCT | null {
  if (data.length < 1 + 32 + 8 + 2 + 2 + 2) return null;

  let offset = 0;

  const version = data[offset]! as SCTVersion;
  if (version !== SCTVersion.V1) return null;
  offset += 1;

  const logId = Buffer.from(data.subarray(offset, offset + 32));
  offset += 32;

  const timestampMs = Number(data.readBigUInt64BE(offset));
  const timestamp = new Date(timestampMs);
  offset += 8;

  const extensionsLength = data.readUInt16BE(offset);
  offset += 2;
  const extensions = Buffer.from(data.subarray(offset, offset + extensionsLength));
  offset += extensionsLength;

  if (offset + 4 > data.length) return null;

  const hashAlgorithm = data[offset]! as SCTHashAlgorithm;
  offset += 1;
  const signatureAlgorithm = data[offset]! as SCTSignatureAlgorithm;
  offset += 1;

  const signatureLength = data.readUInt16BE(offset);
  offset += 2;

  if (offset + signatureLength > data.length) return null;
  const signature = Buffer.from(data.subarray(offset, offset + signatureLength));

  return {
    version,
    logId,
    timestamp,
    extensions,
    hashAlgorithm,
    signatureAlgorithm,
    signature,
  };
}

/**
 * Validate a set of SCTs for Certificate Transparency compliance.
 *
 * Deduplicates by log ID and requires at least two unique logs.
 *
 * @param {SCT[]} scts - Array of parsed SCTs.
 * @returns {SCTValidationResult} Validation result with compliance status.
 */
export function validateSCTs(scts: SCT[]): SCTValidationResult {
  const uniqueLogs = new Set<string>();
  const uniqueSCTs: SCT[] = [];
  for (const sct of scts) {
    const logIdHex = sct.logId.toString("hex");
    if (!uniqueLogs.has(logIdHex)) {
      uniqueLogs.add(logIdHex);
      uniqueSCTs.push(sct);
    }
  }

  return {
    compliant: uniqueLogs.size >= 2,
    sctCount: uniqueSCTs.length,
    scts: uniqueSCTs,
  };
}

/**
 * Extract embedded SCTs from a TLS socket's peer certificate.
 *
 * @param {{ getPeerCertificate?: (detailed?: boolean) => { raw?: Buffer; serialNumber?: string } }} socket - Socket with a `getPeerCertificate` method.
 * @returns {SCTValidationResult | undefined} Validation result, or `undefined` if SCTs cannot be extracted.
 */
export function extractSCTsFromSocket(socket: { getPeerCertificate?: (detailed?: boolean) => { raw?: Buffer; serialNumber?: string } }): SCTValidationResult | undefined {
  if (!socket.getPeerCertificate) return undefined;

  const cert = socket.getPeerCertificate(true);
  if (!cert || !cert.raw) return undefined;

  const sctExtOid = Buffer.from([0x06, 0x0a, 0x2b, 0x06, 0x01, 0x04, 0x01, 0xd6, 0x79, 0x02, 0x04, 0x02]);
  const extIdx = cert.raw.indexOf(sctExtOid);

  if (extIdx === -1) {
    return { compliant: false, sctCount: 0, scts: [] };
  }

  let offset = extIdx + sctExtOid.length;

  if (offset < cert.raw.length && cert.raw[offset] === 0x01) {
    offset += 3;
  }

  if (offset >= cert.raw.length || cert.raw[offset] !== 0x04) {
    return { compliant: false, sctCount: 0, scts: [] };
  }
  offset++;
  const result = readLength(cert.raw, offset);
  if (result.value === -1) return { compliant: false, sctCount: 0, scts: [] };
  offset += result.bytesRead;

  if (offset >= cert.raw.length || cert.raw[offset] !== 0x04) {
    const scts = parseSCTList(cert.raw.subarray(offset));
    const validation = validateSCTs(scts);
    validation.source = "embedded";
    return validation;
  }
  offset++;
  const innerResult = readLength(cert.raw, offset);
  if (innerResult.value === -1) return { compliant: false, sctCount: 0, scts: [] };
  offset += innerResult.bytesRead;

  const sctData = cert.raw.subarray(offset, offset + innerResult.value);
  const scts = parseSCTList(sctData);
  const validation = validateSCTs(scts);
  validation.source = "embedded";
  return validation;
}

function readLength(buf: Buffer, offset: number): { value: number; bytesRead: number } {
  if (offset >= buf.length) return { value: -1, bytesRead: 0 };
  const first = buf[offset]!;
  if (first < 0x80) return { value: first, bytesRead: 1 };
  const numBytes = first & 0x7f;
  if (numBytes === 0 || numBytes > 4 || offset + numBytes >= buf.length) return { value: -1, bytesRead: 0 };
  let value = 0;
  for (let i = 0; i < numBytes; i++) {
    value = (value << 8) | buf[offset + 1 + i]!;
  }
  return { value, bytesRead: 1 + numBytes };
}
