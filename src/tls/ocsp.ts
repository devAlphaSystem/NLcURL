/** OCSP response status codes (RFC 6960). */
export enum OCSPResponseStatus {
  SUCCESSFUL = 0,
  MALFORMED_REQUEST = 1,
  INTERNAL_ERROR = 2,
  TRY_LATER = 3,
  SIG_REQUIRED = 5,
  UNAUTHORIZED = 6,
}

/** Certificate revocation status from an OCSP response. */
export enum OCSPCertStatus {
  GOOD = 0,
  REVOKED = 1,
  UNKNOWN = 2,
}

/** Parsed result of an OCSP response. */
export interface OCSPResult {
  /** Overall OCSP response status. */
  status: OCSPResponseStatus;
  /** Revocation status of the queried certificate. */
  certStatus?: OCSPCertStatus;
  /** Start of the validity window for this response. */
  thisUpdate?: Date;
  /** End of the validity window for this response. */
  nextUpdate?: Date;
  /** Time when the OCSP responder produced this response. */
  producedAt?: Date;
}

/**
 * Parse a DER-encoded OCSP response.
 *
 * @param {Buffer} derResponse - Raw DER bytes.
 * @returns {OCSPResult} Parsed OCSP result.
 */
export function parseOCSPResponse(derResponse: Buffer): OCSPResult {
  if (!derResponse || derResponse.length < 3) {
    return { status: OCSPResponseStatus.MALFORMED_REQUEST };
  }

  let offset = 0;

  if (derResponse[offset] !== 0x30) {
    return { status: OCSPResponseStatus.MALFORMED_REQUEST };
  }
  offset++;
  const { value: outerLen, bytesRead: outerLenBytes } = readASN1Length(derResponse, offset);
  if (outerLen === -1) return { status: OCSPResponseStatus.MALFORMED_REQUEST };
  offset += outerLenBytes;

  if (derResponse[offset] !== 0x0a) {
    return { status: OCSPResponseStatus.MALFORMED_REQUEST };
  }
  offset++;
  const statusLen = derResponse[offset]!;
  offset++;
  if (statusLen !== 1 || offset >= derResponse.length) {
    return { status: OCSPResponseStatus.MALFORMED_REQUEST };
  }
  const responseStatus = derResponse[offset]! as OCSPResponseStatus;
  offset++;

  if (responseStatus !== OCSPResponseStatus.SUCCESSFUL) {
    return { status: responseStatus };
  }

  const result: OCSPResult = { status: responseStatus };

  const certStatusResult = findCertStatus(derResponse, offset);
  if (certStatusResult !== undefined) {
    result.certStatus = certStatusResult;
  }

  return result;
}

/**
 * Check whether an OCSP result indicates the certificate is valid.
 *
 * @param {OCSPResult} result - Parsed OCSP result.
 * @returns {boolean} `false` only if the certificate is explicitly revoked.
 */
export function isOCSPValid(result: OCSPResult): boolean {
  if (result.status !== OCSPResponseStatus.SUCCESSFUL) {
    return true;
  }
  if (result.certStatus === OCSPCertStatus.REVOKED) {
    return false;
  }
  return true;
}

/**
 * Validate OCSP stapling on a TLS socket.
 *
 * @param {{ once(event: string, handler: (...args: any[]) => void): void }} socket - Socket emitter that fires an `"OCSPResponse"` event.
 * @param {{ timeout?: number }} [options] - Optional timeout configuration.
 * @returns {Promise<OCSPResult|undefined>} Parsed OCSP result, or `undefined` if no stapled response.
 */
export function validateOCSPStapling(socket: { once(event: string, handler: (...args: any[]) => void): void }, options?: { timeout?: number }): Promise<OCSPResult | undefined> {
  return new Promise((resolve) => {
    const timeout = options?.timeout ?? 5000;
    let timer: ReturnType<typeof setTimeout> | undefined;

    const onResponse = (response: Buffer) => {
      if (timer) clearTimeout(timer);
      if (!response || response.length === 0) {
        resolve(undefined);
        return;
      }
      resolve(parseOCSPResponse(response));
    };

    socket.once("OCSPResponse", onResponse);

    timer = setTimeout(() => {
      resolve(undefined);
    }, timeout);
  });
}

function readASN1Length(buf: Buffer, offset: number): { value: number; bytesRead: number } {
  if (offset >= buf.length) return { value: -1, bytesRead: 0 };
  const first = buf[offset]!;
  if (first < 0x80) {
    return { value: first, bytesRead: 1 };
  }
  const numBytes = first & 0x7f;
  if (numBytes === 0 || numBytes > 4 || offset + numBytes >= buf.length) {
    return { value: -1, bytesRead: 0 };
  }
  let value = 0;
  for (let i = 0; i < numBytes; i++) {
    value = (value << 8) | buf[offset + 1 + i]!;
  }
  return { value, bytesRead: 1 + numBytes };
}

function findCertStatus(buf: Buffer, startOffset: number): OCSPCertStatus | undefined {
  for (let i = startOffset; i < buf.length - 2; i++) {
    const tag = buf[i]!;
    if (tag === 0x80 && buf[i + 1] === 0x00) {
      return OCSPCertStatus.GOOD;
    }
    if (tag === 0xa1) {
      return OCSPCertStatus.REVOKED;
    }
    if (tag === 0x82 && buf[i + 1] === 0x00) {
      return OCSPCertStatus.UNKNOWN;
    }
  }
  return undefined;
}
