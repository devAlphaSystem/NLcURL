const FORBIDDEN_TRAILER_FIELDS = new Set(["transfer-encoding", "content-length", "host", "cache-control", "expect", "max-forwards", "pragma", "range", "te", "authorization", "content-encoding", "content-range", "content-type", "trailer", "set-cookie"]);

/**
 * Check whether a header name is allowed as an HTTP trailer field.
 *
 * @param {string} name - Header field name.
 * @returns {boolean} `true` if the name is not in the forbidden trailer fields set.
 */
export function isValidTrailerField(name: string): boolean {
  return !FORBIDDEN_TRAILER_FIELDS.has(name.toLowerCase());
}

/**
 * Serialize trailer fields into a wire-format buffer.
 *
 * @param {Record<string, string>} trailers - Key-value pairs of trailer fields.
 * @returns {Buffer} CRLF-delimited buffer of valid trailer fields.
 */
export function serializeTrailers(trailers: Record<string, string>): Buffer {
  const lines: string[] = [];
  for (const [name, value] of Object.entries(trailers)) {
    if (isValidTrailerField(name)) {
      lines.push(`${name}: ${value}`);
    }
  }
  return Buffer.from(lines.join("\r\n") + "\r\n", "ascii");
}

/**
 * Parse trailer field data into a key-value record.
 *
 * @param {Buffer} data - Raw trailer data buffer.
 * @returns {Record<string, string>} Parsed trailer fields keyed by lowercase name.
 */
export function parseTrailers(data: Buffer): Record<string, string> {
  const trailers: Record<string, string> = {};
  const text = data.toString("ascii");
  const lines = text.split("\r\n");
  for (const line of lines) {
    const colonIdx = line.indexOf(":");
    if (colonIdx < 0) continue;
    const name = line.substring(0, colonIdx).trim().toLowerCase();
    const value = line.substring(colonIdx + 1).trim();
    if (name && isValidTrailerField(name)) {
      trailers[name] = value;
    }
  }
  return trailers;
}

/**
 * Build a Trailer header value listing the trailer field names.
 *
 * @param {string[]} fieldNames - Trailer field names to advertise.
 * @returns {string} Comma-separated string of valid trailer field names.
 */
export function buildTrailerHeader(fieldNames: string[]): string {
  return fieldNames.filter(isValidTrailerField).join(", ");
}
