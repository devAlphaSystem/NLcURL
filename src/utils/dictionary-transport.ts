import { createHash } from "node:crypto";

/** Stored compression dictionary with associated metadata. */
export interface CompressionDictionary {
  /** SHA-256 hash of the dictionary data in structured field format. */
  hash: string;
  /** URL from which the dictionary was fetched. */
  url: string;
  /** Raw dictionary bytes. */
  data: Buffer;
  /** Timestamp (ms since epoch) when the dictionary was stored. */
  storedAt: number;
  /** URL match pattern from the `Use-As-Dictionary` header. */
  matchPattern?: string;
  /** Expiry timestamp (ms since epoch). */
  expiresAt?: number;
}

/** Configuration for the compression dictionary store. */
export interface DictionaryConfig {
  /** Maximum number of dictionaries to cache. */
  maxEntries?: number;
  /** Maximum individual dictionary size in bytes. */
  maxDictionarySize?: number;
}

/**
 * Parse a `Use-As-Dictionary` response header.
 *
 * @param {string} header - Raw header value.
 * @returns {{ match?: string; matchDest?: string[]; id?: string } | null} Parsed fields, or `null` if the header is empty.
 */
export function parseUseAsDictionary(header: string): {
  match?: string;
  matchDest?: string[];
  id?: string;
} | null {
  if (!header) return null;

  const result: { match?: string; matchDest?: string[]; id?: string } = {};

  const matchRegex = /match="([^"]+)"/;
  const matchMatch = header.match(matchRegex);
  if (matchMatch) {
    result.match = matchMatch[1];
  }

  const destRegex = /match-dest=\(([^)]*)\)/;
  const destMatch = header.match(destRegex);
  if (destMatch) {
    result.matchDest = destMatch[1]!
      .split(/\s+/)
      .map((s) => s.replace(/"/g, ""))
      .filter(Boolean);
  }

  const idRegex = /id="([^"]+)"/;
  const idMatch = header.match(idRegex);
  if (idMatch) {
    result.id = idMatch[1];
  }

  return result;
}

/**
 * Compute the SHA-256 structured hash of dictionary data.
 *
 * @param {Buffer} data - Raw dictionary bytes.
 * @returns {string} Hash string in structured field byte-sequence format.
 */
export function computeDictionaryHash(data: Buffer): string {
  const hash = createHash("sha256").update(data).digest("base64");
  return `:${hash}:`;
}

/**
 * Build an `Available-Dictionary` request header value.
 *
 * @param {string} hash - Dictionary hash.
 * @returns {string} Header value string.
 */
export function buildAvailableDictionaryHeader(hash: string): string {
  return hash;
}

/**
 * Append dictionary-based encodings to an `Accept-Encoding` header.
 *
 * @param {string} [existingEncoding] - Current `Accept-Encoding` value.
 * @returns {string} Updated encoding string with `dcb` and `dcz` appended.
 */
export function buildDictionaryAcceptEncoding(existingEncoding?: string): string {
  const base = existingEncoding ?? "gzip, deflate, br";
  const encodings = base.split(",").map((s) => s.trim());

  if (!encodings.includes("dcb")) encodings.push("dcb");
  if (!encodings.includes("dcz")) encodings.push("dcz");

  return encodings.join(", ");
}

/** Cache of compression dictionaries for shared dictionary transport. */
export class DictionaryStore {
  private readonly dictionaries = new Map<string, CompressionDictionary>();
  private readonly maxEntries: number;
  private readonly maxDictionarySize: number;

  /**
   * Create a new dictionary store.
   *
   * @param {DictionaryConfig} [config] - Cache size and dictionary size limits.
   */
  constructor(config?: DictionaryConfig) {
    this.maxEntries = config?.maxEntries ?? 50;
    this.maxDictionarySize = config?.maxDictionarySize ?? 10 * 1024 * 1024;
  }

  /**
   * Store a dictionary response.
   *
   * @param {string} url - URL the dictionary was fetched from.
   * @param {Buffer} data - Raw dictionary bytes.
   * @param {{ match?: string; id?: string }} [metadata] - Match pattern and ID from the response header.
   * @param {number} [maxAge] - Maximum age in seconds.
   */
  store(url: string, data: Buffer, metadata?: { match?: string; id?: string }, maxAge?: number): void {
    if (data.length > this.maxDictionarySize) return;

    if (this.dictionaries.size >= this.maxEntries) {
      let oldest: string | undefined;
      let oldestTime = Infinity;
      for (const [key, entry] of this.dictionaries) {
        if (entry.storedAt < oldestTime) {
          oldestTime = entry.storedAt;
          oldest = key;
        }
      }
      if (oldest) this.dictionaries.delete(oldest);
    }

    const hash = computeDictionaryHash(data);
    const now = Date.now();
    this.dictionaries.set(hash, {
      hash,
      url,
      data,
      storedAt: now,
      matchPattern: metadata?.match,
      expiresAt: maxAge ? now + maxAge * 1000 : undefined,
    });
  }

  /**
   * Find a dictionary whose match pattern covers the given request URL.
   *
   * @param {string} requestUrl - URL being requested.
   * @returns {CompressionDictionary | undefined} Matching dictionary, or `undefined` if none found.
   */
  findForUrl(requestUrl: string): CompressionDictionary | undefined {
    const now = Date.now();

    for (const dict of this.dictionaries.values()) {
      if (dict.expiresAt && dict.expiresAt < now) {
        this.dictionaries.delete(dict.hash);
        continue;
      }

      if (dict.matchPattern) {
        if (matchesPattern(requestUrl, dict.matchPattern, dict.url)) {
          return dict;
        }
      }
    }

    return undefined;
  }

  /**
   * Retrieve a dictionary by its hash.
   *
   * @param {string} hash - Dictionary hash string.
   * @returns {CompressionDictionary | undefined} Dictionary entry, or `undefined` if not found.
   */
  getByHash(hash: string): CompressionDictionary | undefined {
    return this.dictionaries.get(hash);
  }

  /** Number of dictionaries currently stored. */
  get size(): number {
    return this.dictionaries.size;
  }

  /** Remove all stored dictionaries. */
  clear(): void {
    this.dictionaries.clear();
  }
}

function matchesPattern(requestUrl: string, pattern: string, dictionaryUrl: string): boolean {
  try {
    const dictBase = new URL(dictionaryUrl);
    const reqUrl = new URL(requestUrl);

    if (reqUrl.origin !== dictBase.origin) return false;

    if (pattern === "*" || pattern === "/*") return true;

    if (pattern.endsWith("*")) {
      const prefix = pattern.slice(0, -1);
      return reqUrl.pathname.startsWith(prefix);
    }

    return reqUrl.pathname === pattern;
  } catch {
    return false;
  }
}
