/**
 * Parsed Content-Range header fields.
 */
export interface ContentRange {
  unit: string;
  start: number;
  end: number;
  total: number;
}

/**
 * A contiguous byte range segment stored in cache.
 */
export interface RangeSegment {
  start: number;
  end: number;
  data: Buffer;
  etag?: string;
  storedAt: number;
}

/**
 * Represents all cached range segments for a given URL.
 */
export interface RangeCacheEntry {
  url: string;
  segments: RangeSegment[];
  totalSize: number;
  etag?: string;
  lastModified?: string;
}

/**
 * Parses a Content-Range header value into its component fields.
 *
 * @param {string} header - The raw Content-Range header value.
 * @returns {ContentRange|null} The parsed range, or `null` if the header is malformed.
 */
export function parseContentRange(header: string): ContentRange | null {
  const match = header.match(/^(\w+)\s+(\d+)-(\d+)\/(\d+|\*)/);
  if (!match) return null;

  const unit = match[1]!;
  const start = parseInt(match[2]!, 10);
  const end = parseInt(match[3]!, 10);
  const total = match[4] === "*" ? -1 : parseInt(match[4]!, 10);

  if (start > end) return null;
  if (total !== -1 && end >= total) return null;

  return { unit, start, end, total };
}

/**
 * Parses a Range request header into an array of byte ranges.
 *
 * @param {string} header - The raw Range header value (e.g. "bytes=0-499,1000-1499").
 * @returns {Array<[number, number|undefined]>|null} Parsed ranges, or `null` if invalid.
 */
export function parseRangeHeader(header: string): Array<[number, number | undefined]> | null {
  const match = header.match(/^bytes=(.+)/);
  if (!match) return null;

  const ranges: Array<[number, number | undefined]> = [];
  const parts = match[1]!.split(",");

  for (const part of parts) {
    const trimmed = part.trim();
    const dashIdx = trimmed.indexOf("-");
    if (dashIdx === -1) return null;

    const startStr = trimmed.substring(0, dashIdx);
    const endStr = trimmed.substring(dashIdx + 1);

    if (startStr === "" && endStr === "") return null;

    const start = startStr === "" ? -parseInt(endStr, 10) : parseInt(startStr, 10);
    const end = endStr === "" ? undefined : parseInt(endStr, 10);

    if (Number.isNaN(start)) return null;
    if (end !== undefined && Number.isNaN(end)) return null;

    ranges.push([start, end]);
  }

  return ranges.length > 0 ? ranges : null;
}

/**
 * Caches partial HTTP responses (206 Partial Content) and reassembles
 * byte ranges on subsequent lookups.
 *
 * @class
 */
export class RangeCache {
  private readonly entries = new Map<string, RangeCacheEntry>();
  private readonly maxEntries: number;
  private readonly maxSegmentsPerEntry: number;

  /**
   * Creates a new RangeCache.
   *
   * @param {Object} [config] - Optional cache limits.
   * @param {number} [config.maxEntries=200] - Maximum number of URLs to cache.
   * @param {number} [config.maxSegmentsPerEntry=100] - Maximum segments per URL.
   */
  constructor(config?: { maxEntries?: number; maxSegmentsPerEntry?: number }) {
    this.maxEntries = config?.maxEntries ?? 200;
    this.maxSegmentsPerEntry = config?.maxSegmentsPerEntry ?? 100;
  }

  /**
   * Stores a range segment for the given URL.
   *
   * @param {string} url - The resource URL.
   * @param {ContentRange} range - The content range descriptor.
   * @param {Buffer} data - The response body bytes for this range.
   * @param {Object} [meta] - Optional metadata.
   * @param {string} [meta.etag] - The entity tag for cache coherence.
   * @param {string} [meta.lastModified] - The Last-Modified date.
   */
  store(url: string, range: ContentRange, data: Buffer, meta?: { etag?: string; lastModified?: string }): void {
    let entry = this.entries.get(url);

    if (entry) {
      if (meta?.etag && entry.etag && meta.etag !== entry.etag) {
        entry.segments = [];
        entry.etag = meta.etag;
      }
    } else {
      if (this.entries.size >= this.maxEntries) {
        const firstKey = this.entries.keys().next().value;
        if (firstKey) this.entries.delete(firstKey);
      }
      entry = {
        url,
        segments: [],
        totalSize: range.total,
        etag: meta?.etag,
        lastModified: meta?.lastModified,
      };
      this.entries.set(url, entry);
    }

    if (range.total !== -1) {
      entry.totalSize = range.total;
    }

    entry.segments = entry.segments.filter((s) => s.end < range.start || s.start > range.end);

    if (entry.segments.length < this.maxSegmentsPerEntry) {
      entry.segments.push({
        start: range.start,
        end: range.end,
        data: Buffer.from(data),
        etag: meta?.etag,
        storedAt: Date.now(),
      });

      entry.segments.sort((a, b) => a.start - b.start);
    }
  }

  /**
   * Looks up cached bytes for a given byte range.
   *
   * @param {string} url - The resource URL.
   * @param {number} start - Start byte offset (inclusive).
   * @param {number} end - End byte offset (inclusive).
   * @returns {Buffer|null} The cached bytes, or `null` on a miss.
   */
  lookup(url: string, start: number, end: number): Buffer | null {
    const entry = this.entries.get(url);
    if (!entry) return null;

    const segment = entry.segments.find((s) => s.start <= start && s.end >= end);

    if (segment) {
      const offsetStart = start - segment.start;
      const offsetEnd = end - segment.start + 1;
      return segment.data.subarray(offsetStart, offsetEnd);
    }

    return null;
  }

  /**
   * Checks whether all bytes for a URL have been cached.
   *
   * @param {string} url - The resource URL.
   * @returns {boolean} `true` if the full resource is cached.
   */
  isComplete(url: string): boolean {
    const entry = this.entries.get(url);
    if (!entry || entry.totalSize <= 0) return false;

    let covered = 0;
    for (const segment of entry.segments) {
      if (segment.start > covered) return false;
      covered = Math.max(covered, segment.end + 1);
    }
    return covered >= entry.totalSize;
  }

  /**
   * Returns the range cache entry for a URL, if present.
   *
   * @param {string} url - The resource URL.
   * @returns {RangeCacheEntry|undefined} The cached entry.
   */
  get(url: string): RangeCacheEntry | undefined {
    return this.entries.get(url);
  }

  /**
   * Removes the cache entry for a URL.
   *
   * @param {string} url - The resource URL to evict.
   * @returns {boolean} `true` if an entry was removed.
   */
  delete(url: string): boolean {
    return this.entries.delete(url);
  }

  /**
   * Removes all cached range entries.
   */
  clear(): void {
    this.entries.clear();
  }

  /**
   * Returns the number of URLs with cached ranges.
   *
   * @returns {number} The entry count.
   */
  get size(): number {
    return this.entries.size;
  }
}
