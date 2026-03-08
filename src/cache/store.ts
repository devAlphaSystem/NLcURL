import type { CacheConfig, CacheDirectives, CacheEntry, CacheLookupResult, CacheMode } from "./types.js";
import type { NLcURLRequest } from "../core/request.js";
import { NLcURLResponse } from "../core/response.js";

const DEFAULT_MAX_ENTRIES = 1000;
const DEFAULT_MAX_SIZE = 50 * 1024 * 1024;

/** HTTP methods whose responses may be cached (RFC 9111 §3). */
const CACHEABLE_METHODS = new Set(["GET", "HEAD"]);

/** Status codes that are cacheable by default (RFC 9111 §3). */
const CACHEABLE_STATUS = new Set([200, 203, 204, 206, 300, 301, 308, 404, 405, 410, 414, 501]);

/**
 * In-memory HTTP response cache implementing RFC 9111.
 *
 * Features:
 * - Cache-Control directive parsing and freshness calculation
 * - ETag / Last-Modified conditional request header injection
 * - 304 Not Modified response merging
 * - Vary header support
 * - LRU eviction by entry count and total body size
 * - Range request passthrough (does not cache partial responses by default)
 */
export class CacheStore {
  private readonly entries = new Map<string, CacheEntry>();
  private readonly maxEntries: number;
  private readonly maxSize: number;
  private currentSize = 0;
  private readonly mode: CacheMode;
  /** Monotonic counter for deterministic LRU ordering within the same ms. */
  private accessCounter = 0;

  constructor(config?: CacheConfig) {
    this.maxEntries = config?.maxEntries ?? DEFAULT_MAX_ENTRIES;
    this.maxSize = config?.maxSize ?? DEFAULT_MAX_SIZE;
    this.mode = config?.mode ?? "default";
  }

  /**
   * Generates a cache key from a request. The key is `METHOD:URL`.
   */
  static cacheKey(method: string, url: string): string {
    return `${method.toUpperCase()}:${url}`;
  }

  /**
   * Looks up a cached response and evaluates its freshness.
   *
   * @param req - The outgoing request to match against cache.
   * @returns A lookup result with the entry and freshness status.
   */
  lookup(req: NLcURLRequest): CacheLookupResult {
    const method = (req.method ?? "GET").toUpperCase();
    if (!CACHEABLE_METHODS.has(method)) {
      return { fresh: false, staleWhileRevalidate: false };
    }

    const key = CacheStore.cacheKey(method, req.url);
    const entry = this.entries.get(key);
    if (!entry) {
      return { fresh: false, staleWhileRevalidate: false };
    }

    if (!this.varyMatches(entry, req)) {
      return { fresh: false, staleWhileRevalidate: false };
    }

    entry.lastAccessedAt = ++this.accessCounter;

    const age = (Date.now() - entry.storedAt) / 1000;
    const freshness = computeFreshnessLifetime(entry);
    const fresh = age < freshness;

    let staleWhileRevalidate = false;
    if (!fresh && entry.directives.staleWhileRevalidate !== undefined) {
      staleWhileRevalidate = age < freshness + entry.directives.staleWhileRevalidate;
    }

    return { entry, fresh, staleWhileRevalidate };
  }

  /**
   * Determines what action to take for a request given the cache state
   * and the configured cache mode.
   *
   * Returns conditional headers to add (If-None-Match / If-Modified-Since)
   * when the entry is stale and needs revalidation.
   */
  evaluate(
    req: NLcURLRequest,
    modeOverride?: CacheMode,
  ): {
    conditionalHeaders?: Record<string, string>;
    shouldStore: boolean;
    matchedEntry?: CacheEntry;
    serveCached?: CacheEntry;
  } {
    const mode = modeOverride ?? this.mode;

    if (mode === "no-store") {
      return { shouldStore: false };
    }

    const result = this.lookup(req);

    if (mode === "force-cache" && result.entry) {
      return { serveCached: result.entry, shouldStore: false };
    }

    if (mode === "only-if-cached") {
      if (result.entry) {
        return { serveCached: result.entry, shouldStore: false };
      }
      return { shouldStore: false };
    }

    if (result.fresh && mode === "default") {
      return { serveCached: result.entry, shouldStore: false };
    }

    const conditionalHeaders: Record<string, string> = {};
    let matchedEntry: CacheEntry | undefined;

    if (result.entry) {
      matchedEntry = result.entry;
      if (result.entry.etag) {
        conditionalHeaders["if-none-match"] = result.entry.etag;
      }
      if (result.entry.lastModified) {
        conditionalHeaders["if-modified-since"] = result.entry.lastModified;
      }
    }

    const hasConditional = Object.keys(conditionalHeaders).length > 0;
    return {
      conditionalHeaders: hasConditional ? conditionalHeaders : undefined,
      shouldStore: true,
      matchedEntry,
    };
  }

  /**
   * Stores a response in the cache if it is cacheable per RFC 9111 §3.
   */
  store(req: NLcURLRequest, response: NLcURLResponse): void {
    const method = (req.method ?? "GET").toUpperCase();
    if (!CACHEABLE_METHODS.has(method)) return;

    const directives = parseCacheControl(response.headers["cache-control"] ?? "");

    if (directives.noStore) return;

    if (!CACHEABLE_STATUS.has(response.status) && directives.maxAge === undefined && directives.sMaxAge === undefined) {
      return;
    }

    if (response.status === 206) return;

    const key = CacheStore.cacheKey(method, req.url);
    const varyFields = parseVary(response.headers["vary"] ?? "");

    if (varyFields.includes("*")) return;

    const varyHeaders: Record<string, string> = {};
    for (const field of varyFields) {
      varyHeaders[field] = req.headers?.[field] ?? "";
    }

    const bodySize = response.rawBody.length;

    this.evictIfNeeded(bodySize);

    const existing = this.entries.get(key);
    if (existing) {
      this.currentSize -= existing.bodySize;
      this.entries.delete(key);
    }

    const now = Date.now();
    const entry: CacheEntry = {
      key,
      status: response.status,
      statusText: response.statusText,
      headers: { ...response.headers },
      body: Buffer.from(response.rawBody),
      httpVersion: response.httpVersion,
      url: response.url,
      storedAt: now,
      etag: response.headers["etag"],
      lastModified: response.headers["last-modified"],
      directives,
      varyFields,
      varyHeaders,
      bodySize,
      lastAccessedAt: ++this.accessCounter,
    };

    this.entries.set(key, entry);
    this.currentSize += bodySize;
  }

  /**
   * Merges a 304 Not Modified response with a cached entry, producing
   * a full response with updated headers.
   */
  mergeNotModified(entry: CacheEntry, response304: NLcURLResponse): NLcURLResponse {
    const mergedHeaders = { ...entry.headers };
    for (const [k, v] of Object.entries(response304.headers)) {
      if (k === "content-length" || k === "content-encoding" || k === "transfer-encoding") continue;
      mergedHeaders[k] = v;
    }

    entry.headers = mergedHeaders;
    entry.storedAt = Date.now();
    if (response304.headers["etag"]) entry.etag = response304.headers["etag"];
    if (response304.headers["last-modified"]) entry.lastModified = response304.headers["last-modified"];
    entry.directives = parseCacheControl(mergedHeaders["cache-control"] ?? "");

    return new NLcURLResponse({
      status: entry.status,
      statusText: entry.statusText,
      headers: mergedHeaders,
      rawBody: entry.body,
      httpVersion: entry.httpVersion,
      url: entry.url,
      redirectCount: response304.redirectCount,
      timings: response304.timings,
      request: response304.request,
    });
  }

  /**
   * Constructs a full NLcURLResponse from a cache entry for direct serving.
   */
  responseFromEntry(entry: CacheEntry, req: NLcURLRequest): NLcURLResponse {
    return new NLcURLResponse({
      status: entry.status,
      statusText: entry.statusText,
      headers: { ...entry.headers },
      rawBody: entry.body,
      httpVersion: entry.httpVersion,
      url: entry.url,
      redirectCount: 0,
      timings: { dns: 0, connect: 0, tls: 0, firstByte: 0, total: 0 },
      request: { url: req.url, method: (req.method ?? "GET") as "GET", headers: req.headers ?? {} },
    });
  }

  /** Returns the number of cached entries. */
  get size(): number {
    return this.entries.size;
  }

  /** Returns the total byte size of all cached response bodies. */
  get totalSize(): number {
    return this.currentSize;
  }

  /** Clears all cached entries. */
  clear(): void {
    this.entries.clear();
    this.currentSize = 0;
  }

  /**
   * Removes a specific cache entry by method and URL.
   */
  delete(method: string, url: string): boolean {
    const key = CacheStore.cacheKey(method, url);
    const entry = this.entries.get(key);
    if (entry) {
      this.currentSize -= entry.bodySize;
      this.entries.delete(key);
      return true;
    }
    return false;
  }

  /**
   * Checks whether request headers match the stored Vary fields.
   */
  private varyMatches(entry: CacheEntry, req: NLcURLRequest): boolean {
    for (const field of entry.varyFields) {
      const stored = entry.varyHeaders[field] ?? "";
      const current = req.headers?.[field] ?? "";
      if (stored !== current) return false;
    }
    return true;
  }

  /**
   * Finds the key of the least recently accessed entry.
   */
  private findLRUKey(): string | undefined {
    let lruKey: string | undefined;
    let lruTime = Infinity;
    for (const [key, entry] of this.entries) {
      if (entry.lastAccessedAt < lruTime) {
        lruTime = entry.lastAccessedAt;
        lruKey = key;
      }
    }
    return lruKey;
  }

  /**
   * Evicts least-recently-used entries until there is room for a new entry
   * of the given size.
   */
  private evictIfNeeded(incomingSize: number): void {
    while (this.entries.size >= this.maxEntries) {
      const lruKey = this.findLRUKey();
      if (lruKey === undefined) break;
      const entry = this.entries.get(lruKey);
      if (entry) this.currentSize -= entry.bodySize;
      this.entries.delete(lruKey);
    }

    while (this.currentSize + incomingSize > this.maxSize && this.entries.size > 0) {
      const lruKey = this.findLRUKey();
      if (lruKey === undefined) break;
      const entry = this.entries.get(lruKey);
      if (entry) this.currentSize -= entry.bodySize;
      this.entries.delete(lruKey);
    }
  }
}

/**
 * Parses a `Cache-Control` header value into structured directives.
 */
export function parseCacheControl(value: string): CacheDirectives {
  const directives: CacheDirectives = {
    noCache: false,
    noStore: false,
    mustRevalidate: false,
    proxyRevalidate: false,
    public: false,
    private: false,
    immutable: false,
  };

  if (!value) return directives;

  const parts = value.toLowerCase().split(",");
  for (const part of parts) {
    const trimmed = part.trim();
    if (!trimmed) continue;

    const eqIdx = trimmed.indexOf("=");
    const name = eqIdx === -1 ? trimmed : trimmed.slice(0, eqIdx).trim();
    const val =
      eqIdx === -1
        ? undefined
        : trimmed
            .slice(eqIdx + 1)
            .trim()
            .replace(/^"|"$/g, "");

    switch (name) {
      case "max-age": {
        const n = parseInt(val ?? "", 10);
        if (Number.isFinite(n) && n >= 0) directives.maxAge = n;
        break;
      }
      case "s-maxage": {
        const n = parseInt(val ?? "", 10);
        if (Number.isFinite(n) && n >= 0) directives.sMaxAge = n;
        break;
      }
      case "no-cache":
        directives.noCache = true;
        break;
      case "no-store":
        directives.noStore = true;
        break;
      case "must-revalidate":
        directives.mustRevalidate = true;
        break;
      case "proxy-revalidate":
        directives.proxyRevalidate = true;
        break;
      case "public":
        directives.public = true;
        break;
      case "private":
        directives.private = true;
        break;
      case "immutable":
        directives.immutable = true;
        break;
      case "stale-while-revalidate": {
        const n = parseInt(val ?? "", 10);
        if (Number.isFinite(n) && n >= 0) directives.staleWhileRevalidate = n;
        break;
      }
      case "stale-if-error": {
        const n = parseInt(val ?? "", 10);
        if (Number.isFinite(n) && n >= 0) directives.staleIfError = n;
        break;
      }
    }
  }

  return directives;
}

/**
 * Computes the freshness lifetime in seconds for a cache entry (RFC 9111 §4.2).
 *
 * Priority: Cache-Control max-age > Expires header > heuristic.
 */
function computeFreshnessLifetime(entry: CacheEntry): number {
  if (entry.directives.maxAge !== undefined) {
    return entry.directives.maxAge;
  }

  const expires = entry.headers["expires"];
  if (expires) {
    const expTime = Date.parse(expires);
    if (!Number.isNaN(expTime)) {
      const dateHeader = entry.headers["date"];
      const responseDate = dateHeader ? Date.parse(dateHeader) : entry.storedAt;
      if (!Number.isNaN(responseDate)) {
        return Math.max(0, (expTime - responseDate) / 1000);
      }
    }
  }

  if (entry.lastModified) {
    const lmTime = Date.parse(entry.lastModified);
    if (!Number.isNaN(lmTime)) {
      const age = (entry.storedAt - lmTime) / 1000;
      return Math.min(age * 0.1, 86400);
    }
  }

  return 0;
}

/**
 * Parses a Vary header into an array of lowercased field names.
 */
function parseVary(value: string): string[] {
  if (!value) return [];
  return value
    .split(",")
    .map((v) => v.trim().toLowerCase())
    .filter(Boolean);
}
