import type { CacheConfig, CacheDirectives, CacheEntry, CacheLookupResult, CacheMode } from "./types.js";
import type { NLcURLRequest } from "../core/request.js";
import { NLcURLResponse } from "../core/response.js";

const DEFAULT_MAX_ENTRIES = 1000;
const DEFAULT_MAX_SIZE = 50 * 1024 * 1024;

const CACHEABLE_METHODS = new Set(["GET", "HEAD"]);

const CACHEABLE_STATUS = new Set([200, 203, 204, 206, 300, 301, 308, 404, 405, 410, 414, 501]);

/**
 * In-memory HTTP response cache implementing RFC 9111 semantics with LRU eviction,
 * Vary-based multi-variant matching, conditional revalidation, Age header,
 * unsafe method invalidation, and request-side Cache-Control support.
 *
 * @class
 */
export class CacheStore {
  private readonly variants = new Map<string, CacheEntry[]>();
  private readonly maxEntries: number;
  private readonly maxSize: number;
  private currentSize = 0;
  private entryCount = 0;
  private readonly mode: CacheMode;
  private accessCounter = 0;

  /**
   * Creates a new CacheStore with the given limits and default mode.
   *
   * @param {CacheConfig} [config] - Cache configuration.
   */
  constructor(config?: CacheConfig) {
    this.maxEntries = config?.maxEntries ?? DEFAULT_MAX_ENTRIES;
    this.maxSize = config?.maxSize ?? DEFAULT_MAX_SIZE;
    this.mode = config?.mode ?? "default";
  }

  /**
   * Generates a deterministic cache key from an HTTP method and URL.
   *
   * @param {string} method - The HTTP method.
   * @param {string} url - The request URL.
   * @returns {string} The cache key.
   */
  static cacheKey(method: string, url: string): string {
    return `${method.toUpperCase()}:${url}`;
  }

  /**
   * Looks up a request in the cache and evaluates freshness.
   * Supports multiple Vary variants per URL (RFC 9111 §4.1).
   *
   * @param {NLcURLRequest} req - The request to look up.
   * @returns {CacheLookupResult} Freshness status and the matched entry, if any.
   */
  lookup(req: NLcURLRequest): CacheLookupResult {
    const method = (req.method ?? "GET").toUpperCase();
    if (!CACHEABLE_METHODS.has(method)) {
      return { fresh: false, staleWhileRevalidate: false };
    }

    const reqDirectives = parseCacheControl(req.headers?.["cache-control"] ?? "");

    if (reqDirectives.noStore) {
      return { fresh: false, staleWhileRevalidate: false };
    }

    const key = CacheStore.cacheKey(method, req.url);
    const entries = this.variants.get(key);
    if (!entries || entries.length === 0) {
      return { fresh: false, staleWhileRevalidate: false };
    }

    const entry = entries.find((e) => this.varyMatches(e, req));
    if (!entry) {
      return { fresh: false, staleWhileRevalidate: false };
    }

    entry.lastAccessedAt = ++this.accessCounter;

    const age = this.computeCurrentAge(entry);
    const freshness = computeFreshnessLifetime(entry);

    if (reqDirectives.maxAge !== undefined && age > reqDirectives.maxAge) {
      return { entry, fresh: false, staleWhileRevalidate: false };
    }

    if (reqDirectives.minFresh !== undefined && freshness - age < reqDirectives.minFresh) {
      return { entry, fresh: false, staleWhileRevalidate: false };
    }

    let fresh = age < freshness;

    if (reqDirectives.noCache) {
      fresh = false;
    }

    if (entry.directives.noCache) {
      fresh = false;
    }

    let staleWhileRevalidate = false;
    if (!fresh) {
      if (entry.directives.mustRevalidate) {
        return { entry, fresh: false, staleWhileRevalidate: false };
      }

      if (reqDirectives.maxStale !== undefined) {
        if (age < freshness + reqDirectives.maxStale) {
          return { entry, fresh: true, staleWhileRevalidate: false };
        }
      }

      if (entry.directives.staleWhileRevalidate !== undefined) {
        staleWhileRevalidate = age < freshness + entry.directives.staleWhileRevalidate;
      }
    }

    return { entry, fresh, staleWhileRevalidate };
  }

  /**
   * Evaluates a request against the cache and returns instructions for
   * serving, revalidating, or storing the response.
   *
   * @param {NLcURLRequest} req - The incoming request.
   * @param {CacheMode} [modeOverride] - Overrides the store's default cache mode.
   * @returns {Object} Evaluation decision with conditional headers and matched entry.
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
   * Stores a response in the cache, subject to cacheability rules.
   * Multiple Vary variants may be stored per URL (RFC 9111 §4.1).
   *
   * @param {NLcURLRequest} req - The originating request.
   * @param {NLcURLResponse} response - The response to cache.
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

    let entries = this.variants.get(key);
    if (!entries) {
      entries = [];
      this.variants.set(key, entries);
    }

    const existingIdx = entries.findIndex((e) => this.varyMatchesEntry(e, varyFields, varyHeaders));
    if (existingIdx !== -1) {
      const existing = entries[existingIdx]!;
      this.currentSize -= existing.bodySize;
      this.entryCount--;
      entries.splice(existingIdx, 1);
    }

    const now = Date.now();

    const ageHeader = response.headers["age"];
    const ageValue = ageHeader ? parseInt(ageHeader, 10) : 0;
    const dateHeader = response.headers["date"];
    const responseDate = dateHeader ? Date.parse(dateHeader) : now;
    const apparentAge = Math.max(0, (now - (Number.isNaN(responseDate) ? now : responseDate)) / 1000);
    const correctedAgeValue = Math.max(apparentAge, Number.isFinite(ageValue) ? ageValue : 0);

    const entry: CacheEntry = {
      key,
      status: response.status,
      statusText: response.statusText,
      headers: { ...response.headers },
      body: Buffer.from(response.rawBody),
      httpVersion: response.httpVersion,
      url: response.url,
      storedAt: now,
      correctedInitialAge: correctedAgeValue,
      etag: response.headers["etag"],
      lastModified: response.headers["last-modified"],
      directives,
      varyFields,
      varyHeaders,
      bodySize,
      lastAccessedAt: ++this.accessCounter,
    };

    entries.push(entry);
    this.entryCount++;
    this.currentSize += bodySize;
  }

  /**
   * Invalidate cached entries when an unsafe method (POST, PUT, DELETE, PATCH)
   * receives a successful (2xx) response (RFC 9111 §4.4).
   *
   * @param {string} method - The HTTP method.
   * @param {string} url - The request URL.
   * @param {number} status - The response status code.
   */
  invalidateIfUnsafe(method: string, url: string, status: number): void {
    const upper = method.toUpperCase();
    if (CACHEABLE_METHODS.has(upper)) return;
    if (status < 200 || status >= 400) return;

    for (const m of ["GET", "HEAD"]) {
      const key = CacheStore.cacheKey(m, url);
      const entries = this.variants.get(key);
      if (entries) {
        for (const e of entries) {
          this.currentSize -= e.bodySize;
          this.entryCount--;
        }
        this.variants.delete(key);
      }
    }
  }

  /**
   * Merges a 304 Not Modified response with a stale cache entry, producing
   * a fresh response with updated headers.
   *
   * @param {CacheEntry} entry - The stale cache entry.
   * @param {NLcURLResponse} response304 - The 304 response.
   * @returns {NLcURLResponse} A new response with merged headers and the cached body.
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
   * Constructs a full NLcURLResponse from a cache entry, including Age header.
   *
   * @param {CacheEntry} entry - The cache entry to serve.
   * @param {NLcURLRequest} req - The request context.
   * @returns {NLcURLResponse} The reconstituted response with Age header.
   */
  responseFromEntry(entry: CacheEntry, req: NLcURLRequest): NLcURLResponse {
    const headers = { ...entry.headers };
    headers["age"] = String(Math.floor(this.computeCurrentAge(entry)));
    return new NLcURLResponse({
      status: entry.status,
      statusText: entry.statusText,
      headers,
      rawBody: entry.body,
      httpVersion: entry.httpVersion,
      url: entry.url,
      redirectCount: 0,
      timings: { dns: 0, connect: 0, tls: 0, firstByte: 0, total: 0 },
      request: { url: req.url, method: (req.method ?? "GET") as "GET", headers: req.headers ?? {} },
    });
  }

  /**
   * Returns the number of entries in the cache.
   *
   * @returns {number} The entry count.
   */
  get size(): number {
    return this.entryCount;
  }

  /**
   * Returns the total size of cached bodies in bytes.
   *
   * @returns {number} Total cached body size.
   */
  get totalSize(): number {
    return this.currentSize;
  }

  /**
   * Removes all entries from the cache.
   */
  clear(): void {
    this.variants.clear();
    this.currentSize = 0;
    this.entryCount = 0;
  }

  /**
   * Removes all cache entries for a method and URL.
   *
   * @param {string} method - The HTTP method.
   * @param {string} url - The request URL.
   * @returns {boolean} `true` if entries were removed.
   */
  delete(method: string, url: string): boolean {
    const key = CacheStore.cacheKey(method, url);
    const entries = this.variants.get(key);
    if (entries && entries.length > 0) {
      for (const e of entries) {
        this.currentSize -= e.bodySize;
        this.entryCount--;
      }
      this.variants.delete(key);
      return true;
    }
    return false;
  }

  /** Compute current age in seconds (RFC 9111 §5.1). */
  private computeCurrentAge(entry: CacheEntry): number {
    const residentTime = (Date.now() - entry.storedAt) / 1000;
    return (entry.correctedInitialAge ?? 0) + residentTime;
  }

  private varyMatches(entry: CacheEntry, req: NLcURLRequest): boolean {
    for (const field of entry.varyFields) {
      const stored = entry.varyHeaders[field] ?? "";
      const current = req.headers?.[field] ?? "";
      if (stored !== current) return false;
    }
    return true;
  }

  private varyMatchesEntry(entry: CacheEntry, varyFields: string[], varyHeaders: Record<string, string>): boolean {
    if (entry.varyFields.length !== varyFields.length) return false;
    for (const field of varyFields) {
      if ((entry.varyHeaders[field] ?? "") !== (varyHeaders[field] ?? "")) return false;
    }
    return true;
  }

  private evictOne(): boolean {
    let lruKey: string | undefined;
    let lruIdx = -1;
    let lruTime = Infinity;
    for (const [key, entries] of this.variants) {
      for (let i = 0; i < entries.length; i++) {
        if (entries[i]!.lastAccessedAt < lruTime) {
          lruTime = entries[i]!.lastAccessedAt;
          lruKey = key;
          lruIdx = i;
        }
      }
    }
    if (lruKey === undefined) return false;
    const entries = this.variants.get(lruKey)!;
    const removed = entries.splice(lruIdx, 1)[0]!;
    this.currentSize -= removed.bodySize;
    this.entryCount--;
    if (entries.length === 0) this.variants.delete(lruKey);
    return true;
  }

  private evictIfNeeded(incomingSize: number): void {
    while (this.entryCount >= this.maxEntries || this.currentSize + incomingSize > this.maxSize) {
      if (!this.evictOne()) break;
    }
  }
}

const ccCache = new Map<string, CacheDirectives>();
const CC_CACHE_MAX = 256;

/**
 * Parses a Cache-Control header value into structured directives.
 *
 * @param {string} value - The raw Cache-Control header value.
 * @returns {CacheDirectives} The parsed directives.
 */
export function parseCacheControl(value: string): CacheDirectives {
  const cached = ccCache.get(value);
  if (cached !== undefined) return cached;

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
      case "min-fresh": {
        const n = parseInt(val ?? "", 10);
        if (Number.isFinite(n) && n >= 0) directives.minFresh = n;
        break;
      }
      case "max-stale": {
        if (val !== undefined) {
          const n = parseInt(val, 10);
          if (Number.isFinite(n) && n >= 0) directives.maxStale = n;
        } else {
          directives.maxStale = Infinity;
        }
        break;
      }
    }
  }

  if (ccCache.size < CC_CACHE_MAX) {
    ccCache.set(value, directives);
  }

  return directives;
}

function computeFreshnessLifetime(entry: CacheEntry): number {
  if (entry.directives.sMaxAge !== undefined) {
    return entry.directives.sMaxAge;
  }

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

function parseVary(value: string): string[] {
  if (!value) return [];
  return value
    .split(",")
    .map((v) => v.trim().toLowerCase())
    .filter(Boolean);
}
