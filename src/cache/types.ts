import type { NLcURLResponse } from "../core/response.js";

/**
 * Configuration for the HTTP cache layer (RFC 9111).
 */
export interface CacheConfig {
  /** Enable response caching. Defaults to `true` when a CacheStore is provided. */
  enabled?: boolean;
  /** Maximum number of entries to store. Defaults to `1000`. */
  maxEntries?: number;
  /** Maximum total byte size of cached response bodies. Defaults to `50 * 1024 * 1024` (50 MB). */
  maxSize?: number;
  /** Cache mode controlling request/response behavior. */
  mode?: CacheMode;
}

/**
 * Cache modes mirroring the Fetch API `cache` option but adapted for
 * a full HTTP client.
 *
 * - `"default"` — Standard caching: serve fresh, revalidate stale.
 * - `"no-store"` — Never read from or write to cache.
 * - `"no-cache"` — Always revalidate with the origin, even if the response is fresh.
 * - `"force-cache"` — Serve from cache regardless of freshness; only fetch on miss.
 * - `"only-if-cached"` — Only return cached responses; fail with 504 on miss.
 */
export type CacheMode = "default" | "no-store" | "no-cache" | "force-cache" | "only-if-cached";

/**
 * Parsed Cache-Control directives from a response header.
 */
export interface CacheDirectives {
  maxAge?: number;
  sMaxAge?: number;
  noCache: boolean;
  noStore: boolean;
  mustRevalidate: boolean;
  proxyRevalidate: boolean;
  public: boolean;
  private: boolean;
  immutable: boolean;
  staleWhileRevalidate?: number;
  staleIfError?: number;
}

/**
 * Serializable metadata for a cached response.
 */
export interface CacheEntry {
  /** Cache key (method + URL). */
  key: string;
  /** HTTP status code. */
  status: number;
  /** HTTP status text. */
  statusText: string;
  /** Response headers (normalized lowercase). */
  headers: Record<string, string>;
  /** Raw response body bytes. */
  body: Buffer;
  /** HTTP version string. */
  httpVersion: string;
  /** The final URL of the response. */
  url: string;
  /** Timestamp (ms since epoch) when the response was stored. */
  storedAt: number;
  /** ETag value from the response, if present. */
  etag?: string;
  /** Last-Modified value from the response, if present. */
  lastModified?: string;
  /** Parsed Cache-Control directives. */
  directives: CacheDirectives;
  /** The Vary header field names, lowercased. */
  varyFields: string[];
  /** The request headers that matched the Vary fields at storage time. */
  varyHeaders: Record<string, string>;
  /** Byte size of the body for LRU accounting. */
  bodySize: number;
  /** Timestamp (ms since epoch) when the entry was last accessed (for LRU). */
  lastAccessedAt: number;
}

/**
 * Describes a cache lookup result.
 */
export interface CacheLookupResult {
  /** The matching cache entry, or undefined on a miss. */
  entry?: CacheEntry;
  /** Whether the entry is still fresh. */
  fresh: boolean;
  /** Whether the entry can be served stale while revalidating. */
  staleWhileRevalidate: boolean;
}

/**
 * Result of applying cache logic to decide request behavior.
 */
export interface CacheDecision {
  /** If set, the cached response to serve directly. */
  cachedResponse?: NLcURLResponse;
  /** If set, conditional headers to add to the outgoing request. */
  conditionalHeaders?: Record<string, string>;
  /** Whether to store the response in cache after receiving it. */
  shouldStore: boolean;
  /** The cache entry that was matched (for 304 merging). */
  matchedEntry?: CacheEntry;
}
