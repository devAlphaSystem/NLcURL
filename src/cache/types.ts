import type { NLcURLResponse } from "../core/response.js";

/**
 * Configuration options for the HTTP response cache.
 */
export interface CacheConfig {
  enabled?: boolean;
  maxEntries?: number;
  maxSize?: number;
  mode?: CacheMode;
}

/**
 * Cache mode controlling how cached responses are used and stored.
 */
export type CacheMode = "default" | "no-store" | "no-cache" | "force-cache" | "only-if-cached";

/**
 * Parsed Cache-Control header directives (RFC 9111).
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
  minFresh?: number;
  maxStale?: number;
}

/**
 * Represents a single stored cache entry with metadata for freshness evaluation.
 */
export interface CacheEntry {
  key: string;
  status: number;
  statusText: string;
  headers: Record<string, string>;
  body: Buffer;
  httpVersion: string;
  url: string;
  storedAt: number;
  etag?: string;
  lastModified?: string;
  directives: CacheDirectives;
  varyFields: string[];
  varyHeaders: Record<string, string>;
  bodySize: number;
  lastAccessedAt: number;
  correctedInitialAge?: number;
}

/**
 * Result of a cache lookup indicating freshness and stale-while-revalidate eligibility.
 */
export interface CacheLookupResult {
  entry?: CacheEntry;
  fresh: boolean;
  staleWhileRevalidate: boolean;
}

/**
 * Decision produced by cache evaluation, indicating whether to serve from cache,
 * attach conditional headers, or store the upcoming response.
 */
export interface CacheDecision {
  cachedResponse?: NLcURLResponse;
  conditionalHeaders?: Record<string, string>;
  shouldStore: boolean;
  matchedEntry?: CacheEntry;
}
