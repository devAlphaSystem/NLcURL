import { parseSetCookie, serializeCookies, type Cookie } from "./parser.js";

const DEFAULT_MAX_COOKIES = 3000;
const DEFAULT_MAX_COOKIES_PER_DOMAIN = 180;
/** Maximum number of Set-Cookie headers to process per response. */
const MAX_SET_COOKIE_PER_RESPONSE = 50;
/** Maximum Cookie header line length in bytes. */
const MAX_COOKIE_HEADER_LENGTH = 8190;
/** Maximum cookies to include in a single request. */
const MAX_COOKIES_PER_REQUEST = 150;

/**
 * Configuration options for the cookie jar.
 */
export interface CookieJarOptions {
  maxCookies?: number;
  maxCookiesPerDomain?: number;
}

/**
 * Manages HTTP cookies across requests, enforcing RFC 6265 semantics including
 * domain scoping, path matching, __Host- / __Secure- prefix validation, and
 * SameSite defaults.
 *
 * @class
 */
export class CookieJar {
  private cookies: Cookie[] = [];
  private readonly maxCookies: number;
  private readonly maxCookiesPerDomain: number;
  private accessCounter = 0;
  private readonly cookieIndex = new Map<string, number>();
  private readonly domainCounts = new Map<string, number>();
  private readonly cookiesByDomain = new Map<string, Set<Cookie>>();

  /**
   * Creates a new CookieJar.
   *
   * @param {CookieJarOptions} [options] - Jar capacity limits.
   */
  constructor(options?: CookieJarOptions) {
    this.maxCookies = options?.maxCookies ?? DEFAULT_MAX_COOKIES;
    this.maxCookiesPerDomain = options?.maxCookiesPerDomain ?? DEFAULT_MAX_COOKIES_PER_DOMAIN;
  }

  /**
   * Extracts and stores cookies from Set-Cookie response headers.
   *
   * @param {Record<string, string>} headers - The response headers.
   * @param {URL} requestUrl - The URL that produced the response.
   * @param {Array<[string, string]>} [rawHeaders] - Raw header pairs for duplicate Set-Cookie handling.
   */
  setCookies(headers: Record<string, string>, requestUrl: URL, rawHeaders?: Array<[string, string]>): void {
    const setCookieValues = this.extractSetCookieValues(headers, rawHeaders);

    const limited = setCookieValues.slice(0, MAX_SET_COOKIE_PER_RESPONSE);

    for (const value of limited) {
      const cookie = parseSetCookie(value, requestUrl);
      if (cookie) {
        this.store(cookie);
      }
    }
  }

  /**
   * Builds a Cookie header value for the given URL.
   *
   * @param {URL} url - The target URL.
   * @param {object} [context] - Additional context for SameSite enforcement.
   * @param {URL} [context.siteOrigin] - The top-level site origin for SameSite checks.
   * @param {boolean} [context.isSameSite] - Whether the request is same-site (default: true).
   * @param {"navigate"|"subresource"} [context.type] - Request type for SameSite Lax handling.
   * @param {string} [context.method] - HTTP method (for SameSite Lax top-level navigation).
   * @returns {string} The serialized cookie string, or an empty string if no cookies match.
   */
  getCookieHeader(url: URL, context?: { siteOrigin?: URL; isSameSite?: boolean; type?: "navigate" | "subresource"; method?: string }): string {
    const now = Date.now();
    const isSameSite = context?.isSameSite ?? true;
    const hostLower = url.hostname.toLowerCase();
    const candidates: Cookie[] = [];
    let d = hostLower;
    while (true) {
      const domSet = this.cookiesByDomain.get(d);
      if (domSet) {
        for (const c of domSet) candidates.push(c);
      }
      const dot = d.indexOf(".");
      if (dot === -1) break;
      d = d.substring(dot + 1);
    }
    if (candidates.length === 0) return "";
    const matching = candidates.filter((c) => this.matches(c, url, now, isSameSite, context?.type, context?.method, hostLower));
    if (matching.length === 0) return "";

    for (const c of matching) {
      c.lastAccessedAt = ++this.accessCounter;
    }

    matching.sort((a, b) => {
      if (a.path.length !== b.path.length) return b.path.length - a.path.length;
      return a.createdAt - b.createdAt;
    });

    const capped = matching.slice(0, MAX_COOKIES_PER_REQUEST);
    let header = serializeCookies(capped);
    while (Buffer.byteLength(header, "utf-8") > MAX_COOKIE_HEADER_LENGTH && capped.length > 1) {
      capped.pop();
      header = serializeCookies(capped);
    }

    return header;
  }

  /**
   * Removes all cookies from the jar.
   */
  clear(): void {
    this.cookies = [];
    this.cookieIndex.clear();
    this.domainCounts.clear();
    this.cookiesByDomain.clear();
  }

  /**
   * Removes all cookies for a specific domain.
   *
   * @param {string} domain - The domain whose cookies should be removed.
   */
  clearDomain(domain: string): void {
    const lower = domain.toLowerCase();
    this.cookies = this.cookies.filter((c) => c.domain !== lower);
    this.rebuildIndex();
  }

  /**
   * Returns a read-only view of stored cookies.
   *
   * @param {object} [options] - Filter options.
   * @param {boolean} [options.includeHttpOnly=false] - Include httpOnly cookies (default: excluded for safety).
   * @returns {ReadonlyArray<Cookie>} Matching cookies in the jar.
   */
  all(options?: { includeHttpOnly?: boolean }): ReadonlyArray<Cookie> {
    if (options?.includeHttpOnly) return this.cookies;
    return this.cookies.filter((c) => !c.httpOnly);
  }

  /**
   * Returns the number of cookies stored in the jar.
   *
   * @returns {number} The cookie count.
   */
  get size(): number {
    return this.cookies.length;
  }

  /**
   * Serializes all cookies to Netscape cookie file format.
   *
   * @returns {string} The cookie file content.
   */
  toNetscapeString(): string {
    const lines = ["# Netscape HTTP Cookie File"];
    for (const c of this.cookies) {
      const domain = c.domain.startsWith(".") ? c.domain : "." + c.domain;
      const includeSubdomains = domain.startsWith(".") ? "TRUE" : "FALSE";
      const path = c.path || "/";
      const secure = c.secure ? "TRUE" : "FALSE";
      const httpOnly = c.httpOnly ? "TRUE" : "FALSE";
      let expires = "0";
      if (c.maxAge !== undefined) {
        expires = String(Math.floor((c.createdAt + c.maxAge * 1000) / 1000));
      } else if (c.expires) {
        expires = String(Math.floor(c.expires.getTime() / 1000));
      }
      lines.push(`${domain}\t${includeSubdomains}\t${path}\t${secure}\t${expires}\t${c.name}\t${c.value}\t${httpOnly}`);
    }
    return lines.join("\n") + "\n";
  }

  /** Maximum expiry date: 400 days from now (RFC 6265bis recommendation). */
  private static readonly MAX_EXPIRY_DAYS = 400;

  /**
   * Loads cookies from a Netscape cookie file format string.
   *
   * Performs validation including: prefix checks (__Host- / __Secure-),
   * expiry capping, and basic domain sanity checks.
   *
   * @param {string} content - The cookie file content.
   */
  loadNetscapeString(content: string): void {
    const now = Date.now();
    const maxExpiry = now + CookieJar.MAX_EXPIRY_DAYS * 24 * 60 * 60 * 1000;

    for (const line of content.split("\n")) {
      const trimmed = line.trim();
      if (!trimmed || trimmed.startsWith("#")) continue;
      const parts = trimmed.split("\t");
      if (parts.length < 7) continue;
      const [domain, , path, secure, expires, name, value] = parts;
      const httpOnlyField = parts[7];

      const cleanDomain = domain!.startsWith(".") ? domain!.slice(1) : domain!;
      if (!cleanDomain || (!cleanDomain.includes(".") && cleanDomain !== "localhost")) continue;

      const isSecure = secure === "TRUE";

      if (name!.startsWith("__Host-")) {
        if (!isSecure || path !== "/" || domain!.startsWith(".")) continue;
      } else if (name!.startsWith("__Secure-")) {
        if (!isSecure) continue;
      }

      const cookie: Cookie = {
        name: name!,
        value: value!,
        domain: cleanDomain,
        path: path!,
        secure: isSecure,
        httpOnly: httpOnlyField === "TRUE",
        sameSite: undefined,
        createdAt: now,
        lastAccessedAt: now,
      };
      const expiresNum = parseInt(expires!, 10);
      if (expiresNum > 0) {
        const expiryMs = Math.min(expiresNum * 1000, maxExpiry);
        if (expiryMs < now) continue;
        cookie.expires = new Date(expiryMs);
      }
      this.store(cookie);
    }
  }

  private static cookieKey(name: string, domain: string, path: string): string {
    return `${name}\0${domain}\0${path}`;
  }

  private rebuildIndex(): void {
    this.cookieIndex.clear();
    this.domainCounts.clear();
    this.cookiesByDomain.clear();
    for (let i = 0; i < this.cookies.length; i++) {
      const c = this.cookies[i]!;
      this.cookieIndex.set(CookieJar.cookieKey(c.name, c.domain, c.path), i);
      this.domainCounts.set(c.domain, (this.domainCounts.get(c.domain) ?? 0) + 1);
      let domSet = this.cookiesByDomain.get(c.domain);
      if (!domSet) {
        domSet = new Set();
        this.cookiesByDomain.set(c.domain, domSet);
      }
      domSet.add(c);
    }
  }

  private removeAt(idx: number): void {
    const removed = this.cookies[idx]!;
    const lastIdx = this.cookies.length - 1;
    if (idx !== lastIdx) {
      const last = this.cookies[lastIdx]!;
      this.cookies[idx] = last;
      this.cookieIndex.set(CookieJar.cookieKey(last.name, last.domain, last.path), idx);
    }
    this.cookies.pop();
    this.cookieIndex.delete(CookieJar.cookieKey(removed.name, removed.domain, removed.path));
    const domSet = this.cookiesByDomain.get(removed.domain);
    if (domSet) {
      domSet.delete(removed);
      if (domSet.size === 0) this.cookiesByDomain.delete(removed.domain);
    }
    const dc = (this.domainCounts.get(removed.domain) ?? 1) - 1;
    if (dc <= 0) this.domainCounts.delete(removed.domain);
    else this.domainCounts.set(removed.domain, dc);
  }

  private store(cookie: Cookie): void {
    const key = CookieJar.cookieKey(cookie.name, cookie.domain, cookie.path);

    if (cookie.maxAge !== undefined && cookie.maxAge <= 0) {
      const idx = this.cookieIndex.get(key);
      if (idx !== undefined) {
        this.removeAt(idx);
      }
      return;
    }

    const existingIdx = this.cookieIndex.get(key);
    if (existingIdx !== undefined) {
      const old = this.cookies[existingIdx]!;
      cookie.lastAccessedAt = ++this.accessCounter;
      this.cookies[existingIdx] = cookie;
      const domSet = this.cookiesByDomain.get(cookie.domain);
      if (domSet) {
        domSet.delete(old);
        domSet.add(cookie);
      }
    } else {
      cookie.lastAccessedAt = ++this.accessCounter;
      const domainCount = this.domainCounts.get(cookie.domain) ?? 0;
      if (domainCount >= this.maxCookiesPerDomain) {
        this.evictLRUForDomain(cookie.domain);
      }
      if (this.cookies.length >= this.maxCookies) {
        this.evictGlobalLRU();
      }
      const newIdx = this.cookies.length;
      this.cookies.push(cookie);
      this.cookieIndex.set(key, newIdx);
      this.domainCounts.set(cookie.domain, (this.domainCounts.get(cookie.domain) ?? 0) + 1);
      let domSet = this.cookiesByDomain.get(cookie.domain);
      if (!domSet) {
        domSet = new Set();
        this.cookiesByDomain.set(cookie.domain, domSet);
      }
      domSet.add(cookie);
    }
  }

  private evictLRUForDomain(domain: string): void {
    const domSet = this.cookiesByDomain.get(domain);
    if (!domSet || domSet.size === 0) return;
    let lruCookie: Cookie | undefined;
    let lruTime = Infinity;
    for (const c of domSet) {
      if (c.lastAccessedAt < lruTime) {
        lruTime = c.lastAccessedAt;
        lruCookie = c;
      }
    }
    if (lruCookie) {
      const idx = this.cookieIndex.get(CookieJar.cookieKey(lruCookie.name, lruCookie.domain, lruCookie.path));
      if (idx !== undefined) {
        this.removeAt(idx);
      }
    }
  }

  private evictGlobalLRU(): void {
    let fatDomain = "";
    let fatCount = 0;
    for (const [d, count] of this.domainCounts) {
      if (count > fatCount) {
        fatCount = count;
        fatDomain = d;
      }
    }

    if (fatDomain) {
      this.evictLRUForDomain(fatDomain);
    } else if (this.cookies.length > 0) {
      this.removeAt(0);
    }
  }

  private matches(cookie: Cookie, url: URL, now: number, isSameSite: boolean = true, requestType?: "navigate" | "subresource", method?: string, hostLower?: string): boolean {
    if (cookie.maxAge !== undefined) {
      if (now > cookie.createdAt + cookie.maxAge * 1000) return false;
    }
    if (cookie.expires && now > cookie.expires.getTime()) return false;

    const host = hostLower ?? url.hostname.toLowerCase();
    if (!this.domainMatches(host, cookie.domain)) return false;

    if (!this.pathMatches(url.pathname, cookie.path)) return false;

    if (cookie.secure && url.protocol !== "https:") return false;

    if (!isSameSite) {
      const sameSite = cookie.sameSite ?? "lax";
      if (sameSite === "strict") return false;
      if (sameSite === "lax") {
        if (requestType !== "navigate") return false;
        const safeMethod = !method || method === "GET" || method === "HEAD";
        if (!safeMethod) return false;
      }
    }

    if (cookie.partitioned && !isSameSite) return false;

    return true;
  }

  private domainMatches(host: string, domain: string): boolean {
    if (host === domain) return true;
    if (host.length <= domain.length) return false;
    return host.charCodeAt(host.length - domain.length - 1) === 0x2e && host.endsWith(domain);
  }

  private pathMatches(requestPath: string, cookiePath: string): boolean {
    if (requestPath === cookiePath) return true;
    if (requestPath.startsWith(cookiePath)) {
      if (cookiePath.endsWith("/")) return true;
      if (requestPath[cookiePath.length] === "/") return true;
    }
    return false;
  }

  private extractSetCookieValues(headers: Record<string, string>, rawHeaders?: Array<[string, string]>): string[] {
    if (rawHeaders) {
      const values: string[] = [];
      for (const [k, v] of rawHeaders) {
        if (k === "set-cookie" || k === "Set-Cookie" || k.toLowerCase() === "set-cookie") {
          values.push(v);
        }
      }
      return values;
    }
    const values: string[] = [];
    for (const [key, value] of Object.entries(headers)) {
      if (key.toLowerCase() === "set-cookie") {
        values.push(value);
      }
    }
    return values;
  }
}
