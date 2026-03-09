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
    const matching = this.cookies.filter((c) => this.matches(c, url, now, isSameSite, context?.type, context?.method));
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
  }

  /**
   * Removes all cookies for a specific domain.
   *
   * @param {string} domain - The domain whose cookies should be removed.
   */
  clearDomain(domain: string): void {
    this.cookies = this.cookies.filter((c) => c.domain !== domain.toLowerCase());
  }

  /**
   * Returns a read-only view of all stored cookies.
   *
   * @returns {ReadonlyArray<Cookie>} All cookies in the jar.
   */
  all(): ReadonlyArray<Cookie> {
    return this.cookies;
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

  /**
   * Loads cookies from a Netscape cookie file format string.
   *
   * @param {string} content - The cookie file content.
   */
  loadNetscapeString(content: string): void {
    for (const line of content.split("\n")) {
      const trimmed = line.trim();
      if (!trimmed || trimmed.startsWith("#")) continue;
      const parts = trimmed.split("\t");
      if (parts.length < 7) continue;
      const [domain, , path, secure, expires, name, value] = parts;
      const httpOnlyField = parts[7];
      const cookie: Cookie = {
        name: name!,
        value: value!,
        domain: domain!.startsWith(".") ? domain!.slice(1) : domain!,
        path: path!,
        secure: secure === "TRUE",
        httpOnly: httpOnlyField === "TRUE",
        sameSite: undefined,
        createdAt: Date.now(),
        lastAccessedAt: Date.now(),
      };
      const expiresNum = parseInt(expires!, 10);
      if (expiresNum > 0) {
        cookie.expires = new Date(expiresNum * 1000);
      }
      this.store(cookie);
    }
  }

  private store(cookie: Cookie): void {
    if (cookie.maxAge !== undefined && cookie.maxAge <= 0) {
      this.cookies = this.cookies.filter((c) => !(c.name === cookie.name && c.domain === cookie.domain && c.path === cookie.path));
      return;
    }

    const idx = this.cookies.findIndex((c) => c.name === cookie.name && c.domain === cookie.domain && c.path === cookie.path);
    if (idx >= 0) {
      cookie.lastAccessedAt = this.cookies[idx]!.lastAccessedAt;
      this.cookies[idx] = cookie;
    } else {
      cookie.lastAccessedAt = ++this.accessCounter;
      const domainCount = this.cookies.filter((c) => c.domain === cookie.domain).length;
      if (domainCount >= this.maxCookiesPerDomain) {
        this.evictLRUForDomain(cookie.domain);
      }
      if (this.cookies.length >= this.maxCookies) {
        this.evictGlobalLRU();
      }
      this.cookies.push(cookie);
    }
  }

  private evictLRUForDomain(domain: string): void {
    let lruIdx = -1;
    let lruTime = Infinity;
    for (let i = 0; i < this.cookies.length; i++) {
      const c = this.cookies[i]!;
      if (c.domain === domain && c.lastAccessedAt < lruTime) {
        lruTime = c.lastAccessedAt;
        lruIdx = i;
      }
    }
    if (lruIdx >= 0) this.cookies.splice(lruIdx, 1);
  }

  private evictGlobalLRU(): void {
    const domainCounts = new Map<string, number>();
    for (const c of this.cookies) {
      domainCounts.set(c.domain, (domainCounts.get(c.domain) ?? 0) + 1);
    }

    let fatDomain = "";
    let fatCount = 0;
    for (const [d, count] of domainCounts) {
      if (count > fatCount) {
        fatCount = count;
        fatDomain = d;
      }
    }

    if (fatDomain) {
      this.evictLRUForDomain(fatDomain);
    } else if (this.cookies.length > 0) {
      this.cookies.shift();
    }
  }

  private matches(cookie: Cookie, url: URL, now: number, isSameSite: boolean = true, requestType?: "navigate" | "subresource", method?: string): boolean {
    if (cookie.maxAge !== undefined) {
      if (now > cookie.createdAt + cookie.maxAge * 1000) return false;
    }
    if (cookie.expires && now > cookie.expires.getTime()) return false;

    const host = url.hostname.toLowerCase();
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
    return host.endsWith("." + domain);
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
      return rawHeaders.filter(([k]) => k.toLowerCase() === "set-cookie").map(([, v]) => v);
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
