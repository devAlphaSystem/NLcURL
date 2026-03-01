/**
 * Cookie jar (RFC 6265).
 *
 * Thread-safe, in-memory cookie storage with domain/path matching
 * and expiration handling.
 */

import { parseSetCookie, serializeCookies, type Cookie } from './parser.js';

/** Maximum number of cookies stored (per RFC 6265 §6.1 guidance). */
const MAX_COOKIES = 3000;
const MAX_COOKIES_PER_DOMAIN = 50;

export class CookieJar {
  private cookies: Cookie[] = [];

  /**
   * Store cookies from Set-Cookie response headers.
   *
   * Accepts either a flat Record (with optional rawHeaders for proper
   * multi-value handling) or processes the merged header value.
   */
  setCookies(
    headers: Record<string, string>,
    requestUrl: URL,
    rawHeaders?: Array<[string, string]>,
  ): void {
    const setCookieValues = this.extractSetCookieValues(headers, rawHeaders);

    for (const value of setCookieValues) {
      const cookie = parseSetCookie(value, requestUrl);
      if (cookie) {
        this.store(cookie);
      }
    }
  }

  /**
   * Get the Cookie header value for a request URL.
   * Returns empty string if no cookies match.
   */
  getCookieHeader(url: URL): string {
    const now = Date.now();
    const matching = this.cookies.filter((c) => this.matches(c, url, now));
    if (matching.length === 0) return '';

    // Sort by path length (longest first), then creation time (earliest first)
    matching.sort((a, b) => {
      if (a.path.length !== b.path.length) return b.path.length - a.path.length;
      return a.createdAt - b.createdAt;
    });

    return serializeCookies(matching);
  }

  /**
   * Clear all cookies.
   */
  clear(): void {
    this.cookies = [];
  }

  /**
   * Clear cookies for a specific domain.
   */
  clearDomain(domain: string): void {
    this.cookies = this.cookies.filter((c) => c.domain !== domain.toLowerCase());
  }

  /**
   * Get all stored cookies (for inspection/debugging).
   */
  all(): ReadonlyArray<Cookie> {
    return this.cookies;
  }

  get size(): number {
    return this.cookies.length;
  }

  // ---- Internal ----

  private store(cookie: Cookie): void {
    // Max-Age = 0 means delete
    if (cookie.maxAge !== undefined && cookie.maxAge <= 0) {
      this.cookies = this.cookies.filter(
        (c) => !(c.name === cookie.name && c.domain === cookie.domain && c.path === cookie.path),
      );
      return;
    }

    // Replace existing cookie with same name/domain/path
    const idx = this.cookies.findIndex(
      (c) => c.name === cookie.name && c.domain === cookie.domain && c.path === cookie.path,
    );
    if (idx >= 0) {
      this.cookies[idx] = cookie;
    } else {
      // Enforce per-domain limit
      const domainCount = this.cookies.filter((c) => c.domain === cookie.domain).length;
      if (domainCount >= MAX_COOKIES_PER_DOMAIN) {
        // Evict oldest cookie for this domain
        const oldest = this.cookies.findIndex((c) => c.domain === cookie.domain);
        if (oldest >= 0) this.cookies.splice(oldest, 1);
      }
      // Enforce global limit
      if (this.cookies.length >= MAX_COOKIES) {
        this.cookies.shift();
      }
      this.cookies.push(cookie);
    }
  }

  private matches(cookie: Cookie, url: URL, now: number): boolean {
    // Check expiration
    if (cookie.maxAge !== undefined) {
      if (now > cookie.createdAt + cookie.maxAge * 1000) return false;
    }
    if (cookie.expires && now > cookie.expires.getTime()) return false;

    // Domain matching
    const host = url.hostname.toLowerCase();
    if (!this.domainMatches(host, cookie.domain)) return false;

    // Path matching
    if (!this.pathMatches(url.pathname, cookie.path)) return false;

    // Secure flag
    if (cookie.secure && url.protocol !== 'https:') return false;

    return true;
  }

  private domainMatches(host: string, domain: string): boolean {
    if (host === domain) return true;
    // Host must end with .domain
    return host.endsWith('.' + domain);
  }

  private pathMatches(requestPath: string, cookiePath: string): boolean {
    if (requestPath === cookiePath) return true;
    if (requestPath.startsWith(cookiePath)) {
      if (cookiePath.endsWith('/')) return true;
      if (requestPath[cookiePath.length] === '/') return true;
    }
    return false;
  }

  private extractSetCookieValues(
    headers: Record<string, string>,
    rawHeaders?: Array<[string, string]>,
  ): string[] {
    // Prefer raw headers to preserve individual Set-Cookie values
    if (rawHeaders) {
      return rawHeaders
        .filter(([k]) => k.toLowerCase() === 'set-cookie')
        .map(([, v]) => v);
    }
    // Fallback: extract from merged Record
    const values: string[] = [];
    for (const [key, value] of Object.entries(headers)) {
      if (key.toLowerCase() === 'set-cookie') {
        values.push(value);
      }
    }
    return values;
  }
}
