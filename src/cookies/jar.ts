
import { parseSetCookie, serializeCookies, type Cookie } from './parser.js';

const MAX_COOKIES = 3000;
const MAX_COOKIES_PER_DOMAIN = 50;

/**
 * In-memory cookie store implementing RFC 6265 semantics. Manages cookie
 * scoping by domain and path, enforces per-domain and global cookie limits,
 * and supports Netscape cookie file import/export for persistence.
 */
export class CookieJar {
  private cookies: Cookie[] = [];

  /**
   * Parses all `Set-Cookie` values from `headers` (or from `rawHeaders` when
   * available to handle multiple `Set-Cookie` entries) and stores any valid
   * cookies scoped to the request URL.
   *
   * @param {Record<string, string>}    headers    - Normalized response headers.
   * @param {URL}                       requestUrl - URL of the originating request (used for domain scoping).
   * @param {Array<[string, string]>}   [rawHeaders] - Original header pairs, allowing multiple `set-cookie` entries.
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
   * Builds the `Cookie` request header value for cookies that match `url`.
   * Cookies are sorted by longest path prefix first, then by creation time.
   * Expired cookies are excluded automatically.
   *
   * @param {URL} url - The URL of the outgoing request.
   * @returns {string} Serialized cookie string suitable for the `Cookie` header,
   *   or an empty string if no cookies match.
   */
  getCookieHeader(url: URL): string {
    const now = Date.now();
    const matching = this.cookies.filter((c) => this.matches(c, url, now));
    if (matching.length === 0) return '';

    matching.sort((a, b) => {
      if (a.path.length !== b.path.length) return b.path.length - a.path.length;
      return a.createdAt - b.createdAt;
    });

    return serializeCookies(matching);
  }

  /**
   * Removes all cookies from the jar.
   */
  clear(): void {
    this.cookies = [];
  }

  /**
   * Removes all cookies whose domain matches `domain` (case-insensitive).
   *
   * @param {string} domain - Domain string to clear (e.g. `"example.com"`).
   */
  clearDomain(domain: string): void {
    this.cookies = this.cookies.filter((c) => c.domain !== domain.toLowerCase());
  }

  /**
   * Returns a read-only snapshot of all cookies currently in the jar,
   * including any that may already be expired.
   *
   * @returns {ReadonlyArray<Cookie>} All stored cookies.
   */
  all(): ReadonlyArray<Cookie> {
    return this.cookies;
  }

  /**
   * Returns the total number of cookies currently in the jar.
   *
   * @returns {number} Cookie count.
   */
  get size(): number {
    return this.cookies.length;
  }

  /**
   * Serializes all cookies to Netscape cookie file format. The output can be
   * saved to disk and reloaded via {@link CookieJar.loadNetscapeString}.
   *
   * @returns {string} Netscape-format cookie file content (newline-terminated).
   */
  toNetscapeString(): string {
    const lines = ['# Netscape HTTP Cookie File'];
    for (const c of this.cookies) {
      const domain = c.domain.startsWith('.') ? c.domain : '.' + c.domain;
      const includeSubdomains = domain.startsWith('.') ? 'TRUE' : 'FALSE';
      const path = c.path || '/';
      const secure = c.secure ? 'TRUE' : 'FALSE';
      let expires = '0';
      if (c.maxAge !== undefined) {
        expires = String(Math.floor((c.createdAt + c.maxAge * 1000) / 1000));
      } else if (c.expires) {
        expires = String(Math.floor(c.expires.getTime() / 1000));
      }
      lines.push(`${domain}\t${includeSubdomains}\t${path}\t${secure}\t${expires}\t${c.name}\t${c.value}`);
    }
    return lines.join('\n') + '\n';
  }

  /**
   * Imports cookies from a Netscape cookie file string. Lines beginning with
   * `#` or blank lines are ignored. Cookies with invalid formats are skipped.
   * Imported cookies are merged with any existing cookies in the jar.
   *
   * @param {string} content - Netscape cookie file content.
   */
  loadNetscapeString(content: string): void {
    for (const line of content.split('\n')) {
      const trimmed = line.trim();
      if (!trimmed || trimmed.startsWith('#')) continue;
      const parts = trimmed.split('\t');
      if (parts.length < 7) continue;
      const [domain, , path, secure, expires, name, value] = parts;
      const cookie: Cookie = {
        name: name!,
        value: value!,
        domain: domain!.startsWith('.') ? domain!.slice(1) : domain!,
        path: path!,
        secure: secure === 'TRUE',
        httpOnly: false,
        sameSite: undefined,
        createdAt: Date.now(),
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
      this.cookies = this.cookies.filter(
        (c) => !(c.name === cookie.name && c.domain === cookie.domain && c.path === cookie.path),
      );
      return;
    }

    const idx = this.cookies.findIndex(
      (c) => c.name === cookie.name && c.domain === cookie.domain && c.path === cookie.path,
    );
    if (idx >= 0) {
      this.cookies[idx] = cookie;
    } else {
      const domainCount = this.cookies.filter((c) => c.domain === cookie.domain).length;
      if (domainCount >= MAX_COOKIES_PER_DOMAIN) {
        const oldest = this.cookies.findIndex((c) => c.domain === cookie.domain);
        if (oldest >= 0) this.cookies.splice(oldest, 1);
      }
      if (this.cookies.length >= MAX_COOKIES) {
        this.cookies.shift();
      }
      this.cookies.push(cookie);
    }
  }

  private matches(cookie: Cookie, url: URL, now: number): boolean {
    if (cookie.maxAge !== undefined) {
      if (now > cookie.createdAt + cookie.maxAge * 1000) return false;
    }
    if (cookie.expires && now > cookie.expires.getTime()) return false;

    const host = url.hostname.toLowerCase();
    if (!this.domainMatches(host, cookie.domain)) return false;

    if (!this.pathMatches(url.pathname, cookie.path)) return false;

    if (cookie.secure && url.protocol !== 'https:') return false;

    return true;
  }

  private domainMatches(host: string, domain: string): boolean {
    if (host === domain) return true;
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
    if (rawHeaders) {
      return rawHeaders
        .filter(([k]) => k.toLowerCase() === 'set-cookie')
        .map(([, v]) => v);
    }
    const values: string[] = [];
    for (const [key, value] of Object.entries(headers)) {
      if (key.toLowerCase() === 'set-cookie') {
        values.push(value);
      }
    }
    return values;
  }
}
