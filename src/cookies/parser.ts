import { isPublicSuffix } from "./public-suffix.js";

/**
 * Represents a parsed HTTP cookie as stored in the `CookieJar`.
 *
 * @typedef  {Object}                           Cookie
 * @property {string}                           name       - Cookie name.
 * @property {string}                           value      - Cookie value.
 * @property {string}                           domain     - Effective domain (without leading dot).
 * @property {string}                           path       - Cookie path scope.
 * @property {Date}                             [expires]  - Absolute expiry date (from the `Expires` attribute).
 * @property {number}                           [maxAge]   - Relative lifetime in seconds (from the `Max-Age` attribute).
 * @property {boolean}                          secure     - Whether the cookie is restricted to HTTPS.
 * @property {boolean}                          httpOnly   - Whether the cookie is inaccessible to client-side scripts.
 * @property {'strict' | 'lax' | 'none'}        [sameSite] - SameSite policy.
 * @property {number}                           createdAt  - Unix timestamp (ms) when the cookie was created.
 */
export interface Cookie {
  name: string;
  value: string;
  domain: string;
  path: string;
  expires?: Date;
  maxAge?: number;
  secure: boolean;
  httpOnly: boolean;
  sameSite?: "strict" | "lax" | "none";
  createdAt: number;
}

/**
 * Parses a `Set-Cookie` header value into a {@link Cookie} object.
 * Validates the cookie against the request URL to enforce domain and path
 * scoping rules per RFC 6265.
 *
 * @param {string} header     - Raw `Set-Cookie` header value.
 * @param {URL}    requestUrl - URL of the request that received the header.
 * @returns {Cookie | null} Parsed cookie, or `null` if the header is invalid or
 *   the domain attribute fails validation against the request origin.
 */

const COOKIE_NAME_RE = /^[!#$%&'*+\-.^_`|~\w]+$/;
const COOKIE_VALUE_CTL_RE = /[\x00-\x1f\x7f]/;
const MAX_COOKIE_SIZE = 4096;

const VALID_SAMESITE = new Set(["strict", "lax", "none"]);

export function parseSetCookie(header: string, requestUrl: URL): Cookie | null {
  const parts = header.split(";").map((s) => s.trim());
  if (parts.length === 0) return null;

  const nameValue = parts[0]!;
  const eqIdx = nameValue.indexOf("=");
  if (eqIdx < 0) return null;

  const name = nameValue.substring(0, eqIdx).trim();
  const value = nameValue.substring(eqIdx + 1).trim();

  if (!name) return null;

  if (!COOKIE_NAME_RE.test(name)) return null;

  if (COOKIE_VALUE_CTL_RE.test(value)) return null;

  if (name.length + value.length > MAX_COOKIE_SIZE) return null;

  const cookie: Cookie = {
    name,
    value,
    domain: requestUrl.hostname,
    path: defaultPath(requestUrl.pathname),
    secure: false,
    httpOnly: false,
    createdAt: Date.now(),
  };

  for (let i = 1; i < parts.length; i++) {
    const attr = parts[i]!;
    const attrEq = attr.indexOf("=");
    const attrName = (attrEq >= 0 ? attr.substring(0, attrEq) : attr).trim().toLowerCase();
    const attrValue = attrEq >= 0 ? attr.substring(attrEq + 1).trim() : "";

    switch (attrName) {
      case "domain": {
        let d = attrValue.toLowerCase();
        if (d.startsWith(".")) d = d.substring(1);
        const host = requestUrl.hostname.toLowerCase();
        if (d !== host && !host.endsWith("." + d)) {
          return null;
        }
        if (isPublicSuffix(d)) {
          return null;
        }
        cookie.domain = d;
        break;
      }
      case "path":
        cookie.path = attrValue || "/";
        break;
      case "expires": {
        const date = new Date(attrValue);
        if (!Number.isNaN(date.getTime())) {
          cookie.expires = date;
        }
        break;
      }
      case "max-age": {
        const secs = parseInt(attrValue, 10);
        if (!Number.isNaN(secs)) {
          cookie.maxAge = secs;
        }
        break;
      }
      case "secure":
        cookie.secure = true;
        break;
      case "httponly":
        cookie.httpOnly = true;
        break;
      case "samesite": {
        const sv = attrValue.toLowerCase();
        if (VALID_SAMESITE.has(sv)) {
          cookie.sameSite = sv as Cookie["sameSite"];
        }
        break;
      }
    }
  }

  if (cookie.sameSite === undefined) {
    cookie.sameSite = "lax";
  }

  if (cookie.name.startsWith("__Host-")) {
    if (!cookie.secure) return null;
    if (cookie.domain !== requestUrl.hostname.toLowerCase()) return null;
    if (cookie.path !== "/") return null;
  }

  if (cookie.name.startsWith("__Secure-")) {
    if (!cookie.secure) return null;
  }

  return cookie;
}

function defaultPath(path: string): string {
  if (!path || !path.startsWith("/")) return "/";
  const lastSlash = path.lastIndexOf("/");
  if (lastSlash === 0) return "/";
  return path.substring(0, lastSlash);
}

/**
 * Serializes an array of cookies into the `Cookie` request header value.
 *
 * @param {Cookie[]} cookies - Cookies to serialize (in desired send order).
 * @returns {string} Semicolon-separated `name=value` string suitable for the `Cookie` header.
 */
export function serializeCookies(cookies: Cookie[]): string {
  return cookies.map((c) => `${c.name}=${c.value}`).join("; ");
}
