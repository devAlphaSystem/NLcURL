import { isPublicSuffix } from "./public-suffix.js";

/**
 * Represents a parsed HTTP cookie with all standard attributes.
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
  partitioned?: boolean;
  createdAt: number;
  lastAccessedAt: number;
}

const COOKIE_NAME_RE = /^[!#$%&'*+\-.^_`|~\w]+$/;
const COOKIE_VALUE_CTL_RE = /[\x00-\x1f\x7f]/;
const MAX_COOKIE_SIZE = 4096;

/** Maximum Max-Age: 400 days in seconds (per Chromium and RFC 6265bis). */
const MAX_COOKIE_AGE_SECONDS = 400 * 24 * 60 * 60;

const VALID_SAMESITE = new Set(["strict", "lax", "none"]);

function looksLikeIP(host: string): boolean {
  if (host.includes(":")) return true;
  const parts = host.split(".");
  return parts.length === 4 && parts.every((p) => /^\d{1,3}$/.test(p));
}

/**
 * Parses a Set-Cookie response header into a Cookie object, enforcing
 * __Host- / __Secure- prefix rules, public suffix rejection, and SameSite defaults.
 *
 * @param {string} header - The raw Set-Cookie header value.
 * @param {URL} requestUrl - The URL of the originating request.
 * @returns {Cookie|null} The parsed cookie, or `null` if validation fails.
 */
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
    lastAccessedAt: Date.now(),
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
        if (looksLikeIP(d) || looksLikeIP(host)) {
          if (d !== host) return null;
          cookie.domain = d;
          break;
        }
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
          cookie.maxAge = Math.min(secs, MAX_COOKIE_AGE_SECONDS);
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
      case "partitioned":
        cookie.partitioned = true;
        break;
    }
  }

  if (cookie.sameSite === undefined) {
    cookie.sameSite = "lax";
  }

  if (cookie.sameSite === "none" && !cookie.secure) {
    return null;
  }

  if (cookie.name.startsWith("__Host-")) {
    if (!cookie.secure) return null;
    if (cookie.domain !== requestUrl.hostname.toLowerCase()) return null;
    if (cookie.path !== "/") return null;
  }

  if (cookie.name.startsWith("__Secure-")) {
    if (!cookie.secure) return null;
  }

  if (cookie.partitioned && !cookie.secure) {
    return null;
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
 * Serializes an array of cookies into a Cookie header value string.
 *
 * @param {Cookie[]} cookies - The cookies to serialize.
 * @returns {string} The serialized "name=value; name=value" string.
 */
export function serializeCookies(cookies: Cookie[]): string {
  if (cookies.length === 0) return "";
  if (cookies.length === 1) return `${cookies[0]!.name}=${cookies[0]!.value}`;
  let result = `${cookies[0]!.name}=${cookies[0]!.value}`;
  for (let i = 1; i < cookies.length; i++) {
    result += `; ${cookies[i]!.name}=${cookies[i]!.value}`;
  }
  return result;
}
