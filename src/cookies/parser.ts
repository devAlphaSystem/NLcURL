/**
 * Cookie parser and serializer (RFC 6265).
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
  sameSite?: 'strict' | 'lax' | 'none';
  createdAt: number;
}

/**
 * Parse a Set-Cookie header value into a Cookie object.
 */
export function parseSetCookie(header: string, requestUrl: URL): Cookie | null {
  const parts = header.split(';').map((s) => s.trim());
  if (parts.length === 0) return null;

  const nameValue = parts[0]!;
  const eqIdx = nameValue.indexOf('=');
  if (eqIdx < 0) return null;

  const name = nameValue.substring(0, eqIdx).trim();
  const value = nameValue.substring(eqIdx + 1).trim();

  if (!name) return null;

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
    const attrEq = attr.indexOf('=');
    const attrName = (attrEq >= 0 ? attr.substring(0, attrEq) : attr)
      .trim()
      .toLowerCase();
    const attrValue = attrEq >= 0 ? attr.substring(attrEq + 1).trim() : '';

    switch (attrName) {
      case 'domain': {
        let d = attrValue.toLowerCase();
        if (d.startsWith('.')) d = d.substring(1);
        // Validate domain matches request host (RFC 6265 §5.3.6)
        const host = requestUrl.hostname.toLowerCase();
        if (d !== host && !host.endsWith('.' + d)) {
          // Reject cookie — domain doesn't match request
          return null;
        }
        cookie.domain = d;
        break;
      }
      case 'path':
        cookie.path = attrValue || '/';
        break;
      case 'expires': {
        const date = new Date(attrValue);
        if (!Number.isNaN(date.getTime())) {
          cookie.expires = date;
        }
        break;
      }
      case 'max-age': {
        const secs = parseInt(attrValue, 10);
        if (!Number.isNaN(secs)) {
          cookie.maxAge = secs;
        }
        break;
      }
      case 'secure':
        cookie.secure = true;
        break;
      case 'httponly':
        cookie.httpOnly = true;
        break;
      case 'samesite':
        cookie.sameSite = attrValue.toLowerCase() as Cookie['sameSite'];
        break;
    }
  }

  return cookie;
}

function defaultPath(path: string): string {
  if (!path || !path.startsWith('/')) return '/';
  const lastSlash = path.lastIndexOf('/');
  if (lastSlash === 0) return '/';
  return path.substring(0, lastSlash);
}

/**
 * Serialize cookies for the Cookie header.
 */
export function serializeCookies(cookies: Cookie[]): string {
  return cookies.map((c) => `${c.name}=${c.value}`).join('; ');
}
