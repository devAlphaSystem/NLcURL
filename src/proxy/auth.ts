import { createHash, randomBytes } from "node:crypto";

/** Supported proxy authentication scheme identifiers. */
export type ProxyAuthScheme = "basic" | "digest" | "negotiate" | "ntlm";

/** Credentials and scheme selection for proxy authentication. */
export interface ProxyAuthConfig {
  /** Proxy account username. */
  username: string;
  /** Proxy account password. */
  password: string;
  /** Authentication scheme to use — defaults to `"basic"`. */
  scheme?: ProxyAuthScheme;
}

/** Parsed parameters from an HTTP Digest authentication challenge. */
export interface DigestChallenge {
  /** Protection realm name. */
  realm: string;
  /** Server-generated nonce value. */
  nonce: string;
  /** Quality-of-protection directive (e.g. `"auth"`). */
  qop?: string;
  /** Opaque value to be returned unchanged to the server. */
  opaque?: string;
  /** Hash algorithm name (e.g. `"MD5"`, `"SHA-256"`). */
  algorithm?: string;
  /** Whether the previous nonce has gone stale. */
  stale?: boolean;
  /** Space-delimited list of URIs defining the protection space. */
  domain?: string;
}

/**
 * Parse a `Proxy-Authenticate` response header into its scheme and raw challenge.
 *
 * @param {string} header - Raw header value.
 * @returns {object|null} Parsed scheme and challenge string, or `null` if unrecognized.
 */
export function parseProxyAuthenticate(header: string): {
  scheme: ProxyAuthScheme;
  challenge: string;
} | null {
  if (!header) return null;

  const lower = header.trimStart().toLowerCase();
  if (lower.startsWith("digest ")) {
    return { scheme: "digest", challenge: header.substring(7) };
  }
  if (lower.startsWith("negotiate")) {
    return { scheme: "negotiate", challenge: header.substring(10).trim() };
  }
  if (lower.startsWith("ntlm")) {
    return { scheme: "ntlm", challenge: header.substring(5).trim() };
  }
  if (lower.startsWith("basic ")) {
    return { scheme: "basic", challenge: header.substring(6) };
  }
  return null;
}

/**
 * Parse a raw Digest challenge string into structured parameters.
 *
 * @param {string} challenge - The challenge portion after `Digest `.
 * @returns {DigestChallenge|null} Parsed {@link DigestChallenge}, or `null` if required fields are missing.
 */
export function parseDigestChallenge(challenge: string): DigestChallenge | null {
  const params: Record<string, string> = {};

  const regex = /(\w+)=(?:"([^"]*)"|([\w.]+))/g;
  let match: RegExpExecArray | null;
  while ((match = regex.exec(challenge)) !== null) {
    params[match[1]!.toLowerCase()] = match[2] ?? match[3] ?? "";
  }

  if (!params["realm"] || !params["nonce"]) return null;

  return {
    realm: params["realm"],
    nonce: params["nonce"],
    qop: params["qop"],
    opaque: params["opaque"],
    algorithm: params["algorithm"],
    stale: params["stale"]?.toLowerCase() === "true",
    domain: params["domain"],
  };
}

let nonceCount = 0;

/**
 * Build an HTTP Digest `Proxy-Authorization` header value.
 *
 * @param {string} method - HTTP method (e.g. `"CONNECT"`).
 * @param {string} uri - Request URI.
 * @param {ProxyAuthConfig} auth - Proxy credentials.
 * @param {DigestChallenge} challenge - Parsed digest challenge from the proxy.
 * @returns {string} Fully-formed `Digest` authorization header value.
 */
export function buildDigestAuth(method: string, uri: string, auth: ProxyAuthConfig, challenge: DigestChallenge): string {
  const algorithm = (challenge.algorithm ?? "MD5").toUpperCase();
  const hashFn = algorithm === "SHA-256" ? "sha256" : "md5";

  const ha1 = md(hashFn, `${auth.username}:${challenge.realm}:${auth.password}`);

  const ha2 = md(hashFn, `${method}:${uri}`);

  nonceCount++;
  const nc = nonceCount.toString(16).padStart(8, "0");
  const cnonce = randomBytes(16).toString("hex");

  let response: string;
  if (challenge.qop) {
    const qop = challenge.qop.includes("auth") ? "auth" : challenge.qop;
    response = md(hashFn, `${ha1}:${challenge.nonce}:${nc}:${cnonce}:${qop}:${ha2}`);

    let header = `Digest username="${auth.username}", realm="${challenge.realm}", `;
    header += `nonce="${challenge.nonce}", uri="${uri}", `;
    header += `algorithm=${algorithm}, qop=${qop}, nc=${nc}, cnonce="${cnonce}", `;
    header += `response="${response}"`;
    if (challenge.opaque) header += `, opaque="${challenge.opaque}"`;
    return header;
  }

  response = md(hashFn, `${ha1}:${challenge.nonce}:${ha2}`);

  let header = `Digest username="${auth.username}", realm="${challenge.realm}", `;
  header += `nonce="${challenge.nonce}", uri="${uri}", `;
  header += `algorithm=${algorithm}, response="${response}"`;
  if (challenge.opaque) header += `, opaque="${challenge.opaque}"`;
  return header;
}

/**
 * Build an HTTP Basic `Proxy-Authorization` header value.
 *
 * @param {ProxyAuthConfig} auth - Proxy credentials.
 * @returns {string} Base64-encoded `Basic` authorization header value.
 */
export function buildBasicProxyAuth(auth: ProxyAuthConfig): string {
  const encoded = Buffer.from(`${auth.username}:${auth.password}`).toString("base64");
  return `Basic ${encoded}`;
}

/**
 * Build a `Proxy-Authorization` header for the configured scheme.
 *
 * @param {string} method - HTTP method.
 * @param {string} uri - Request URI.
 * @param {ProxyAuthConfig} auth - Proxy credentials and scheme preference.
 * @param {string} [proxyAuthHeader] - Optional raw `Proxy-Authenticate` header for digest negotiation.
 * @returns {string|null} Header value string, or `null` if the scheme cannot be satisfied.
 */
export function buildProxyAuthorization(method: string, uri: string, auth: ProxyAuthConfig, proxyAuthHeader?: string): string | null {
  const scheme = auth.scheme ?? "basic";

  if (scheme === "basic") {
    return buildBasicProxyAuth(auth);
  }

  if (scheme === "digest" && proxyAuthHeader) {
    const parsed = parseProxyAuthenticate(proxyAuthHeader);
    if (parsed?.scheme === "digest") {
      const challenge = parseDigestChallenge(parsed.challenge);
      if (challenge) {
        return buildDigestAuth(method, uri, auth, challenge);
      }
    }
    return null;
  }

  return null;
}

function md(algorithm: string, data: string): string {
  return createHash(algorithm).update(data).digest("hex");
}
