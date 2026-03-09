import { createHash, createHmac, randomBytes } from "node:crypto";

/**
 * Configuration for HTTP authentication.
 *
 * @typedef {Object} AuthConfig
 * @property {"basic"|"bearer"|"digest"|"aws-sigv4"} type - The authentication scheme to use.
 * @property {string} [username] - Username for Basic/Digest authentication.
 * @property {string} [password] - Password for Basic/Digest authentication.
 * @property {string} [token] - Bearer token for Bearer authentication.
 * @property {string} [awsRegion] - AWS region for SigV4.
 * @property {string} [awsService] - AWS service for SigV4.
 * @property {string} [awsAccessKeyId] - AWS access key ID for SigV4.
 * @property {string} [awsSecretKey] - AWS secret access key for SigV4.
 * @property {string} [awsSessionToken] - AWS session token (optional) for SigV4.
 */
export interface AuthConfig {
  type: "basic" | "bearer" | "digest" | "aws-sigv4" | "negotiate" | "ntlm";
  username?: string;
  password?: string;
  token?: string;
  awsRegion?: string;
  awsService?: string;
  awsAccessKeyId?: string;
  awsSecretKey?: string;
  awsSessionToken?: string;
}

/** Parsed Digest challenge from WWW-Authenticate header. */
export interface DigestChallenge {
  realm: string;
  nonce: string;
  qop?: string;
  opaque?: string;
  algorithm?: string;
  stale?: boolean;
}

const digestNonceCounters = new Map<string, number>();

/**
 * Builds an HTTP Authorization header value from the given auth configuration.
 *
 * @param {AuthConfig} auth - The authentication configuration.
 * @param {Object} [context] - Additional context for stateful schemes.
 * @param {string} [context.method] - HTTP method for Digest/SigV4.
 * @param {string} [context.url] - Request URL for Digest/SigV4.
 * @param {string} [context.wwwAuthenticate] - WWW-Authenticate header for Digest.
 * @param {Record<string, string>} [context.headers] - Request headers for SigV4.
 * @param {Buffer} [context.body] - Request body for SigV4.
 * @returns {string|undefined} The formatted Authorization header value, or `undefined` if credentials are incomplete.
 */
export function buildAuthHeader(
  auth: AuthConfig,
  context?: {
    method?: string;
    url?: string;
    wwwAuthenticate?: string;
    headers?: Record<string, string>;
    body?: Buffer;
  },
): string | undefined {
  switch (auth.type) {
    case "basic": {
      if (!auth.username) return undefined;
      const credentials = `${auth.username}:${auth.password ?? ""}`;
      return `Basic ${Buffer.from(credentials, "utf-8").toString("base64")}`;
    }
    case "bearer": {
      if (!auth.token) return undefined;
      return `Bearer ${auth.token}`;
    }
    case "digest": {
      if (!auth.username || !context?.wwwAuthenticate || !context?.method || !context?.url) return undefined;
      const challenge = parseDigestChallenge(context.wwwAuthenticate);
      if (!challenge) return undefined;
      return buildDigestAuthHeader(context.method, context.url, auth.username, auth.password ?? "", challenge, context.body);
    }
    case "aws-sigv4": {
      if (!auth.awsAccessKeyId || !auth.awsSecretKey || !auth.awsRegion || !auth.awsService || !context?.method || !context?.url) return undefined;
      return buildAWSSigV4(context.method, context.url, context.headers ?? {}, context.body ?? Buffer.alloc(0), auth.awsAccessKeyId, auth.awsSecretKey, auth.awsRegion, auth.awsService, auth.awsSessionToken);
    }
    case "negotiate": {
      if (!auth.token) return undefined;
      return `Negotiate ${auth.token}`;
    }
    case "ntlm": {
      if (!auth.token) return undefined;
      return `NTLM ${auth.token}`;
    }
    default:
      return undefined;
  }
}

/**
 * Parse a Digest challenge from WWW-Authenticate header.
 */
function parseDigestChallenge(header: string): DigestChallenge | null {
  const lower = header.toLowerCase().trim();
  if (!lower.startsWith("digest ")) return null;
  const challenge = header.substring(7);

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
  };
}

function md(algo: string, data: string): string {
  return createHash(algo).update(data).digest("hex");
}

/**
 * Build a Digest Authorization header value (RFC 7616).
 * Supports both qop="auth" and qop="auth-int" (B10).
 */
function buildDigestAuthHeader(method: string, uri: string, username: string, password: string, challenge: DigestChallenge, body?: Buffer): string {
  const algorithm = (challenge.algorithm ?? "MD5").toUpperCase();
  const hashFn = algorithm === "SHA-256" || algorithm === "SHA-256-SESS" ? "sha256" : algorithm === "SHA-512-256" || algorithm === "SHA-512-256-SESS" ? "sha512-256" : "md5";

  let ha1 = md(hashFn, `${username}:${challenge.realm}:${password}`);

  const cnonce = randomBytes(16).toString("hex");
  if (algorithm.endsWith("-SESS")) {
    ha1 = md(hashFn, `${ha1}:${challenge.nonce}:${cnonce}`);
  }

  const parsedUrl = new URL(uri, "http://localhost");
  const digestUri = parsedUrl.pathname + parsedUrl.search;

  let ha2: string;
  let qop: string | undefined;
  if (challenge.qop) {
    if (challenge.qop.includes("auth-int") && body) {
      qop = "auth-int";
      const entityBody = md(hashFn, body.toString("binary"));
      ha2 = md(hashFn, `${method}:${digestUri}:${entityBody}`);
    } else if (challenge.qop.includes("auth")) {
      qop = "auth";
      ha2 = md(hashFn, `${method}:${digestUri}`);
    } else {
      qop = challenge.qop;
      ha2 = md(hashFn, `${method}:${digestUri}`);
    }
  } else {
    ha2 = md(hashFn, `${method}:${digestUri}`);
  }

  const count = (digestNonceCounters.get(challenge.nonce) ?? 0) + 1;
  digestNonceCounters.set(challenge.nonce, count);
  const nc = count.toString(16).padStart(8, "0");

  let response: string;
  let headerStr: string;

  if (qop) {
    response = md(hashFn, `${ha1}:${challenge.nonce}:${nc}:${cnonce}:${qop}:${ha2}`);
    headerStr = `Digest username="${username}", realm="${challenge.realm}", `;
    headerStr += `nonce="${challenge.nonce}", uri="${digestUri}", `;
    headerStr += `algorithm=${algorithm}, qop=${qop}, nc=${nc}, cnonce="${cnonce}", `;
    headerStr += `response="${response}"`;
  } else {
    response = md(hashFn, `${ha1}:${challenge.nonce}:${ha2}`);
    headerStr = `Digest username="${username}", realm="${challenge.realm}", `;
    headerStr += `nonce="${challenge.nonce}", uri="${digestUri}", `;
    headerStr += `algorithm=${algorithm}, response="${response}"`;
  }

  if (challenge.opaque) headerStr += `, opaque="${challenge.opaque}"`;
  return headerStr;
}

/**
 * AWS Signature Version 4 signing (simplified).
 */
function buildAWSSigV4(method: string, url: string, headers: Record<string, string>, body: Buffer, accessKeyId: string, secretKey: string, region: string, service: string, sessionToken?: string): string {
  const parsed = new URL(url);
  const now = new Date();
  const dateStamp = now.toISOString().replace(/[-:T]/g, "").substring(0, 8);
  const amzDate = now
    .toISOString()
    .replace(/[-:]/g, "")
    .replace(/\.\d{3}/, "");

  const signedHeaders: Record<string, string> = {};
  signedHeaders["host"] = parsed.host;
  for (const [k, v] of Object.entries(headers)) {
    signedHeaders[k.toLowerCase().trim()] = v.trim();
  }
  signedHeaders["x-amz-date"] = amzDate;
  if (sessionToken) {
    signedHeaders["x-amz-security-token"] = sessionToken;
  }

  const sortedHeaderNames = Object.keys(signedHeaders).sort();
  const canonicalHeaders = sortedHeaderNames.map((k) => `${k}:${signedHeaders[k]}`).join("\n") + "\n";
  const signedHeadersList = sortedHeaderNames.join(";");

  const payloadHash = createHash("sha256").update(body).digest("hex");

  const canonicalUri = parsed.pathname || "/";
  const canonicalQueryString = [...parsed.searchParams]
    .sort((a, b) => a[0].localeCompare(b[0]))
    .map(([k, v]) => `${encodeURIComponent(k)}=${encodeURIComponent(v)}`)
    .join("&");

  const canonicalRequest = [method.toUpperCase(), canonicalUri, canonicalQueryString, canonicalHeaders, signedHeadersList, payloadHash].join("\n");

  const credentialScope = `${dateStamp}/${region}/${service}/aws4_request`;
  const stringToSign = ["AWS4-HMAC-SHA256", amzDate, credentialScope, createHash("sha256").update(canonicalRequest).digest("hex")].join("\n");

  const kDate = createHmac("sha256", `AWS4${secretKey}`).update(dateStamp).digest();
  const kRegion = createHmac("sha256", kDate).update(region).digest();
  const kService = createHmac("sha256", kRegion).update(service).digest();
  const kSigning = createHmac("sha256", kService).update("aws4_request").digest();
  const signature = createHmac("sha256", kSigning).update(stringToSign).digest("hex");

  return `AWS4-HMAC-SHA256 Credential=${accessKeyId}/${credentialScope}, SignedHeaders=${signedHeadersList}, Signature=${signature}`;
}

/**
 * Extracts the authentication scheme name from a WWW-Authenticate or Proxy-Authenticate header.
 *
 * @param {string} header - The raw authenticate header value.
 * @returns {string|undefined} The lowercase scheme name (e.g. "basic", "bearer"), or `undefined` if not parseable.
 */
export function parseAuthenticateScheme(header: string): string | undefined {
  const match = /^(\w+)\s/i.exec(header.trim());
  return match ? match[1]!.toLowerCase() : undefined;
}
