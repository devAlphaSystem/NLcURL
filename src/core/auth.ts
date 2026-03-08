/**
 * Configuration for HTTP authentication.
 *
 * @typedef {Object} AuthConfig
 * @property {"basic"|"bearer"} type - The authentication scheme to use.
 * @property {string} [username] - Username for Basic authentication.
 * @property {string} [password] - Password for Basic authentication.
 * @property {string} [token] - Bearer token for Bearer authentication.
 */
export interface AuthConfig {
  type: "basic" | "bearer";
  username?: string;
  password?: string;
  token?: string;
}

/**
 * Builds an HTTP Authorization header value from the given auth configuration.
 *
 * @param {AuthConfig} auth - The authentication configuration.
 * @returns {string|undefined} The formatted Authorization header value, or `undefined` if credentials are incomplete.
 */
export function buildAuthHeader(auth: AuthConfig): string | undefined {
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
    default:
      return undefined;
  }
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
