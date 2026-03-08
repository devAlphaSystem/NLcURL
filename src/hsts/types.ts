/**
 * Configuration for HTTP Strict Transport Security (RFC 6797).
 */
export interface HSTSConfig {
  /** Enable HSTS policy enforcement. Defaults to `true` when an HSTSStore is provided. */
  enabled?: boolean;
  /** Optional preload entries to seed the store with known HSTS hosts. */
  preload?: HSTSPreloadEntry[];
}

/**
 * A preload entry for seeding the HSTS store with known-secure hosts.
 */
export interface HSTSPreloadEntry {
  host: string;
  includeSubDomains?: boolean;
}

/**
 * Internal representation of a stored HSTS policy for a single host.
 */
export interface HSTSEntry {
  /** The canonicalized hostname (lowercase, no trailing dot). */
  host: string;
  /** Absolute timestamp (ms since epoch) when this policy expires. */
  expires: number;
  /** Whether the policy applies to all subdomains of the host. */
  includeSubDomains: boolean;
}
