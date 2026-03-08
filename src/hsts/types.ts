/** Configuration for the HSTS policy store. */
export interface HSTSConfig {
  /** Whether HSTS enforcement is enabled. */
  enabled?: boolean;
  /** Preloaded HSTS entries applied on construction. */
  preload?: HSTSPreloadEntry[];
}

/** Preloaded HSTS entry for a specific host. */
export interface HSTSPreloadEntry {
  /** Hostname to apply the HSTS policy to. */
  host: string;
  /** Whether the policy extends to all subdomains. */
  includeSubDomains?: boolean;
}

/** Active HSTS policy entry with expiration. */
export interface HSTSEntry {
  /** Canonical hostname the policy applies to. */
  host: string;
  /** Timestamp in milliseconds when the policy expires. */
  expires: number;
  /** Whether the policy extends to all subdomains. */
  includeSubDomains: boolean;
}
