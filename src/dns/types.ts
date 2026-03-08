/**
 * Type definitions for the DNS resolution subsystem, including DNS-over-HTTPS
 * (RFC 8484), HTTPS/SVCB resource records (RFC 9460), and resolver interfaces.
 */

/**
 * A resolved IP address entry.
 */
export interface ResolvedAddress {
  address: string;
  family: 4 | 6;
}

/**
 * DNS query types used by the resolver.
 */
export type DNSRecordType = "A" | "AAAA" | "HTTPS" | "SVCB";

/**
 * A parsed DNS resource record.
 */
export interface DNSRecord {
  name: string;
  type: number;
  ttl: number;
  data: Buffer;
}

/**
 * Wire-format DNS record type numbers.
 */
export const RTYPE = {
  A: 1,
  AAAA: 28,
  HTTPS: 65,
  SVCB: 64,
} as const;

/**
 * Wire-format DNS class numbers.
 */
export const RCLASS = {
  IN: 1,
} as const;

/**
 * SvcParam keys defined in RFC 9460 §14.3.
 */
export const SvcParamKey = {
  MANDATORY: 0,
  ALPN: 1,
  NO_DEFAULT_ALPN: 2,
  PORT: 3,
  IPV4HINT: 4,
  ECH: 5,
  IPV6HINT: 6,
  /** draft-ietf-dnsop-svcb-https §14 — DNS-over-HTTPS path template */
  DOHPATH: 7,
} as const;

/**
 * Parsed HTTPS/SVCB record service parameters (RFC 9460).
 */
export interface SVCBRecord {
  /** SvcPriority — 0 = AliasMode, >0 = ServiceMode. */
  priority: number;
  /** TargetName — the target domain (empty = use record owner). */
  target: string;
  /** ALPN protocol identifiers (e.g. ["h2", "h3"]). */
  alpn?: string[];
  /** TCP port override. */
  port?: number;
  /** IPv4 address hints. */
  ipv4Hints?: string[];
  /** IPv6 address hints. */
  ipv6Hints?: string[];
  /** ECH configuration (raw bytes). */
  echConfigList?: Buffer;
  /** Whether no-default-alpn is set. */
  noDefaultAlpn?: boolean;
}

/**
 * Configuration options for the DoH resolver.
 */
export interface DoHConfig {
  /** DoH server URL (e.g. "https://1.1.1.1/dns-query"). */
  server: string;
  /**
   * HTTP method for DoH queries.
   * - `"GET"`: DNS wire-format base64url-encoded in `?dns=` query parameter.
   * - `"POST"`: DNS wire-format in request body.
   * @default "POST"
   */
  method?: "GET" | "POST";
  /** Timeout in ms for each DoH query. @default 5000 */
  timeout?: number;
  /**
   * Whether to bootstrap the DoH server address via system DNS if the
   * server URL uses a hostname instead of an IP.
   * @default true
   */
  bootstrap?: boolean;
}

/**
 * Combined DNS configuration for the library.
 */
export interface DNSConfig {
  /** DoH resolver configuration. When set, DNS queries use DNS-over-HTTPS. */
  doh?: DoHConfig;
  /**
   * Whether to query HTTPS/SVCB records alongside A/AAAA.
   * Enables ECH key discovery, ALPN hints, and IP hints.
   * @default false
   */
  httpsRR?: boolean;
}
