/** Resolved IP address with protocol family. */
export interface ResolvedAddress {
  /** IP address string. */
  address: string;
  /** Internet protocol family — 4 for IPv4, 6 for IPv6. */
  family: 4 | 6;
}

/** Supported DNS resource record type names. */
export type DNSRecordType = "A" | "AAAA" | "HTTPS" | "SVCB";

/** Parsed DNS resource record. */
export interface DNSRecord {
  /** Domain name the record belongs to. */
  name: string;
  /** Numeric record type (matches RTYPE constants). */
  type: number;
  /** Time-to-live in seconds. */
  ttl: number;
  /** Raw record data. */
  data: Buffer;
}

/** Numeric DNS record type constants. */
export const RTYPE = {
  A: 1,
  AAAA: 28,
  HTTPS: 65,
  SVCB: 64,
} as const;

/** DNS record class constants. */
export const RCLASS = {
  IN: 1,
} as const;

/** SVCB/HTTPS service parameter key constants. */
export const SvcParamKey = {
  MANDATORY: 0,
  ALPN: 1,
  NO_DEFAULT_ALPN: 2,
  PORT: 3,
  IPV4HINT: 4,
  ECH: 5,
  IPV6HINT: 6,
  DOHPATH: 7,
} as const;

/** Parsed SVCB/HTTPS DNS resource record. */
export interface SVCBRecord {
  /** Record priority — 0 indicates an alias record. */
  priority: number;
  /** Target domain name for the service. */
  target: string;
  /** Supported ALPN protocol identifiers. */
  alpn?: string[];
  /** Alternate port for the service. */
  port?: number;
  /** IPv4 address hints for the service. */
  ipv4Hints?: string[];
  /** IPv6 address hints for the service. */
  ipv6Hints?: string[];
  /** Encrypted Client Hello configuration list. */
  echConfigList?: Buffer;
  /** Whether the default ALPN should not be used. */
  noDefaultAlpn?: boolean;
}

/** Configuration for a DNS-over-HTTPS resolver. */
export interface DoHConfig {
  /** DoH server URL (e.g. "https://cloudflare-dns.com/dns-query"). */
  server: string;
  /** HTTP method to use for queries. */
  method?: "GET" | "POST";
  /** Query timeout in milliseconds. */
  timeout?: number;
  /** Whether to use system DNS to bootstrap the DoH server address. */
  bootstrap?: boolean;
  /** DNS cache configuration. */
  cache?: import("./cache.js").DNSCacheConfig;
}

/** Top-level DNS resolver configuration. */
export interface DNSConfig {
  /** DNS-over-HTTPS resolver configuration. */
  doh?: DoHConfig;
  /** Whether to query HTTPS resource records for ECH and ALPN hints. */
  httpsRR?: boolean;
}
