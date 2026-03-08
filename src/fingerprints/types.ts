/** Definition of a TLS extension with optional data generator. */
export interface TLSExtensionDef {
  /** Numeric TLS extension type identifier. */
  type: number;
  /** Generate extension data for the given server hostname. */
  data?: (sni: string) => Buffer;
}

/** Complete TLS ClientHello fingerprint profile. */
export interface TLSProfile {
  /** TLS record layer version. */
  recordVersion: number;
  /** TLS ClientHello version field. */
  clientVersion: number;
  /** Cipher suite code points. */
  cipherSuites: number[];
  /** Compression method code points. */
  compressionMethods: number[];
  /** TLS extensions to include in the ClientHello. */
  extensions: TLSExtensionDef[];
  /** Named groups (elliptic curves) to advertise. */
  supportedGroups: number[];
  /** Signature algorithm code points. */
  signatureAlgorithms: number[];
  /** ALPN protocol identifiers. */
  alpnProtocols: string[];
  /** Whether to insert GREASE values. */
  grease: boolean;
  /** Whether to generate a random 32-byte session ID. */
  randomSessionId: boolean;
  /** Certificate compression algorithm identifiers. */
  certCompressAlgorithms?: number[];
  /** Named groups to generate key shares for. */
  keyShareGroups: number[];
  /** PSK key exchange mode identifiers. */
  pskKeyExchangeModes?: number[];
  /** TLS version code points for the supported_versions extension. */
  supportedVersions: number[];
  /** EC point format identifiers. */
  ecPointFormats?: number[];
  /** Token binding parameters extension data. */
  tokenBindingParams?: Buffer;
  /** Delegated credentials signature algorithm code points. */
  delegatedCredentials?: number[];
  /** Maximum TLS record fragment size. */
  recordSizeLimit?: number;
  /** ALPS protocol identifiers. */
  applicationSettings?: string[];
}

/** Single HTTP/2 SETTINGS frame parameter. */
export interface H2Setting {
  /** Setting identifier. */
  id: number;
  /** Setting value. */
  value: number;
}

/** HTTP/2 connection fingerprint profile. */
export interface H2Profile {
  /** Initial SETTINGS frame parameters. */
  settings: H2Setting[];
  /** Connection-level flow-control window update size. */
  windowUpdate: number;
  /** Ordering of HTTP/2 pseudo-headers. */
  pseudoHeaderOrder: string[];
  /** Priority frames to send on connection establishment. */
  priorityFrames?: Array<{
    streamId: number;
    exclusive: boolean;
    dependsOn: number;
    weight: number;
  }>;
  /** Custom header field ordering. */
  headerOrder?: string[];
}

/** HTTP header fingerprint profile. */
export interface HeaderProfile {
  /** Default header name/value pairs. */
  headers: Array<[string, string]>;
  /** User-Agent header value. */
  userAgent: string;
}

/** Complete browser fingerprint combining TLS, HTTP/2, and header profiles. */
export interface BrowserProfile {
  /** Human-readable profile name. */
  name: string;
  /** Browser engine type. */
  browser: "chrome" | "firefox" | "safari" | "edge" | "tor";
  /** Browser version string. */
  version: string;
  /** TLS ClientHello fingerprint. */
  tls: TLSProfile;
  /** HTTP/2 connection fingerprint. */
  h2: H2Profile;
  /** HTTP header configuration. */
  headers: HeaderProfile;
}
