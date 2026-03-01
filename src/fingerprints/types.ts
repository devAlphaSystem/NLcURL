/**
 * Fingerprint profile types.
 *
 * Each BrowserProfile captures every parameter needed to replicate a
 * specific browser's TLS ClientHello and HTTP/2 connection preface so
 * that the JA3 and Akamai h2 fingerprints match the real browser.
 */

// ---- TLS profile ----

export interface TLSExtensionDef {
  /** IANA extension type (e.g. 0x0000 for SNI). */
  type: number;
  /**
   * Opaque payload builder.  Receives the SNI hostname at runtime and
   * must return the extension_data bytes (without the type/length
   * header -- that is added automatically).
   *
   * If undefined the extension carries an empty payload.
   */
  data?: (sni: string) => Buffer;
}

export interface TLSProfile {
  /** TLS record-layer version sent in the ClientHello record header.
   *  Almost always 0x0301 (TLS 1.0) for compatibility. */
  recordVersion: number;
  /** Client version field inside the ClientHello body.
   *  0x0303 (TLS 1.2) for modern browsers -- real negotiation happens
   *  via the supported_versions extension. */
  clientVersion: number;
  /** Ordered list of cipher suite IDs (including any GREASE values). */
  cipherSuites: number[];
  /** Compression methods (always [0] for modern browsers). */
  compressionMethods: number[];
  /** Extensions in exact order.  The ordering determines the JA3 hash. */
  extensions: TLSExtensionDef[];
  /** Named groups (supported_groups extension value). */
  supportedGroups: number[];
  /** Signature algorithms (signature_algorithms extension value). */
  signatureAlgorithms: number[];
  /** ALPN protocol list. */
  alpnProtocols: string[];
  /** Whether to include GREASE values for cipher suites, extensions,
   *  supported groups, and key share. */
  grease: boolean;
  /** If true, generate a random session ID (32 bytes). Chrome does this. */
  randomSessionId: boolean;
  /** Compress-certificate algorithm IDs (if the extension is present). */
  certCompressAlgorithms?: number[];
  /** Key-share groups to send in the ClientHello (must be a subset of
   *  supportedGroups). */
  keyShareGroups: number[];
  /** PSK key exchange modes. */
  pskKeyExchangeModes?: number[];
  /** Supported TLS versions (for the supported_versions extension). */
  supportedVersions: number[];
  /** EC point formats. */
  ecPointFormats?: number[];
  /** Token binding parameters (if the extension is present). */
  tokenBindingParams?: Buffer;
  /** Delegated credentials signature algorithms. */
  delegatedCredentials?: number[];
  /** Record size limit value. */
  recordSizeLimit?: number;
  /** Application settings protocols (ALPS). */
  applicationSettings?: string[];
}

// ---- HTTP/2 profile ----

export interface H2Setting {
  id: number;
  value: number;
}

export interface H2Profile {
  /** SETTINGS frame entries in exact order. */
  settings: H2Setting[];
  /** WINDOW_UPDATE increment sent immediately after the SETTINGS. */
  windowUpdate: number;
  /** Pseudo-header order for requests (e.g. [":method", ":authority",
   *  ":scheme", ":path"]). */
  pseudoHeaderOrder: string[];
  /** Priority frames sent in the connection preface (optional). */
  priorityFrames?: Array<{
    streamId: number;
    exclusive: boolean;
    dependsOn: number;
    weight: number;
  }>;
  /** Header order hint -- browsers send certain headers in a fixed order. */
  headerOrder?: string[];
}

// ---- HTTP headers ----

export interface HeaderProfile {
  /** Default HTTP headers in the order the browser sends them. */
  headers: Array<[string, string]>;
  /** User-Agent string. */
  userAgent: string;
}

// ---- Combined profile ----

export interface BrowserProfile {
  /** Canonical name, e.g. "chrome136". */
  name: string;
  /** Browser family. */
  browser: 'chrome' | 'firefox' | 'safari' | 'edge' | 'tor';
  /** Browser version string. */
  version: string;
  tls: TLSProfile;
  h2: H2Profile;
  headers: HeaderProfile;
}
