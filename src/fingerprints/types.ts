
/**
 * Defines a single TLS extension that will be included in the ClientHello
 * message. The optional `data` factory is called at handshake time to produce
 * the extension payload bytes.
 *
 * @typedef  {Object}   TLSExtensionDef
 * @property {number}   type  - IANA extension type code.
 * @property {Function} [data] - Factory that receives the SNI hostname and returns the extension payload.
 */
export interface TLSExtensionDef {
  type: number;
  data?: (sni: string) => Buffer;
}

/**
 * Full TLS fingerprint configuration used to construct a ClientHello message
 * that mirrors a specific browser's TLS behaviour.
 *
 * @typedef  {Object}            TLSProfile
 * @property {number}            recordVersion             - TLS record layer version sent in the ClientHello record header.
 * @property {number}            clientVersion             - Legacy version field inside the ClientHello body.
 * @property {number[]}          cipherSuites              - Ordered list of IANA cipher suite codes to advertise.
 * @property {number[]}          compressionMethods        - Compression method codes (typically `[0]` for none).
 * @property {TLSExtensionDef[]} extensions                - Ordered list of extensions to include in the ClientHello.
 * @property {number[]}          supportedGroups           - Named groups (key exchange curves) to advertise.
 * @property {number[]}          signatureAlgorithms       - Signature scheme codes to advertise.
 * @property {string[]}          alpnProtocols             - ALPN protocol names in preference order.
 * @property {boolean}           grease                    - Whether to inject GREASE values (RFC 8701).
 * @property {boolean}           randomSessionId           - Whether to include a random legacy session ID.
 * @property {number[]}          [certCompressAlgorithms]  - Certificate compression algorithm codes.
 * @property {number[]}          keyShareGroups            - Groups for which to generate key share entries.
 * @property {number[]}          [pskKeyExchangeModes]     - PSK key exchange mode codes.
 * @property {number[]}          supportedVersions         - TLS versions to advertise in the supported_versions extension.
 * @property {number[]}          [ecPointFormats]          - EC point format codes.
 * @property {Buffer}            [tokenBindingParams]      - Token binding extension payload.
 * @property {number[]}          [delegatedCredentials]    - Signature algorithms for delegated credentials.
 * @property {number}            [recordSizeLimit]         - Maximum record size limit value.
 * @property {string[]}          [applicationSettings]     - ALPS protocol names (Chrome-specific).
 */
export interface TLSProfile {
  recordVersion: number;
  clientVersion: number;
  cipherSuites: number[];
  compressionMethods: number[];
  extensions: TLSExtensionDef[];
  supportedGroups: number[];
  signatureAlgorithms: number[];
  alpnProtocols: string[];
  grease: boolean;
  randomSessionId: boolean;
  certCompressAlgorithms?: number[];
  keyShareGroups: number[];
  pskKeyExchangeModes?: number[];
  supportedVersions: number[];
  ecPointFormats?: number[];
  tokenBindingParams?: Buffer;
  delegatedCredentials?: number[];
  recordSizeLimit?: number;
  applicationSettings?: string[];
}

/**
 * A single HTTP/2 SETTINGS parameter and its value.
 *
 * @typedef  {Object} H2Setting
 * @property {number} id    - SETTINGS parameter identifier (RFC 9113).
 * @property {number} value - Parameter value.
 */
export interface H2Setting {
  id: number;
  value: number;
}

/**
 * HTTP/2 connection fingerprint that controls the SETTINGS frame, initial
 * WINDOW_UPDATE values, pseudo-header ordering, and optional PRIORITY frames
 * sent at connection open, matching those emitted by a specific browser.
 *
 * @typedef  {Object}     H2Profile
 * @property {H2Setting[]} settings             - SETTINGS parameters sent immediately after the preface.
 * @property {number}      windowUpdate          - Connection-level initial window increment sent after SETTINGS.
 * @property {string[]}    pseudoHeaderOrder     - Ordered list of HTTP/2 pseudo-header names (e.g. `[':method', ':path', ...]`).
 * @property {Array<{streamId:number,exclusive:boolean,dependsOn:number,weight:number}>} [priorityFrames] - Optional PRIORITY frames sent after the preface.
 * @property {string[]}   [headerOrder]          - Preferred ordering for regular (non-pseudo) request headers.
 */
export interface H2Profile {
  settings: H2Setting[];
  windowUpdate: number;
  pseudoHeaderOrder: string[];
  priorityFrames?: Array<{
    streamId: number;
    exclusive: boolean;
    dependsOn: number;
    weight: number;
  }>;
  headerOrder?: string[];
}

/**
 * HTTP header fingerprint containing the ordered headers and `User-Agent`
 * string that a browser sends with every request.
 *
 * @typedef  {Object}              HeaderProfile
 * @property {Array<[string,string]>} headers    - Ordered name-value header pairs.
 * @property {string}              userAgent      - The browser `User-Agent` string.
 */
export interface HeaderProfile {
  headers: Array<[string, string]>;
  userAgent: string;
}

/**
 * Combined browser impersonation fingerprint that bundles TLS, HTTP/2, and
 * HTTP header profiles under a single named browser identity.
 *
 * @typedef  {Object}        BrowserProfile
 * @property {string}        name     - Human-readable profile identifier (e.g. `"chrome136"`).
 * @property {'chrome'|'firefox'|'safari'|'edge'|'tor'} browser - Browser family.
 * @property {string}        version  - Browser version string (e.g. `"136"`).
 * @property {TLSProfile}    tls      - TLS ClientHello fingerprint configuration.
 * @property {H2Profile}     h2       - HTTP/2 connection fingerprint configuration.
 * @property {HeaderProfile} headers  - Default HTTP headers and `User-Agent` string.
 */
export interface BrowserProfile {
  name: string;
  browser: 'chrome' | 'firefox' | 'safari' | 'edge' | 'tor';
  version: string;
  tls: TLSProfile;
  h2: H2Profile;
  headers: HeaderProfile;
}
