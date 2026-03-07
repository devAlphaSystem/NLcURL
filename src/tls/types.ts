import type { Socket } from "node:net";
import type { Duplex } from "node:stream";
import type { BrowserProfile } from "../fingerprints/types.js";
import type { Logger } from "../utils/logger.js";

/**
 * Options required to establish a TLS connection to a remote server.
 *
 * @typedef  {Object}        TLSConnectOptions
 * @property {string}        host              - Remote hostname or IP address.
 * @property {number}        port              - Remote TCP port.
 * @property {Socket}        [socket]          - Pre-connected TCP socket to upgrade (e.g. after proxy CONNECT).
 * @property {string}        [servername]      - TLS SNI hostname; defaults to `host`.
 * @property {boolean}       [insecure]        - Skip TLS certificate verification when `true`.
 * @property {string[]}      [alpnProtocols]   - ALPN protocol names to advertise (e.g. `['h2', 'http/1.1']`).
 * @property {number}        [timeout]         - Handshake timeout in milliseconds.
 * @property {AbortSignal}   [signal]          - Signal used to abort the connection attempt.
 * @property {4|6}           [family]          - Force IPv4 (`4`) or IPv6 (`6`) for DNS resolution.
 * @property {Logger}        [logger]          - Optional logger for diagnostic output.
 */
export interface TLSConnectOptions {
  host: string;
  port: number;
  socket?: Socket;
  servername?: string;
  insecure?: boolean;
  alpnProtocols?: string[];
  timeout?: number;
  signal?: AbortSignal;
  family?: 4 | 6;
  logger?: Logger;
  cert?: string | Buffer;
  key?: string | Buffer;
  passphrase?: string;
  pfx?: string | Buffer;
  ca?: string | Buffer | Array<string | Buffer>;
}

/**
 * Metadata describing a successfully negotiated TLS connection.
 *
 * @typedef  {Object}       TLSConnectionInfo
 * @property {string}       version      - Negotiated TLS version string (e.g. `"TLSv1.3"`).
 * @property {string|null}  alpnProtocol - Negotiated ALPN protocol (e.g. `"h2"`), or `null`.
 * @property {string}       cipher       - Negotiated cipher suite name.
 * @property {string}       [ja3Hash]    - JA3 fingerprint hash of the ClientHello, if computed.
 */
export interface TLSConnectionInfo {
  version: string;
  alpnProtocol: string | null;
  cipher: string;
  ja3Hash?: string;
}

/**
 * A duplex stream representing an established TLS connection. Extends
 * `Duplex` with connection metadata and a controlled teardown method.
 *
 * @typedef  {Duplex}  TLSSocket
 * @property {TLSConnectionInfo} connectionInfo - Metadata about the negotiated TLS session.
 */
export interface TLSSocket extends Duplex {
  connectionInfo: TLSConnectionInfo;
  destroyTLS(): void;
}

/**
 * Contract for TLS engine implementations. Both the standard Node.js TLS
 * engine and the custom stealth engine implement this interface, allowing
 * them to be substituted transparently by the {@link ProtocolNegotiator}.
 */
export interface ITLSEngine {
  connect(options: TLSConnectOptions, profile?: BrowserProfile): Promise<TLSSocket>;
}

/**
 * User-facing TLS configuration for mTLS (client certificates) and custom
 * trust stores. These options are set on `NLcURLRequest.tls` or
 * `NLcURLSessionConfig.tls` and forwarded to the TLS engine.
 *
 * @typedef  {Object}              TLSOptions
 * @property {string|Buffer}       [cert]       - PEM-encoded client certificate (or chain).
 * @property {string|Buffer}       [key]        - PEM-encoded private key for the client certificate.
 * @property {string}              [passphrase] - Passphrase to decrypt the private key, if encrypted.
 * @property {string|Buffer}       [pfx]        - PFX/PKCS#12 bundle containing cert + key.
 * @property {string|Buffer|Array<string|Buffer>} [ca] - Custom CA certificate(s) to trust.
 */
export interface TLSOptions {
  cert?: string | Buffer;
  key?: string | Buffer;
  passphrase?: string;
  pfx?: string | Buffer;
  ca?: string | Buffer | Array<string | Buffer>;
}
