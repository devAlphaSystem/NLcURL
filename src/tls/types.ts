import type { Socket } from "node:net";
import type { Duplex } from "node:stream";
import type { BrowserProfile } from "../fingerprints/types.js";
import type { Logger } from "../utils/logger.js";

/** Options for establishing a TLS connection. */
export interface TLSConnectOptions {
  /** Remote host name or IP address. */
  host: string;
  /** Remote port number. */
  port: number;
  /** Existing TCP socket to upgrade to TLS. */
  socket?: Socket;
  /** Server name for SNI extension. */
  servername?: string;
  /** Skip certificate verification. */
  insecure?: boolean;
  /** ALPN protocol identifiers to offer. */
  alpnProtocols?: string[];
  /** Connection timeout in milliseconds. */
  timeout?: number;
  /** Abort signal to cancel the connection. */
  signal?: AbortSignal;
  /** IP address family (`4` or `6`). */
  family?: 4 | 6;
  /** Logger instance for diagnostic output. */
  logger?: Logger;
  /** Client certificate in PEM or DER format. */
  cert?: string | Buffer;
  /** Private key for client certificate authentication. */
  key?: string | Buffer;
  /** Passphrase for encrypted private keys. */
  passphrase?: string;
  /** PKCS#12 / PFX certificate bundle. */
  pfx?: string | Buffer;
  /** Custom certificate authority chain. */
  ca?: string | Buffer | Array<string | Buffer>;
  /** ECH config list for Encrypted Client Hello. */
  echConfigList?: Buffer;
  /** Expected SPKI pin(s) for public-key pinning. */
  pinnedPublicKey?: string | string[];
}

/** Metadata about a completed TLS connection. */
export interface TLSConnectionInfo {
  /** Negotiated protocol version string (e.g. `"TLSv1.3"`). */
  version: string;
  /** Negotiated ALPN protocol, or `null` if none. */
  alpnProtocol: string | null;
  /** Negotiated cipher suite name. */
  cipher: string;
  /** JA3 fingerprint hash of the connection, if computed. */
  ja3Hash?: string;
  /** Whether the session was resumed via a session ticket. */
  resumed?: boolean;
}

/** Duplex stream extended with TLS connection metadata. */
export interface TLSSocket extends Duplex {
  /** Information about the negotiated TLS parameters. */
  connectionInfo: TLSConnectionInfo;
  /** Tear down the TLS layer and release resources. */
  destroyTLS(): void;
  /** Get channel binding token for tls-server-end-point (RFC 5929). */
  getChannelBinding?(type: "tls-server-end-point"): Buffer | null;
}

/** Engine interface for pluggable TLS implementations. */
export interface ITLSEngine {
  /**
   * Establish a TLS connection.
   *
   * @param {TLSConnectOptions} options - Connection parameters.
   * @param {BrowserProfile} [profile] - Optional browser profile for fingerprint impersonation.
   * @returns {Promise<TLSSocket>} Connected TLS socket.
   */
  connect(options: TLSConnectOptions, profile?: BrowserProfile): Promise<TLSSocket>;
}

/** Client certificate and key configuration subset. */
export interface TLSOptions {
  /** Client certificate in PEM or DER format. */
  cert?: string | Buffer;
  /** Private key for client authentication. */
  key?: string | Buffer;
  /** Passphrase for encrypted private keys. */
  passphrase?: string;
  /** PKCS#12 / PFX certificate bundle. */
  pfx?: string | Buffer;
  /** Custom certificate authority chain. */
  ca?: string | Buffer | Array<string | Buffer>;
  /** Expected SPKI pin(s) for public-key pinning. */
  pinnedPublicKey?: string | string[];
  /** Certificate Revocation List(s) in PEM format. */
  crl?: string | Buffer | Array<string | Buffer>;
}
