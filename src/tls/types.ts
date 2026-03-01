/**
 * TLS engine types and the ITLSEngine interface that both standard
 * (node:tls) and stealth (raw handshake) engines implement.
 */

import type { Socket } from 'node:net';
import type { Duplex } from 'node:stream';
import type { BrowserProfile } from '../fingerprints/types.js';
import type { Logger } from '../utils/logger.js';

export interface TLSConnectOptions {
  host: string;
  port: number;
  /** Existing TCP socket to wrap (for proxy tunneling). */
  socket?: Socket;
  /** Server name for SNI. Defaults to `host`. */
  servername?: string;
  /** Skip certificate verification. */
  insecure?: boolean;
  /** ALPN protocols to offer. Derived from profile if not given. */
  alpnProtocols?: string[];
  /** Timeout for the TLS handshake in milliseconds. */
  timeout?: number;
  /** Abort signal. */
  signal?: AbortSignal;
  logger?: Logger;
}

export interface TLSConnectionInfo {
  /** Negotiated TLS protocol version, e.g. "TLSv1.3". */
  version: string;
  /** Negotiated ALPN protocol, e.g. "h2" or "http/1.1". */
  alpnProtocol: string | null;
  /** Negotiated cipher suite name. */
  cipher: string;
  /** The JA3 hash of the ClientHello actually sent. */
  ja3Hash?: string;
}

/**
 * A TLS-encrypted duplex stream augmented with connection metadata.
 */
export interface TLSSocket extends Duplex {
  /** Connection metadata (available after the handshake completes). */
  connectionInfo: TLSConnectionInfo;
  /** Gracefully close the TLS connection. */
  destroyTLS(): void;
}

/**
 * Both the standard and stealth TLS engines implement this interface.
 */
export interface ITLSEngine {
  /**
   * Open a TLS connection to the given host:port.
   *
   * If a BrowserProfile is supplied the engine MUST configure TLS
   * parameters (cipher suites, curves, extensions, ALPN) to match the
   * profile so that the JA3 fingerprint is correct.
   */
  connect(options: TLSConnectOptions, profile?: BrowserProfile): Promise<TLSSocket>;
}
