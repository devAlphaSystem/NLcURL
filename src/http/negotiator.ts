/**
 * Protocol negotiator.
 *
 * Establishes TLS connections, determines the negotiated ALPN protocol,
 * and returns either an H1 or H2 transport ready for request dispatch.
 */

import type { Duplex } from 'node:stream';
import type { BrowserProfile } from '../fingerprints/types.js';
import type { ITLSEngine, TLSSocket, TLSConnectOptions } from '../tls/types.js';
import { NodeTLSEngine } from '../tls/node-engine.js';
import { StealthTLSEngine } from '../tls/stealth/engine.js';
import { originOf } from '../utils/url.js';
import { supportsZstd, sanitizeAcceptEncoding } from '../utils/encoding.js';
import { ConnectionPool, type PoolEntry, type PoolOptions } from './pool.js';
import { H2Client } from './h2/client.js';
import { sendH1Request } from './h1/client.js';
import type { NLcURLRequest, RequestTimings } from '../core/request.js';
import { NLcURLResponse } from '../core/response.js';

export interface NegotiatorOptions {
  /** Use stealth TLS engine for full fingerprint control. */
  stealth?: boolean;
  /** Browser profile for TLS/H2 fingerprinting. */
  profile?: BrowserProfile;
  /** Allow insecure TLS connections (skip certificate verification). */
  insecure?: boolean;
  /** Connection pool options. */
  pool?: PoolOptions;
}

export class ProtocolNegotiator {
  private readonly standardEngine: NodeTLSEngine;
  private readonly stealthEngine: StealthTLSEngine;
  private readonly pool: ConnectionPool;

  constructor(poolOptions?: PoolOptions) {
    this.standardEngine = new NodeTLSEngine();
    this.stealthEngine = new StealthTLSEngine();
    this.pool = new ConnectionPool(poolOptions);
  }

  /**
   * Send a request, reusing pooled connections when possible.
   */
  async send(
    request: NLcURLRequest,
    options: NegotiatorOptions = {},
  ): Promise<NLcURLResponse> {
    const url = new URL(request.url);
    const origin = originOf(url.toString());
    const timings: Partial<RequestTimings> = {};

    // Try to reuse a pooled connection
    let poolEntry = this.pool.get(origin);

    if (!poolEntry) {
      // Establish new connection
      const connectStart = Date.now();
      const socket = await this.connect(url, request, options);
      const connectEnd = Date.now();
      timings.connect = connectEnd - connectStart;

      const alpn = socket.connectionInfo.alpnProtocol;
      const protocol = alpn === 'h2' ? 'h2' : 'h1';

      const defaultHeaders = sanitizeProfileHeaders(options.profile?.headers.headers ?? []);
      poolEntry = this.pool.put(
        origin,
        socket,
        protocol,
        protocol === 'h2' ? options.profile?.h2 : undefined,
        defaultHeaders,
      );
    }

    // Dispatch based on protocol
    if (poolEntry.protocol === 'h2' && poolEntry.h2Client) {
      poolEntry.h2Client.sendPreface();
      const response = await poolEntry.h2Client.request(request, timings);
      return response;
    }

    // HTTP/1.1
    let response: NLcURLResponse;
    try {
      response = await sendH1Request(
        poolEntry.socket as unknown as Duplex,
        request,
        { defaultHeaders: sanitizeProfileHeaders(options.profile?.headers.headers ?? []) },
        timings,
      );
    } catch (err) {
      // Connection is in unknown state — remove from pool
      this.pool.remove(poolEntry);
      throw err;
    }

    // Check if we can reuse the connection
    const connection = response.headers['connection'];
    if (connection?.toLowerCase() === 'close') {
      this.pool.remove(poolEntry);
    } else {
      this.pool.release(poolEntry);
    }

    return response;
  }

  /**
   * Close all connections.
   */
  close(): void {
    this.pool.close();
  }

  // ---- Internal ----

  private async connect(
    url: URL,
    request: NLcURLRequest,
    options: NegotiatorOptions,
  ): Promise<TLSSocket> {
    const engine: ITLSEngine =
      (request.stealth ?? options.stealth) ? this.stealthEngine : this.standardEngine;

    const port = url.port ? parseInt(url.port, 10) : url.protocol === 'https:' ? 443 : 80;

    const tlsOptions: TLSConnectOptions = {
      host: url.hostname,
      port,
      servername: url.hostname,
      insecure: options.insecure ?? false,
      alpnProtocols: options.profile?.tls.alpnProtocols ?? ['h2', 'http/1.1'],
      timeout: typeof request.timeout === 'number' ? request.timeout : request.timeout?.connect,
      signal: request.signal,
    };

    return engine.connect(tlsOptions, options.profile);
  }
}

/**
 * On runtimes that lack zstd decompression (Node < 22), strip zstd from
 * the accept-encoding default header so servers never respond with it.
 */
function sanitizeProfileHeaders(
  headers: Array<[string, string]>,
): Array<[string, string]> {
  if (supportsZstd) return headers;
  return headers.map(([k, v]) =>
    k.toLowerCase() === 'accept-encoding'
      ? [k, sanitizeAcceptEncoding(v)]
      : [k, v],
  );
}
