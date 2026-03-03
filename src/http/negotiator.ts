
import type { Duplex } from 'node:stream';
import { lookup } from 'node:dns/promises';
import type { BrowserProfile } from '../fingerprints/types.js';
import type { ITLSEngine, TLSSocket, TLSConnectOptions } from '../tls/types.js';
import { NodeTLSEngine } from '../tls/node-engine.js';
import { StealthTLSEngine } from '../tls/stealth/engine.js';
import { originOf } from '../utils/url.js';
import { supportsZstd, sanitizeAcceptEncoding } from '../utils/encoding.js';
import { ConnectionPool, type PoolEntry, type PoolOptions } from './pool.js';
import { H2Client } from './h2/client.js';
import { sendH1Request, sendH1StreamingRequest } from './h1/client.js';
import type { NLcURLRequest, RequestTimings } from '../core/request.js';
import { NLcURLResponse } from '../core/response.js';
import { ProtocolError } from '../core/errors.js';
import { httpProxyConnect } from '../proxy/http-proxy.js';
import { socksConnect } from '../proxy/socks.js';

/**
 * Controls which TLS engine and browser profile the {@link ProtocolNegotiator}
 * uses when establishing a new connection.
 *
 * @typedef  {Object}         NegotiatorOptions
 * @property {boolean}        [stealth]  - Use the stealth TLS engine instead of the Node.js native engine.
 * @property {BrowserProfile} [profile]  - Browser profile for TLS, HTTP/2, and header fingerprinting.
 * @property {boolean}        [insecure] - Skip TLS certificate verification.
 * @property {PoolOptions}    [pool]     - Connection pool configuration overrides.
 */
export interface NegotiatorOptions {
  stealth?: boolean;
  profile?: BrowserProfile;
  insecure?: boolean;
  pool?: PoolOptions;
}

/**
 * Manages the full lifecycle of an outgoing HTTP request: DNS resolution,
 * TCP/TLS connection establishment (via proxy if configured), HTTP/1.1 or
 * HTTP/2 protocol negotiation through ALPN, connection pooling, and response
 * collection. Uses a shared {@link ConnectionPool} to reuse connections.
 */
export class ProtocolNegotiator {
  private readonly standardEngine: NodeTLSEngine;
  private readonly stealthEngine: StealthTLSEngine;
  private readonly pool: ConnectionPool;

  /**
   * Creates a new ProtocolNegotiator with an internal connection pool.
   *
   * @param {PoolOptions} [poolOptions] - Optional configuration for the underlying connection pool.
   */
  constructor(poolOptions?: PoolOptions) {
    this.standardEngine = new NodeTLSEngine();
    this.stealthEngine = new StealthTLSEngine();
    this.pool = new ConnectionPool(poolOptions);
  }

  /**
   * Dispatches a single HTTP request. Reuses a pooled connection when one is
   * available for the request’s origin; otherwise establishes a new TCP/TLS
   * connection (with optional proxy tunnelling) and negotiates HTTP/1.1 or
   * HTTP/2 via ALPN. Returns the server’s response.
   *
   * @param {NLcURLRequest}      request - The request to send.
   * @param {NegotiatorOptions}  [options={}] - Engine and profile options.
   * @returns {Promise<NLcURLResponse>} Resolves with the response from the server.
   * @throws {ConnectionError} If the TCP or TLS connection cannot be established.
   * @throws {TLSError}        If the TLS handshake fails.
   * @throws {ProxyError}      If proxy tunnel negotiation fails.
   * @throws {TimeoutError}    If any configured timeout is exceeded.
   */
  async send(
    request: NLcURLRequest,
    options: NegotiatorOptions = {},
  ): Promise<NLcURLResponse> {
    return this._send(request, options, false);
  }

  private async _send(
    request: NLcURLRequest,
    options: NegotiatorOptions,
    isRetry: boolean,
  ): Promise<NLcURLResponse> {
    const url = new URL(request.url);
    const origin = originOf(url.toString());
    const timings: Partial<RequestTimings> = {};

    let poolEntry = this.pool.get(origin);

    if (!poolEntry) {
      const dnsStart = Date.now();
      try {
        await lookup(url.hostname, { family: request.dnsFamily });
      } catch {
      }
      timings.dns = Date.now() - dnsStart;

      const connectStart = Date.now();
      const socket = await this.connect(url, request, options);
      const connectEnd = Date.now();
      timings.connect = connectEnd - connectStart;

      const alpn = socket.connectionInfo.alpnProtocol;
      const protocol = alpn === 'h2' ? 'h2' : 'h1';

      const defaultHeaders = sanitizeProfileHeaders(options.profile?.headers.headers ?? []);
      if (protocol === 'h2') {
        poolEntry = this.pool.put(
          origin,
          socket,
          protocol,
          options.profile?.h2,
          defaultHeaders,
        );

        const poolRef = poolEntry;
        const pool = this.pool;
        poolEntry.h2Client!.onClose = () => {
          pool.remove(poolRef);
        };
      } else {
        poolEntry = this.pool.put(
          origin,
          socket,
          protocol,
          undefined,
          defaultHeaders,
        );
      }
    }

    if (poolEntry.protocol === 'h2' && poolEntry.h2Client) {
      poolEntry.h2Client.sendPreface();
      try {
        const response = request.stream
          ? await poolEntry.h2Client.streamRequest(request, timings)
          : await poolEntry.h2Client.request(request, timings);
        return response;
      } catch (err) {
        this.pool.remove(poolEntry);
        if (!isRetry && err instanceof ProtocolError && err.errorCode === 0) {
          return this._send(request, options, true);
        }
        throw err;
      }
    }

    const h1Send = request.stream ? sendH1StreamingRequest : sendH1Request;
    let response: NLcURLResponse;
    try {
      response = await h1Send(
        poolEntry.socket as unknown as Duplex,
        request,
        { defaultHeaders: sanitizeProfileHeaders(options.profile?.headers.headers ?? []) },
        timings,
      );
    } catch (err) {
      this.pool.remove(poolEntry);
      throw err;
    }

    const connection = response.headers['connection'];
    if (connection?.toLowerCase() === 'close') {
      this.pool.remove(poolEntry);
    } else {
      this.pool.release(poolEntry);
    }

    return response;
  }

  /**
   * Closes the underlying connection pool, destroying all idle and active
   * connections. After calling this method the negotiator must not be reused.
   */
  close(): void {
    this.pool.close();
  }

  private async connect(
    url: URL,
    request: NLcURLRequest,
    options: NegotiatorOptions,
  ): Promise<TLSSocket> {
    const engine: ITLSEngine =
      (request.stealth ?? options.stealth) ? this.stealthEngine : this.standardEngine;

    const port = url.port ? parseInt(url.port, 10) : url.protocol === 'https:' ? 443 : 80;

    const defaultAlpn: string[] = request.httpVersion === '1.1'
      ? ['http/1.1']
      : request.httpVersion === '2'
        ? ['h2']
        : ['h2', 'http/1.1'];

    const tlsOptions: TLSConnectOptions = {
      host: url.hostname,
      port,
      servername: url.hostname,
      insecure: options.insecure ?? false,
      alpnProtocols: options.profile?.tls.alpnProtocols ?? defaultAlpn,
      timeout: typeof request.timeout === 'number'
        ? request.timeout
        : (request.timeout?.tls ?? request.timeout?.connect),
      signal: request.signal,
      family: request.dnsFamily,
    };

    if (request.proxy) {
      const proxyUrl = new URL(request.proxy);
      const proxyAuth = request.proxyAuth
        ? `${request.proxyAuth[0]}:${request.proxyAuth[1]}`
        : undefined;
      const scheme = proxyUrl.protocol.replace(':', '');

      if (scheme === 'socks5' || scheme === 'socks4') {
        const tunnelSocket = await socksConnect(
          {
            host: proxyUrl.hostname,
            port: parseInt(proxyUrl.port, 10) || 1080,
            version: scheme === 'socks5' ? 5 : 4,
            username: request.proxyAuth?.[0],
            password: request.proxyAuth?.[1],
            timeout: tlsOptions.timeout,
            family: request.dnsFamily,
          },
          url.hostname,
          port,
        );
        tlsOptions.socket = tunnelSocket;
      } else {
        const tunnelSocket = await httpProxyConnect(
          {
            host: proxyUrl.hostname,
            port: parseInt(proxyUrl.port, 10) || (scheme === 'https' ? 443 : 8080),
            auth: proxyAuth,
            timeout: tlsOptions.timeout,
            family: request.dnsFamily,
          },
          url.hostname,
          port,
        );
        tlsOptions.socket = tunnelSocket;
      }
    }

    return engine.connect(tlsOptions, options.profile);
  }
}

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
