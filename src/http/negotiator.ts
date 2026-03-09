import type { Duplex } from "node:stream";
import type { BrowserProfile } from "../fingerprints/types.js";
import type { ITLSEngine, TLSSocket, TLSConnectOptions, TLSOptions } from "../tls/types.js";
import { NodeTLSEngine } from "../tls/node-engine.js";
import { StealthTLSEngine } from "../tls/stealth/engine.js";
import { TLSSessionCache } from "../tls/session-cache.js";
import { originOf } from "../utils/url.js";
import { supportsZstd, sanitizeAcceptEncoding } from "../utils/encoding.js";
import { happyEyeballsConnect } from "../utils/happy-eyeballs.js";
import { ConnectionPool, type PoolOptions } from "./pool.js";
import { sendH1Request, sendH1StreamingRequest } from "./h1/client.js";
import type { NLcURLRequest, RequestTimings } from "../core/request.js";
import { NLcURLResponse } from "../core/response.js";
import { ProtocolError } from "../core/errors.js";
import { httpProxyConnect } from "../proxy/http-proxy.js";
import { socksConnect } from "../proxy/socks.js";
import { AltSvcStore } from "./alt-svc.js";
import { HTTPSRRResolver, type HTTPSRRResult } from "../dns/https-rr.js";
import { DoHResolver } from "../dns/doh-resolver.js";
import type { DNSConfig } from "../dns/types.js";
import type { ECHOptions } from "../tls/ech.js";

/** Options controlling protocol negotiation behavior. */
export interface NegotiatorOptions {
  /** Whether to use stealth TLS fingerprinting. */
  stealth?: boolean;
  /** Browser profile to impersonate. */
  profile?: BrowserProfile;
  /** Whether to skip TLS certificate verification. */
  insecure?: boolean;
  /** Connection pool options. */
  pool?: PoolOptions;
  /** TLS engine options. */
  tls?: TLSOptions;
  /** DNS resolver configuration. */
  dns?: DNSConfig;
  /** Encrypted Client Hello options. */
  ech?: ECHOptions;
  /** Whether to use Alt-Svc for protocol upgrades. */
  altSvc?: boolean;
}

/** HTTP protocol negotiator managing TLS, connection pooling, and ALPN selection. */
export class ProtocolNegotiator {
  private readonly standardEngine: NodeTLSEngine;
  private readonly stealthEngine: StealthTLSEngine;
  private readonly pool: ConnectionPool;
  private readonly sessionCache: TLSSessionCache;
  /** Alt-Svc store tracking alternative service advertisements. */
  readonly altSvcStore: AltSvcStore;
  private httpsRRResolver: HTTPSRRResolver | null = null;
  private dohResolver: DoHResolver | null = null;

  /**
   * Create a new protocol negotiator.
   *
   * @param {PoolOptions} [poolOptions] - Connection pool configuration.
   * @param {DNSConfig} [dnsConfig] - DNS resolver configuration.
   */
  constructor(poolOptions?: PoolOptions, dnsConfig?: DNSConfig) {
    this.sessionCache = new TLSSessionCache();
    this.standardEngine = new NodeTLSEngine(this.sessionCache);
    this.stealthEngine = new StealthTLSEngine(this.sessionCache);
    this.pool = new ConnectionPool(poolOptions);
    this.altSvcStore = new AltSvcStore();

    if (dnsConfig?.doh) {
      this.dohResolver = new DoHResolver(dnsConfig.doh);
      this.httpsRRResolver = new HTTPSRRResolver(dnsConfig.doh);
    } else if (dnsConfig?.httpsRR !== false) {
      this.httpsRRResolver = new HTTPSRRResolver();
    }
  }

  /**
   * Send an HTTP request, negotiating the protocol automatically.
   *
   * @param {NLcURLRequest} request - Request to send.
   * @param {NegotiatorOptions} [options] - Negotiation options.
   * @returns {Promise<NLcURLResponse>} HTTP response.
   */
  async send(request: NLcURLRequest, options: NegotiatorOptions = {}): Promise<NLcURLResponse> {
    return this._send(request, options, false);
  }

  private async _send(request: NLcURLRequest, options: NegotiatorOptions, isRetry: boolean): Promise<NLcURLResponse> {
    const url = new URL(request.url);
    const origin = originOf(url.toString());
    const timings: Partial<RequestTimings> = {};

    const useAltSvc = options.altSvc !== false;

    let poolEntry = this.pool.get(origin);

    if (!poolEntry) {
      const connectStart = Date.now();
      const { socket, dnsTimeMs } = await this.connect(url, request, options);
      const connectEnd = Date.now();
      timings.dns = dnsTimeMs;
      timings.connect = connectEnd - connectStart;

      const alpn = socket.connectionInfo.alpnProtocol;
      const protocol = alpn === "h2" ? "h2" : "h1";

      const defaultHeaders = sanitizeProfileHeaders(options.profile?.headers.headers ?? []);
      if (protocol === "h2") {
        poolEntry = this.pool.put(origin, socket, protocol, options.profile?.h2, defaultHeaders);

        const poolRef = poolEntry;
        const pool = this.pool;
        poolEntry.h2Client!.onClose = () => {
          pool.remove(poolRef);
        };
      } else {
        poolEntry = this.pool.put(origin, socket, protocol, undefined, defaultHeaders);
      }
    }

    let response: NLcURLResponse;

    if (poolEntry.protocol === "h2" && poolEntry.h2Client) {
      poolEntry.h2Client.sendPreface();
      try {
        response = request.stream ? await poolEntry.h2Client.streamRequest(request, timings) : await poolEntry.h2Client.request(request, timings);
      } catch (err) {
        this.pool.remove(poolEntry);
        if (!isRetry && err instanceof ProtocolError && err.errorCode === 0) {
          return this._send(request, options, true);
        }
        throw err;
      }
    } else {
      const h1Send = request.stream ? sendH1StreamingRequest : sendH1Request;
      try {
        response = await h1Send(poolEntry.socket as unknown as Duplex, request, { defaultHeaders: sanitizeProfileHeaders(options.profile?.headers.headers ?? []) }, timings);
      } catch (err) {
        this.pool.remove(poolEntry);
        throw err;
      }

      const connection = response.headers["connection"];
      if (connection?.toLowerCase() === "close") {
        this.pool.remove(poolEntry);
      } else {
        this.pool.release(poolEntry);
      }
    }

    if (useAltSvc) {
      const altSvcHeader = response.headers["alt-svc"];
      if (altSvcHeader) {
        this.altSvcStore.parseHeader(origin, altSvcHeader);
      }
    }

    return response;
  }

  /** Close all pooled connections and release resources. */
  close(): void {
    this.pool.close();
  }

  /**
   * Return the HTTPS resource record resolver, if configured.
   *
   * @returns {HTTPSRRResolver | null} HTTPS RR resolver instance, or `null`.
   */
  getHTTPSRRResolver(): HTTPSRRResolver | null {
    return this.httpsRRResolver;
  }

  /**
   * Return the DNS-over-HTTPS resolver, if configured.
   *
   * @returns {DoHResolver | null} DoH resolver instance, or `null`.
   */
  getDoHResolver(): DoHResolver | null {
    return this.dohResolver;
  }

  private async connect(url: URL, request: NLcURLRequest, options: NegotiatorOptions): Promise<{ socket: TLSSocket; dnsTimeMs: number }> {
    const engine: ITLSEngine = (request.stealth ?? options.stealth) ? this.stealthEngine : this.standardEngine;

    const port = url.port ? parseInt(url.port, 10) : url.protocol === "https:" ? 443 : 80;

    const defaultAlpn: string[] = request.httpVersion === "1.1" ? ["http/1.1"] : request.httpVersion === "2" ? ["h2"] : ["h2", "http/1.1"];

    const tcpTimeout = typeof request.timeout === "number" ? request.timeout : request.timeout?.connect;
    const tlsTimeout = typeof request.timeout === "number" ? request.timeout : (request.timeout?.tls ?? request.timeout?.connect);

    let httpsRR: HTTPSRRResult | null = null;
    let echConfigList: Buffer | undefined;

    const echOpts = options.ech ?? request.ech;
    const echEnabled = echOpts?.enabled !== false;

    if (echOpts?.echConfigList) {
      echConfigList = typeof echOpts.echConfigList === "string" ? Buffer.from(echOpts.echConfigList, "base64") : echOpts.echConfigList;
    }

    if (this.httpsRRResolver && url.protocol === "https:" && !request.proxy) {
      try {
        httpsRR = await this.httpsRRResolver.resolve(url.hostname, request.signal);
      } catch {}

      if (httpsRR) {
        if (!echConfigList && echEnabled && httpsRR.echConfigList) {
          echConfigList = httpsRR.echConfigList;
        }
      }
    }

    const tlsOptions: TLSConnectOptions = {
      host: url.hostname,
      port,
      servername: url.hostname,
      insecure: options.insecure ?? false,
      alpnProtocols: options.profile?.tls.alpnProtocols ?? defaultAlpn,
      timeout: tlsTimeout,
      signal: request.signal,
      family: request.dnsFamily,
      cert: options.tls?.cert,
      key: options.tls?.key,
      passphrase: options.tls?.passphrase,
      pfx: options.tls?.pfx,
      ca: options.tls?.ca,
      pinnedPublicKey: options.tls?.pinnedPublicKey,
      echConfigList,
    };

    let dnsTimeMs = 0;

    if (request.proxy) {
      const proxyUrl = new URL(request.proxy);
      const proxyAuth = request.proxyAuth ? `${request.proxyAuth[0]}:${request.proxyAuth[1]}` : undefined;
      const scheme = proxyUrl.protocol.replace(":", "");

      if (scheme === "socks5" || scheme === "socks4") {
        const tunnelSocket = await socksConnect(
          {
            host: proxyUrl.hostname,
            port: parseInt(proxyUrl.port, 10) || 1080,
            version: scheme === "socks5" ? 5 : 4,
            username: request.proxyAuth?.[0],
            password: request.proxyAuth?.[1],
            timeout: tcpTimeout,
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
            port: parseInt(proxyUrl.port, 10) || (scheme === "https" ? 443 : 8080),
            auth: proxyAuth,
            timeout: tcpTimeout,
            family: request.dnsFamily,
            secure: scheme === "https",
          },
          url.hostname,
          port,
        );
        tlsOptions.socket = tunnelSocket;
      }
    } else {
      const heb = await happyEyeballsConnect({
        host: url.hostname,
        port,
        family: request.dnsFamily,
        timeout: tcpTimeout,
        signal: request.signal,
      });
      dnsTimeMs = heb.dnsTimeMs;
      tlsOptions.socket = heb.socket;
    }

    const socket = await engine.connect(tlsOptions, options.profile);
    return { socket, dnsTimeMs };
  }
}

function sanitizeProfileHeaders(headers: Array<[string, string]>): Array<[string, string]> {
  if (supportsZstd) return headers;
  return headers.map(([k, v]) => (k.toLowerCase() === "accept-encoding" ? [k, sanitizeAcceptEncoding(v)] : [k, v]));
}
