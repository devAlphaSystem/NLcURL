import * as https from "node:https";
import * as http from "node:http";
import { lookup } from "node:dns/promises";
import { buildDNSQuery, parseDNSResponse } from "./codec.js";
import type { DoHConfig, DNSRecord } from "./types.js";
import { RTYPE } from "./types.js";
import { DNSCache } from "./cache.js";

const DOH_CONTENT_TYPE = "application/dns-message";
const DEFAULT_TIMEOUT = 5000;
const BOOTSTRAP_CACHE_MAX = 50;
const BOOTSTRAP_CACHE_TTL = 300_000;

const bootstrapCache = new Map<string, { address: string; storedAt: number }>();

/** DNS-over-HTTPS resolver supporting GET and POST wire-format queries. */
export class DoHResolver {
  private readonly serverUrl: URL;
  private readonly method: "GET" | "POST";
  private readonly timeout: number;
  private readonly bootstrap: boolean;
  private readonly cache: DNSCache;
  private queryId = 0;

  /**
   * Create a new DoH resolver.
   *
   * @param {DoHConfig} config - DoH connection and cache configuration.
   */
  constructor(config: DoHConfig) {
    this.serverUrl = new URL(config.server);
    this.method = config.method ?? "POST";
    this.timeout = config.timeout ?? DEFAULT_TIMEOUT;
    this.bootstrap = config.bootstrap ?? true;
    this.cache = new DNSCache(config.cache);
  }

  /**
   * Perform a DNS query over HTTPS.
   *
   * @param {string} name - Domain name to resolve.
   * @param {"A"|"AAAA"|"HTTPS"|"SVCB"} type - Record type to query.
   * @param {AbortSignal} [signal] - Optional abort signal.
   * @returns {Promise<DNSRecord[]>} Array of DNS records from the response.
   */
  async query(name: string, type: "A" | "AAAA" | "HTTPS" | "SVCB", signal?: AbortSignal): Promise<DNSRecord[]> {
    const cached = this.cache.get(name, type);
    if (cached) return cached;

    const rtype = RTYPE[type];
    const id = this.queryId++ & 0xffff;
    const queryPacket = buildDNSQuery(name, rtype, id, { udpPayloadSize: 4096, padding: true });

    const responseData = await this.sendQuery(queryPacket, signal);
    const records = parseDNSResponse(responseData);

    this.cache.set(name, type, records);

    return records;
  }

  /**
   * Return the underlying DNS cache.
   *
   * @returns {DNSCache} The resolver's DNS cache instance.
   */
  getCache(): DNSCache {
    return this.cache;
  }

  private async sendQuery(packet: Buffer, signal?: AbortSignal): Promise<Buffer> {
    const host = await this.resolveServerHost();

    if (this.method === "GET") {
      return this.sendGET(packet, host, signal);
    }
    return this.sendPOST(packet, host, signal);
  }

  private sendGET(packet: Buffer, host: string, signal?: AbortSignal): Promise<Buffer> {
    const encoded = packet.toString("base64url");
    const url = new URL(this.serverUrl.toString());
    url.searchParams.set("dns", encoded);

    return this.httpRequest(
      {
        method: "GET",
        hostname: host,
        port: parseInt(this.serverUrl.port) || 443,
        path: `${url.pathname}${url.search}`,
        headers: {
          accept: DOH_CONTENT_TYPE,
          host: this.serverUrl.hostname,
        },
      },
      undefined,
      signal,
    );
  }

  private sendPOST(packet: Buffer, host: string, signal?: AbortSignal): Promise<Buffer> {
    return this.httpRequest(
      {
        method: "POST",
        hostname: host,
        port: parseInt(this.serverUrl.port) || 443,
        path: this.serverUrl.pathname,
        headers: {
          "content-type": DOH_CONTENT_TYPE,
          accept: DOH_CONTENT_TYPE,
          "content-length": packet.length.toString(),
          host: this.serverUrl.hostname,
        },
      },
      packet,
      signal,
    );
  }

  private httpRequest(options: https.RequestOptions, body: Buffer | undefined, signal?: AbortSignal): Promise<Buffer> {
    return new Promise<Buffer>((resolve, reject) => {
      if (signal?.aborted) {
        reject(new Error("DoH query aborted"));
        return;
      }

      const isHTTPS = this.serverUrl.protocol === "https:";
      const requestFn = isHTTPS ? https.request : http.request;

      const tlsOpts: https.RequestOptions = isHTTPS
        ? {
            ...options,
            rejectUnauthorized: true,
            servername: this.serverUrl.hostname,
          }
        : options;

      const req = requestFn(tlsOpts, (res) => {
        if (res.statusCode !== 200) {
          req.destroy();
          reject(new Error(`DoH server returned HTTP ${res.statusCode}`));
          return;
        }

        const contentType = res.headers["content-type"];
        if (contentType && !contentType.includes(DOH_CONTENT_TYPE)) {
          req.destroy();
          reject(new Error(`DoH server returned unexpected content-type: ${contentType}`));
          return;
        }

        const chunks: Buffer[] = [];
        let totalSize = 0;
        const MAX_DNS_RESPONSE = 65535;

        res.on("data", (chunk: Buffer) => {
          totalSize += chunk.length;
          if (totalSize > MAX_DNS_RESPONSE) {
            req.destroy();
            reject(new Error("DoH response exceeds maximum DNS message size"));
            return;
          }
          chunks.push(chunk);
        });

        res.on("end", () => {
          resolve(Buffer.concat(chunks));
        });

        res.on("error", reject);
      });

      req.on("error", reject);

      const timer = setTimeout(() => {
        req.destroy();
        reject(new Error("DoH query timed out"));
      }, this.timeout);

      req.once("close", () => {
        clearTimeout(timer);
      });

      if (signal) {
        const onAbort = () => {
          clearTimeout(timer);
          req.destroy();
          reject(new Error("DoH query aborted"));
        };
        signal.addEventListener("abort", onAbort, { once: true });
        req.once("close", () => {
          signal.removeEventListener("abort", onAbort);
        });
      }

      if (body) {
        req.write(body);
      }
      req.end();
    });
  }

  private async resolveServerHost(): Promise<string> {
    const host = this.serverUrl.hostname;

    if (/^\d+\.\d+\.\d+\.\d+$/.test(host) || host.includes(":")) {
      return host;
    }

    const cached = bootstrapCache.get(host);
    if (cached) {
      if (Date.now() - cached.storedAt < BOOTSTRAP_CACHE_TTL) {
        return cached.address;
      }
      bootstrapCache.delete(host);
    }

    if (!this.bootstrap) {
      return host;
    }

    const result = await lookup(host, { family: 0 });
    const address = Array.isArray(result) ? result[0]!.address : result.address;

    if (bootstrapCache.size >= BOOTSTRAP_CACHE_MAX) {
      const firstKey = bootstrapCache.keys().next().value;
      if (firstKey) bootstrapCache.delete(firstKey);
    }

    bootstrapCache.set(host, { address, storedAt: Date.now() });
    return address;
  }
}
