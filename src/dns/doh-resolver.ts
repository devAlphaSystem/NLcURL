/**
 * DNS-over-HTTPS (DoH) resolver implementing RFC 8484.
 *
 * Sends DNS queries over HTTPS to a configured DoH server, providing
 * encrypted DNS resolution for privacy. Supports both GET (wire-format
 * in query parameter) and POST (wire-format in body) methods.
 *
 * @see https://datatracker.ietf.org/doc/html/rfc8484
 */
import * as https from "node:https";
import * as http from "node:http";
import { lookup } from "node:dns/promises";
import { buildDNSQuery, parseDNSResponse } from "./codec.js";
import type { DoHConfig, DNSRecord } from "./types.js";
import { RTYPE } from "./types.js";

const DOH_CONTENT_TYPE = "application/dns-message";
const DEFAULT_TIMEOUT = 5000;

/** Cache of bootstrapped DoH server IP → avoid infinite recursion. */
const bootstrapCache = new Map<string, string>();

/**
 * DNS-over-HTTPS resolver for encrypted DNS resolution.
 *
 * Usage:
 * ```typescript
 * const resolver = new DoHResolver({ server: "https://1.1.1.1/dns-query" });
 * const records = await resolver.query("example.com", "A");
 * ```
 */
export class DoHResolver {
  private readonly serverUrl: URL;
  private readonly method: "GET" | "POST";
  private readonly timeout: number;
  private readonly bootstrap: boolean;
  private queryId = 0;

  constructor(config: DoHConfig) {
    this.serverUrl = new URL(config.server);
    this.method = config.method ?? "POST";
    this.timeout = config.timeout ?? DEFAULT_TIMEOUT;
    this.bootstrap = config.bootstrap ?? true;
  }

  /**
   * Sends a DNS query over HTTPS and returns the parsed answer records.
   *
   * @param name   Domain name to resolve.
   * @param type   Record type: "A", "AAAA", "HTTPS", or "SVCB".
   * @param signal Optional AbortSignal for cancellation.
   * @returns Array of raw DNS records from the answer section.
   */
  async query(name: string, type: "A" | "AAAA" | "HTTPS" | "SVCB", signal?: AbortSignal): Promise<DNSRecord[]> {
    const rtype = RTYPE[type];
    const id = this.queryId++ & 0xffff;
    const queryPacket = buildDNSQuery(name, rtype, id);

    const responseData = await this.sendQuery(queryPacket, signal);
    return parseDNSResponse(responseData);
  }

  /**
   * Sends the DNS wire-format query to the DoH server.
   */
  private async sendQuery(packet: Buffer, signal?: AbortSignal): Promise<Buffer> {
    const host = await this.resolveServerHost();

    if (this.method === "GET") {
      return this.sendGET(packet, host, signal);
    }
    return this.sendPOST(packet, host, signal);
  }

  /**
   * GET method: base64url-encode the DNS query in the `dns` query parameter.
   */
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

  /**
   * POST method: send DNS wire-format directly in the request body.
   */
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

  /**
   * Make the HTTPS request with timeout and abort support.
   */
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

      req.once("close", () => clearTimeout(timer));

      if (signal) {
        const onAbort = () => {
          clearTimeout(timer);
          req.destroy();
          reject(new Error("DoH query aborted"));
        };
        signal.addEventListener("abort", onAbort, { once: true });
        req.once("close", () => signal.removeEventListener("abort", onAbort));
      }

      if (body) {
        req.write(body);
      }
      req.end();
    });
  }

  /**
   * Resolves the DoH server hostname to an IP address (bootstrap).
   * Uses the system DNS resolver for this bootstrap step to avoid
   * a circular dependency (we can't use DoH to resolve the DoH server).
   *
   * If the server URL already uses an IP address, returns it directly.
   */
  private async resolveServerHost(): Promise<string> {
    const host = this.serverUrl.hostname;

    if (/^\d+\.\d+\.\d+\.\d+$/.test(host) || host.includes(":")) {
      return host;
    }

    const cached = bootstrapCache.get(host);
    if (cached) return cached;

    if (!this.bootstrap) {
      return host;
    }

    const result = await lookup(host, { family: 0 });
    const address = Array.isArray(result) ? result[0]!.address : result.address;
    bootstrapCache.set(host, address);
    return address;
  }
}
