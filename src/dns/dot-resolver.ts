import * as tls from "node:tls";
import { buildDNSQuery, parseDNSResponse } from "./codec.js";
import { RTYPE, type DNSRecord } from "./types.js";

type RTYPEValue = (typeof RTYPE)[keyof typeof RTYPE];

/** Configuration for a DNS-over-TLS resolver. */
export interface DoTConfig {
  /** DoT server IP address or hostname. */
  server?: string;
  /** Server port (default 853). */
  port?: number;
  /** TLS server name for certificate verification. */
  servername?: string;
  /** Query timeout in milliseconds. */
  timeout?: number;
  /** Whether to reuse the TLS connection across queries. */
  keepAlive?: boolean;
  /** Whether to skip TLS certificate verification. */
  insecure?: boolean;
}

/** Pre-configured DNS-over-TLS server entries. */
export const DOT_SERVERS = {
  cloudflare: { server: "1.1.1.1", servername: "cloudflare-dns.com" },
  "cloudflare-ipv6": { server: "2606:4700:4700::1111", servername: "cloudflare-dns.com" },
  google: { server: "8.8.8.8", servername: "dns.google" },
  "google-ipv6": { server: "2001:4860:4860::8888", servername: "dns.google" },
  quad9: { server: "9.9.9.9", servername: "dns.quad9.net" },
  adguard: { server: "94.140.14.14", servername: "dns.adguard-dns.com" },
} as const;

/** DNS-over-TLS resolver using a persistent TLS connection. */
export class DoTResolver {
  private readonly server: string;
  private readonly port: number;
  private readonly servername: string;
  private readonly timeout: number;
  private readonly insecure: boolean;
  private readonly keepAlive: boolean;
  private socket: tls.TLSSocket | null = null;
  private connected = false;

  /**
   * Create a new DoT resolver.
   *
   * @param {DoTConfig} [config] - DoT connection configuration.
   */
  constructor(config?: DoTConfig) {
    this.server = config?.server ?? "1.1.1.1";
    this.port = config?.port ?? 853;
    this.servername = config?.servername ?? "cloudflare-dns.com";
    this.timeout = config?.timeout ?? 5000;
    this.insecure = config?.insecure ?? false;
    this.keepAlive = config?.keepAlive ?? false;
  }

  /**
   * Resolve a domain name to DNS records over TLS.
   *
   * @param {string} name - Domain name to resolve.
   * @param {RTYPEValue} [type] - Numeric record type (defaults to A).
   * @returns {Promise<DNSRecord[]>} Array of parsed DNS records.
   */
  async resolve(name: string, type: RTYPEValue = RTYPE.A): Promise<DNSRecord[]> {
    const queryBuf = buildDNSQuery(name, type);

    const framed = Buffer.allocUnsafe(2 + queryBuf.length);
    framed.writeUInt16BE(queryBuf.length, 0);
    queryBuf.copy(framed, 2);

    const responseData = await this.send(framed);

    if (responseData.length < 2) {
      throw new Error("DoT response too short");
    }
    const msgLen = responseData.readUInt16BE(0);
    const dnsMsg = responseData.subarray(2, 2 + msgLen);

    return parseDNSResponse(dnsMsg);
  }

  /**
   * Resolve a domain name to IPv4 addresses.
   *
   * @param {string} name - Domain name to resolve.
   * @returns {Promise<string[]>} Array of IPv4 address strings.
   */
  async resolve4(name: string): Promise<string[]> {
    const records = await this.resolve(name, RTYPE.A);
    return records.filter((r): r is DNSRecord & { data: string } => r.type === RTYPE.A && typeof r.data === "string").map((r) => r.data);
  }

  /**
   * Resolve a domain name to IPv6 addresses.
   *
   * @param {string} name - Domain name to resolve.
   * @returns {Promise<string[]>} Array of IPv6 address strings.
   */
  async resolve6(name: string): Promise<string[]> {
    const records = await this.resolve(name, RTYPE.AAAA);
    return records.filter((r): r is DNSRecord & { data: string } => r.type === RTYPE.AAAA && typeof r.data === "string").map((r) => r.data);
  }

  /** Close the underlying TLS socket and release resources. */
  close(): void {
    if (this.socket) {
      this.socket.destroy();
      this.socket = null;
      this.connected = false;
    }
  }

  private async send(data: Buffer): Promise<Buffer> {
    const socket = await this.getSocket();

    return new Promise<Buffer>((resolve, reject) => {
      let timer: ReturnType<typeof setTimeout> | undefined;
      let response = Buffer.alloc(0);

      const cleanup = () => {
        if (timer) clearTimeout(timer);
        socket.removeListener("data", onData);
        socket.removeListener("error", onError);
      };

      const onData = (chunk: Buffer) => {
        response = Buffer.concat([response, chunk]);

        if (response.length >= 2) {
          const expectedLen = response.readUInt16BE(0) + 2;
          if (response.length >= expectedLen) {
            cleanup();
            if (!this.keepAlive) {
              socket.destroy();
              this.socket = null;
              this.connected = false;
            }
            resolve(response);
          }
        }
      };

      const onError = (err: Error) => {
        cleanup();
        this.socket = null;
        this.connected = false;
        reject(err);
      };

      timer = setTimeout(() => {
        cleanup();
        if (!this.keepAlive) {
          socket.destroy();
          this.socket = null;
          this.connected = false;
        }
        reject(new Error("DoT query timed out"));
      }, this.timeout);

      socket.on("data", onData);
      socket.on("error", onError);
      socket.write(data);
    });
  }

  private async getSocket(): Promise<tls.TLSSocket> {
    if (this.socket && this.connected) {
      return this.socket;
    }

    return new Promise<tls.TLSSocket>((resolve, reject) => {
      const socket = tls.connect(
        {
          host: this.server,
          port: this.port,
          servername: this.servername,
          rejectUnauthorized: !this.insecure,
          ALPNProtocols: ["dot"],
        },
        () => {
          this.socket = socket;
          this.connected = true;
          resolve(socket);
        },
      );

      socket.once("error", (err) => {
        this.socket = null;
        this.connected = false;
        reject(err);
      });

      socket.setTimeout(this.timeout, () => {
        socket.destroy();
        reject(new Error("DoT connection timed out"));
      });
    });
  }
}
