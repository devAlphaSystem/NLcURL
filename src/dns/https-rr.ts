import { Resolver } from "node:dns/promises";
import { DoHResolver } from "./doh-resolver.js";
import { parseSVCBRecord } from "./codec.js";
import { RTYPE, type SVCBRecord, type DoHConfig, type ResolvedAddress } from "./types.js";
import { type Logger, getDefaultLogger } from "../utils/logger.js";

interface NativeHTTPSRecord {
  priority?: number;
  target?: string;
  alpn?: string | string[];
  port?: number;
  ipv4hint?: string | string[];
  ipv6hint?: string | string[];
  ech?: Buffer | string;
}

/** Resolved HTTPS resource record data including ECH, ALPN, and address hints. */
export interface HTTPSRRResult {
  /** All SVCB records returned by the query. */
  svcb: SVCBRecord[];
  /** Encrypted Client Hello configuration list, if present. */
  echConfigList?: Buffer;
  /** Advertised ALPN protocol identifiers from the best record. */
  alpn?: string[];
  /** IPv4 and IPv6 address hints extracted from service records. */
  addresses: ResolvedAddress[];
  /** Alternate port from the highest-priority service record. */
  port?: number;
}

/** Resolver for HTTPS/SVCB resource records via DoH or the system resolver. */
export class HTTPSRRResolver {
  private readonly dohResolver?: DoHResolver;
  private readonly systemResolver: Resolver;
  private readonly logger: Logger;

  /**
   * Create a new HTTPS RR resolver.
   *
   * @param {DoHConfig} [dohConfig] - Optional DoH configuration; falls back to system DNS when omitted.
   * @param {Logger} [logger] - Optional logger; falls back to the default logger.
   */
  constructor(dohConfig?: DoHConfig, logger?: Logger) {
    if (dohConfig) {
      this.dohResolver = new DoHResolver(dohConfig);
    }
    this.systemResolver = new Resolver();
    this.logger = logger ?? getDefaultLogger();
  }

  /**
   * Resolve HTTPS resource records for a hostname.
   *
   * @param {string} hostname - Domain name to query.
   * @param {AbortSignal} [signal] - Optional abort signal.
   * @returns {Promise<HTTPSRRResult|null>} Parsed HTTPS RR result, or `null` if no service records are found.
   */
  async resolve(hostname: string, signal?: AbortSignal): Promise<HTTPSRRResult | null> {
    try {
      let svcbRecords: SVCBRecord[];

      if (this.dohResolver) {
        svcbRecords = await this.resolveViaDoH(hostname, signal);
      } else {
        svcbRecords = await this.resolveViaSystem(hostname);
      }

      if (svcbRecords.length === 0) return null;

      svcbRecords.sort((a, b) => a.priority - b.priority);

      const serviceRecords = svcbRecords.filter((r) => r.priority > 0);
      if (serviceRecords.length === 0) return null;

      const best = serviceRecords[0]!;

      const addresses: ResolvedAddress[] = [];
      for (const rec of serviceRecords) {
        if (rec.ipv4Hints) {
          for (const addr of rec.ipv4Hints) {
            addresses.push({ address: addr, family: 4 });
          }
        }
        if (rec.ipv6Hints) {
          for (const addr of rec.ipv6Hints) {
            addresses.push({ address: addr, family: 6 });
          }
        }
      }

      const echRecord = serviceRecords.find((r) => r.echConfigList);

      return {
        svcb: svcbRecords,
        echConfigList: echRecord?.echConfigList,
        alpn: best.alpn,
        addresses,
        port: best.port,
      };
    } catch (err) {
      this.logger.debug("HTTPS RR resolution failed", err instanceof Error ? err.message : String(err));
      return null;
    }
  }

  private async resolveViaDoH(hostname: string, signal?: AbortSignal): Promise<SVCBRecord[]> {
    const records = await this.dohResolver!.query(hostname, "HTTPS", signal);
    return records.filter((r) => r.type === RTYPE.HTTPS || r.type === RTYPE.SVCB).map((r) => parseSVCBRecord(r.data));
  }

  private async resolveViaSystem(hostname: string): Promise<SVCBRecord[]> {
    try {
      const resolver = this.systemResolver as Resolver & { resolve(hostname: string, rrtype: string): Promise<unknown[]> };
      const results = await resolver.resolve(hostname, "HTTPS").catch(() => [] as unknown[]);
      if (Array.isArray(results) && results.length > 0) {
        return results.map((r) => this.parseNativeHTTPSRecord(r as NativeHTTPSRecord));
      }
    } catch (err) {
      this.logger.debug("System HTTPS RR lookup unsupported", err instanceof Error ? err.message : String(err));
    }
    return [];
  }

  private parseNativeHTTPSRecord(record: NativeHTTPSRecord): SVCBRecord {
    const result: SVCBRecord = {
      priority: record.priority ?? 0,
      target: record.target ?? "",
    };

    if (record.alpn) result.alpn = Array.isArray(record.alpn) ? record.alpn : [record.alpn];
    if (record.port) result.port = record.port;
    if (record.ipv4hint) result.ipv4Hints = Array.isArray(record.ipv4hint) ? record.ipv4hint : [record.ipv4hint];
    if (record.ipv6hint) result.ipv6Hints = Array.isArray(record.ipv6hint) ? record.ipv6hint : [record.ipv6hint];
    if (record.ech) result.echConfigList = Buffer.isBuffer(record.ech) ? record.ech : Buffer.from(record.ech, "base64");

    return result;
  }
}
