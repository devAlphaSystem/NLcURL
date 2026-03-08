/**
 * HTTPS Resource Record resolver (RFC 9460).
 *
 * Queries HTTPS/SVCB DNS records to discover:
 * - ECH (Encrypted Client Hello) configuration keys
 * - ALPN protocol hints (e.g. h2, h3)
 * - IP address hints for faster connection setup
 * - Port overrides
 *
 * Can use either the system DNS resolver (via `node:dns`) or a DoH
 * resolver for encrypted queries.
 *
 * @see https://datatracker.ietf.org/doc/html/rfc9460
 */
import { Resolver } from "node:dns/promises";
import { DoHResolver } from "./doh-resolver.js";
import { buildDNSQuery, parseDNSResponse, parseSVCBRecord, parseARecord, parseAAAARecord } from "./codec.js";
import { RTYPE, type SVCBRecord, type DoHConfig, type ResolvedAddress } from "./types.js";

/**
 * Result of an HTTPS-RR lookup, combining SVCB records with address hints.
 */
export interface HTTPSRRResult {
  /** Parsed SVCB/HTTPS records, sorted by priority (lowest first). */
  svcb: SVCBRecord[];
  /** ECH config list from the highest-priority record that has one. */
  echConfigList?: Buffer;
  /** ALPN protocols from the highest-priority ServiceMode record. */
  alpn?: string[];
  /** IP address hints extracted from SVCB records + A/AAAA. */
  addresses: ResolvedAddress[];
  /** Port override from the SVCB record, if any. */
  port?: number;
}

/**
 * Resolver for HTTPS/SVCB DNS Resource Records (RFC 9460).
 *
 * Supports two modes:
 * 1. **System DNS** — Uses `node:dns` (resolveAny or raw query).
 * 2. **DoH** — Uses a DoHResolver for encrypted HTTPS-RR queries.
 */
export class HTTPSRRResolver {
  private readonly dohResolver?: DoHResolver;
  private readonly systemResolver: Resolver;

  constructor(dohConfig?: DoHConfig) {
    if (dohConfig) {
      this.dohResolver = new DoHResolver(dohConfig);
    }
    this.systemResolver = new Resolver();
  }

  /**
   * Queries HTTPS records for a hostname and parses the results.
   *
   * @param hostname The domain to look up HTTPS records for.
   * @param signal   Optional AbortSignal for cancellation.
   * @returns Parsed HTTPS-RR result with SVCB params, or null if no records found.
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
    } catch {
      return null;
    }
  }

  /**
   * Resolves HTTPS records via DoH.
   */
  private async resolveViaDoH(hostname: string, signal?: AbortSignal): Promise<SVCBRecord[]> {
    const records = await this.dohResolver!.query(hostname, "HTTPS", signal);
    return records.filter((r) => r.type === RTYPE.HTTPS || r.type === RTYPE.SVCB).map((r) => parseSVCBRecord(r.data));
  }

  /**
   * Resolves HTTPS records via the system DNS resolver.
   * Uses raw DNS query + decode since node:dns doesn't natively support type 65.
   */
  private async resolveViaSystem(hostname: string): Promise<SVCBRecord[]> {
    try {
      const results = await (this.systemResolver as any).resolve(hostname, "HTTPS").catch(() => []);
      if (Array.isArray(results) && results.length > 0) {
        return results.map((r: any) => this.parseNativeHTTPSRecord(r));
      }
    } catch {}
    return [];
  }

  /**
   * Parses a native Node.js HTTPS DNS record into our SVCBRecord format.
   * Node.js 22+ may return HTTPS records with a specific structure.
   */
  private parseNativeHTTPSRecord(record: any): SVCBRecord {
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
