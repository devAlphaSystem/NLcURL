/**
 * Minimal DNS wire-format encoder/decoder for DNS-over-HTTPS (RFC 8484)
 * and HTTPS/SVCB record parsing (RFC 9460).
 *
 * Supports building A/AAAA/HTTPS queries and parsing response packets
 * including SvcParam extraction. Uses only Node.js built-in `Buffer`.
 */
import { RTYPE, RCLASS, SvcParamKey, type DNSRecord, type SVCBRecord } from "./types.js";

/**
 * Builds a DNS query packet in wire format (RFC 1035 §4).
 *
 * @param name  The domain name to query.
 * @param type  DNS record type (A = 1, AAAA = 28, HTTPS = 65).
 * @param id    16-bit query ID.
 * @returns Raw DNS query packet.
 */
export function buildDNSQuery(name: string, type: number, id: number = 0): Buffer {
  const labels = encodeName(name);
  const buf = Buffer.alloc(12 + labels.length + 4);

  buf.writeUInt16BE(id & 0xffff, 0);
  buf.writeUInt16BE(0x0100, 2);
  buf.writeUInt16BE(1, 4);
  buf.writeUInt16BE(0, 6);
  buf.writeUInt16BE(0, 8);
  buf.writeUInt16BE(0, 10);

  labels.copy(buf, 12);
  buf.writeUInt16BE(type, 12 + labels.length);
  buf.writeUInt16BE(RCLASS.IN, 12 + labels.length + 2);

  return buf;
}

/**
 * Encodes a domain name into DNS wire format labels.
 */
function encodeName(name: string): Buffer {
  const parts = name.replace(/\.$/, "").split(".");
  const buffers: Buffer[] = [];
  for (const part of parts) {
    const label = Buffer.from(part, "ascii");
    if (label.length > 63) throw new Error(`DNS label too long: "${part}"`);
    buffers.push(Buffer.from([label.length]), label);
  }
  buffers.push(Buffer.from([0]));
  return Buffer.concat(buffers);
}

/**
 * Parses a DNS response packet and extracts answer records.
 *
 * @param packet Raw DNS response bytes.
 * @returns Array of parsed DNS records from the answer section.
 */
export function parseDNSResponse(packet: Buffer): DNSRecord[] {
  if (packet.length < 12) throw new Error("DNS packet too short");

  const flags = packet.readUInt16BE(2);
  const rcode = flags & 0x000f;
  if (rcode !== 0) {
    throw new Error(`DNS query failed with RCODE ${rcode}`);
  }

  const qdcount = packet.readUInt16BE(4);
  const ancount = packet.readUInt16BE(6);

  let offset = 12;

  for (let i = 0; i < qdcount; i++) {
    const result = skipName(packet, offset);
    offset = result + 4;
  }

  const records: DNSRecord[] = [];
  for (let i = 0; i < ancount; i++) {
    const { name, newOffset } = decodeName(packet, offset);
    offset = newOffset;

    if (offset + 10 > packet.length) break;

    const type = packet.readUInt16BE(offset);
    offset += 2;
    packet.readUInt16BE(offset);
    offset += 2;
    const ttl = packet.readUInt32BE(offset);
    offset += 4;
    const rdlength = packet.readUInt16BE(offset);
    offset += 2;

    if (offset + rdlength > packet.length) break;

    const data = packet.subarray(offset, offset + rdlength);
    offset += rdlength;

    records.push({ name, type, ttl, data });
  }

  return records;
}

/**
 * Decodes a DNS compressed name from a packet.
 */
function decodeName(packet: Buffer, offset: number): { name: string; newOffset: number } {
  const labels: string[] = [];
  let jumped = false;
  let returnOffset = offset;
  let depth = 0;

  while (offset < packet.length) {
    if (depth++ > 128) throw new Error("DNS name compression loop detected");

    const len = packet[offset]!;
    if (len === 0) {
      if (!jumped) returnOffset = offset + 1;
      break;
    }

    if ((len & 0xc0) === 0xc0) {
      if (!jumped) returnOffset = offset + 2;
      offset = ((len & 0x3f) << 8) | packet[offset + 1]!;
      jumped = true;
      continue;
    }

    offset++;
    labels.push(packet.subarray(offset, offset + len).toString("ascii"));
    offset += len;
  }

  if (!jumped && labels.length > 0) returnOffset = offset + 1;

  return { name: labels.join("."), newOffset: returnOffset };
}

/**
 * Skips past a DNS name in a packet (handles compression pointers).
 */
function skipName(packet: Buffer, offset: number): number {
  let depth = 0;
  while (offset < packet.length) {
    if (depth++ > 128) throw new Error("DNS name compression loop detected");
    const len = packet[offset]!;
    if (len === 0) return offset + 1;
    if ((len & 0xc0) === 0xc0) return offset + 2;
    offset += 1 + len;
  }
  return offset;
}

/**
 * Parses an A record (IPv4 address) from rdata.
 */
export function parseARecord(data: Buffer): string {
  if (data.length !== 4) throw new Error("Invalid A record length");
  return `${data[0]}.${data[1]}.${data[2]}.${data[3]}`;
}

/**
 * Parses an AAAA record (IPv6 address) from rdata.
 */
export function parseAAAARecord(data: Buffer): string {
  if (data.length !== 16) throw new Error("Invalid AAAA record length");
  const groups: string[] = [];
  for (let i = 0; i < 16; i += 2) {
    groups.push(data.readUInt16BE(i).toString(16));
  }
  return groups.join(":");
}

/**
 * Parses an HTTPS/SVCB record from rdata (RFC 9460 §2.2).
 */
export function parseSVCBRecord(data: Buffer): SVCBRecord {
  if (data.length < 3) throw new Error("SVCB record too short");

  const priority = data.readUInt16BE(0);
  let offset = 2;

  const labels: string[] = [];
  while (offset < data.length) {
    const len = data[offset]!;
    if (len === 0) {
      offset++;
      break;
    }
    offset++;
    if (offset + len > data.length) break;
    labels.push(data.subarray(offset, offset + len).toString("ascii"));
    offset += len;
  }
  const target = labels.join(".");

  const record: SVCBRecord = { priority, target };

  while (offset + 4 <= data.length) {
    const key = data.readUInt16BE(offset);
    offset += 2;
    const valLen = data.readUInt16BE(offset);
    offset += 2;

    if (offset + valLen > data.length) break;
    const value = data.subarray(offset, offset + valLen);
    offset += valLen;

    switch (key) {
      case SvcParamKey.ALPN:
        record.alpn = parseAlpnParam(value);
        break;
      case SvcParamKey.NO_DEFAULT_ALPN:
        record.noDefaultAlpn = true;
        break;
      case SvcParamKey.PORT:
        if (value.length >= 2) record.port = value.readUInt16BE(0);
        break;
      case SvcParamKey.IPV4HINT:
        record.ipv4Hints = parseIPv4Hints(value);
        break;
      case SvcParamKey.IPV6HINT:
        record.ipv6Hints = parseIPv6Hints(value);
        break;
      case SvcParamKey.ECH:
        record.echConfigList = Buffer.from(value);
        break;
    }
  }

  return record;
}

/**
 * Parses the ALPN SvcParam — length-prefixed protocol identifier list.
 */
function parseAlpnParam(data: Buffer): string[] {
  const protocols: string[] = [];
  let offset = 0;
  while (offset < data.length) {
    const len = data[offset]!;
    offset++;
    if (offset + len > data.length) break;
    protocols.push(data.subarray(offset, offset + len).toString("ascii"));
    offset += len;
  }
  return protocols;
}

/**
 * Parses IPv4 address hints from SvcParam value.
 */
function parseIPv4Hints(data: Buffer): string[] {
  const addresses: string[] = [];
  for (let i = 0; i + 4 <= data.length; i += 4) {
    addresses.push(`${data[i]}.${data[i + 1]}.${data[i + 2]}.${data[i + 3]}`);
  }
  return addresses;
}

/**
 * Parses IPv6 address hints from SvcParam value.
 */
function parseIPv6Hints(data: Buffer): string[] {
  const addresses: string[] = [];
  for (let i = 0; i + 16 <= data.length; i += 16) {
    const groups: string[] = [];
    for (let j = 0; j < 16; j += 2) {
      groups.push(data.readUInt16BE(i + j).toString(16));
    }
    addresses.push(groups.join(":"));
  }
  return addresses;
}
