import { RCLASS, SvcParamKey, type DNSRecord, type SVCBRecord } from "./types.js";

/**
 * Build a raw DNS query packet.
 *
 * @param {string} name - Domain name to query.
 * @param {number} type - Numeric record type.
 * @param {number} [id] - Query identifier (defaults to 0).
 * @param {object} [edns] - EDNS(0) options (RFC 6891).
 * @param {number} [edns.udpPayloadSize] - Max UDP payload size (default 4096).
 * @param {boolean} [edns.dnssecOk] - Set the DO (DNSSEC OK) bit.
 * @param {boolean} [edns.padding] - Add padding option (RFC 7830) to pad to 128-byte blocks.
 * @returns {Buffer} Wire-format DNS query buffer.
 */
export function buildDNSQuery(name: string, type: number, id: number = 0, edns?: { udpPayloadSize?: number; dnssecOk?: boolean; padding?: boolean }): Buffer {
  const labels = encodeName(name);
  const queryLen = 12 + labels.length + 4;

  if (!edns) {
    const buf = Buffer.alloc(queryLen);
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

  const udpSize = edns.udpPayloadSize ?? 4096;
  const dnssecOk = edns.dnssecOk ?? false;

  const ednsOptions: Buffer[] = [];

  let ednsRdataLen = ednsOptions.reduce((sum, o) => sum + o.length, 0);

  if (edns.padding) {
    const baseLen = queryLen + 1 + 10 + ednsRdataLen;
    const targetBlock = 128;
    const paddingNeeded = (targetBlock - (baseLen % targetBlock)) % targetBlock;
    if (paddingNeeded > 4) {
      const padOption = Buffer.alloc(4 + (paddingNeeded - 4));
      padOption.writeUInt16BE(0x000c, 0);
      padOption.writeUInt16BE(paddingNeeded - 4, 2);
      ednsOptions.push(padOption);
      ednsRdataLen += padOption.length;
    }
  }

  const ednsRdata = ednsOptions.length > 0 ? Buffer.concat(ednsOptions) : Buffer.alloc(0);
  const optRecordLen = 1 + 10 + ednsRdata.length;
  const buf = Buffer.alloc(queryLen + optRecordLen);

  buf.writeUInt16BE(id & 0xffff, 0);
  buf.writeUInt16BE(0x0100, 2);
  buf.writeUInt16BE(1, 4);
  buf.writeUInt16BE(0, 6);
  buf.writeUInt16BE(0, 8);
  buf.writeUInt16BE(1, 10);

  labels.copy(buf, 12);
  buf.writeUInt16BE(type, 12 + labels.length);
  buf.writeUInt16BE(RCLASS.IN, 12 + labels.length + 2);

  let off = queryLen;
  buf[off++] = 0x00;
  buf.writeUInt16BE(41, off);
  off += 2;
  buf.writeUInt16BE(udpSize, off);
  off += 2;
  const ttlFlags = dnssecOk ? 0x00008000 : 0x00000000;
  buf.writeUInt32BE(ttlFlags, off);
  off += 4;
  buf.writeUInt16BE(ednsRdata.length, off);
  off += 2;
  if (ednsRdata.length > 0) {
    ednsRdata.copy(buf, off);
  }

  return buf;
}

function encodeName(name: string): Buffer {
  const cleaned = name.endsWith(".") ? name.slice(0, -1) : name;
  const parts = cleaned.split(".");
  let totalLen = 1;
  for (const part of parts) {
    if (part.length > 63) throw new Error(`DNS label too long: "${part}"`);
    totalLen += 1 + part.length;
  }
  const buf = Buffer.allocUnsafe(totalLen);
  let offset = 0;
  for (const part of parts) {
    buf[offset++] = part.length;
    buf.write(part, offset, part.length, "ascii");
    offset += part.length;
  }
  buf[offset] = 0;
  return buf;
}

/**
 * Parse a wire-format DNS response packet into records.
 *
 * @param {Buffer} packet - Raw DNS response data.
 * @returns {DNSRecord[]} Array of parsed DNS records from the answer section.
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
 * Parse a 4-byte buffer into a dotted-decimal IPv4 address string.
 *
 * @param {Buffer} data - Raw A record data.
 * @returns {string} IPv4 address string.
 */
export function parseARecord(data: Buffer): string {
  if (data.length !== 4) throw new Error("Invalid A record length");
  return `${data[0]}.${data[1]}.${data[2]}.${data[3]}`;
}

/**
 * Parse a 16-byte buffer into a colon-hex IPv6 address string.
 *
 * @param {Buffer} data - Raw AAAA record data.
 * @returns {string} IPv6 address string.
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
 * Parse raw SVCB/HTTPS record data into a structured record.
 *
 * @param {Buffer} data - Raw SVCB record data.
 * @returns {SVCBRecord} Parsed SVCB record with service parameters.
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

function parseIPv4Hints(data: Buffer): string[] {
  const addresses: string[] = [];
  for (let i = 0; i + 4 <= data.length; i += 4) {
    addresses.push(`${data[i]}.${data[i + 1]}.${data[i + 2]}.${data[i + 3]}`);
  }
  return addresses;
}

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
