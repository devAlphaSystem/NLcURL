import { describe, it } from "node:test";
import assert from "node:assert/strict";
import { buildDNSQuery, parseDNSResponse, parseSVCBRecord, parseARecord, parseAAAARecord } from "../../src/dns/codec.js";
import { RTYPE } from "../../src/dns/types.js";

describe("DNS Codec", () => {
  describe("buildDNSQuery", () => {
    it("builds a valid A query for a simple domain", () => {
      const packet = buildDNSQuery("example.com", RTYPE.A, 0x1234);
      assert.ok(packet.length > 12, "packet must include header + question");

      assert.equal(packet.readUInt16BE(0), 0x1234, "query ID");
      assert.equal(packet.readUInt16BE(2), 0x0100, "flags: RD=1");
      assert.equal(packet.readUInt16BE(4), 1, "QDCOUNT = 1");
      assert.equal(packet.readUInt16BE(6), 0, "ANCOUNT = 0");

      const labelStart = 12;
      assert.equal(packet[labelStart], 7, 'first label length = 7 ("example")');
      assert.equal(packet.subarray(labelStart + 1, labelStart + 8).toString("ascii"), "example");
      assert.equal(packet[labelStart + 8], 3, 'second label length = 3 ("com")');
      assert.equal(packet.subarray(labelStart + 9, labelStart + 12).toString("ascii"), "com");
      assert.equal(packet[labelStart + 12], 0, "root label");

      assert.equal(packet.readUInt16BE(labelStart + 13), RTYPE.A, "QTYPE = A");
      assert.equal(packet.readUInt16BE(labelStart + 15), 1, "QCLASS = IN");
    });

    it("builds an AAAA query", () => {
      const packet = buildDNSQuery("test.example.com", RTYPE.AAAA, 0);
      assert.equal(packet.readUInt16BE(4), 1, "QDCOUNT = 1");

      const qtypeOffset = 12 + 18;
      assert.equal(packet.readUInt16BE(qtypeOffset), RTYPE.AAAA, "QTYPE = AAAA");
    });

    it("builds an HTTPS query", () => {
      const packet = buildDNSQuery("cloudflare.com", RTYPE.HTTPS, 42);
      assert.equal(packet.readUInt16BE(0), 42, "query ID");
    });
  });

  describe("parseDNSResponse", () => {
    it("parses a minimal A record response", () => {
      const header = Buffer.alloc(12);
      header.writeUInt16BE(0x1234, 0);
      header.writeUInt16BE(0x8180, 2);
      header.writeUInt16BE(1, 4);
      header.writeUInt16BE(1, 6);

      const question = Buffer.from([1, 0x61, 1, 0x62, 0, 0x00, 0x01, 0x00, 0x01]);

      const answer = Buffer.from([1, 0x61, 1, 0x62, 0, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x01, 0x2c, 0x00, 0x04, 0x01, 0x02, 0x03, 0x04]);

      const packet = Buffer.concat([header, question, answer]);
      const records = parseDNSResponse(packet);

      assert.equal(records.length, 1);
      assert.equal(records[0]!.type, RTYPE.A);
      assert.equal(records[0]!.ttl, 300);
      assert.equal(records[0]!.data.length, 4);
    });

    it("throws on NXDOMAIN (RCODE 3)", () => {
      const header = Buffer.alloc(12);
      header.writeUInt16BE(0, 0);
      header.writeUInt16BE(0x8183, 2);
      header.writeUInt16BE(0, 4);
      header.writeUInt16BE(0, 6);

      assert.throws(() => parseDNSResponse(header), /RCODE 3/);
    });

    it("throws on packet too short", () => {
      assert.throws(() => parseDNSResponse(Buffer.alloc(5)), /too short/);
    });
  });

  describe("parseARecord / parseAAAARecord", () => {
    it("parses a 4-byte A record to an IPv4 string", () => {
      const data = Buffer.from([192, 168, 1, 1]);
      assert.equal(parseARecord(data), "192.168.1.1");
    });

    it("parses a 4-byte A record (all zeros)", () => {
      assert.equal(parseARecord(Buffer.from([0, 0, 0, 0])), "0.0.0.0");
    });

    it("parses a 16-byte AAAA record to an IPv6 string", () => {
      const data = Buffer.from([0x20, 0x01, 0x0d, 0xb8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01]);
      const result = parseAAAARecord(data);
      assert.ok(result.includes("2001"), "should contain 2001");
      assert.ok(result.includes("db8") || result.includes("0db8"), "should contain db8");
    });

    it("parses loopback IPv6 address", () => {
      const data = Buffer.alloc(16);
      data[15] = 1;
      const result = parseAAAARecord(data);
      assert.ok(result.includes("1"), "should end with ::1 or similar");
    });
  });

  describe("parseSVCBRecord", () => {
    it("parses a basic SVCB record with priority and target", () => {
      const priority = Buffer.alloc(2);
      priority.writeUInt16BE(1, 0);

      const target = Buffer.from([3, 0x63, 0x64, 0x6e, 7, 0x65, 0x78, 0x61, 0x6d, 0x70, 0x6c, 0x65, 3, 0x63, 0x6f, 0x6d, 0]);

      const data = Buffer.concat([priority, target]);
      const record = parseSVCBRecord(data);

      assert.equal(record.priority, 1);
      assert.equal(record.target, "cdn.example.com");
    });

    it("parses an AliasMode record (priority 0)", () => {
      const priority = Buffer.alloc(2);
      priority.writeUInt16BE(0, 0);
      const target = Buffer.from([1, 0x61, 0]);

      const data = Buffer.concat([priority, target]);
      const record = parseSVCBRecord(data);

      assert.equal(record.priority, 0);
      assert.equal(record.target, "a");
    });

    it("parses ALPN SvcParam", () => {
      const priority = Buffer.alloc(2);
      priority.writeUInt16BE(1, 0);
      const target = Buffer.from([0]);

      const paramKey = Buffer.alloc(2);
      paramKey.writeUInt16BE(1, 0);
      const alpnValue = Buffer.from([2, 0x68, 0x32, 2, 0x68, 0x33]);
      const paramLength = Buffer.alloc(2);
      paramLength.writeUInt16BE(alpnValue.length, 0);

      const data = Buffer.concat([priority, target, paramKey, paramLength, alpnValue]);
      const record = parseSVCBRecord(data);

      assert.equal(record.priority, 1);
      assert.deepEqual(record.alpn, ["h2", "h3"]);
    });

    it("parses PORT SvcParam", () => {
      const priority = Buffer.alloc(2);
      priority.writeUInt16BE(1, 0);
      const target = Buffer.from([0]);

      const paramKey = Buffer.alloc(2);
      paramKey.writeUInt16BE(3, 0);
      const paramLength = Buffer.alloc(2);
      paramLength.writeUInt16BE(2, 0);
      const portValue = Buffer.alloc(2);
      portValue.writeUInt16BE(8443, 0);

      const data = Buffer.concat([priority, target, paramKey, paramLength, portValue]);
      const record = parseSVCBRecord(data);

      assert.equal(record.port, 8443);
    });
  });
});
