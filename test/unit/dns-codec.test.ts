/**
 * Unit tests for src/dns/codec.ts
 * DNS wire format encoding/decoding per RFC 1035 §4, RFC 6891 EDNS(0).
 */
import { describe, it } from "node:test";
import { strict as assert } from "node:assert";
import { buildDNSQuery, parseDNSResponse, parseARecord, parseAAAARecord, parseSVCBRecord } from "../../src/dns/codec.js";
import { RTYPE, RCLASS } from "../../src/dns/types.js";

describe("buildDNSQuery", () => {
  it("builds a minimal DNS query with correct header fields", () => {
    const buf = buildDNSQuery("example.com", RTYPE.A, 0x1234);
    assert.equal(buf.readUInt16BE(0), 0x1234);
    assert.equal(buf.readUInt16BE(2), 0x0100);
    assert.equal(buf.readUInt16BE(4), 1);
    assert.equal(buf.readUInt16BE(6), 0);
    assert.equal(buf.readUInt16BE(8), 0);
    assert.equal(buf.readUInt16BE(10), 0);
  });

  it("encodes domain labels correctly (RFC 1035 §4.1.2)", () => {
    const buf = buildDNSQuery("example.com", RTYPE.A);
    assert.equal(buf[12], 7);
    assert.equal(buf.subarray(13, 20).toString("ascii"), "example");
    assert.equal(buf[20], 3);
    assert.equal(buf.subarray(21, 24).toString("ascii"), "com");
    assert.equal(buf[24], 0);
  });

  it("sets QTYPE and QCLASS correctly", () => {
    const buf = buildDNSQuery("example.com", RTYPE.AAAA);
    const afterDomain = 12 + 13;
    assert.equal(buf.readUInt16BE(afterDomain), RTYPE.AAAA);
    assert.equal(buf.readUInt16BE(afterDomain + 2), RCLASS.IN);
  });

  it("includes EDNS(0) OPT record when edns option provided", () => {
    const buf = buildDNSQuery("example.com", RTYPE.A, 0, { udpPayloadSize: 4096 });
    assert.equal(buf.readUInt16BE(10), 1);
  });

  it("defaults to 0 ID when omitted", () => {
    const buf = buildDNSQuery("example.com", RTYPE.A);
    assert.equal(buf.readUInt16BE(0), 0);
  });

  it("throws for label exceeding 63 characters", () => {
    const longLabel = "a".repeat(64) + ".com";
    assert.throws(() => buildDNSQuery(longLabel, RTYPE.A));
  });

  it("handles trailing dot in name", () => {
    const buf = buildDNSQuery("example.com.", RTYPE.A);
    assert.equal(buf[12], 7);
  });

  it("sets DNSSEC OK bit when requested", () => {
    const buf = buildDNSQuery("example.com", RTYPE.A, 0, {
      udpPayloadSize: 4096,
      dnssecOk: true,
    });
    const afterQuery = 12 + 13 + 4;
    const ttlOffset = afterQuery + 1 + 2 + 2;
    const ttlFlags = buf.readUInt32BE(ttlOffset);
    assert.ok((ttlFlags & 0x00008000) !== 0, "DO bit should be set");
  });
});

describe("parseDNSResponse", () => {
  it("throws for packet shorter than 12 bytes", () => {
    assert.throws(() => parseDNSResponse(Buffer.alloc(11)));
  });

  it("throws for non-zero RCODE", () => {
    const packet = Buffer.alloc(12);
    packet.writeUInt16BE(0x8003, 2);
    assert.throws(() => parseDNSResponse(packet), /RCODE 3/);
  });

  it("parses a response with one A record", () => {
    const name = Buffer.from([0x04, 0x74, 0x65, 0x73, 0x74, 0x00]);
    const header = Buffer.alloc(12);
    header.writeUInt16BE(0x0001, 0);
    header.writeUInt16BE(0x8180, 2);
    header.writeUInt16BE(1, 4);
    header.writeUInt16BE(1, 6);
    header.writeUInt16BE(0, 8);
    header.writeUInt16BE(0, 10);

    const question = Buffer.concat([name, Buffer.from([0x00, 0x01, 0x00, 0x01])]);

    const answer = Buffer.alloc(16);
    answer.writeUInt16BE(0xc00c, 0);
    answer.writeUInt16BE(1, 2);
    answer.writeUInt16BE(1, 4);
    answer.writeUInt32BE(300, 6);
    answer.writeUInt16BE(4, 10);
    answer[12] = 93;
    answer[13] = 184;
    answer[14] = 216;
    answer[15] = 34;

    const packet = Buffer.concat([header, question, answer]);
    const records = parseDNSResponse(packet);
    assert.equal(records.length, 1);
    assert.equal(records[0]!.type, 1);
    assert.equal(records[0]!.ttl, 300);
    assert.equal(records[0]!.data.length, 4);
  });
});

describe("parseARecord", () => {
  it("parses a 4-byte buffer into dotted decimal IPv4", () => {
    assert.equal(parseARecord(Buffer.from([93, 184, 216, 34])), "93.184.216.34");
  });

  it("parses 127.0.0.1", () => {
    assert.equal(parseARecord(Buffer.from([127, 0, 0, 1])), "127.0.0.1");
  });

  it("parses 0.0.0.0", () => {
    assert.equal(parseARecord(Buffer.from([0, 0, 0, 0])), "0.0.0.0");
  });

  it("parses 255.255.255.255", () => {
    assert.equal(parseARecord(Buffer.from([255, 255, 255, 255])), "255.255.255.255");
  });

  it("throws for wrong length", () => {
    assert.throws(() => parseARecord(Buffer.from([1, 2, 3])));
    assert.throws(() => parseARecord(Buffer.from([1, 2, 3, 4, 5])));
  });
});

describe("parseAAAARecord", () => {
  it("parses 16-byte buffer into colon-hex IPv6", () => {
    const buf = Buffer.from([0x26, 0x06, 0x47, 0x00, 0x47, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x11, 0x11]);
    assert.equal(parseAAAARecord(buf), "2606:4700:4700:0:0:0:0:1111");
  });

  it("parses ::1 (loopback)", () => {
    const buf = Buffer.alloc(16);
    buf[15] = 1;
    assert.equal(parseAAAARecord(buf), "0:0:0:0:0:0:0:1");
  });

  it("throws for wrong length", () => {
    assert.throws(() => parseAAAARecord(Buffer.alloc(4)));
    assert.throws(() => parseAAAARecord(Buffer.alloc(17)));
  });
});

describe("parseSVCBRecord", () => {
  it("parses a minimal SVCB record with priority and target", () => {
    const buf = Buffer.from([0x00, 0x01, 0x00]);
    const rec = parseSVCBRecord(buf);
    assert.equal(rec.priority, 1);
    assert.equal(rec.target, "");
  });

  it("throws for record shorter than 3 bytes", () => {
    assert.throws(() => parseSVCBRecord(Buffer.from([0x00, 0x01])));
  });

  it("parses ALPN parameter", () => {
    const buf = Buffer.from([0x00, 0x01, 0x00, 0x00, 0x01, 0x00, 0x03, 0x02, 0x68, 0x32]);
    const rec = parseSVCBRecord(buf);
    assert.deepEqual(rec.alpn, ["h2"]);
  });

  it("parses PORT parameter", () => {
    const buf = Buffer.from([0x00, 0x01, 0x00, 0x00, 0x03, 0x00, 0x02, 0x20, 0xfb]);
    const rec = parseSVCBRecord(buf);
    assert.equal(rec.port, 8443);
  });

  it("parses IPv4 hints", () => {
    const buf = Buffer.from([0x00, 0x01, 0x00, 0x00, 0x04, 0x00, 0x04, 0x01, 0x02, 0x03, 0x04]);
    const rec = parseSVCBRecord(buf);
    assert.deepEqual(rec.ipv4Hints, ["1.2.3.4"]);
  });
});
