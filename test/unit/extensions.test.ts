/**
 * Unit tests for src/fingerprints/extensions.ts
 *
 * Validates TLS extension wire format encoding against RFC specifications.
 * These tests verify exact byte layouts that real TLS servers parse, catching
 * encoding bugs that only manifest against production servers.
 */
import { describe, it } from "node:test";
import { strict as assert } from "node:assert";
import { sniData, supportedVersionsData, supportedGroupsData, signatureAlgorithmsData, alpnData, applicationSettingsData, echGreaseData, paddingData, ecPointFormatsData, compressCertData, pskKeyExchangeModesData, recordSizeLimitData, delegatedCredentialsData } from "../../src/fingerprints/extensions.js";
import { BufferReader } from "../../src/utils/buffer-reader.js";

describe("sniData", () => {
  it("encodes SNI with correct wire format per RFC 6066 §3", () => {
    const data = sniData("example.com");
    const r = new BufferReader(data);

    const listLen = r.readUInt16();
    assert.equal(listLen, 1 + 2 + 11);

    const nameType = r.readUInt8();
    assert.equal(nameType, 0);

    const nameLen = r.readUInt16();
    assert.equal(nameLen, 11);

    const hostname = r.readBytes(nameLen).toString("ascii");
    assert.equal(hostname, "example.com");

    assert.equal(r.remaining, 0);
  });

  it("produces exact byte sequence for known hostname", () => {
    const data = sniData("test.io");
    const expected = Buffer.from([0x00, 0x0a, 0x00, 0x00, 0x07, 0x74, 0x65, 0x73, 0x74, 0x2e, 0x69, 0x6f]);
    assert.deepStrictEqual(data, expected);
  });

  it("does not double-wrap the list length (regression: extra length prefix bug)", () => {
    const data = sniData("a.com");
    assert.equal(data.length, 10);
    assert.equal(data.readUInt16BE(0), 8);
  });

  it("handles long hostnames", () => {
    const long = "a".repeat(200) + ".example.com";
    const data = sniData(long);
    const r = new BufferReader(data);
    const listLen = r.readUInt16();
    assert.equal(listLen, 3 + long.length);
  });
});

describe("applicationSettingsData", () => {
  it("encodes ALPS protocol list with 1-byte length per protocol per draft-vvv-tls-alps-01", () => {
    const data = applicationSettingsData(["h2"]);
    const r = new BufferReader(data);

    const listLen = r.readUInt16();
    assert.equal(listLen, 3);

    const protoLen = r.readUInt8();
    assert.equal(protoLen, 2);

    const proto = r.readBytes(protoLen).toString("ascii");
    assert.equal(proto, "h2");

    assert.equal(r.remaining, 0);
  });

  it("produces exact bytes for h2 protocol", () => {
    const data = applicationSettingsData(["h2"]);
    const expected = Buffer.from([0x00, 0x03, 0x02, 0x68, 0x32]);
    assert.deepStrictEqual(data, expected);
  });

  it("uses 1-byte protocol length not 2-byte (regression: encoding bug)", () => {
    const data = applicationSettingsData(["h2"]);
    assert.equal(data.length, 5);
    assert.equal(data[2], 0x02);
    assert.equal(data[3], 0x68);
  });

  it("handles multiple protocols", () => {
    const data = applicationSettingsData(["h2", "http/1.1"]);
    const r = new BufferReader(data);
    const listLen = r.readUInt16();
    assert.equal(listLen, 12);

    const p1Len = r.readUInt8();
    assert.equal(p1Len, 2);
    assert.equal(r.readBytes(p1Len).toString("ascii"), "h2");

    const p2Len = r.readUInt8();
    assert.equal(p2Len, 8);
    assert.equal(r.readBytes(p2Len).toString("ascii"), "http/1.1");
  });
});

describe("echGreaseData", () => {
  it("has correct HPKE KEM ID encoding (1 byte config_id, 2 byte KEM)", () => {
    const data = echGreaseData();
    const r = new BufferReader(data);

    const chType = r.readUInt8();
    assert.equal(chType, 0);

    const kdfId = r.readUInt16();
    assert.equal(kdfId, 0x0020);

    const aeadId = r.readUInt16();
    assert.equal(aeadId, 0x0001);

    const configId = r.readUInt8();
    assert.ok(configId >= 0 && configId <= 255);
  });

  it("config_id is uint8 not uint16 (regression: wrong field width)", () => {
    const data = echGreaseData();
    assert.equal(data.length, 58);
  });

  it("enc field has correct length prefix and 32-byte payload", () => {
    const data = echGreaseData();
    const encLen = data.readUInt16BE(6);
    assert.equal(encLen, 32);
    const payloadLen = data.readUInt16BE(40);
    assert.equal(payloadLen, 16);
    assert.equal(data.length, 42 + payloadLen);
  });
});

describe("alpnData", () => {
  it("encodes ALPN protocol list per RFC 7301 §3.1", () => {
    const data = alpnData(["h2", "http/1.1"]);
    const r = new BufferReader(data);

    const listLen = r.readUInt16();
    const p1Len = r.readUInt8();
    assert.equal(p1Len, 2);
    assert.equal(r.readBytes(p1Len).toString("ascii"), "h2");

    const p2Len = r.readUInt8();
    assert.equal(p2Len, 8);
    assert.equal(r.readBytes(p2Len).toString("ascii"), "http/1.1");

    assert.equal(listLen, 1 + 2 + 1 + 8);
    assert.equal(r.remaining, 0);
  });
});

describe("supportedVersionsData", () => {
  it("encodes version list with 1-byte length prefix", () => {
    const data = supportedVersionsData([0x0304, 0x0303]);
    assert.equal(data[0], 4);
    assert.equal(data.readUInt16BE(1), 0x0304);
    assert.equal(data.readUInt16BE(3), 0x0303);
    assert.equal(data.length, 5);
  });
});

describe("supportedGroupsData", () => {
  it("encodes group list with 2-byte length prefix", () => {
    const data = supportedGroupsData([0x001d, 0x0017]);
    assert.equal(data.readUInt16BE(0), 4);
    assert.equal(data.readUInt16BE(2), 0x001d);
    assert.equal(data.readUInt16BE(4), 0x0017);
    assert.equal(data.length, 6);
  });
});

describe("paddingData", () => {
  it("creates zero-filled buffer of specified length", () => {
    const data = paddingData(100);
    assert.equal(data.length, 100);
    assert.ok(data.every((b) => b === 0));
  });

  it("handles zero-length padding", () => {
    const data = paddingData(0);
    assert.equal(data.length, 0);
  });
});

describe("recordSizeLimitData", () => {
  it("encodes as 2-byte big-endian value", () => {
    const data = recordSizeLimitData(16385);
    assert.equal(data.length, 2);
    assert.equal(data.readUInt16BE(0), 16385);
  });
});

describe("signatureAlgorithmsData", () => {
  it("encodes signature algorithm list with 2-byte length prefix", () => {
    const data = signatureAlgorithmsData([0x0403, 0x0804]);
    assert.equal(data.readUInt16BE(0), 4);
    assert.equal(data.readUInt16BE(2), 0x0403);
    assert.equal(data.readUInt16BE(4), 0x0804);
    assert.equal(data.length, 6);
  });
});

describe("ecPointFormatsData", () => {
  it("encodes point format list with 1-byte length prefix", () => {
    const data = ecPointFormatsData([0]);
    assert.equal(data[0], 1);
    assert.equal(data[1], 0);
    assert.equal(data.length, 2);
  });
});

describe("compressCertData", () => {
  it("encodes compression algorithm list", () => {
    const data = compressCertData([2, 1]);
    assert.equal(data[0], 4);
    assert.equal(data.readUInt16BE(1), 2);
    assert.equal(data.readUInt16BE(3), 1);
    assert.equal(data.length, 5);
  });
});

describe("pskKeyExchangeModesData", () => {
  it("encodes PSK mode list with 1-byte length prefix", () => {
    const data = pskKeyExchangeModesData([1]);
    assert.equal(data[0], 1);
    assert.equal(data[1], 1);
    assert.equal(data.length, 2);
  });
});

describe("delegatedCredentialsData", () => {
  it("encodes algorithm list with 2-byte length prefix", () => {
    const data = delegatedCredentialsData([0x0403, 0x0503]);
    assert.equal(data.readUInt16BE(0), 4);
    assert.equal(data.readUInt16BE(2), 0x0403);
    assert.equal(data.readUInt16BE(4), 0x0503);
    assert.equal(data.length, 6);
  });
});
