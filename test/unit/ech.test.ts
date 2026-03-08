import { describe, it } from "node:test";
import assert from "node:assert/strict";
import { parseECHConfigList, generateGreaseECH, type ECHParameters } from "../../src/tls/ech.js";

describe("ECH (Encrypted Client Hello)", () => {
  describe("parseECHConfigList", () => {
    it("returns null for empty buffer", () => {
      assert.equal(parseECHConfigList(Buffer.alloc(0)), null);
    });

    it("returns null for buffer too short", () => {
      assert.equal(parseECHConfigList(Buffer.from([0x00])), null);
    });

    it("returns null for invalid length field", () => {
      const buf = Buffer.from([0x00, 0x64, 0x00, 0x00]);
      assert.equal(parseECHConfigList(buf), null);
    });

    it("parses a minimal ECHConfigList with one config", () => {
      const publicName = "cover.example.com";
      const nameBytes = Buffer.from(publicName, "ascii");

      const hpkeConfig = Buffer.alloc(1 + 2 + 2 + 32 + 2 + 4);
      let off = 0;
      hpkeConfig[off++] = 0x42;
      hpkeConfig.writeUInt16BE(0x0020, off);
      off += 2;
      hpkeConfig.writeUInt16BE(32, off);
      off += 2;
      off += 32;
      hpkeConfig.writeUInt16BE(4, off);
      off += 2;
      hpkeConfig.writeUInt16BE(0x0001, off);
      off += 2;
      hpkeConfig.writeUInt16BE(0x0001, off);
      off += 2;

      const suffix = Buffer.alloc(1 + 1 + nameBytes.length + 2);
      let soff = 0;
      suffix[soff++] = 64;
      suffix[soff++] = nameBytes.length;
      nameBytes.copy(suffix, soff);
      soff += nameBytes.length;
      suffix.writeUInt16BE(0, soff);

      const contents = Buffer.concat([hpkeConfig, suffix]);

      const version = Buffer.alloc(2);
      version.writeUInt16BE(0xfe0d, 0);
      const configLen = Buffer.alloc(2);
      configLen.writeUInt16BE(contents.length, 0);
      const echConfig = Buffer.concat([version, configLen, contents]);

      const listLen = Buffer.alloc(2);
      listLen.writeUInt16BE(echConfig.length, 0);
      const echConfigList = Buffer.concat([listLen, echConfig]);

      const result = parseECHConfigList(echConfigList);
      assert.ok(result, "should parse successfully");
      assert.equal(result!.configs.length, 1);
      assert.equal(result!.configs[0]!.version, 0xfe0d);
      assert.equal(result!.outerSNI, publicName);
      assert.ok(Buffer.isBuffer(result!.echConfigList));
    });

    it("returns null when configs list is empty", () => {
      const buf = Buffer.from([0x00, 0x00]);
      assert.equal(parseECHConfigList(buf), null);
    });
  });

  describe("generateGreaseECH", () => {
    it("generates a buffer of reasonable size", () => {
      const grease = generateGreaseECH();
      assert.ok(Buffer.isBuffer(grease));
      assert.ok(grease.length > 100, `GREASE ECH should be > 100 bytes, got ${grease.length}`);
      assert.ok(grease.length < 300, `GREASE ECH should be < 300 bytes, got ${grease.length}`);
    });

    it("generates different payloads each time", () => {
      const a = generateGreaseECH();
      const b = generateGreaseECH();
      assert.ok(!a.equals(b), "GREASE ECH should be random each time");
    });

    it("has correct ECH client hello type byte (outer = 0x00)", () => {
      const grease = generateGreaseECH();
      assert.equal(grease[0], 0x00, "first byte should be 0x00 (outer)");
    });
  });
});
