import { describe, it } from "node:test";
import assert from "node:assert/strict";
import { buildClientHello, generateKeyShare } from "../../src/tls/stealth/client-hello.js";
import { getProfile } from "../../src/fingerprints/database.js";
import { RecordType, HandshakeType, NamedGroup } from "../../src/tls/constants.js";
import { BufferReader } from "../../src/utils/buffer-reader.js";

describe("generateKeyShare", () => {
  it("generates X25519 key pair", () => {
    const ks = generateKeyShare(NamedGroup.X25519);
    assert.equal(ks.group, NamedGroup.X25519);
    assert.equal(ks.publicKey.length, 32);
    assert.equal(ks.privateKey.length, 32);
  });

  it("generates P-256 key pair", () => {
    const ks = generateKeyShare(NamedGroup.SECP256R1);
    assert.equal(ks.group, NamedGroup.SECP256R1);
    assert.ok(ks.publicKey.length > 0);
    assert.ok(ks.privateKey.length > 0);
  });

  it("generates P-384 key pair", () => {
    const ks = generateKeyShare(NamedGroup.SECP384R1);
    assert.equal(ks.group, NamedGroup.SECP384R1);
    assert.ok(ks.publicKey.length > 0);
  });

  it("returns null for unsupported group", () => {
    assert.strictEqual(generateKeyShare(0xffff), null);
  });
});

describe("buildClientHello", () => {
  it("produces a valid TLS record", () => {
    const profile = getProfile("chrome");
    assert.ok(profile);

    const result = buildClientHello(profile, "example.com");

    assert.ok(result.record.length > 0);
    assert.ok(result.handshakeMessage.length > 0);
    assert.ok(result.keyShares.length > 0);
    assert.equal(result.clientRandom.length, 32);

    assert.equal(result.record[0], RecordType.HANDSHAKE);
  });

  it("handshake message starts with ClientHello type", () => {
    const profile = getProfile("chrome");
    assert.ok(profile);

    const result = buildClientHello(profile, "test.com");

    assert.equal(result.handshakeMessage[0], HandshakeType.CLIENT_HELLO);
  });

  it("includes client random in the message", () => {
    const profile = getProfile("chrome");
    assert.ok(profile);

    const result = buildClientHello(profile, "test.com");

    const offset = 4 + 2;
    const embeddedRandom = result.handshakeMessage.subarray(offset, offset + 32);
    assert.deepEqual([...embeddedRandom], [...result.clientRandom]);
  });

  it("generates different random each time", () => {
    const profile = getProfile("chrome");
    assert.ok(profile);

    const r1 = buildClientHello(profile, "a.com");
    const r2 = buildClientHello(profile, "a.com");
    assert.notDeepEqual([...r1.clientRandom], [...r2.clientRandom]);
  });

  it("works with different browser profiles", () => {
    for (const name of ["chrome", "firefox", "safari", "tor"]) {
      const profile = getProfile(name);
      assert.ok(profile, `${name} profile should exist`);

      const result = buildClientHello(profile, "example.com");
      assert.ok(result.record.length > 50, `${name} record should be substantial`);
      assert.ok(result.keyShares.length > 0, `${name} should have key shares`);
    }
  });

  it("record can be parsed back", () => {
    const profile = getProfile("chrome");
    assert.ok(profile);

    const result = buildClientHello(profile, "example.com");
    const r = new BufferReader(result.record);

    const recordType = r.readUInt8();
    assert.equal(recordType, RecordType.HANDSHAKE);

    const recordVersion = r.readUInt16();
    assert.ok(recordVersion >= 0x0301);

    const recordLength = r.readUInt16();
    assert.equal(recordLength, r.remaining);
  });
});
