
import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import {
  RecordType,
  ProtocolVersion,
  HandshakeType,
  CipherSuite,
  NamedGroup,
  ExtensionType,
  GREASE_VALUES,
} from '../../src/tls/constants.js';

describe('RecordType', () => {
  it('has correct values', () => {
    assert.equal(RecordType.CHANGE_CIPHER_SPEC, 20);
    assert.equal(RecordType.ALERT, 21);
    assert.equal(RecordType.HANDSHAKE, 22);
    assert.equal(RecordType.APPLICATION_DATA, 23);
  });
});

describe('ProtocolVersion', () => {
  it('has correct values', () => {
    assert.equal(ProtocolVersion.TLS_1_0, 0x0301);
    assert.equal(ProtocolVersion.TLS_1_1, 0x0302);
    assert.equal(ProtocolVersion.TLS_1_2, 0x0303);
    assert.equal(ProtocolVersion.TLS_1_3, 0x0304);
  });
});

describe('HandshakeType', () => {
  it('has correct values', () => {
    assert.equal(HandshakeType.CLIENT_HELLO, 1);
    assert.equal(HandshakeType.SERVER_HELLO, 2);
    assert.equal(HandshakeType.ENCRYPTED_EXTENSIONS, 8);
    assert.equal(HandshakeType.CERTIFICATE, 11);
    assert.equal(HandshakeType.CERTIFICATE_VERIFY, 15);
    assert.equal(HandshakeType.FINISHED, 20);
  });
});

describe('CipherSuite', () => {
  it('has TLS 1.3 suites', () => {
    assert.equal(CipherSuite.TLS_AES_128_GCM_SHA256, 0x1301);
    assert.equal(CipherSuite.TLS_AES_256_GCM_SHA384, 0x1302);
    assert.equal(CipherSuite.TLS_CHACHA20_POLY1305_SHA256, 0x1303);
  });
});

describe('NamedGroup', () => {
  it('has standard curves', () => {
    assert.equal(NamedGroup.SECP256R1, 0x0017);
    assert.equal(NamedGroup.SECP384R1, 0x0018);
    assert.equal(NamedGroup.SECP521R1, 0x0019);
    assert.equal(NamedGroup.X25519, 0x001d);
  });
});

describe('ExtensionType', () => {
  it('has standard extensions', () => {
    assert.equal(ExtensionType.SERVER_NAME, 0x0000);
    assert.equal(ExtensionType.SUPPORTED_GROUPS, 0x000a);
    assert.equal(ExtensionType.SIGNATURE_ALGORITHMS, 0x000d);
    assert.equal(ExtensionType.KEY_SHARE, 0x0033);
    assert.equal(ExtensionType.SUPPORTED_VERSIONS, 0x002b);
  });
});

describe('GREASE_VALUES', () => {
  it('contains standard GREASE values', () => {
    assert.ok(GREASE_VALUES.length > 0);
    for (const v of GREASE_VALUES) {
      assert.equal((v & 0x0f0f), 0x0a0a, `0x${v.toString(16)} should match GREASE pattern`);
    }
  });
});
