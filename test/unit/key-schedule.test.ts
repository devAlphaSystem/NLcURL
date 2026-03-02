
import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import {
  hkdfExtract,
  hkdfExpandLabel,
  hashLength,
  zeroKey,
  deriveSecret,
  keyIVLengths,
} from '../../src/tls/stealth/key-schedule.js';
import { createHash } from 'node:crypto';

describe('hashLength', () => {
  it('SHA-256 is 32 bytes', () => {
    assert.equal(hashLength('sha256'), 32);
  });

  it('SHA-384 is 48 bytes', () => {
    assert.equal(hashLength('sha384'), 48);
  });
});

describe('zeroKey', () => {
  it('returns all zeros of correct length for SHA-256', () => {
    const key = zeroKey('sha256');
    assert.equal(key.length, 32);
    assert.ok(key.every((b) => b === 0));
  });

  it('returns all zeros of correct length for SHA-384', () => {
    const key = zeroKey('sha384');
    assert.equal(key.length, 48);
    assert.ok(key.every((b) => b === 0));
  });
});

describe('hkdfExtract', () => {
  it('produces output of hash length', () => {
    const salt = Buffer.alloc(32, 0);
    const ikm = Buffer.alloc(32, 0x01);
    const prk = hkdfExtract('sha256', salt, ikm);
    assert.equal(prk.length, 32);
  });

  it('is deterministic', () => {
    const salt = Buffer.from('salt');
    const ikm = Buffer.from('input key material');
    const a = hkdfExtract('sha256', salt, ikm);
    const b = hkdfExtract('sha256', salt, ikm);
    assert.deepEqual([...a], [...b]);
  });

  it('different inputs produce different output', () => {
    const salt = Buffer.from('salt');
    const a = hkdfExtract('sha256', salt, Buffer.from('ikm1'));
    const b = hkdfExtract('sha256', salt, Buffer.from('ikm2'));
    assert.notDeepEqual([...a], [...b]);
  });
});

describe('hkdfExpandLabel', () => {
  it('produces output of requested length', () => {
    const secret = hkdfExtract('sha256', Buffer.alloc(32), Buffer.alloc(32, 1));
    const output = hkdfExpandLabel('sha256', secret, 'test', Buffer.alloc(0), 16);
    assert.equal(output.length, 16);
  });

  it('is deterministic', () => {
    const secret = hkdfExtract('sha256', Buffer.alloc(32), Buffer.alloc(32, 1));
    const a = hkdfExpandLabel('sha256', secret, 'label', Buffer.alloc(0), 32);
    const b = hkdfExpandLabel('sha256', secret, 'label', Buffer.alloc(0), 32);
    assert.deepEqual([...a], [...b]);
  });
});

describe('deriveSecret', () => {
  it('produces output of hash length', () => {
    const secret = hkdfExtract('sha256', Buffer.alloc(32), Buffer.alloc(32, 1));
    const hash = createHash('sha256').update('test').digest();
    const derived = deriveSecret('sha256', secret, 'derived', hash);
    assert.equal(derived.length, 32);
  });
});

describe('keyIVLengths', () => {
  it('AES-128-GCM: key=16 iv=12', () => {
    const { keyLen, ivLen } = keyIVLengths('TLS_AES_128_GCM_SHA256');
    assert.equal(keyLen, 16);
    assert.equal(ivLen, 12);
  });

  it('AES-256-GCM: key=32 iv=12', () => {
    const { keyLen, ivLen } = keyIVLengths('TLS_AES_256_GCM_SHA384');
    assert.equal(keyLen, 32);
    assert.equal(ivLen, 12);
  });

  it('ChaCha20: key=32 iv=12', () => {
    const { keyLen, ivLen } = keyIVLengths('TLS_CHACHA20_POLY1305_SHA256');
    assert.equal(keyLen, 32);
    assert.equal(ivLen, 12);
  });
});
