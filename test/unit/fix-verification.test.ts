
import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { createHash, createHmac } from 'node:crypto';

import {
  hkdfExtract,
  hkdfExpandLabel,
  deriveSecret,
  hashLength,
  zeroKey,
  deriveHandshakeKeys,
  deriveApplicationKeys,
  computeFinishedVerifyData,
  createHash as ksCreateHash,
} from '../../src/tls/stealth/key-schedule.js';

describe('Fix 1 – hkdfExpandLabel correctness (RFC 5869 / RFC 8446)', () => {
  it('produces known TLS 1.3 Early Secret → derived secret output', () => {
    const alg = 'sha256' as const;
    const earlySecret = hkdfExtract(alg, Buffer.alloc(32), zeroKey(alg));

    const emptyHash = createHash('sha256').digest();
    const derived = deriveSecret(alg, earlySecret, 'derived', emptyHash);

    const fullLabel = Buffer.from('tls13 derived', 'ascii');
    const hkdfLabel = Buffer.alloc(2 + 1 + fullLabel.length + 1 + emptyHash.length);
    let off = 0;
    hkdfLabel.writeUInt16BE(32, off); off += 2;
    hkdfLabel[off++] = fullLabel.length;
    fullLabel.copy(hkdfLabel, off); off += fullLabel.length;
    hkdfLabel[off++] = emptyHash.length;
    emptyHash.copy(hkdfLabel, off);

    const t1 = createHmac('sha256', earlySecret)
      .update(hkdfLabel)
      .update(Buffer.from([0x01]))
      .digest();
    const expected = t1.subarray(0, 32);

    assert.deepEqual(derived, expected, 'deriveSecret output must match manual HKDF-Expand');
  });

  it('hkdfExpandLabel produces correct length for various sizes', () => {
    const prk = hkdfExtract('sha256', Buffer.alloc(32), Buffer.alloc(32, 0xab));

    for (const len of [12, 16, 32, 48, 64]) {
      const result = hkdfExpandLabel('sha256', prk, 'test', Buffer.alloc(0), len);
      assert.equal(result.length, len, `Expected output length ${len}`);
    }
  });

  it('hkdfExpandLabel with sha384 produces correct length', () => {
    const prk = hkdfExtract('sha384', Buffer.alloc(48), Buffer.alloc(48, 0xab));

    const result = hkdfExpandLabel('sha384', prk, 'key', Buffer.alloc(0), 32);
    assert.equal(result.length, 32);

    const result2 = hkdfExpandLabel('sha384', prk, 'iv', Buffer.alloc(0), 12);
    assert.equal(result2.length, 12);
  });

  it('different labels produce different output', () => {
    const prk = hkdfExtract('sha256', Buffer.alloc(32), Buffer.alloc(32, 0x01));
    const a = hkdfExpandLabel('sha256', prk, 'key', Buffer.alloc(0), 16);
    const b = hkdfExpandLabel('sha256', prk, 'iv', Buffer.alloc(0), 16);
    assert.notDeepEqual([...a], [...b]);
  });

  it('different contexts produce different output', () => {
    const prk = hkdfExtract('sha256', Buffer.alloc(32), Buffer.alloc(32, 0x01));
    const ctx1 = createHash('sha256').update('hello').digest();
    const ctx2 = createHash('sha256').update('world').digest();
    const a = hkdfExpandLabel('sha256', prk, 'test', ctx1, 32);
    const b = hkdfExpandLabel('sha256', prk, 'test', ctx2, 32);
    assert.notDeepEqual([...a], [...b]);
  });

  it('full TLS 1.3 key schedule chain runs without error', () => {
    const alg = 'sha256' as const;
    const sharedSecret = Buffer.alloc(32, 0x42);
    const helloHash = createHash('sha256').update('hello+serverhello').digest();

    const hk = deriveHandshakeKeys(alg, sharedSecret, helloHash, 16, 12);

    assert.equal(hk.clientHandshakeKey.length, 16);
    assert.equal(hk.clientHandshakeIV.length, 12);
    assert.equal(hk.serverHandshakeKey.length, 16);
    assert.equal(hk.serverHandshakeIV.length, 12);
    assert.equal(hk.handshakeSecret.length, 32);
    assert.equal(hk.masterSecret.length, 32);

    assert.notDeepEqual([...hk.clientHandshakeKey], [...hk.serverHandshakeKey]);

    const handshakeHash = createHash('sha256').update('full handshake transcript').digest();
    const ak = deriveApplicationKeys(alg, hk.masterSecret, handshakeHash, 16, 12);

    assert.equal(ak.clientKey.length, 16);
    assert.equal(ak.clientIV.length, 12);
    assert.equal(ak.serverKey.length, 16);
    assert.equal(ak.serverIV.length, 12);
    assert.notDeepEqual([...ak.clientKey], [...ak.serverKey]);
  });

  it('computeFinishedVerifyData produces correct HMAC', () => {
    const alg = 'sha256' as const;
    const sharedSecret = Buffer.alloc(32, 0x42);
    const helloHash = createHash('sha256').update('hello').digest();
    const hk = deriveHandshakeKeys(alg, sharedSecret, helloHash, 16, 12);

    const serverHsSecret = deriveSecret(alg, hk.handshakeSecret, 's hs traffic', helloHash);
    const transcriptHash = createHash('sha256').update('transcript').digest();
    const verifyData = computeFinishedVerifyData(alg, serverHsSecret, transcriptHash);

    assert.equal(verifyData.length, 32);

    const verifyData2 = computeFinishedVerifyData(alg, serverHsSecret, transcriptHash);
    assert.deepEqual(verifyData, verifyData2);
  });
});

describe('Fix 2 – createHash re-export works in ESM', () => {
  it('createHash is exported and functional', () => {
    const hash = ksCreateHash('sha256');
    hash.update('test');
    const digest = hash.digest();
    assert.equal(digest.length, 32);
  });

  it('createHash matches node:crypto createHash', () => {
    const expected = createHash('sha256').update('hello world').digest();
    const actual = ksCreateHash('sha256').update('hello world').digest();
    assert.deepEqual(actual, expected);
  });
});

import { encodeRequest } from '../../src/http/h1/encoder.js';
import type { NLcURLRequest } from '../../src/core/request.js';

describe('Fix 5 – JSON body defaults to application/json', () => {
  it('object body without explicit Content-Type uses application/json', () => {
    const req: NLcURLRequest = {
      url: 'https://example.com/api',
      method: 'POST',
      body: { key: 'value', nested: { n: 1 } },
    };

    const buf = encodeRequest(req, []);
    const text = buf.toString();

    assert.ok(
      text.includes('content-type: application/json'),
      `Expected application/json but got:\n${text}`,
    );
    assert.ok(text.includes('{"key":"value","nested":{"n":1}}'));
  });

  it('string body without explicit Content-Type uses application/x-www-form-urlencoded', () => {
    const req: NLcURLRequest = {
      url: 'https://example.com/api',
      method: 'POST',
      body: 'key=value',
    };

    const buf = encodeRequest(req, []);
    const text = buf.toString('latin1');

    assert.ok(text.includes('content-type: application/x-www-form-urlencoded'));
  });

  it('Buffer body without explicit Content-Type uses application/x-www-form-urlencoded', () => {
    const req: NLcURLRequest = {
      url: 'https://example.com/upload',
      method: 'POST',
      body: Buffer.from([0x01, 0x02]),
    };

    const buf = encodeRequest(req, []);
    const text = buf.toString('latin1');

    assert.ok(text.includes('content-type: application/x-www-form-urlencoded'));
  });

  it('explicit Content-Type is not overridden for object body', () => {
    const req: NLcURLRequest = {
      url: 'https://example.com/api',
      method: 'POST',
      body: { key: 'value' },
      headers: { 'Content-Type': 'text/plain' },
    };

    const buf = encodeRequest(req, []);
    const text = buf.toString();

    assert.ok(text.includes('content-type: text/plain'));
    assert.ok(!text.includes('application/json'));
  });

  it('GET request with no body has no content-type', () => {
    const req: NLcURLRequest = {
      url: 'https://example.com/',
      method: 'GET',
    };

    const buf = encodeRequest(req, []);
    const text = buf.toString('latin1');

    assert.ok(!text.includes('content-type'));
  });
});

describe('Fix 7 – cookieJar field presence', () => {
  it('NLcURLRequest has a cookieJar field', () => {
    const req: NLcURLRequest = {
      url: 'https://example.com/',
      cookieJar: true,
    };
    assert.equal(req.cookieJar, true);
  });

  it('cookieJar can be a string path', () => {
    const req: NLcURLRequest = {
      url: 'https://example.com/',
      cookieJar: '/tmp/cookies.txt',
    };
    assert.equal(req.cookieJar, '/tmp/cookies.txt');
  });
});

import { HPACKEncoder, HPACKDecoder } from '../../src/http/h2/hpack.js';

describe('Fix 10 – HPACK never-indexed header roundtrip', () => {
  it('roundtrips headers that may hit the never-indexed path', () => {
    const encoder = new HPACKEncoder();
    const decoder = new HPACKDecoder();

    const headers: Array<[string, string]> = [
      [':method', 'GET'],
      [':path', '/secret'],
      [':scheme', 'https'],
      [':authority', 'example.com'],
      ['authorization', 'Bearer supersecrettoken'],
      ['cookie', 'session=abc123'],
    ];

    const encoded = encoder.encode(headers);
    const decoded = decoder.decode(encoded);

    assert.deepEqual(decoded, headers);
  });

  it('handles large number of headers through HPACK', () => {
    const encoder = new HPACKEncoder();
    const decoder = new HPACKDecoder();

    const headers: Array<[string, string]> = [];
    for (let i = 0; i < 50; i++) {
      headers.push([`x-header-${i}`, `value-${i}`]);
    }

    const encoded = encoder.encode(headers);
    const decoded = decoder.decode(encoded);

    assert.deepEqual(decoded, headers);
  });
});
