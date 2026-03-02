
import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { HPACKEncoder, HPACKDecoder } from '../../src/http/h2/hpack.js';

describe('HPACK encoder/decoder roundtrip', () => {
  it('roundtrips indexed headers (static table)', () => {
    const encoder = new HPACKEncoder();
    const decoder = new HPACKDecoder();

    const headers: Array<[string, string]> = [
      [':method', 'GET'],
      [':path', '/'],
      [':scheme', 'https'],
    ];

    const encoded = encoder.encode(headers);
    const decoded = decoder.decode(encoded);

    assert.deepEqual(decoded, headers);
  });

  it('roundtrips literal headers with indexing', () => {
    const encoder = new HPACKEncoder();
    const decoder = new HPACKDecoder();

    const headers: Array<[string, string]> = [
      [':method', 'GET'],
      [':path', '/api/data'],
      ['x-custom', 'some-value'],
    ];

    const encoded = encoder.encode(headers);
    const decoded = decoder.decode(encoded);

    assert.deepEqual(decoded, headers);
  });

  it('encodes the same header consistently', () => {
    const encoder = new HPACKEncoder();
    const decoder = new HPACKDecoder();

    const headers1: Array<[string, string]> = [
      ['x-request-id', 'abc'],
    ];

    const headers2: Array<[string, string]> = [
      ['x-request-id', 'abc'],
    ];

    const e1 = encoder.encode(headers1);
    const d1 = decoder.decode(e1);
    assert.deepEqual(d1, headers1);

    const e2 = encoder.encode(headers2);
    const d2 = decoder.decode(e2);
    assert.deepEqual(d2, headers2);
  });

  it('handles empty header list', () => {
    const encoder = new HPACKEncoder();
    const decoder = new HPACKDecoder();

    const encoded = encoder.encode([]);
    assert.equal(encoded.length, 0);

    const decoded = decoder.decode(encoded);
    assert.deepEqual(decoded, []);
  });

  it('handles headers with empty values', () => {
    const encoder = new HPACKEncoder();
    const decoder = new HPACKDecoder();

    const headers: Array<[string, string]> = [
      [':authority', ''],
    ];

    const encoded = encoder.encode(headers);
    const decoded = decoder.decode(encoded);

    assert.deepEqual(decoded, headers);
  });

  it('encodes pseudo-headers from static table', () => {
    const encoder = new HPACKEncoder();
    const decoder = new HPACKDecoder();

    const headers: Array<[string, string]> = [
      [':method', 'POST'],
      [':scheme', 'http'],
      [':status', '200'],
    ];

    const encoded = encoder.encode(headers);
    const decoded = decoder.decode(encoded);

    assert.deepEqual(decoded, headers);
  });
});

describe('HPACKDecoder dynamic table size update', () => {
  it('handles table size update during decode', () => {
    const encoder = new HPACKEncoder(2048);
    const decoder = new HPACKDecoder(2048);

    const headers: Array<[string, string]> = [
      [':method', 'GET'],
      ['custom', 'value'],
    ];

    const encoded = encoder.encode(headers);
    const decoded = decoder.decode(encoded);
    assert.deepEqual(decoded, headers);
  });
});

describe('HPACK Huffman encoding', () => {
  it('encodes with Huffman by default and roundtrips', () => {
    const encoder = new HPACKEncoder();
    const decoder = new HPACKDecoder();

    const headers: Array<[string, string]> = [
      [':method', 'GET'],
      [':path', '/api/test'],
      ['x-custom-header', 'custom-value-here'],
    ];

    const encoded = encoder.encode(headers);
    const decoded = decoder.decode(encoded);
    assert.deepEqual(decoded, headers);
  });

  it('Huffman-encoded output is smaller than plain text for typical headers', () => {
    const encoder = new HPACKEncoder();

    const headers: Array<[string, string]> = [
      ['x-long-header-name', 'this-is-a-reasonably-long-header-value'],
    ];

    const encoded = encoder.encode(headers);
    const rawLen = 'x-long-header-name'.length + 'this-is-a-reasonably-long-header-value'.length;
    assert.ok(encoded.length < rawLen, `Encoded ${encoded.length} should be < raw ${rawLen}`);
  });

  it('roundtrips headers with special characters', () => {
    const encoder = new HPACKEncoder();
    const decoder = new HPACKDecoder();

    const headers: Array<[string, string]> = [
      ['content-type', 'application/json; charset=utf-8'],
      ['accept', 'text/html, application/xhtml+xml'],
    ];

    const encoded = encoder.encode(headers);
    const decoded = decoder.decode(encoded);
    assert.deepEqual(decoded, headers);
  });
});
