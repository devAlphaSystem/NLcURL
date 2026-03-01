/**
 * Tests for URL utilities.
 */

import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { resolveURL, appendParams, originOf, hostPort } from '../../src/utils/url.js';

describe('resolveURL', () => {
  it('resolves a relative URL against a base', () => {
    const result = resolveURL('https://example.com/api/', 'data');
    assert.equal(result, 'https://example.com/api/data');
  });

  it('resolves absolute URL ignoring base', () => {
    const result = resolveURL('https://example.com/', 'https://other.com/page');
    assert.equal(result, 'https://other.com/page');
  });

  it('returns relative when base is undefined', () => {
    const result = resolveURL(undefined, 'https://example.com/x');
    assert.equal(result, 'https://example.com/x');
  });

  it('returns relative on invalid URL', () => {
    const result = resolveURL('not-a-url', 'also-not-a-url');
    assert.equal(result, 'also-not-a-url');
  });
});

describe('appendParams', () => {
  it('appends query parameters', () => {
    const result = appendParams('https://example.com/api', { page: 1, limit: 10 });
    const url = new URL(result);
    assert.equal(url.searchParams.get('page'), '1');
    assert.equal(url.searchParams.get('limit'), '10');
  });

  it('preserves existing query parameters', () => {
    const result = appendParams('https://example.com/api?existing=yes', { added: 'true' });
    const url = new URL(result);
    assert.equal(url.searchParams.get('existing'), 'yes');
    assert.equal(url.searchParams.get('added'), 'true');
  });

  it('returns URL unchanged when no params', () => {
    assert.equal(appendParams('https://example.com/', {}), 'https://example.com/');
    assert.equal(appendParams('https://example.com/'), 'https://example.com/');
  });
});

describe('originOf', () => {
  it('extracts origin with default HTTPS port', () => {
    assert.equal(originOf('https://example.com/path'), 'https://example.com:443');
  });

  it('extracts origin with default HTTP port', () => {
    assert.equal(originOf('http://example.com/path'), 'http://example.com:80');
  });

  it('extracts origin with custom port', () => {
    assert.equal(originOf('https://example.com:8443/path'), 'https://example.com:8443');
  });

  it('normalizes hostname to lowercase', () => {
    assert.equal(originOf('https://EXAMPLE.COM/path'), 'https://example.com:443');
  });
});

describe('hostPort', () => {
  it('extracts host and port from HTTPS URL', () => {
    const result = hostPort('https://example.com/api');
    assert.equal(result.host, 'example.com');
    assert.equal(result.port, 443);
  });

  it('extracts host and port from HTTP URL', () => {
    const result = hostPort('http://example.com/api');
    assert.equal(result.host, 'example.com');
    assert.equal(result.port, 80);
  });

  it('uses custom port when specified', () => {
    const result = hostPort('https://example.com:9000/api');
    assert.equal(result.host, 'example.com');
    assert.equal(result.port, 9000);
  });
});
