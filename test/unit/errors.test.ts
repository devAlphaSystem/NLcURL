/**
 * Unit tests for the error hierarchy.
 */

import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import {
  NLcURLError,
  TLSError,
  HTTPError,
  TimeoutError,
  ProxyError,
  AbortError,
  ConnectionError,
  ProtocolError,
} from '../../src/core/errors.js';

describe('NLcURLError', () => {
  it('has correct name and code', () => {
    const err = new NLcURLError('test', 'ERR_TEST');
    assert.equal(err.name, 'NLcURLError');
    assert.equal(err.code, 'ERR_TEST');
    assert.equal(err.message, 'test');
    assert.ok(err instanceof Error);
    assert.ok(err instanceof NLcURLError);
  });
});

describe('TLSError', () => {
  it('without alertCode', () => {
    const err = new TLSError('handshake failed');
    assert.equal(err.name, 'TLSError');
    assert.equal(err.code, 'ERR_TLS');
    assert.equal(err.alertCode, undefined);
    assert.ok(err instanceof NLcURLError);
  });

  it('with alertCode', () => {
    const err = new TLSError('alert received', 48);
    assert.equal(err.alertCode, 48);
    assert.equal(err.code, 'ERR_TLS');
  });
});

describe('HTTPError', () => {
  it('has statusCode', () => {
    const err = new HTTPError('Not Found', 404);
    assert.equal(err.statusCode, 404);
    assert.equal(err.code, 'ERR_HTTP');
    assert.ok(err instanceof NLcURLError);
  });
});

describe('TimeoutError', () => {
  it('has phase', () => {
    const err = new TimeoutError('connect timed out', 'connect');
    assert.equal(err.phase, 'connect');
    assert.equal(err.code, 'ERR_TIMEOUT');
  });

  for (const phase of ['connect', 'tls', 'response', 'total'] as const) {
    it(`accepts phase: ${phase}`, () => {
      const err = new TimeoutError(`${phase} timeout`, phase);
      assert.equal(err.phase, phase);
    });
  }
});

describe('ProxyError', () => {
  it('creates correctly', () => {
    const err = new ProxyError('proxy refused');
    assert.equal(err.code, 'ERR_PROXY');
    assert.ok(err instanceof NLcURLError);
  });
});

describe('AbortError', () => {
  it('creates with default message', () => {
    const err = new AbortError();
    assert.equal(err.message, 'Request aborted');
    assert.equal(err.code, 'ERR_ABORTED');
  });

  it('creates with custom message', () => {
    const err = new AbortError('user cancelled');
    assert.equal(err.message, 'user cancelled');
  });
});

describe('ConnectionError', () => {
  it('creates correctly', () => {
    const err = new ConnectionError('ECONNREFUSED');
    assert.equal(err.code, 'ERR_CONNECTION');
    assert.ok(err instanceof NLcURLError);
  });
});

describe('ProtocolError', () => {
  it('creates correctly', () => {
    const err = new ProtocolError('invalid frame');
    assert.equal(err.code, 'ERR_PROTOCOL');
    assert.ok(err instanceof NLcURLError);
  });
});

describe('instanceof chain', () => {
  it('all errors extend NLcURLError and Error', () => {
    const errors = [
      new TLSError('tls'),
      new HTTPError('http', 500),
      new TimeoutError('timeout', 'total'),
      new ProxyError('proxy'),
      new AbortError(),
      new ConnectionError('conn'),
      new ProtocolError('proto'),
    ];

    for (const err of errors) {
      assert.ok(err instanceof Error, `${err.name} should be instanceof Error`);
      assert.ok(err instanceof NLcURLError, `${err.name} should be instanceof NLcURLError`);
    }
  });
});
