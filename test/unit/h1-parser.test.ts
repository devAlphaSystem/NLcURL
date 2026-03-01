/**
 * Tests for the HTTP/1.1 response parser.
 */

import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { HttpResponseParser } from '../../src/http/h1/parser.js';

describe('HttpResponseParser', () => {
  it('parses a simple 200 OK response', () => {
    const parser = new HttpResponseParser();
    const raw = Buffer.from(
      'HTTP/1.1 200 OK\r\n' +
      'Content-Type: text/plain\r\n' +
      'Content-Length: 5\r\n' +
      '\r\n' +
      'hello',
      'latin1',
    );

    const done = parser.feed(raw);
    assert.ok(done);

    const result = parser.getResult();
    assert.equal(result.statusCode, 200);
    assert.equal(result.statusMessage, 'OK');
    assert.equal(result.httpVersion, 'HTTP/1.1');
    assert.equal(result.headers.get('content-type'), 'text/plain');
    assert.equal(result.body.toString(), 'hello');
  });

  it('parses response fed in chunks', () => {
    const parser = new HttpResponseParser();
    const lines = [
      'HTTP/1.1 200 OK\r\n',
      'Content-Length: 3\r\n',
      '\r\n',
      'abc',
    ];

    let done = false;
    for (const line of lines) {
      done = parser.feed(Buffer.from(line, 'latin1'));
      if (done) break;
    }

    assert.ok(done);
    const result = parser.getResult();
    assert.equal(result.statusCode, 200);
    assert.equal(result.body.toString(), 'abc');
  });

  it('parses chunked transfer encoding', () => {
    const parser = new HttpResponseParser();
    const raw = Buffer.from(
      'HTTP/1.1 200 OK\r\n' +
      'Transfer-Encoding: chunked\r\n' +
      '\r\n' +
      '5\r\n' +
      'Hello\r\n' +
      '6\r\n' +
      ' World\r\n' +
      '0\r\n' +
      '\r\n',
      'latin1',
    );

    const done = parser.feed(raw);
    assert.ok(done);

    const result = parser.getResult();
    assert.equal(result.body.toString(), 'Hello World');
  });

  it('handles 204 No Content (no body)', () => {
    const parser = new HttpResponseParser();
    const raw = Buffer.from(
      'HTTP/1.1 204 No Content\r\n' +
      '\r\n',
      'latin1',
    );

    const done = parser.feed(raw);
    assert.ok(done);

    const result = parser.getResult();
    assert.equal(result.statusCode, 204);
    assert.equal(result.body.length, 0);
  });

  it('handles 304 Not Modified (no body)', () => {
    const parser = new HttpResponseParser();
    const raw = Buffer.from(
      'HTTP/1.1 304 Not Modified\r\n' +
      'ETag: "abc"\r\n' +
      '\r\n',
      'latin1',
    );

    const done = parser.feed(raw);
    assert.ok(done);

    const result = parser.getResult();
    assert.equal(result.statusCode, 304);
    assert.equal(result.body.length, 0);
  });

  it('preserves multiple headers as comma-separated', () => {
    const parser = new HttpResponseParser();
    const raw = Buffer.from(
      'HTTP/1.1 200 OK\r\n' +
      'Content-Length: 0\r\n' +
      'X-Custom: value1\r\n' +
      'X-Custom: value2\r\n' +
      '\r\n',
      'latin1',
    );

    const done = parser.feed(raw);
    assert.ok(done);

    const result = parser.getResult();
    assert.equal(result.headers.get('x-custom'), 'value1, value2');
  });

  it('preserves raw headers with order and case', () => {
    const parser = new HttpResponseParser();
    const raw = Buffer.from(
      'HTTP/1.1 200 OK\r\n' +
      'Content-Length: 0\r\n' +
      'Set-Cookie: a=1\r\n' +
      'Set-Cookie: b=2\r\n' +
      '\r\n',
      'latin1',
    );

    const done = parser.feed(raw);
    assert.ok(done);

    const result = parser.getResult();
    // Raw headers should preserve duplicates
    const setCookieHeaders = result.rawHeaders.filter(
      ([k]) => k.toLowerCase() === 'set-cookie',
    );
    assert.equal(setCookieHeaders.length, 2);
    assert.equal(setCookieHeaders[0]![1], 'a=1');
    assert.equal(setCookieHeaders[1]![1], 'b=2');
  });

  it('throws on invalid status line', () => {
    const parser = new HttpResponseParser();
    assert.throws(() => {
      parser.feed(Buffer.from('INVALID STATUS LINE\r\n\r\n'));
    });
  });

  it('throws on invalid chunk size', () => {
    const parser = new HttpResponseParser();
    assert.throws(() => {
      parser.feed(Buffer.from(
        'HTTP/1.1 200 OK\r\n' +
        'Transfer-Encoding: chunked\r\n' +
        '\r\n' +
        'ZZZZZ\r\n' +
        '\r\n',
        'latin1',
      ));
    });
  });

  it('returns remainder after complete parse', () => {
    const parser = new HttpResponseParser();
    const raw = Buffer.from(
      'HTTP/1.1 200 OK\r\n' +
      'Content-Length: 2\r\n' +
      '\r\n' +
      'okEXTRA',
      'latin1',
    );

    const done = parser.feed(raw);
    assert.ok(done);

    const result = parser.getResult();
    assert.equal(result.body.toString(), 'ok');

    const remainder = parser.getRemainder();
    assert.equal(remainder.toString(), 'EXTRA');
  });

  it('handles Content-Length: 0', () => {
    const parser = new HttpResponseParser();
    const raw = Buffer.from(
      'HTTP/1.1 200 OK\r\n' +
      'Content-Length: 0\r\n' +
      '\r\n',
      'latin1',
    );

    const done = parser.feed(raw);
    assert.ok(done);

    const result = parser.getResult();
    assert.equal(result.statusCode, 200);
    assert.equal(result.body.length, 0);
  });
});
