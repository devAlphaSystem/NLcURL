/**
 * Unit tests for the cookie parser and jar.
 */

import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { parseSetCookie, serializeCookies } from '../../src/cookies/parser.js';
import { CookieJar } from '../../src/cookies/jar.js';

describe('parseSetCookie', () => {
  const baseUrl = new URL('https://example.com/api/data');

  it('parses a simple name=value cookie', () => {
    const cookie = parseSetCookie('session=abc123', baseUrl);
    assert.ok(cookie);
    assert.equal(cookie.name, 'session');
    assert.equal(cookie.value, 'abc123');
    assert.equal(cookie.domain, 'example.com');
    assert.equal(cookie.path, '/api');
  });

  it('parses cookie with attributes', () => {
    const cookie = parseSetCookie(
      'id=42; Domain=example.com; Path=/; Secure; HttpOnly; SameSite=Strict',
      baseUrl,
    );
    assert.ok(cookie);
    assert.equal(cookie.name, 'id');
    assert.equal(cookie.value, '42');
    assert.equal(cookie.domain, 'example.com');
    assert.equal(cookie.path, '/');
    assert.equal(cookie.secure, true);
    assert.equal(cookie.httpOnly, true);
    assert.equal(cookie.sameSite, 'strict');
  });

  it('parses Max-Age', () => {
    const cookie = parseSetCookie('token=xyz; Max-Age=3600', baseUrl);
    assert.ok(cookie);
    assert.equal(cookie.maxAge, 3600);
  });

  it('parses Expires', () => {
    const cookie = parseSetCookie(
      'token=xyz; Expires=Thu, 01 Jan 2099 00:00:00 GMT',
      baseUrl,
    );
    assert.ok(cookie);
    assert.ok(cookie.expires instanceof Date);
    assert.ok(cookie.expires.getTime() > Date.now());
  });

  it('strips leading dot from domain', () => {
    const cookie = parseSetCookie('id=1; Domain=.example.com', baseUrl);
    assert.ok(cookie);
    assert.equal(cookie.domain, 'example.com');
  });

  it('returns null for empty header', () => {
    assert.equal(parseSetCookie('', baseUrl), null);
  });

  it('returns null for missing name', () => {
    assert.equal(parseSetCookie('=value', baseUrl), null);
  });

  it('defaults path from request URL', () => {
    const url = new URL('https://example.com/a/b/c');
    const cookie = parseSetCookie('x=1', url);
    assert.ok(cookie);
    assert.equal(cookie.path, '/a/b');
  });
});

describe('serializeCookies', () => {
  it('serializes cookies into Cookie header format', () => {
    const result = serializeCookies([
      { name: 'a', value: '1', domain: '', path: '', secure: false, httpOnly: false, createdAt: 0 },
      { name: 'b', value: '2', domain: '', path: '', secure: false, httpOnly: false, createdAt: 0 },
    ]);
    assert.equal(result, 'a=1; b=2');
  });

  it('handles single cookie', () => {
    const result = serializeCookies([
      { name: 'x', value: 'y', domain: '', path: '', secure: false, httpOnly: false, createdAt: 0 },
    ]);
    assert.equal(result, 'x=y');
  });
});

describe('CookieJar', () => {
  it('stores and retrieves cookies', () => {
    const jar = new CookieJar();
    jar.setCookies(
      { 'set-cookie': 'session=abc; Path=/' },
      new URL('https://example.com'),
    );

    const header = jar.getCookieHeader(new URL('https://example.com/page'));
    assert.ok(header.includes('session=abc'));
  });

  it('matches domain correctly', () => {
    const jar = new CookieJar();
    jar.setCookies(
      { 'set-cookie': 'id=1; Domain=example.com; Path=/' },
      new URL('https://example.com'),
    );

    // Should match subdomain
    const header = jar.getCookieHeader(new URL('https://sub.example.com/'));
    assert.ok(header.includes('id=1'));

    // Should not match different domain
    const other = jar.getCookieHeader(new URL('https://other.com/'));
    assert.equal(other, '');
  });

  it('matches path correctly', () => {
    const jar = new CookieJar();
    jar.setCookies(
      { 'set-cookie': 'x=1; Path=/api' },
      new URL('https://example.com/api/test'),
    );

    assert.ok(jar.getCookieHeader(new URL('https://example.com/api/data')).includes('x=1'));
    assert.equal(jar.getCookieHeader(new URL('https://example.com/other')), '');
  });

  it('respects Secure flag', () => {
    const jar = new CookieJar();
    jar.setCookies(
      { 'set-cookie': 'secure=yes; Secure; Path=/' },
      new URL('https://example.com'),
    );

    // HTTPS should match
    assert.ok(jar.getCookieHeader(new URL('https://example.com/')).includes('secure=yes'));

    // HTTP should not match (secure cookie)
    assert.equal(jar.getCookieHeader(new URL('http://example.com/')), '');
  });

  it('clear() removes all cookies', () => {
    const jar = new CookieJar();
    jar.setCookies(
      { 'set-cookie': 'a=1; Path=/' },
      new URL('https://example.com'),
    );
    assert.ok(jar.getCookieHeader(new URL('https://example.com/')));
    jar.clear();
    assert.equal(jar.getCookieHeader(new URL('https://example.com/')), '');
  });

  it('clearDomain() removes cookies for specific domain', () => {
    const jar = new CookieJar();
    jar.setCookies(
      { 'set-cookie': 'a=1; Path=/' },
      new URL('https://example.com'),
    );
    jar.setCookies(
      { 'set-cookie': 'b=2; Path=/' },
      new URL('https://other.com'),
    );

    jar.clearDomain('example.com');
    assert.equal(jar.getCookieHeader(new URL('https://example.com/')), '');
    assert.ok(jar.getCookieHeader(new URL('https://other.com/')).includes('b=2'));
  });

  it('overwrites cookie with same name/domain/path', () => {
    const jar = new CookieJar();
    const url = new URL('https://example.com');
    jar.setCookies({ 'set-cookie': 'x=old; Path=/' }, url);
    jar.setCookies({ 'set-cookie': 'x=new; Path=/' }, url);

    const header = jar.getCookieHeader(new URL('https://example.com/'));
    assert.ok(header.includes('x=new'));
    assert.ok(!header.includes('x=old'));
  });
});
