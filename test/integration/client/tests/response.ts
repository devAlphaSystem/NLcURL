/**
 * Test: Response Properties — status, statusText, headers, url, redirectCount,
 *       rawBody, text(), json(), ok, contentType, contentLength, rawHeaders
 */

import { get, request } from '../../../../src/index.js';
import { test, assertEqual, assert, getBaseURL } from '../runner.js';

export default async function () {
  const BASE = getBaseURL();

  await test('response has status and ok', async () => {
    const res = await get(`${BASE}/json`, { insecure: true });
    assertEqual(res.status, 200, 'status');
    assert(res.ok, 'ok is true');
  });

  await test('response has correct url after redirect', async () => {
    const res = await get(`${BASE}/redirect/302`, { insecure: true });
    assert(res.url.includes('/redirect/target'), `url should be target, got ${res.url}`);
    assert(res.redirectCount >= 1, 'redirect count >= 1');
  });

  await test('response text() returns string', async () => {
    const res = await get(`${BASE}/text`, { insecure: true });
    const text = res.text();
    assertEqual(typeof text, 'string', 'text is string');
    assertEqual(text, 'Hello, NLcURL!', 'text content');
  });

  await test('response json() parses JSON', async () => {
    const res = await get(`${BASE}/json`, { insecure: true });
    const data = res.json<{ message: string; items: number[] }>();
    assertEqual(data.message, 'hello', 'json message');
    assertEqual(data.items.length, 3, 'json items length');
  });

  await test('response rawBody is a Buffer', async () => {
    const res = await get(`${BASE}/text`, { insecure: true });
    assert(Buffer.isBuffer(res.rawBody), 'rawBody is Buffer');
    assert(res.rawBody.length > 0, 'rawBody not empty');
  });

  await test('response has content-type header', async () => {
    const res = await get(`${BASE}/json`, { insecure: true });
    assert(res.contentType.includes('application/json'), `content-type: ${res.contentType}`);
  });

  await test('response contentLength matches body', async () => {
    const res = await get(`${BASE}/text`, { insecure: true });
    assertEqual(res.contentLength, res.rawBody.length, 'contentLength matches rawBody');
  });

  await test('response has rawHeaders array', async () => {
    const res = await get(`${BASE}/custom-headers`, { insecure: true });
    assert(Array.isArray(res.rawHeaders), 'rawHeaders is array');
    assert(res.rawHeaders.length > 0, 'rawHeaders not empty');
    // Each entry should be [key, value]
    for (const [k, v] of res.rawHeaders) {
      assertEqual(typeof k, 'string', 'rawHeader key is string');
      assertEqual(typeof v, 'string', 'rawHeader value is string');
    }
  });

  await test('response timings are present', async () => {
    const res = await get(`${BASE}/json`, { insecure: true });
    assert(res.timings !== undefined, 'timings exist');
    assert(typeof res.timings.total === 'number', 'total timing is a number');
    assert(res.timings.total >= 0, 'total timing >= 0');
  });

  await test('response httpVersion is present', async () => {
    const res = await get(`${BASE}/json`, { insecure: true });
    assert(typeof res.httpVersion === 'string', 'httpVersion is string');
    assert(res.httpVersion.length > 0, 'httpVersion not empty');
  });

  await test('json() on non-JSON throws', async () => {
    const res = await get(`${BASE}/text`, { insecure: true });
    try {
      res.json();
      throw new Error('Should have thrown');
    } catch (err: any) {
      assert(err instanceof SyntaxError || err.message.includes('JSON'), 'should be JSON parse error');
    }
  });
}
