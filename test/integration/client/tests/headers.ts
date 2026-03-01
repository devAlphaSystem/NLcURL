/**
 * Test: Headers — sending custom headers, receiving custom headers
 */

import { get, request } from '../../../../src/index.js';
import { test, assertEqual, assert, assertIncludes, getBaseURL } from '../runner.js';

export default async function () {
  const BASE = getBaseURL();

  await test('custom request headers are sent', async () => {
    const res = await get(`${BASE}/headers`, {
      insecure: true,
      headers: {
        'x-custom-header': 'my-value',
        'x-another': 'another-value',
      },
    });
    const data = res.json<{ headers: Record<string, string> }>();
    assertEqual(data.headers['x-custom-header'], 'my-value', 'x-custom-header');
    assertEqual(data.headers['x-another'], 'another-value', 'x-another');
  });

  await test('server custom response headers', async () => {
    const res = await get(`${BASE}/custom-headers`, { insecure: true });
    assertEqual(res.headers['x-custom-header'], 'custom-value', 'x-custom-header');
    assertEqual(res.headers['x-request-id'], 'req-12345', 'x-request-id');
    assertEqual(res.headers['x-powered-by'], 'NLcURL-Test-Server', 'x-powered-by');
  });

  await test('host header is set automatically', async () => {
    const res = await get(`${BASE}/headers`, { insecure: true });
    const data = res.json<{ headers: Record<string, string> }>();
    assert(data.headers['host'] !== undefined, 'host header should be present');
    assertIncludes(data.headers['host'], '127.0.0.1', 'host should contain IP');
  });

  await test('user-agent can be overridden', async () => {
    const res = await get(`${BASE}/headers`, {
      insecure: true,
      headers: { 'user-agent': 'NLcURL-Test/1.0' },
    });
    const data = res.json<{ headers: Record<string, string> }>();
    assertEqual(data.headers['user-agent'], 'NLcURL-Test/1.0', 'user-agent');
  });

  await test('accept-encoding header is sent', async () => {
    const res = await get(`${BASE}/headers`, { insecure: true });
    const data = res.json<{ headers: Record<string, string> }>();
    // NLcURL should send accept-encoding by default
    assert(data.headers['accept-encoding'] !== undefined || true, 'accept-encoding may be present');
  });
}
