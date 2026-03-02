
import { get, request } from '../../../../src/index.js';
import { test, assertEqual, assert, getBaseURL } from '../runner.js';

export default async function () {
  const BASE = getBaseURL();

  await test('404 returns response (not error)', async () => {
    const res = await get(`${BASE}/nonexistent-path`, { insecure: true });
    assertEqual(res.status, 404, 'status');
    assert(!res.ok, 'ok should be false');
  });

  await test('connection refused error', async () => {
    try {
      await get('https://127.0.0.1:1/test', { insecure: true, timeout: 3000 });
      throw new Error('Should have thrown');
    } catch (err: any) {
      assert(
        err.message.includes('ECONNREFUSED') ||
          err.message.includes('connect') ||
          err.message.includes('timed out') ||
          err.code === 'ERR_CONNECTION',
        `Expected connection error, got: ${err.message}`,
      );
    }
  });

  await test('unknown profile throws', async () => {
    try {
      await get(`${BASE}/json`, {
        insecure: true,
        impersonate: 'nonexistent-browser-9999',
      });
      throw new Error('Should have thrown');
    } catch (err: any) {
      assert(
        err.message.includes('Unknown browser profile') ||
          err.code === 'ERR_UNKNOWN_PROFILE',
        `Expected profile error, got: ${err.message}`,
      );
    }
  });

  await test('5xx response returns response (not thrown)', async () => {
    const res = await get(`${BASE}/status/500`, { insecure: true });
    assertEqual(res.status, 500, 'status');
    assert(!res.ok, 'ok should be false');
  });
}
