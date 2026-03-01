/**
 * Test: Timeouts and AbortController
 */

import { get, request } from '../../../../src/index.js';
import { test, assertEqual, assert, getBaseURL } from '../runner.js';

export default async function () {
  const BASE = getBaseURL();

  await test('request with total timeout succeeds for fast response', async () => {
    const res = await get(`${BASE}/json`, {
      insecure: true,
      timeout: 5000,
    });
    assertEqual(res.status, 200, 'status');
  });

  await test('request with timeout aborts slow response', async () => {
    try {
      await get(`${BASE}/slow?ms=5000`, {
        insecure: true,
        timeout: 500,
      });
      throw new Error('Should have timed out');
    } catch (err: any) {
      assert(
        err.message.includes('timed out') ||
          err.message.includes('timeout') ||
          err.code === 'ERR_TIMEOUT' ||
          err.name === 'TimeoutError',
        `Expected timeout error, got: ${err.message} (${err.code})`,
      );
    }
  });

  await test('AbortController cancels request', async () => {
    const controller = new AbortController();

    // Abort after 200ms
    setTimeout(() => controller.abort(), 200);

    try {
      await get(`${BASE}/slow?ms=5000`, {
        insecure: true,
        signal: controller.signal,
      });
      throw new Error('Should have been aborted');
    } catch (err: any) {
      assert(
        err.message.includes('abort') ||
          err.name === 'AbortError' ||
          err.code === 'ERR_ABORTED',
        `Expected abort error, got: ${err.message}`,
      );
    }
  });

  await test('pre-aborted signal throws immediately', async () => {
    const controller = new AbortController();
    controller.abort();

    try {
      await get(`${BASE}/json`, {
        insecure: true,
        signal: controller.signal,
      });
      throw new Error('Should have thrown');
    } catch (err: any) {
      assert(
        err.message.includes('abort') || err.name === 'AbortError',
        `Expected abort error, got: ${err.message}`,
      );
    }
  });
}
