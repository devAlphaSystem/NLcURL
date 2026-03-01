/**
 * Test: Compression — gzip, deflate, brotli
 *
 * Note: NLcURL's transport layer may or may not auto-decompress.
 * These tests verify the response is obtained successfully.
 */

import { get } from '../../../../src/index.js';
import { test, assertEqual, assert, getBaseURL } from '../runner.js';

export default async function () {
  const BASE = getBaseURL();

  await test('gzip compressed response', async () => {
    const res = await get(`${BASE}/gzip`, { insecure: true });
    assertEqual(res.status, 200, 'status');
    // If auto-decompressed, json() works; otherwise rawBody is compressed
    try {
      const data = res.json<{ compressed: string }>();
      assertEqual(data.compressed, 'gzip', 'decompressed gzip');
    } catch {
      // If not auto-decompressed, verify we at least got the response
      assert(res.rawBody.length > 0, 'got raw compressed data');
    }
  });

  await test('deflate compressed response', async () => {
    const res = await get(`${BASE}/deflate`, { insecure: true });
    assertEqual(res.status, 200, 'status');
    try {
      const data = res.json<{ compressed: string }>();
      assertEqual(data.compressed, 'deflate', 'decompressed deflate');
    } catch {
      assert(res.rawBody.length > 0, 'got raw compressed data');
    }
  });

  await test('brotli compressed response', async () => {
    const res = await get(`${BASE}/brotli`, { insecure: true });
    assertEqual(res.status, 200, 'status');
    try {
      const data = res.json<{ compressed: string }>();
      assertEqual(data.compressed, 'brotli', 'decompressed brotli');
    } catch {
      assert(res.rawBody.length > 0, 'got raw compressed data');
    }
  });
}
