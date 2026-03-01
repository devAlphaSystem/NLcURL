/**
 * Test: Large Payloads & Chunked Transfer Encoding
 */

import { get } from '../../../../src/index.js';
import { test, assertEqual, assert, getBaseURL } from '../runner.js';

export default async function () {
  const BASE = getBaseURL();

  await test('large response (100KB)', async () => {
    const res = await get(`${BASE}/large`, { insecure: true });
    assertEqual(res.status, 200, 'status');
    assertEqual(res.rawBody.length, 100_000, 'body size');
    // Verify content is all 'A' (0x41)
    for (let i = 0; i < 100; i++) {
      assertEqual(res.rawBody[i], 0x41, `byte ${i} should be 0x41`);
    }
  });

  await test('chunked transfer encoding response', async () => {
    const res = await get(`${BASE}/chunked`, { insecure: true });
    assertEqual(res.status, 200, 'status');
    const text = res.text();
    assertEqual(text, 'Hello, chunked world!', 'assembled chunks');
  });
}
