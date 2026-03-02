
import { get } from '../../../../src/index.js';
import { test, assertEqual, assert, getBaseURL } from '../runner.js';

export default async function () {
  const BASE = getBaseURL();

  await test('200 OK', async () => {
    const res = await get(`${BASE}/status/200`, { insecure: true });
    assertEqual(res.status, 200, 'status');
    assert(res.ok, 'ok should be true');
  });

  await test('201 Created', async () => {
    const res = await get(`${BASE}/status/201`, { insecure: true });
    assertEqual(res.status, 201, 'status');
    assert(res.ok, 'ok should be true for 201');
  });

  await test('204 No Content', async () => {
    const res = await get(`${BASE}/no-content`, { insecure: true });
    assertEqual(res.status, 204, 'status');
    assertEqual(res.rawBody.length, 0, 'no body');
  });

  await test('400 Bad Request', async () => {
    const res = await get(`${BASE}/status/400`, { insecure: true });
    assertEqual(res.status, 400, 'status');
    assert(!res.ok, 'ok should be false');
  });

  await test('401 Unauthorized', async () => {
    const res = await get(`${BASE}/status/401`, { insecure: true });
    assertEqual(res.status, 401, 'status');
    assert(!res.ok, 'ok should be false');
  });

  await test('403 Forbidden', async () => {
    const res = await get(`${BASE}/status/403`, { insecure: true });
    assertEqual(res.status, 403, 'status');
  });

  await test('404 Not Found', async () => {
    const res = await get(`${BASE}/status/404`, { insecure: true });
    assertEqual(res.status, 404, 'status');
  });

  await test('500 Internal Server Error', async () => {
    const res = await get(`${BASE}/status/500`, { insecure: true });
    assertEqual(res.status, 500, 'status');
    assert(!res.ok, 'ok should be false for 500');
  });
}
