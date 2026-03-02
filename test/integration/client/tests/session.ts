
import { createSession, NLcURLSession } from '../../../../src/index.js';
import { test, assertEqual, assert, getBaseURL } from '../runner.js';

export default async function () {
  const BASE = getBaseURL();

  await test('session with baseURL', async () => {
    const session = createSession({ baseURL: BASE, insecure: true });
    try {
      const res = await session.get('/json');
      assertEqual(res.status, 200, 'status');
      const data = res.json<{ message: string }>();
      assertEqual(data.message, 'hello', 'message');
    } finally {
      session.close();
    }
  });

  await test('session with default headers', async () => {
    const session = createSession({
      baseURL: BASE,
      insecure: true,
      headers: {
        'x-api-key': 'secret-key-123',
        'x-client': 'nlcurl-test',
      },
    });
    try {
      const res = await session.get('/headers');
      const data = res.json<{ headers: Record<string, string> }>();
      assertEqual(data.headers['x-api-key'], 'secret-key-123', 'x-api-key');
      assertEqual(data.headers['x-client'], 'nlcurl-test', 'x-client');
    } finally {
      session.close();
    }
  });

  await test('per-request headers override session defaults', async () => {
    const session = createSession({
      baseURL: BASE,
      insecure: true,
      headers: { 'x-api-key': 'default-key' },
    });
    try {
      const res = await session.get('/headers', {
        headers: { 'x-api-key': 'override-key' },
      });
      const data = res.json<{ headers: Record<string, string> }>();
      assertEqual(data.headers['x-api-key'], 'override-key', 'overridden header');
    } finally {
      session.close();
    }
  });

  await test('session makes multiple requests', async () => {
    const session = createSession({ baseURL: BASE, insecure: true });
    try {
      const r1 = await session.get('/json');
      assertEqual(r1.status, 200, 'first request');

      const r2 = await session.get('/text');
      assertEqual(r2.status, 200, 'second request');
      assertEqual(r2.text(), 'Hello, NLcURL!', 'second text');

      const r3 = await session.get('/status/201');
      assertEqual(r3.status, 201, 'third request');
    } finally {
      session.close();
    }
  });

  await test('closed session throws', async () => {
    const session = createSession({ baseURL: BASE, insecure: true });
    session.close();
    try {
      await session.get('/json');
      throw new Error('Should have thrown');
    } catch (err: any) {
      assert(
        err.message.includes('closed') || err.code === 'ERR_SESSION_CLOSED',
        `Expected closed error, got: ${err.message}`,
      );
    }
  });

  await test('NLcURLSession class direct construction', async () => {
    const session = new NLcURLSession({ insecure: true });
    try {
      const res = await session.get(`${BASE}/json`);
      assertEqual(res.status, 200, 'status');
    } finally {
      session.close();
    }
  });
}
