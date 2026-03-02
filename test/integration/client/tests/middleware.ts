
import { createSession } from '../../../../src/index.js';
import { test, assertEqual, assert, getBaseURL } from '../runner.js';

export default async function () {
  const BASE = getBaseURL();

  await test('request interceptor adds headers', async () => {
    const session = createSession({ baseURL: BASE, insecure: true });
    session.onRequest((req) => {
      return {
        ...req,
        headers: {
          ...req.headers,
          'x-intercepted': 'yes',
          'x-timestamp': '1234567890',
        },
      };
    });
    try {
      const res = await session.get('/headers');
      const data = res.json<{ headers: Record<string, string> }>();
      assertEqual(data.headers['x-intercepted'], 'yes', 'interceptor header');
      assertEqual(data.headers['x-timestamp'], '1234567890', 'timestamp header');
    } finally {
      session.close();
    }
  });

  await test('response interceptor modifies response', async () => {
    const session = createSession({ baseURL: BASE, insecure: true });
    let interceptedUrl = '';
    session.onResponse((res) => {
      interceptedUrl = res.url;
      return res;
    });
    try {
      await session.get('/json');
      assert(interceptedUrl.includes('/json'), `interceptor saw URL: ${interceptedUrl}`);
    } finally {
      session.close();
    }
  });

  await test('multiple request interceptors chain', async () => {
    const session = createSession({ baseURL: BASE, insecure: true });
    const order: number[] = [];

    session.onRequest((req) => {
      order.push(1);
      return { ...req, headers: { ...req.headers, 'x-first': 'true' } };
    });
    session.onRequest((req) => {
      order.push(2);
      return { ...req, headers: { ...req.headers, 'x-second': 'true' } };
    });

    try {
      const res = await session.get('/headers');
      const data = res.json<{ headers: Record<string, string> }>();
      assertEqual(data.headers['x-first'], 'true', 'first interceptor');
      assertEqual(data.headers['x-second'], 'true', 'second interceptor');
      assertEqual(order[0], 1, 'first ran first');
      assertEqual(order[1], 2, 'second ran second');
    } finally {
      session.close();
    }
  });

  await test('rate limiter restricts request rate', async () => {
    const session = createSession({ baseURL: BASE, insecure: true });
    session.setRateLimit({ maxRequests: 2, windowMs: 300 });
    try {
      const start = Date.now();

      await session.get('/json');
      await session.get('/json');

      await session.get('/json');
      const elapsed = Date.now() - start;

      assert(elapsed >= 150, `rate limiter should delay, elapsed=${elapsed}ms`);
    } finally {
      session.close();
    }
  });
}
