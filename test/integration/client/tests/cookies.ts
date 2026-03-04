import { createSession } from "../../../../src/index.js";
import { test, assertEqual, assert, getBaseURL } from "../runner.js";

export default async function () {
  const BASE = getBaseURL();

  await test("server sets multiple cookies via Set-Cookie", async () => {
    const session = createSession({ insecure: true });
    try {
      const res = await session.get(`${BASE}/cookies/multi`);
      assertEqual(res.status, 200, "status");
      const jar = session.getCookies()!;
      assert(jar !== null, "cookie jar should exist");
      assert(jar.size >= 3, `should have at least 3 cookies, got ${jar.size}`);

      const all = jar.all();
      const names = all.map((c) => c.name);
      assert(names.includes("session"), "should have session cookie");
      assert(names.includes("theme"), "should have theme cookie");
      assert(names.includes("lang"), "should have lang cookie");
    } finally {
      session.close();
    }
  });

  await test("cookies are sent back on subsequent requests", async () => {
    const session = createSession({ insecure: true });
    try {
      await session.get(`${BASE}/cookies/multi`);

      const res = await session.get(`${BASE}/cookies/get`);
      const data = res.json<{ cookies: Record<string, string> }>();
      assertEqual(data.cookies["session"], "abc123", "session cookie");
      assertEqual(data.cookies["theme"], "dark", "theme cookie");
      assertEqual(data.cookies["lang"], "en", "lang cookie");
    } finally {
      session.close();
    }
  });

  await test("cookies persist across multiple requests", async () => {
    const session = createSession({ insecure: true });
    try {
      await session.get(`${BASE}/cookies/multi`);
      await session.get(`${BASE}/json`);

      const res = await session.get(`${BASE}/cookies/get`);
      const data = res.json<{ cookies: Record<string, string> }>();
      assertEqual(data.cookies["session"], "abc123", "session cookie still present");
    } finally {
      session.close();
    }
  });

  await test("cookies set via setmulti endpoint with query params", async () => {
    const session = createSession({ insecure: true });
    try {
      await session.get(`${BASE}/cookies/setmulti?token=xyz789&user=alice`);

      const res = await session.get(`${BASE}/cookies/get`);
      const data = res.json<{ cookies: Record<string, string> }>();
      assertEqual(data.cookies["token"], "xyz789", "token cookie");
      assertEqual(data.cookies["user"], "alice", "user cookie");
    } finally {
      session.close();
    }
  });

  await test("cookie jar can be cleared", async () => {
    const session = createSession({ insecure: true });
    try {
      await session.get(`${BASE}/cookies/multi`);
      const jar = session.getCookies()!;
      assert(jar.size > 0, "cookies should be set");

      jar.clear();
      assertEqual(jar.size, 0, "jar should be empty after clear");

      const res = await session.get(`${BASE}/cookies/get`);
      const data = res.json<{ cookies: Record<string, string> }>();
      assertEqual(Object.keys(data.cookies).length, 0, "no cookies sent");
    } finally {
      session.close();
    }
  });

  await test("session with cookieJar: false does not store cookies", async () => {
    const session = createSession({ insecure: true, cookieJar: false });
    try {
      await session.get(`${BASE}/cookies/multi`);
      assertEqual(session.getCookies(), null, "no cookie jar");
    } finally {
      session.close();
    }
  });
}
