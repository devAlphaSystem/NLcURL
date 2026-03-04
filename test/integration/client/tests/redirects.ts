import { get, post, request, createSession } from "../../../../src/index.js";
import { test, assertEqual, assert, getBaseURL } from "../runner.js";

export default async function () {
  const BASE = getBaseURL();

  await test("follows 301 redirect", async () => {
    const res = await get(`${BASE}/redirect/301`, { insecure: true });
    assertEqual(res.status, 200, "status after redirect");
    const data = res.json<{ redirected: boolean }>();
    assertEqual(data.redirected, true, "reached target");
    assert(res.redirectCount >= 1, "redirect count >= 1");
  });

  await test("follows 302 redirect", async () => {
    const res = await get(`${BASE}/redirect/302`, { insecure: true });
    assertEqual(res.status, 200, "status after redirect");
    const data = res.json<{ redirected: boolean }>();
    assertEqual(data.redirected, true, "reached target");
  });

  await test("follows 303 redirect", async () => {
    const res = await get(`${BASE}/redirect/303`, { insecure: true });
    assertEqual(res.status, 200, "status");
    const data = res.json<{ redirected: boolean }>();
    assertEqual(data.redirected, true, "reached target");
  });

  await test("follows 307 redirect", async () => {
    const res = await get(`${BASE}/redirect/307`, { insecure: true });
    assertEqual(res.status, 200, "status");
    const data = res.json<{ redirected: boolean }>();
    assertEqual(data.redirected, true, "reached target");
  });

  await test("follows 308 redirect", async () => {
    const res = await get(`${BASE}/redirect/308`, { insecure: true });
    assertEqual(res.status, 200, "status");
    const data = res.json<{ redirected: boolean }>();
    assertEqual(data.redirected, true, "reached target");
  });

  await test("303 changes POST to GET", async () => {
    const res = await post(`${BASE}/redirect/303`, "some-body", { insecure: true });
    assertEqual(res.status, 200, "status");
    const data = res.json<{ method: string }>();
    assertEqual(data.method, "GET", "method should become GET");
  });

  await test("307 preserves POST method", async () => {
    const res = await post(`${BASE}/redirect/307`, "preserved-body", {
      insecure: true,
      headers: { "content-type": "text/plain" },
    });
    assertEqual(res.status, 200, "status");
    const data = res.json<{ method: string; body: string }>();
    assertEqual(data.method, "POST", "method should stay POST");
    assertEqual(data.body, "preserved-body", "body should be preserved");
  });

  await test("follows redirect chain", async () => {
    const res = await get(`${BASE}/redirect/chain/5`, { insecure: true });
    assertEqual(res.status, 200, "status");
    const data = res.json<{ chain_complete: boolean }>();
    assertEqual(data.chain_complete, true, "chain complete");
    assert(res.redirectCount >= 5, `redirect count >= 5, got ${res.redirectCount}`);
  });

  await test("redirect with cookie persists cookie", async () => {
    const session = createSession({ insecure: true });
    try {
      const res = await session.get(`${BASE}/redirect/withcookie`);
      assertEqual(res.status, 200, "status after redirect");
      const data = res.json<{ cookies: Record<string, string> }>();
      assertEqual(data.cookies["redirect_cookie"], "from_redirect", "redirect cookie");
    } finally {
      session.close();
    }
  });

  await test("followRedirects: false stops on redirect", async () => {
    const res = await get(`${BASE}/redirect/302`, {
      insecure: true,
      followRedirects: false,
    });
    assertEqual(res.status, 302, "should get 302 directly");
    assert(res.headers["location"] !== undefined, "location header present");
  });

  await test("maxRedirects limits chain", async () => {
    try {
      await get(`${BASE}/redirect/chain/10`, {
        insecure: true,
        maxRedirects: 3,
      });
      throw new Error("Should have thrown");
    } catch (err: any) {
      assert(err.message.includes("redirect") || err.code === "ERR_MAX_REDIRECTS", `Expected redirect error, got: ${err.message}`);
    }
  });
}
