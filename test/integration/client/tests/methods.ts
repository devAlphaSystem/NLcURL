import { get, post, put, patch, del, head } from "../../../../src/index.js";
import { test, assertEqual, assert, getBaseURL } from "../runner.js";

export default async function () {
  const BASE = getBaseURL();

  await test("GET /json returns 200", async () => {
    const res = await get(`${BASE}/json`, { insecure: true });
    assertEqual(res.status, 200, "status");
    const data = res.json<{ message: string }>();
    assertEqual(data.message, "hello", "body.message");
  });

  await test("GET /text returns plain text", async () => {
    const res = await get(`${BASE}/text`, { insecure: true });
    assertEqual(res.status, 200, "status");
    assertEqual(res.text(), "Hello, NLcURL!", "text body");
  });

  await test("POST /echo echoes method", async () => {
    const res = await post(`${BASE}/echo`, "test-body", { insecure: true });
    assertEqual(res.status, 200, "status");
    const data = res.json<{ method: string; body: string }>();
    assertEqual(data.method, "POST", "method");
    assertEqual(data.body, "test-body", "body");
  });

  await test("PUT /put echoes body", async () => {
    const res = await put(`${BASE}/put`, "put-data", { insecure: true });
    assertEqual(res.status, 200, "status");
    const data = res.json<{ method: string; body: string }>();
    assertEqual(data.method, "PUT", "method");
    assertEqual(data.body, "put-data", "body");
  });

  await test("PATCH /patch echoes body", async () => {
    const res = await patch(`${BASE}/patch`, "patch-data", { insecure: true });
    assertEqual(res.status, 200, "status");
    const data = res.json<{ method: string; body: string }>();
    assertEqual(data.method, "PATCH", "method");
    assertEqual(data.body, "patch-data", "body");
  });

  await test("DELETE /delete returns confirmation", async () => {
    const res = await del(`${BASE}/delete`, { insecure: true });
    assertEqual(res.status, 200, "status");
    const data = res.json<{ method: string; deleted: boolean }>();
    assertEqual(data.method, "DELETE", "method");
    assertEqual(data.deleted, true, "deleted");
  });

  await test("HEAD /head returns headers only", async () => {
    const res = await head(`${BASE}/head`, { insecure: true });
    assertEqual(res.status, 200, "status");
    assertEqual(res.headers["x-custom"], "head-test", "custom header");
    assertEqual(res.rawBody.length, 0, "no body");
  });
}
