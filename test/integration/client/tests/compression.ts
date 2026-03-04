import { get } from "../../../../src/index.js";
import { test, assertEqual, assert, getBaseURL } from "../runner.js";

export default async function () {
  const BASE = getBaseURL();

  await test("gzip compressed response", async () => {
    const res = await get(`${BASE}/gzip`, { insecure: true });
    assertEqual(res.status, 200, "status");
    try {
      const data = res.json<{ compressed: string }>();
      assertEqual(data.compressed, "gzip", "decompressed gzip");
    } catch {
      assert(res.rawBody.length > 0, "got raw compressed data");
    }
  });

  await test("deflate compressed response", async () => {
    const res = await get(`${BASE}/deflate`, { insecure: true });
    assertEqual(res.status, 200, "status");
    try {
      const data = res.json<{ compressed: string }>();
      assertEqual(data.compressed, "deflate", "decompressed deflate");
    } catch {
      assert(res.rawBody.length > 0, "got raw compressed data");
    }
  });

  await test("brotli compressed response", async () => {
    const res = await get(`${BASE}/brotli`, { insecure: true });
    assertEqual(res.status, 200, "status");
    try {
      const data = res.json<{ compressed: string }>();
      assertEqual(data.compressed, "brotli", "decompressed brotli");
    } catch {
      assert(res.rawBody.length > 0, "got raw compressed data");
    }
  });
}
