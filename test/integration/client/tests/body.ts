import { post, request } from "../../../../src/index.js";
import { test, assertEqual, assert, getBaseURL } from "../runner.js";

export default async function () {
  const BASE = getBaseURL();

  await test("POST JSON object body", async () => {
    const res = await post(
      `${BASE}/post`,
      { name: "test", value: 42 },
      {
        insecure: true,
        headers: { "content-type": "application/json" },
      },
    );
    const data = res.json<{ received: { name: string; value: number }; contentType: string }>();
    assertEqual(data.received.name, "test", "name");
    assertEqual(data.received.value, 42, "value");
    assert(data.contentType.includes("application/json"), "content-type");
  });

  await test("POST string body", async () => {
    const res = await post(`${BASE}/echo`, "plain string body", { insecure: true });
    const data = res.json<{ body: string }>();
    assertEqual(data.body, "plain string body", "body");
  });

  await test("POST URLSearchParams body", async () => {
    const params = new URLSearchParams({ username: "alice", role: "admin" });
    const res = await post(`${BASE}/post`, params.toString(), {
      insecure: true,
      headers: { "content-type": "application/x-www-form-urlencoded" },
    });
    const data = res.json<{ received: { username: string; role: string } }>();
    assertEqual(data.received.username, "alice", "username");
    assertEqual(data.received.role, "admin", "role");
  });

  await test("POST Buffer body", async () => {
    const buf = Buffer.from("binary data here");
    const res = await post(`${BASE}/echo`, buf, { insecure: true });
    const data = res.json<{ body: string; bodyLength: number }>();
    assertEqual(data.bodyLength, 16, "body length");
    assertEqual(data.body, "binary data here", "body text");
  });

  await test("POST empty body", async () => {
    const res = await request({
      url: `${BASE}/echo`,
      method: "POST",
      insecure: true,
    });
    const data = res.json<{ body: string; bodyLength: number }>();
    assertEqual(data.bodyLength, 0, "empty body");
  });

  await test("POST large JSON body", async () => {
    const largeObj = {
      items: Array.from({ length: 1000 }, (_, i) => ({
        id: i,
        name: `item-${i}`,
        data: "x".repeat(100),
      })),
    };
    const res = await post(`${BASE}/echo`, largeObj, {
      insecure: true,
      headers: { "content-type": "application/json" },
    });
    assertEqual(res.status, 200, "status");
    const data = res.json<{ bodyLength: number }>();
    assert(data.bodyLength > 100_000, `body should be large, got ${data.bodyLength}`);
  });
}
