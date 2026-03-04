import { get, request } from "../../../../src/index.js";
import { test, assertEqual, getBaseURL } from "../runner.js";

export default async function () {
  const BASE = getBaseURL();

  await test("query params in URL are received", async () => {
    const res = await get(`${BASE}/params?foo=bar&count=5`, { insecure: true });
    const data = res.json<{ params: Record<string, string> }>();
    assertEqual(data.params.foo, "bar", "foo");
    assertEqual(data.params.count, "5", "count");
  });

  await test("params option appends query parameters", async () => {
    const res = await request({
      url: `${BASE}/params`,
      insecure: true,
      params: { search: "nlcurl", page: 1, active: true },
    });
    const data = res.json<{ params: Record<string, string> }>();
    assertEqual(data.params.search, "nlcurl", "search");
    assertEqual(data.params.page, "1", "page");
    assertEqual(data.params.active, "true", "active");
  });

  await test("params merges with existing URL params", async () => {
    const res = await request({
      url: `${BASE}/params?existing=yes`,
      insecure: true,
      params: { added: "new" },
    });
    const data = res.json<{ params: Record<string, string> }>();
    assertEqual(data.params.existing, "yes", "existing param");
    assertEqual(data.params.added, "new", "added param");
  });

  await test("special characters in params are encoded", async () => {
    const res = await request({
      url: `${BASE}/params`,
      insecure: true,
      params: { name: "hello world", tag: "a&b=c" },
    });
    const data = res.json<{ params: Record<string, string> }>();
    assertEqual(data.params.name, "hello world", "space encoded");
    assertEqual(data.params.tag, "a&b=c", "special chars encoded");
  });
}
