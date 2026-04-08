/**
 * Live multipart form-data and upload tests.
 *
 * Tests real multipart form uploads, file attachments, and
 * various body encoding paths against httpbin.org.
 */
import { describe, it } from "node:test";
import { strict as assert } from "node:assert";
import { FormData, createSession } from "../../src/index.js";
import { LIVE_TIMEOUT, get, post, assertOk } from "./helpers.js";

describe("Multipart form-data uploads", { timeout: LIVE_TIMEOUT }, () => {
  it("sends a simple text field via FormData", async () => {
    const form = new FormData();
    form.append("username", "testuser");
    form.append("message", "Hello from NLcURL live tests!");

    const resp = await post("https://httpbin.org/post", form, {
      headers: { "content-type": form.contentType },
    });
    assertOk(resp, "httpbin FormData simple text");
    const json = resp.json() as { form: Record<string, string> };
    assert.equal(json.form.username, "testuser");
    assert.equal(json.form.message, "Hello from NLcURL live tests!");
  });

  it("sends multiple fields and a file attachment", async () => {
    const form = new FormData();
    form.append("field1", "value1");
    form.append("field2", "value2");
    form.append("file", {
      data: Buffer.from("file content here"),
      filename: "test.txt",
      contentType: "text/plain",
    });

    const resp = await post("https://httpbin.org/post", form, {
      headers: { "content-type": form.contentType },
    });
    assertOk(resp);

    const json = resp.json() as {
      form: Record<string, string>;
      files: Record<string, string>;
    };
    assert.equal(json.form.field1, "value1");
    assert.equal(json.form.field2, "value2");
    assert.ok(json.files.file, "File should be present");
    assert.ok(json.files.file.includes("file content here"));
  });

  it("sends a binary file attachment", async () => {
    const binaryContent = Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a]);
    const form = new FormData();
    form.append("image", {
      data: binaryContent,
      filename: "image.png",
      contentType: "image/png",
    });

    const resp = await post("https://httpbin.org/post", form, {
      headers: { "content-type": form.contentType },
    });
    assertOk(resp);

    const json = resp.json() as { files: Record<string, string> };
    assert.ok(json.files.image, "Image file should be uploaded");
  });

  it("content-type header includes boundary", async () => {
    const form = new FormData();
    form.append("test", "value");

    assert.ok(form.contentType.startsWith("multipart/form-data; boundary="), `Expected multipart content-type, got: ${form.contentType}`);
  });
});

describe("URL-encoded form bodies", { timeout: LIVE_TIMEOUT }, () => {
  it("sends url-encoded form data manually", async () => {
    const resp = await post("https://httpbin.org/post", "key1=value1&key2=value2&special=%26%3D%3F", {
      headers: { "content-type": "application/x-www-form-urlencoded" },
    });
    assertOk(resp);

    const json = resp.json() as { form: Record<string, string> };
    assert.equal(json.form.key1, "value1");
    assert.equal(json.form.key2, "value2");
    assert.equal(json.form.special, "&=?");
  });
});

describe("Large body uploads", { timeout: LIVE_TIMEOUT }, () => {
  it("sends a large JSON body", async () => {
    const largeArray = Array.from({ length: 500 }, (_, i) => ({
      id: i,
      name: `item-${i}`,
      value: Math.random(),
    }));

    const resp = await post("https://httpbin.org/post", largeArray);
    assertOk(resp);

    const json = resp.json() as { json: typeof largeArray };
    assert.ok(json.json, "JSON body should be echoed back");
    assert.equal(json.json.length, 500);
    assert.equal(json.json[0]!.id, 0);
    assert.equal(json.json[499]!.id, 499);
  });

  it("sends a large string body", async () => {
    const largeString = "x".repeat(10_000);

    const resp = await post("https://httpbin.org/post", largeString);
    assertOk(resp);

    const json = resp.json() as { data: string };
    assert.equal(json.data.length, 10_000);
  });
});

describe("Content negotiation", { timeout: LIVE_TIMEOUT }, () => {
  it("receives JSON when Accept: application/json", async () => {
    const resp = await get("https://httpbin.org/get", {
      headers: { accept: "application/json" },
    });
    assertOk(resp);

    const contentType = resp.headers["content-type"] || "";
    assert.ok(contentType.includes("application/json"), `Expected JSON content-type, got: ${contentType}`);
  });

  it("sends and receives custom content types", async () => {
    const xmlBody = '<?xml version="1.0"?><root><item>test</item></root>';
    const resp = await post("https://httpbin.org/post", xmlBody, {
      headers: { "content-type": "application/xml" },
    });
    assertOk(resp);

    const json = resp.json() as { data: string; headers: Record<string, string> };
    assert.ok(json.data.includes("<root>"));
    assert.ok(json.headers["Content-Type"]?.includes("application/xml"));
  });
});
