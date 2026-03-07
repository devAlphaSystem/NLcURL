import { describe, it } from "node:test";
import assert from "node:assert/strict";
import { FormData } from "../../src/http/form-data.js";

describe("FormData", () => {
  it("encodes a single text field", () => {
    const form = new FormData();
    form.append("name", "alice");
    const buf = form.encode();
    const text = buf.toString("utf-8");

    assert.ok(text.includes('Content-Disposition: form-data; name="name"'));
    assert.ok(text.includes("alice"));
    assert.ok(text.includes(`--${form.getBoundary()}`));
    assert.ok(text.includes(`--${form.getBoundary()}--`));
  });

  it("encodes multiple text fields", () => {
    const form = new FormData();
    form.append("a", "1");
    form.append("b", "2");
    form.append("c", "3");
    const buf = form.encode();
    const text = buf.toString("utf-8");

    assert.ok(text.includes('name="a"'));
    assert.ok(text.includes('name="b"'));
    assert.ok(text.includes('name="c"'));
    assert.ok(text.includes("1"));
    assert.ok(text.includes("2"));
    assert.ok(text.includes("3"));
  });

  it("encodes a file field", () => {
    const form = new FormData();
    const fileContent = Buffer.from("PNG file content");
    form.append("avatar", {
      data: fileContent,
      filename: "avatar.png",
      contentType: "image/png",
    });
    const buf = form.encode();
    const text = buf.toString("utf-8");

    assert.ok(text.includes('name="avatar"; filename="avatar.png"'));
    assert.ok(text.includes("Content-Type: image/png"));
    assert.ok(text.includes("PNG file content"));
  });

  it("uses application/octet-stream for files without contentType", () => {
    const form = new FormData();
    form.append("file", {
      data: Buffer.from("data"),
      filename: "test.bin",
    });
    const buf = form.encode();
    const text = buf.toString("utf-8");

    assert.ok(text.includes("Content-Type: application/octet-stream"));
  });

  it("encodes mixed text and file fields", () => {
    const form = new FormData();
    form.append("title", "My Upload");
    form.append("file", {
      data: Buffer.from([0x89, 0x50, 0x4e, 0x47]),
      filename: "image.png",
      contentType: "image/png",
    });
    form.append("description", "A test file");
    const buf = form.encode();
    const text = buf.toString("utf-8");

    assert.ok(text.includes('name="title"'));
    assert.ok(text.includes("My Upload"));
    assert.ok(text.includes('name="file"; filename="image.png"'));
    assert.ok(text.includes('name="description"'));
    assert.ok(text.includes("A test file"));
  });

  it("generates a valid content-type header", () => {
    const form = new FormData();
    form.append("x", "y");
    const ct = form.contentType;
    assert.ok(ct.startsWith("multipart/form-data; boundary="));
    assert.ok(ct.includes(form.getBoundary()));
  });

  it("generates unique boundaries per instance", () => {
    const f1 = new FormData();
    const f2 = new FormData();
    assert.notEqual(f1.getBoundary(), f2.getBoundary());
  });

  it("escapes quotes in field names", () => {
    const form = new FormData();
    form.append('field"with"quotes', "value");
    const text = form.encode().toString("utf-8");
    assert.ok(text.includes('name="field\\"with\\"quotes"'));
  });

  it("escapes quotes in filenames", () => {
    const form = new FormData();
    form.append("file", {
      data: Buffer.from("x"),
      filename: 'my"file.txt',
    });
    const text = form.encode().toString("utf-8");
    assert.ok(text.includes('filename="my\\"file.txt"'));
  });

  it("produces proper CRLF line endings", () => {
    const form = new FormData();
    form.append("key", "val");
    const text = form.encode().toString("utf-8");
    const lines = text.split("\r\n");
    assert.ok(lines.length >= 5);
  });
});

describe("FormData integration with encodeRequest", () => {
  it("sets correct content-type when FormData is the body", async () => {
    const { encodeRequest } = await import("../../src/http/h1/encoder.js");
    const form = new FormData();
    form.append("field", "value");

    const req = {
      url: "https://example.com/upload",
      method: "POST" as const,
      body: form,
    };

    const buf = encodeRequest(req, []);
    const text = buf.toString("latin1");

    assert.ok(text.includes(`content-type: multipart/form-data; boundary=${form.getBoundary()}`));
    assert.ok(text.includes('Content-Disposition: form-data; name="field"'));
    assert.ok(text.includes("value"));
  });

  it("calculates correct content-length for FormData", async () => {
    const { encodeRequest } = await import("../../src/http/h1/encoder.js");
    const form = new FormData();
    form.append("x", "hello");

    const encoded = form.encode();
    const req = {
      url: "https://example.com/",
      method: "POST" as const,
      body: form,
    };

    const buf = encodeRequest(req, []);
    const text = buf.toString("latin1");

    assert.ok(text.includes(`content-length: ${encoded.length}`));
  });
});
