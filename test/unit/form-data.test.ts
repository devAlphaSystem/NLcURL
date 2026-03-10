/**
 * Unit tests for src/http/form-data.ts
 * Multipart form-data encoding per RFC 7578.
 */
import { describe, it } from "node:test";
import { strict as assert } from "node:assert";
import { FormData } from "../../src/http/form-data.js";

describe("FormData", () => {
  describe("constructor", () => {
    it("generates a unique boundary", () => {
      const fd = new FormData();
      assert.ok(fd.getBoundary().startsWith("----NLcURL"));
      assert.ok(fd.getBoundary().length > 20);
    });

    it("generates different boundaries each time", () => {
      const a = new FormData();
      const b = new FormData();
      assert.notEqual(a.getBoundary(), b.getBoundary());
    });
  });

  describe("contentType", () => {
    it("returns multipart/form-data with boundary parameter", () => {
      const fd = new FormData();
      const ct = fd.contentType;
      assert.ok(ct.startsWith("multipart/form-data; boundary="));
      assert.ok(ct.includes(fd.getBoundary()));
    });
  });

  describe("append", () => {
    it("returns this for chaining", () => {
      const fd = new FormData();
      const result = fd.append("key", "value");
      assert.equal(result, fd);
    });
  });

  describe("encode", () => {
    it("encodes a string field with Content-Disposition", () => {
      const fd = new FormData();
      fd.append("username", "alice");
      const encoded = fd.encode();
      const str = encoded.toString("utf-8");
      assert.ok(str.includes('Content-Disposition: form-data; name="username"'));
      assert.ok(str.includes("alice"));
    });

    it("encodes a file field with filename and Content-Type", () => {
      const fd = new FormData();
      fd.append("avatar", {
        data: Buffer.from("PNG_DATA"),
        filename: "avatar.png",
        contentType: "image/png",
      });
      const encoded = fd.encode();
      const str = encoded.toString("utf-8");
      assert.ok(str.includes('filename="avatar.png"'));
      assert.ok(str.includes("Content-Type: image/png"));
      assert.ok(str.includes("PNG_DATA"));
    });

    it("defaults file Content-Type to application/octet-stream", () => {
      const fd = new FormData();
      fd.append("file", {
        data: Buffer.from("binary"),
        filename: "data.bin",
      });
      const encoded = fd.encode();
      const str = encoded.toString("utf-8");
      assert.ok(str.includes("Content-Type: application/octet-stream"));
    });

    it("starts each part with the boundary line", () => {
      const fd = new FormData();
      fd.append("k1", "v1");
      fd.append("k2", "v2");
      const encoded = fd.encode();
      const str = encoded.toString("utf-8");
      const boundary = fd.getBoundary();
      const parts = str.split(`--${boundary}`);
      assert.ok(parts.length >= 3);
    });

    it("ends with closing boundary (--boundary--)", () => {
      const fd = new FormData();
      fd.append("a", "b");
      const encoded = fd.encode();
      const str = encoded.toString("utf-8");
      assert.ok(str.includes(`--${fd.getBoundary()}--`));
    });

    it("encodes multiple fields including text and files", () => {
      const fd = new FormData();
      fd.append("name", "test");
      fd.append("doc", {
        data: Buffer.from("Hello PDF"),
        filename: "doc.pdf",
        contentType: "application/pdf",
      });
      fd.append("note", "additional text");
      const encoded = fd.encode();
      const str = encoded.toString("utf-8");
      assert.ok(str.includes('"name"'));
      assert.ok(str.includes('"doc"'));
      assert.ok(str.includes('"note"'));
    });

    it("escapes quotes in field names", () => {
      const fd = new FormData();
      fd.append('field"name', "value");
      const encoded = fd.encode();
      const str = encoded.toString("utf-8");
      assert.ok(str.includes('field\\"name'));
    });

    it("escapes quotes in filenames", () => {
      const fd = new FormData();
      fd.append("file", {
        data: Buffer.from("data"),
        filename: 'my"file.txt',
      });
      const encoded = fd.encode();
      const str = encoded.toString("utf-8");
      assert.ok(str.includes('my\\"file.txt'));
    });

    it("strips control characters from names", () => {
      const fd = new FormData();
      fd.append("file", {
        data: Buffer.from("data"),
        filename: "file\r\nname.txt",
      });
      const encoded = fd.encode();
      const str = encoded.toString("utf-8");
      assert.ok(!str.includes("\r\nname"));
    });

    it("produces valid Buffer output for binary file content", () => {
      const fd = new FormData();
      const binaryData = Buffer.from([0x00, 0xff, 0x42, 0x89]);
      fd.append("bin", {
        data: binaryData,
        filename: "binary.dat",
      });
      const encoded = fd.encode();
      assert.ok(Buffer.isBuffer(encoded));
      const idx = encoded.indexOf(binaryData);
      assert.ok(idx >= 0, "Binary data should be present in encoded output");
    });
  });
});
