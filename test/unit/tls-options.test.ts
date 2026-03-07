import { describe, it } from "node:test";
import assert from "node:assert/strict";

describe("TLSOptions type", () => {
  it("TLSOptions supports all mTLS and CA fields", async () => {
    const { NodeTLSEngine } = await import("../../src/tls/node-engine.js");
    const engine = new NodeTLSEngine();
    assert.ok(engine);

    const opts: import("../../src/tls/types.js").TLSConnectOptions = {
      host: "example.com",
      port: 443,
      cert: "-----BEGIN CERTIFICATE-----\nfake\n-----END CERTIFICATE-----",
      key: "-----BEGIN PRIVATE KEY-----\nfake\n-----END PRIVATE KEY-----",
      passphrase: "test-passphrase",
      ca: "-----BEGIN CERTIFICATE-----\nfake-ca\n-----END CERTIFICATE-----",
    };
    assert.equal(opts.host, "example.com");
    assert.equal(opts.cert, "-----BEGIN CERTIFICATE-----\nfake\n-----END CERTIFICATE-----");
    assert.equal(opts.key, "-----BEGIN PRIVATE KEY-----\nfake\n-----END PRIVATE KEY-----");
    assert.equal(opts.passphrase, "test-passphrase");
  });

  it("TLSOptions accepts Buffer values", () => {
    const opts: import("../../src/tls/types.js").TLSConnectOptions = {
      host: "example.com",
      port: 443,
      cert: Buffer.from("cert-data"),
      key: Buffer.from("key-data"),
      pfx: Buffer.from("pfx-data"),
      ca: [Buffer.from("ca1"), Buffer.from("ca2")],
    };
    assert.ok(Buffer.isBuffer(opts.cert));
    assert.ok(Buffer.isBuffer(opts.key));
    assert.ok(Buffer.isBuffer(opts.pfx));
    assert.ok(Array.isArray(opts.ca));
  });

  it("TLSOptions fields flow through NLcURLRequest", async () => {
    const req: import("../../src/core/request.js").NLcURLRequest = {
      url: "https://example.com",
      tls: {
        cert: "cert",
        key: "key",
        ca: "ca",
      },
    };
    assert.ok(req.tls);
    assert.equal(req.tls.cert, "cert");
    assert.equal(req.tls.key, "key");
    assert.equal(req.tls.ca, "ca");
  });

  it("NLcURLSessionConfig accepts tls option", async () => {
    const config: import("../../src/core/request.js").NLcURLSessionConfig = {
      tls: {
        cert: Buffer.from("cert"),
        key: Buffer.from("key"),
        passphrase: "secret",
        ca: [Buffer.from("ca")],
      },
    };
    assert.ok(config.tls);
    assert.equal(config.tls.passphrase, "secret");
  });
});
