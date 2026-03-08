import { describe, it } from "node:test";
import assert from "node:assert/strict";
import { PerMessageDeflate, buildDeflateOffer, parseDeflateResponse, type DeflateParams } from "../../src/ws/permessage-deflate.js";

describe("buildDeflateOffer", () => {
  it("returns a valid extension offer string", () => {
    const offer = buildDeflateOffer();
    assert.ok(offer.includes("permessage-deflate"));
    assert.ok(offer.includes("client_max_window_bits"));
  });
});

describe("parseDeflateResponse", () => {
  it("parses minimal response", () => {
    const params = parseDeflateResponse("permessage-deflate");
    assert.ok(params);
    assert.equal(params.serverNoContextTakeover, false);
    assert.equal(params.clientNoContextTakeover, false);
    assert.equal(params.serverMaxWindowBits, 15);
    assert.equal(params.clientMaxWindowBits, 15);
  });

  it("parses response with all parameters", () => {
    const params = parseDeflateResponse("permessage-deflate; server_no_context_takeover; client_no_context_takeover; server_max_window_bits=12; client_max_window_bits=10");
    assert.ok(params);
    assert.equal(params.serverNoContextTakeover, true);
    assert.equal(params.clientNoContextTakeover, true);
    assert.equal(params.serverMaxWindowBits, 12);
    assert.equal(params.clientMaxWindowBits, 10);
  });

  it("returns null when extension not present", () => {
    assert.equal(parseDeflateResponse("x-some-other-ext"), null);
  });

  it("handles multiple extensions in header", () => {
    const params = parseDeflateResponse("x-ext, permessage-deflate; server_max_window_bits=9");
    assert.ok(params);
    assert.equal(params.serverMaxWindowBits, 9);
  });
});

describe("PerMessageDeflate", () => {
  const defaultParams: DeflateParams = {
    serverNoContextTakeover: false,
    clientNoContextTakeover: false,
    serverMaxWindowBits: 15,
    clientMaxWindowBits: 15,
  };

  it("compresses and decompresses a message", async () => {
    const deflate = new PerMessageDeflate(defaultParams);
    const original = Buffer.from("Hello, WebSocket compression world!");
    const compressed = await deflate.compress(original);
    assert.ok(compressed.length > 0);
    assert.notDeepEqual(compressed, original);

    const decompressed = await deflate.decompress(compressed);
    assert.deepEqual(decompressed, original);
    deflate.close();
  });

  it("handles multiple messages with context takeover", async () => {
    const deflate = new PerMessageDeflate(defaultParams);
    const msg1 = Buffer.from("First message with repeated data repeated data");
    const msg2 = Buffer.from("Second message with repeated data repeated data");

    const c1 = await deflate.compress(msg1);
    const c2 = await deflate.compress(msg2);

    const d1 = await deflate.decompress(c1);
    const d2 = await deflate.decompress(c2);

    assert.deepEqual(d1, msg1);
    assert.deepEqual(d2, msg2);
    deflate.close();
  });

  it("works with no_context_takeover", async () => {
    const params: DeflateParams = {
      ...defaultParams,
      serverNoContextTakeover: true,
      clientNoContextTakeover: true,
    };
    const deflate = new PerMessageDeflate(params);
    const msg = Buffer.from("No context takeover test message");

    const compressed = await deflate.compress(msg);
    const decompressed = await deflate.decompress(compressed);
    assert.deepEqual(decompressed, msg);
    deflate.close();
  });

  it("handles empty payload", async () => {
    const deflate = new PerMessageDeflate(defaultParams);
    const original = Buffer.alloc(0);
    const compressed = await deflate.compress(original);
    const decompressed = await deflate.decompress(compressed);
    assert.deepEqual(decompressed, original);
    deflate.close();
  });

  it("close can be called multiple times safely", () => {
    const deflate = new PerMessageDeflate(defaultParams);
    deflate.close();
    deflate.close();
  });
});
