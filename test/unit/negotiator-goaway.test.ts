import { describe, it } from "node:test";
import assert from "node:assert/strict";
import { PassThrough } from "node:stream";
import type { Duplex } from "node:stream";
import { ProtocolNegotiator } from "../../src/http/negotiator.js";
import { ProtocolError, HTTPError } from "../../src/core/errors.js";
import { NLcURLResponse } from "../../src/core/response.js";
import type { TLSSocket, TLSConnectionInfo } from "../../src/tls/types.js";
import { buildGoawayFrame, buildSettingsFrame } from "../../src/http/h2/frames.js";

/**
 * Creates a mock TLS socket (PassThrough) that pretends to have negotiated h2.
 * Writes from the H2Client go into `written`; the test pushes frames via
 * `transport.push(...)`.
 */
function createMockH2Socket(): { socket: TLSSocket; transport: PassThrough } {
  const transport = new PassThrough();
  const written: Buffer[] = [];

  const origWrite = transport.write.bind(transport);
  transport.write = function (chunk: any, ...args: any[]): boolean {
    written.push(Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk));
    return true;
  } as any;

  const socket = Object.assign(transport, {
    connectionInfo: {
      version: "TLSv1.3",
      alpnProtocol: "h2",
      cipher: "TLS_AES_128_GCM_SHA256",
    } as TLSConnectionInfo,
    destroyTLS() {},
  }) as unknown as TLSSocket;

  return { socket, transport };
}

/**
 * Injects a fake `connect` method into the negotiator so we control socket
 * creation without needing real DNS/TLS. Returns a function that provides the
 * "server" side passthrough for the most recently created socket.
 */
function patchConnect(negotiator: ProtocolNegotiator) {
  const sockets: Array<{ socket: TLSSocket; transport: PassThrough }> = [];

  (negotiator as any).connect = async () => {
    const pair = createMockH2Socket();
    sockets.push(pair);
    return pair.socket;
  };

  return {
    /** Returns mock socket pairs in creation order. */
    get sockets() {
      return sockets;
    },
    /**
     * Send SETTINGS ACK + GOAWAY on the Nth socket (0-indexed).
     * If no socket exists at that index yet, waits briefly.
     */
    async sendGoaway(index: number, errorCode: number) {
      for (let i = 0; i < 50; i++) {
        if (sockets[index]) break;
        await new Promise((r) => setTimeout(r, 10));
      }
      const { transport } = sockets[index];
      transport.push(buildSettingsFrame([], true));
      transport.push(buildGoawayFrame(0, errorCode));
    },
  };
}

describe("ProtocolNegotiator — GOAWAY retry behaviour", () => {
  it("retries transparently on graceful GOAWAY (error code 0)", async () => {
    const negotiator = new ProtocolNegotiator();
    const mock = patchConnect(negotiator);

    const sendPromise = negotiator.send({ url: "https://example.com/", method: "GET", headers: {} });

    await mock.sendGoaway(0, 0);

    await mock.sendGoaway(1, 0);

    await assert.rejects(sendPromise, (err: Error) => {
      assert.ok(err instanceof ProtocolError);
      assert.equal((err as ProtocolError).errorCode, 0);
      return true;
    });

    assert.equal(mock.sockets.length, 2);
    negotiator.close();
  });

  it("does NOT retry on non-graceful GOAWAY (error code != 0)", async () => {
    const negotiator = new ProtocolNegotiator();
    const mock = patchConnect(negotiator);

    const sendPromise = negotiator.send({ url: "https://example.com/", method: "GET", headers: {} });

    await mock.sendGoaway(0, 1);

    await assert.rejects(sendPromise, (err: Error) => {
      assert.ok(err instanceof ProtocolError);
      assert.equal((err as ProtocolError).errorCode, 1);
      return true;
    });

    assert.equal(mock.sockets.length, 1);
    negotiator.close();
  });

  it("retries at most once — does not loop on repeated graceful GOAWAYs", async () => {
    const negotiator = new ProtocolNegotiator();
    const mock = patchConnect(negotiator);

    const sendPromise = negotiator.send({ url: "https://example.com/", method: "GET", headers: {} });

    await mock.sendGoaway(0, 0);
    await mock.sendGoaway(1, 0);

    await assert.rejects(sendPromise, ProtocolError);

    assert.equal(mock.sockets.length, 2);
    negotiator.close();
  });

  it("does NOT retry non-ProtocolError failures", async () => {
    const negotiator = new ProtocolNegotiator();

    let connectCount = 0;
    (negotiator as any).connect = async () => {
      connectCount++;
      const { socket, transport } = createMockH2Socket();
      process.nextTick(() => transport.destroy(new Error("TCP reset")));
      return socket;
    };

    await assert.rejects(negotiator.send({ url: "https://example.com/", method: "GET", headers: {} }));

    assert.equal(connectCount, 1);
    negotiator.close();
  });

  it("does NOT retry on GOAWAY with ENHANCE_YOUR_CALM (code 11)", async () => {
    const negotiator = new ProtocolNegotiator();
    const mock = patchConnect(negotiator);

    const sendPromise = negotiator.send({ url: "https://example.com/", method: "GET", headers: {} });

    await mock.sendGoaway(0, 11);

    await assert.rejects(sendPromise, (err: Error) => {
      assert.ok(err instanceof ProtocolError);
      assert.equal((err as ProtocolError).errorCode, 11);
      return true;
    });

    assert.equal(mock.sockets.length, 1);
    negotiator.close();
  });
});
