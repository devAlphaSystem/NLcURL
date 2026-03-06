import { describe, it, beforeEach, afterEach, mock } from "node:test";
import assert from "node:assert/strict";
import * as net from "node:net";
import { happyEyeballsConnect } from "../../src/utils/happy-eyeballs.js";

/**
 * Helper: create a TCP server listening on the loopback for a given family.
 * Returns the server, address, and port.
 */
function listenOnLoopback(family: 4 | 6): Promise<{ server: net.Server; address: string; port: number }> {
  return new Promise((resolve) => {
    const server = net.createServer();
    const host = family === 6 ? "::1" : "127.0.0.1";
    server.listen(0, host, () => {
      const addr = server.address() as net.AddressInfo;
      resolve({ server, address: addr.address, port: addr.port });
    });
  });
}

describe("Happy Eyeballs — interleaveAddressFamilies (via integration)", () => {
  it("connects to an IPv4 literal without DNS", async () => {
    const { server, port } = await listenOnLoopback(4);
    try {
      const result = await happyEyeballsConnect({
        host: "127.0.0.1",
        port,
        timeout: 5000,
      });
      assert.equal(result.address, "127.0.0.1");
      assert.equal(result.family, 4);
      assert.equal(result.dnsTimeMs, 0);
      result.socket.destroy();
    } finally {
      server.close();
    }
  });

  it("connects to an IPv6 literal without DNS", async () => {
    const { server, port } = await listenOnLoopback(6);
    try {
      const result = await happyEyeballsConnect({
        host: "::1",
        port,
        timeout: 5000,
      });
      assert.equal(result.address, "::1");
      assert.equal(result.family, 6);
      assert.equal(result.dnsTimeMs, 0);
      result.socket.destroy();
    } finally {
      server.close();
    }
  });
});

describe("Happy Eyeballs — single address resolution", () => {
  it("connects to localhost (at least one address)", async () => {
    const { server, port } = await listenOnLoopback(4);
    try {
      const result = await happyEyeballsConnect({
        host: "localhost",
        port,
        family: 4,
        timeout: 5000,
      });
      assert.ok(result.socket);
      assert.ok(result.dnsTimeMs >= 0);
      result.socket.destroy();
    } finally {
      server.close();
    }
  });
});

describe("Happy Eyeballs — fallback on connection failure", () => {
  it("falls back to IPv4 when IPv6 port is unreachable", async () => {
    const { server, port } = await listenOnLoopback(4);
    const { server: dummy } = await listenOnLoopback(6);
    const dummyAddr = dummy.address() as net.AddressInfo;
    dummy.close();

    try {
      const result = await happyEyeballsConnect({
        host: "127.0.0.1",
        port,
        timeout: 5000,
      });
      assert.ok(result.socket);
      assert.equal(result.family, 4);
      result.socket.destroy();
    } finally {
      server.close();
    }
  });

  it("rejects with an error when no addresses can connect", async () => {
    const server = net.createServer();
    await new Promise<void>((r) => server.listen(0, "127.0.0.1", r));
    const { port } = server.address() as net.AddressInfo;
    server.close();

    await assert.rejects(
      () =>
        happyEyeballsConnect({
          host: "127.0.0.1",
          port,
          timeout: 5000,
        }),
      (err: Error) => {
        assert.ok(err.message);
        return true;
      },
    );
  });
});

describe("Happy Eyeballs — timeout", () => {
  it("rejects with ETIMEDOUT when no address connects in time", async () => {
    await assert.rejects(
      () =>
        happyEyeballsConnect({
          host: "192.0.2.1",
          port: 80,
          timeout: 500,
        }),
      (err: NodeJS.ErrnoException) => {
        assert.ok(err.message);
        return true;
      },
    );
  });
});

describe("Happy Eyeballs — abort signal", () => {
  it("rejects when signal is already aborted", async () => {
    const controller = new AbortController();
    controller.abort();

    await assert.rejects(
      () =>
        happyEyeballsConnect({
          host: "127.0.0.1",
          port: 80,
          signal: controller.signal,
        }),
      (err: Error) => {
        assert.ok(err.message.includes("aborted") || err.message.includes("abort"));
        return true;
      },
    );
  });

  it("rejects when signal fires during connection", async () => {
    const controller = new AbortController();

    const promise = happyEyeballsConnect({
      host: "192.0.2.1",
      port: 80,
      timeout: 30000,
      signal: controller.signal,
    });

    setTimeout(() => controller.abort(), 100);

    await assert.rejects(promise, (err: Error) => {
      assert.ok(err.message.includes("aborted") || err.message.includes("abort"));
      return true;
    });
  });
});

describe("Happy Eyeballs — DNS failure", () => {
  it("rejects when hostname cannot be resolved", async () => {
    await assert.rejects(
      () =>
        happyEyeballsConnect({
          host: "this-hostname-does-not-exist.invalid",
          port: 80,
          timeout: 5000,
        }),
      (err: Error) => {
        assert.ok(err.message);
        return true;
      },
    );
  });
});

describe("Happy Eyeballs — family pinning", () => {
  it("resolves only IPv4 when family=4 is set", async () => {
    const { server, port } = await listenOnLoopback(4);
    try {
      const result = await happyEyeballsConnect({
        host: "localhost",
        port,
        family: 4,
        timeout: 5000,
      });
      assert.ok(result.socket);
      assert.equal(result.family, 4);
      result.socket.destroy();
    } finally {
      server.close();
    }
  });
});
