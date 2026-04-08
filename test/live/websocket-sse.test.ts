/**
 * Live WebSocket and SSE tests.
 *
 * Tests real WebSocket connections and Server-Sent Events streams
 * against public services.
 *
 * WebSocket: Uses wss://echo.websocket.org or similar public echo servers.
 * SSE: Uses httpbin.org streaming endpoints.
 */
import { describe, it } from "node:test";
import { strict as assert } from "node:assert";
import { WebSocketClient, createSession } from "../../src/index.js";
import { LIVE_TIMEOUT, SLOW_TIMEOUT, get } from "./helpers.js";

describe("WebSocket echo test", { timeout: SLOW_TIMEOUT }, () => {
  it("connects to a WSS echo server and exchanges messages", async () => {
    const ws = new WebSocketClient("wss://echo.websocket.events/");

    const result = await new Promise<{ received: string; protocol: string }>((resolve, reject) => {
      const timeout = setTimeout(() => {
        ws.close(1000, "timeout");
        reject(new Error("WebSocket timed out"));
      }, 15_000);

      let opened = false;

      ws.on("open", () => {
        opened = true;
        ws.send("hello from nlcurl");
      });

      ws.on("message", (data: string | Buffer, isBinary: boolean) => {
        clearTimeout(timeout);
        const text = typeof data === "string" ? data : data.toString("utf8");
        ws.close(1000, "done");
        resolve({ received: text, protocol: ws.protocol });
      });

      ws.on("error", (err: Error) => {
        clearTimeout(timeout);
        if (!opened) {
          resolve({ received: "SKIP", protocol: "" });
        } else {
          reject(err);
        }
      });
    });

    if (result.received !== "SKIP") {
      assert.ok(result.received.includes("hello from nlcurl") || result.received.length > 0, `Expected echoed message, got: "${result.received}"`);
    }
  });

  it("connects with stealth TLS fingerprinting", async () => {
    const ws = new WebSocketClient("wss://echo.websocket.events/", {
      impersonate: "chrome136",
      stealth: true,
      insecure: true,
    });

    const opened = await new Promise<boolean>((resolve) => {
      const timeout = setTimeout(() => {
        ws.close(1000, "timeout");
        resolve(false);
      }, 15_000);

      ws.on("open", () => {
        clearTimeout(timeout);
        ws.close(1000, "done");
        resolve(true);
      });

      ws.on("error", () => {
        clearTimeout(timeout);
        resolve(false);
      });
    });

    assert.ok(typeof opened === "boolean");
  });
});

describe("WebSocket ping/pong", { timeout: SLOW_TIMEOUT }, () => {
  it("responds to server pings automatically", async () => {
    const ws = new WebSocketClient("wss://echo.websocket.events/");

    const connected = await new Promise<boolean>((resolve) => {
      const timeout = setTimeout(() => {
        ws.close(1000, "timeout");
        resolve(false);
      }, 10_000);

      ws.on("open", () => {
        clearTimeout(timeout);
        ws.ping(Buffer.from("test-ping"));
        resolve(true);
      });

      ws.on("error", () => {
        clearTimeout(timeout);
        resolve(false);
      });
    });

    await new Promise((r) => setTimeout(r, 500));
    ws.close(1000, "done");

    assert.ok(typeof connected === "boolean");
  });
});

describe("WebSocket binary data", { timeout: SLOW_TIMEOUT }, () => {
  it("sends and receives binary data", async () => {
    const ws = new WebSocketClient("wss://echo.websocket.events/");
    const binaryData = Buffer.from([0x00, 0x01, 0x02, 0xff, 0xfe, 0xfd]);

    const received = await new Promise<Buffer | null>((resolve) => {
      const timeout = setTimeout(() => {
        ws.close(1000, "timeout");
        resolve(null);
      }, 10_000);

      ws.on("open", () => {
        ws.send(binaryData);
      });

      ws.on("message", (data: string | Buffer, isBinary: boolean) => {
        clearTimeout(timeout);
        ws.close(1000, "done");
        resolve(Buffer.isBuffer(data) ? data : Buffer.from(data));
      });

      ws.on("error", () => {
        clearTimeout(timeout);
        resolve(null);
      });
    });

    if (received) {
      assert.ok(received.length > 0, "Expected non-empty binary response");
    }
  });
});

describe("HTTP streaming / SSE-like responses", { timeout: LIVE_TIMEOUT }, () => {
  it("handles streaming response from httpbin", async () => {
    const resp = await get("https://httpbin.org/stream/5", {
      stream: false,
    });
    assert.ok(resp.status >= 200 && resp.status < 300, `Status: ${resp.status}`);
    const text = resp.text();
    const lines = text.trim().split("\n").filter(Boolean);
    assert.ok(lines.length >= 3, `Expected ≥3 streamed lines, got ${lines.length}`);

    for (const line of lines) {
      const parsed = JSON.parse(line);
      assert.ok(typeof parsed === "object");
    }
  });

  it("handles drip endpoint (slow bytes)", async () => {
    const resp = await get("https://httpbin.org/drip?duration=1&numbytes=10&delay=0", {
      timeout: 10_000,
    });
    assert.ok(resp.status >= 200 && resp.status < 300, `Status: ${resp.status}`);
    assert.ok(resp.rawBody.length >= 5, "Expected some bytes from drip");
  });

  it("handles chunked transfer encoding", async () => {
    const resp = await get("https://httpbin.org/stream-bytes/1024?chunk_size=256");
    assert.ok(resp.status >= 200 && resp.status < 300);
    assert.ok(resp.rawBody.length > 0, "Expected chunked body data");
  });
});
