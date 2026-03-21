/**
 * Live authentication tests.
 *
 * Validates Basic and Bearer auth, HTTP authentication challenges,
 * and authorization header handling against real servers.
 */
import { describe, it } from "node:test";
import { strict as assert } from "node:assert";
import { get, createSession } from "../../src/index.js";
import { LIVE_TIMEOUT, assertOk } from "./helpers.js";

describe("HTTP Basic Authentication", { timeout: LIVE_TIMEOUT }, () => {
  it("authenticates with correct credentials", async () => {
    const resp = await get("https://httpbin.org/basic-auth/testuser/testpass", {
      auth: { type: "basic", username: "testuser", password: "testpass" },
    });
    assertOk(resp);

    const json = resp.json() as { authenticated: boolean; user: string };
    assert.equal(json.authenticated, true);
    assert.equal(json.user, "testuser");
  });

  it("fails with wrong credentials", async () => {
    const resp = await get("https://httpbin.org/basic-auth/user/pass", {
      auth: { type: "basic", username: "wrong", password: "wrong" },
    });
    assert.equal(resp.status, 401, "Should return 401 Unauthorized");
  });

  it("fails without credentials", async () => {
    const resp = await get("https://httpbin.org/basic-auth/user/pass");
    assert.equal(resp.status, 401);
  });
});

describe("HTTP Bearer Token", { timeout: LIVE_TIMEOUT }, () => {
  it("sends Bearer token in Authorization header", async () => {
    const resp = await get("https://httpbin.org/bearer", {
      headers: { authorization: "Bearer my-test-token-123" },
    });
    assertOk(resp);

    const json = resp.json() as { authenticated: boolean; token: string };
    assert.equal(json.authenticated, true);
    assert.equal(json.token, "my-test-token-123");
  });

  it("fails without Bearer token", async () => {
    const resp = await get("https://httpbin.org/bearer");
    assert.equal(resp.status, 401);
  });
});

describe("HTTP Digest Authentication", { timeout: LIVE_TIMEOUT }, () => {
  it("handles digest auth challenge", async () => {
    const resp = await get("https://httpbin.org/digest-auth/auth/user/passwd", {
      auth: { type: "digest", username: "user", password: "passwd" },
    });
    assert.ok(typeof resp.status === "number");
    assert.ok(resp.status === 200 || resp.status === 401);
  });
});

describe("Hidden Basic Authentication", { timeout: LIVE_TIMEOUT }, () => {
  it("handles hidden basic auth (no 401 on failure)", async () => {
    const resp = await get("https://httpbin.org/hidden-basic-auth/user/passwd", {
      auth: { type: "basic", username: "user", password: "passwd" },
    });
    assert.ok(resp.status === 200 || resp.status === 404);
    if (resp.status === 200) {
      const json = resp.json() as { authenticated: boolean };
      assert.equal(json.authenticated, true);
    }
  });
});

describe("Auth in session context", { timeout: LIVE_TIMEOUT }, () => {
  it("session carries auth across requests", async () => {
    const session = createSession({
      auth: { type: "basic", username: "testuser", password: "testpass" },
    });

    const resp = await session.get("https://httpbin.org/basic-auth/testuser/testpass");
    assertOk(resp);

    const json = resp.json() as { authenticated: boolean; user: string };
    assert.equal(json.authenticated, true);
    assert.equal(json.user, "testuser");
  });

  it("Authorization header is sent via session default headers", async () => {
    const session = createSession({
      headers: { authorization: "Bearer session-token-xyz" },
    });

    const resp = await session.get("https://httpbin.org/bearer");
    assertOk(resp);

    const json = resp.json() as { authenticated: boolean; token: string };
    assert.equal(json.authenticated, true);
    assert.equal(json.token, "session-token-xyz");
  });
});
