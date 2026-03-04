import { describe, it } from "node:test";
import assert from "node:assert/strict";

/**
 * Extracts the redirect logic from session.ts executeWithRedirects as a
 * pure function we can unit-test without needing a negotiator or sockets.
 */
function computeRedirect(statusCode: number, method: string, headers: Record<string, string>, body: string | null): { method: string; body: string | null; headers: Record<string, string> } {
  let newMethod = method;
  let newBody: string | null = body;

  if (statusCode === 303) {
    newMethod = "GET";
    newBody = null;
  } else if ((statusCode === 301 || statusCode === 302) && method === "POST") {
    newMethod = "GET";
    newBody = null;
  }

  const newHeaders = { ...headers };
  if (newBody === null) {
    delete newHeaders["content-type"];
    delete newHeaders["content-length"];
  }

  return { method: newMethod, body: newBody, headers: newHeaders };
}

describe("Fix 3 – redirect header stripping conditions", () => {
  const postHeaders = {
    "content-type": "application/json",
    "content-length": "42",
    authorization: "Bearer token",
  };
  const body = '{"key":"value"}';

  it("303 strips body, content-type, and content-length (any method)", () => {
    const result = computeRedirect(303, "POST", postHeaders, body);
    assert.equal(result.method, "GET");
    assert.equal(result.body, null);
    assert.equal(result.headers["content-type"], undefined, "content-type should be stripped on 303");
    assert.equal(result.headers["content-length"], undefined, "content-length should be stripped on 303");
    assert.equal(result.headers["authorization"], "Bearer token", "other headers should be preserved");
  });

  it("301 + POST→GET strips body and content headers", () => {
    const result = computeRedirect(301, "POST", postHeaders, body);
    assert.equal(result.method, "GET");
    assert.equal(result.body, null);
    assert.equal(result.headers["content-type"], undefined);
    assert.equal(result.headers["content-length"], undefined);
  });

  it("302 + POST→GET strips body and content headers", () => {
    const result = computeRedirect(302, "POST", postHeaders, body);
    assert.equal(result.method, "GET");
    assert.equal(result.body, null);
    assert.equal(result.headers["content-type"], undefined);
    assert.equal(result.headers["content-length"], undefined);
  });

  it("307 preserves method, body, content-type, and content-length", () => {
    const result = computeRedirect(307, "POST", postHeaders, body);
    assert.equal(result.method, "POST", "307 must preserve method");
    assert.equal(result.body, body, "307 must preserve body");
    assert.equal(result.headers["content-type"], "application/json", "307 must preserve content-type");
    assert.equal(result.headers["content-length"], "42", "307 must preserve content-length");
  });

  it("308 preserves method, body, content-type, and content-length", () => {
    const result = computeRedirect(308, "POST", postHeaders, body);
    assert.equal(result.method, "POST", "308 must preserve method");
    assert.equal(result.body, body, "308 must preserve body");
    assert.equal(result.headers["content-type"], "application/json", "308 must preserve content-type");
    assert.equal(result.headers["content-length"], "42", "308 must preserve content-length");
  });

  it("307 with PUT preserves all content headers", () => {
    const putHeaders = {
      "content-type": "text/plain",
      "content-length": "5",
    };
    const result = computeRedirect(307, "PUT", putHeaders, "hello");
    assert.equal(result.method, "PUT");
    assert.equal(result.body, "hello");
    assert.equal(result.headers["content-type"], "text/plain");
    assert.equal(result.headers["content-length"], "5");
  });

  it("301 + GET preserves body (null) and does not strip content headers", () => {
    const getHeaders = {
      accept: "text/html",
    };
    const result = computeRedirect(301, "GET", getHeaders, null);
    assert.equal(result.method, "GET");
    assert.equal(result.body, null);
    assert.equal(result.headers["accept"], "text/html");
  });

  it("303 + GET strips body content headers", () => {
    const result = computeRedirect(303, "GET", { accept: "text/html" }, null);
    assert.equal(result.method, "GET");
    assert.equal(result.body, null);
  });

  it("302 + PUT keeps method and body (only POST→GET is converted)", () => {
    const putHeaders = {
      "content-type": "application/octet-stream",
      "content-length": "1024",
    };
    const result = computeRedirect(302, "PUT", putHeaders, "data");
    assert.equal(result.method, "PUT", "302 + PUT should NOT change method");
    assert.equal(result.body, "data", "302 + PUT should NOT clear body");
    assert.equal(result.headers["content-type"], "application/octet-stream", "302 + PUT should NOT strip content-type");
  });
});
