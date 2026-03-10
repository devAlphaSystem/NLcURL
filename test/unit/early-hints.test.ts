/**
 * Unit tests for src/http/early-hints.ts
 * Link header parsing per RFC 8288.
 */
import { describe, it } from "node:test";
import { strict as assert } from "node:assert";
import { parseLinkHeader } from "../../src/http/early-hints.js";

describe("parseLinkHeader", () => {
  it("parses single preload hint", () => {
    const hints = parseLinkHeader('</style.css>; rel="preload"; as="style"');
    assert.equal(hints.length, 1);
    assert.equal(hints[0]!.uri, "/style.css");
    assert.equal(hints[0]!.rel, "preload");
    assert.equal(hints[0]!.as, "style");
  });

  it("parses multiple comma-separated hints", () => {
    const hints = parseLinkHeader('</a.js>; rel="preload"; as="script", </b.css>; rel="preload"; as="style"');
    assert.equal(hints.length, 2);
    assert.equal(hints[0]!.uri, "/a.js");
    assert.equal(hints[1]!.uri, "/b.css");
  });

  it("parses type attribute", () => {
    const hints = parseLinkHeader('</font.woff2>; rel="preload"; as="font"; type="font/woff2"');
    assert.equal(hints[0]!.type, "font/woff2");
  });

  it("detects crossorigin attribute", () => {
    const hints = parseLinkHeader('</api/data>; rel="preload"; crossorigin');
    assert.equal(hints[0]!.crossorigin, true);
  });

  it("handles hints without crossorigin", () => {
    const hints = parseLinkHeader('</style.css>; rel="preload"');
    assert.equal(hints[0]!.crossorigin, undefined);
  });

  it("returns empty array for empty string", () => {
    assert.deepEqual(parseLinkHeader(""), []);
  });

  it("skips entries without URI in angle brackets", () => {
    const hints = parseLinkHeader('invalid; rel="preload"');
    assert.equal(hints.length, 0);
  });

  it("handles full URLs", () => {
    const hints = parseLinkHeader('<https://cdn.example.com/script.js>; rel="preload"; as="script"');
    assert.equal(hints[0]!.uri, "https://cdn.example.com/script.js");
  });

  it("parses rel without quotes", () => {
    const hints = parseLinkHeader("</file.js>; rel=preload; as=script");
    assert.equal(hints[0]!.rel, "preload");
    assert.equal(hints[0]!.as, "script");
  });
});
