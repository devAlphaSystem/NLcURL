/**
 * Unit tests for src/cookies/public-suffix.ts
 * Trie-based PSL matching per Mozilla Public Suffix List specification.
 * Test domains are from the PSL test suite: https://raw.githubusercontent.com/nickg/publicsuffixlist/master/test/test_psl.txt
 */
import { describe, it } from "node:test";
import { strict as assert } from "node:assert";
import { isPublicSuffix, getRegistrableDomain } from "../../src/cookies/public-suffix.js";

describe("isPublicSuffix", () => {
  it("recognizes .com as a public suffix", () => {
    assert.equal(isPublicSuffix("com"), true);
  });

  it("recognizes .org as a public suffix", () => {
    assert.equal(isPublicSuffix("org"), true);
  });

  it("recognizes .co.uk as a public suffix", () => {
    assert.equal(isPublicSuffix("co.uk"), true);
  });

  it("recognizes .uk as a public suffix", () => {
    assert.equal(isPublicSuffix("uk"), true);
  });

  it("does not consider example.com as a public suffix", () => {
    assert.equal(isPublicSuffix("example.com"), false);
  });

  it("does not consider www.example.com as a public suffix", () => {
    assert.equal(isPublicSuffix("www.example.com"), false);
  });

  it("recognizes .net as a public suffix", () => {
    assert.equal(isPublicSuffix("net"), true);
  });

  it("recognizes .edu as a public suffix", () => {
    assert.equal(isPublicSuffix("edu"), true);
  });

  it("is case-insensitive", () => {
    assert.equal(isPublicSuffix("COM"), true);
    assert.equal(isPublicSuffix("Co.Uk"), true);
  });

  it("recognizes wildcard rule domains (e.g. *.ck → test.ck is public suffix)", () => {
    assert.equal(isPublicSuffix("test.ck"), true);
  });

  it("recognizes ck as a public suffix", () => {
    assert.equal(isPublicSuffix("ck"), true);
  });

  it("recognizes .github.io as a public suffix", () => {
    assert.equal(isPublicSuffix("github.io"), true);
  });

  it("recognizes .blogspot.com as a public suffix", () => {
    assert.equal(isPublicSuffix("blogspot.com"), true);
  });

  it("does not consider amazonaws.com itself as a public suffix", () => {
    assert.equal(isPublicSuffix("amazonaws.com"), false);
  });
});

describe("getRegistrableDomain", () => {
  it("returns eTLD+1 for simple .com domain", () => {
    assert.equal(getRegistrableDomain("www.example.com"), "example.com");
  });

  it("returns eTLD+1 for deeper subdomain", () => {
    assert.equal(getRegistrableDomain("a.b.c.example.com"), "example.com");
  });

  it("returns eTLD+1 for .co.uk domain", () => {
    assert.equal(getRegistrableDomain("www.example.co.uk"), "example.co.uk");
  });

  it("returns null when hostname is itself a public suffix", () => {
    assert.equal(getRegistrableDomain("com"), null);
    assert.equal(getRegistrableDomain("co.uk"), null);
  });

  it("returns the domain itself if it is eTLD+1", () => {
    assert.equal(getRegistrableDomain("example.com"), "example.com");
  });

  it("returns null for single-label domains", () => {
    assert.equal(getRegistrableDomain("localhost"), null);
  });

  it("is case-insensitive", () => {
    assert.equal(getRegistrableDomain("WWW.Example.COM"), "example.com");
  });

  it("handles github.io subdomains", () => {
    assert.equal(getRegistrableDomain("myuser.github.io"), "myuser.github.io");
  });

  it("handles blogspot.com subdomains", () => {
    assert.equal(getRegistrableDomain("myblog.blogspot.com"), "myblog.blogspot.com");
  });
});
