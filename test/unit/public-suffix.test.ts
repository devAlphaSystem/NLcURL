import { describe, it } from "node:test";
import assert from "node:assert/strict";
import { isPublicSuffix, getRegistrableDomain } from "../../src/cookies/public-suffix.js";

describe("isPublicSuffix", () => {
  it("returns true for generic TLDs", () => {
    assert.equal(isPublicSuffix("com"), true);
    assert.equal(isPublicSuffix("org"), true);
    assert.equal(isPublicSuffix("net"), true);
    assert.equal(isPublicSuffix("io"), true);
    assert.equal(isPublicSuffix("dev"), true);
  });

  it("returns true for country-code second-level domains", () => {
    assert.equal(isPublicSuffix("co.uk"), true);
    assert.equal(isPublicSuffix("org.uk"), true);
    assert.equal(isPublicSuffix("co.jp"), true);
    assert.equal(isPublicSuffix("com.br"), true);
    assert.equal(isPublicSuffix("com.au"), true);
    assert.equal(isPublicSuffix("co.nz"), true);
    assert.equal(isPublicSuffix("com.cn"), true);
    assert.equal(isPublicSuffix("co.in"), true);
  });

  it("returns true for hosting/PaaS suffixes", () => {
    assert.equal(isPublicSuffix("github.io"), true);
    assert.equal(isPublicSuffix("herokuapp.com"), true);
    assert.equal(isPublicSuffix("netlify.app"), true);
    assert.equal(isPublicSuffix("vercel.app"), true);
    assert.equal(isPublicSuffix("pages.dev"), true);
    assert.equal(isPublicSuffix("workers.dev"), true);
    assert.equal(isPublicSuffix("cloudfront.net"), true);
    assert.equal(isPublicSuffix("azurewebsites.net"), true);
  });

  it("returns false for registrable domains", () => {
    assert.equal(isPublicSuffix("example.com"), false);
    assert.equal(isPublicSuffix("google.com"), false);
    assert.equal(isPublicSuffix("example.co.uk"), false);
    assert.equal(isPublicSuffix("bbc.co.uk"), false);
    assert.equal(isPublicSuffix("myapp.herokuapp.com"), false);
    assert.equal(isPublicSuffix("mysite.github.io"), false);
  });

  it("returns false for subdomains", () => {
    assert.equal(isPublicSuffix("www.example.com"), false);
    assert.equal(isPublicSuffix("api.example.co.uk"), false);
  });

  it("handles wildcard rules (*.ck)", () => {
    assert.equal(isPublicSuffix("co.ck"), true);
    assert.equal(isPublicSuffix("org.ck"), true);
  });

  it("handles wildcard exceptions (!www.ck)", () => {
    assert.equal(isPublicSuffix("www.ck"), false);
  });

  it("is case-insensitive", () => {
    assert.equal(isPublicSuffix("COM"), true);
    assert.equal(isPublicSuffix("Co.Uk"), true);
    assert.equal(isPublicSuffix("GitHub.IO"), true);
  });
});

describe("isPublicSuffix — full Mozilla PSL coverage", () => {
  it("returns true for less common ICANN TLDs", () => {
    assert.equal(isPublicSuffix("museum"), true);
    assert.equal(isPublicSuffix("aero"), true);
    assert.equal(isPublicSuffix("coop"), true);
    assert.equal(isPublicSuffix("post"), true);
    assert.equal(isPublicSuffix("tel"), true);
  });

  it("returns true for government ccSLDs worldwide", () => {
    assert.equal(isPublicSuffix("gov.uk"), true);
    assert.equal(isPublicSuffix("go.jp"), true);
    assert.equal(isPublicSuffix("gov.au"), true);
    assert.equal(isPublicSuffix("gc.ca"), true);
    assert.equal(isPublicSuffix("gob.mx"), true);
    assert.equal(isPublicSuffix("gov.in"), true);
    assert.equal(isPublicSuffix("gov.br"), true);
    assert.equal(isPublicSuffix("gov.za"), true);
    assert.equal(isPublicSuffix("go.kr"), true);
    assert.equal(isPublicSuffix("gov.cn"), true);
  });

  it("returns true for private/hosting domains in full list", () => {
    assert.equal(isPublicSuffix("s3.amazonaws.com"), true);
    assert.equal(isPublicSuffix("blogspot.com"), true);
    assert.equal(isPublicSuffix("appspot.com"), true);
    assert.equal(isPublicSuffix("firebaseapp.com"), true);
    assert.equal(isPublicSuffix("fly.dev"), true);
    assert.equal(isPublicSuffix("deno.dev"), true);
    assert.equal(isPublicSuffix("onrender.com"), true);
    assert.equal(isPublicSuffix("myshopify.com"), true);
    assert.equal(isPublicSuffix("trafficmanager.net"), true);
    assert.equal(isPublicSuffix("up.railway.app"), true);
  });

  it("handles wildcard exceptions (*.kawasaki.jp / !city.kawasaki.jp)", () => {
    assert.equal(isPublicSuffix("foo.kawasaki.jp"), true);
    assert.equal(isPublicSuffix("takatsu.kawasaki.jp"), true);
    assert.equal(isPublicSuffix("city.kawasaki.jp"), false);
    assert.equal(isPublicSuffix("example.city.kawasaki.jp"), false);
  });

  it("correctly handles *.compute.amazonaws.com wildcard", () => {
    assert.equal(isPublicSuffix("eu-west-1.compute.amazonaws.com"), true);
    assert.equal(isPublicSuffix("us-east-1.compute.amazonaws.com"), true);
    assert.equal(isPublicSuffix("myhost.eu-west-1.compute.amazonaws.com"), false);
  });
});

describe("getRegistrableDomain — full Mozilla PSL coverage", () => {
  it("correctly resolves under multi-level ccSLDs", () => {
    assert.equal(getRegistrableDomain("www.nhs.gov.uk"), "nhs.gov.uk");
    assert.equal(getRegistrableDomain("service.digital.cabinet-office.gov.uk"), "cabinet-office.gov.uk");
  });

  it("correctly resolves under Japanese city wildcards with exceptions", () => {
    assert.equal(getRegistrableDomain("example.city.kawasaki.jp"), "city.kawasaki.jp");
    assert.equal(getRegistrableDomain("sub.example.city.kawasaki.jp"), "city.kawasaki.jp");
    assert.equal(getRegistrableDomain("bar.foo.kawasaki.jp"), "bar.foo.kawasaki.jp");
  });

  it("correctly resolves AWS compute hostnames", () => {
    assert.equal(getRegistrableDomain("i-1234.eu-west-1.compute.amazonaws.com"), "i-1234.eu-west-1.compute.amazonaws.com");
  });
});

describe("getRegistrableDomain", () => {
  it("extracts eTLD+1 for simple TLDs", () => {
    assert.equal(getRegistrableDomain("www.example.com"), "example.com");
    assert.equal(getRegistrableDomain("sub.domain.example.com"), "example.com");
    assert.equal(getRegistrableDomain("example.com"), "example.com");
  });

  it("extracts eTLD+1 for ccSLDs", () => {
    assert.equal(getRegistrableDomain("www.bbc.co.uk"), "bbc.co.uk");
    assert.equal(getRegistrableDomain("bbc.co.uk"), "bbc.co.uk");
    assert.equal(getRegistrableDomain("deep.sub.bbc.co.uk"), "bbc.co.uk");
  });

  it("extracts eTLD+1 for hosting suffixes", () => {
    assert.equal(getRegistrableDomain("myapp.github.io"), "myapp.github.io");
    assert.equal(getRegistrableDomain("sub.myapp.github.io"), "myapp.github.io");
    assert.equal(getRegistrableDomain("mysite.herokuapp.com"), "mysite.herokuapp.com");
  });

  it("returns null for public suffixes", () => {
    assert.equal(getRegistrableDomain("com"), null);
    assert.equal(getRegistrableDomain("co.uk"), null);
    assert.equal(getRegistrableDomain("github.io"), null);
  });

  it("returns null for single-label domains", () => {
    assert.equal(getRegistrableDomain("localhost"), null);
  });
});
