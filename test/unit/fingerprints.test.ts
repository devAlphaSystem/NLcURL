import { describe, it } from "node:test";
import assert from "node:assert/strict";
import { getProfile, listProfiles, DEFAULT_PROFILE } from "../../src/fingerprints/database.js";
import type { BrowserProfile } from "../../src/fingerprints/types.js";

describe("listProfiles", () => {
  it("returns a non-empty array of profile names", () => {
    const profiles = listProfiles();
    assert.ok(Array.isArray(profiles));
    assert.ok(profiles.length > 0, "Should have at least one profile");
  });

  it("contains expected browser families", () => {
    const profiles = listProfiles();
    const names = profiles.join(",");
    assert.ok(names.includes("chrome"), "Should include Chrome profiles");
    assert.ok(names.includes("firefox"), "Should include Firefox profiles");
    assert.ok(names.includes("safari"), "Should include Safari profiles");
  });
});

describe("getProfile", () => {
  it('returns a profile for "chrome"', () => {
    const profile = getProfile("chrome");
    assert.ok(profile);
    assertValidProfile(profile);
  });

  it('returns a profile for "firefox"', () => {
    const profile = getProfile("firefox");
    assert.ok(profile);
    assertValidProfile(profile);
  });

  it('returns a profile for "safari"', () => {
    const profile = getProfile("safari");
    assert.ok(profile);
    assertValidProfile(profile);
  });

  it('returns a profile for "edge"', () => {
    const profile = getProfile("edge");
    assert.ok(profile);
    assertValidProfile(profile);
  });

  it('returns a profile for "tor"', () => {
    const profile = getProfile("tor");
    assert.ok(profile);
    assertValidProfile(profile);
  });

  it("returns undefined for unknown profile", () => {
    const profile = getProfile("nonexistent-browser-999");
    assert.equal(profile, undefined);
  });

  it("is case and separator insensitive", () => {
    const a = getProfile("chrome");
    const b = getProfile("Chrome");
    const c = getProfile("CHROME");
    assert.ok(a);
    assert.ok(b);
    assert.ok(c);
    assert.deepEqual(a.tls.cipherSuites, b.tls.cipherSuites);
    assert.deepEqual(b.tls.cipherSuites, c.tls.cipherSuites);
  });
});

describe("DEFAULT_PROFILE", () => {
  it("is a valid profile", () => {
    assert.ok(DEFAULT_PROFILE);
    assertValidProfile(DEFAULT_PROFILE);
  });
});

describe("profile structure", () => {
  const profiles = listProfiles();

  for (const name of profiles) {
    it(`${name} has valid TLS config`, () => {
      const p = getProfile(name);
      assert.ok(p, `Profile ${name} should exist`);
      assertValidProfile(p);
    });
  }
});

function assertValidProfile(p: BrowserProfile): void {
  assert.ok(p.tls, "Should have tls config");
  assert.ok(p.tls.cipherSuites.length > 0, "Should have cipher suites");
  assert.ok(p.tls.supportedGroups.length > 0, "Should have supported groups");
  assert.ok(p.tls.extensions.length > 0, "Should have extensions");
  assert.ok(p.tls.signatureAlgorithms.length > 0, "Should have signature algorithms");
  assert.ok(p.tls.alpnProtocols.length > 0, "Should have ALPN protocols");
  assert.ok(typeof p.tls.clientVersion === "number", "clientVersion should be a number");
  assert.ok(typeof p.tls.recordVersion === "number", "recordVersion should be a number");

  assert.ok(p.h2, "Should have h2 config");
  assert.ok(Array.isArray(p.h2.settings), "h2 settings should be an array");
  assert.ok(p.h2.settings.length > 0, "h2 should have at least one setting");
  assert.ok(typeof p.h2.windowUpdate === "number", "windowUpdate should be a number");
  assert.ok(Array.isArray(p.h2.pseudoHeaderOrder), "pseudoHeaderOrder should be an array");

  assert.ok(p.headers, "Should have headers config");
  assert.ok(typeof p.headers.userAgent === "string");
  assert.ok(p.headers.userAgent.length > 0, "User agent should not be empty");
}
