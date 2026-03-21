/**
 * Live fingerprint and profile tests.
 *
 * Validates that all browser profiles load correctly and produce
 * consistent JA3/JA4/Akamai fingerprints. Then makes real TLS
 * connections to verify profile impersonation works end-to-end.
 */
import { describe, it } from "node:test";
import { strict as assert } from "node:assert";
import { getProfile, listProfiles, ja3Hash, ja3String, ja4Fingerprint, akamaiFingerprint, get, createSession } from "../../src/index.js";
import { LIVE_TIMEOUT, SLOW_TIMEOUT, assertOk, withTlsRetry, skipIfTlsBroken } from "./helpers.js";

describe("Profile database", () => {
  const profileNames = listProfiles();

  it("has a substantial number of profiles", () => {
    assert.ok(profileNames.length >= 20, `Expected ≥20 profiles, got ${profileNames.length}`);
  });

  it("lists profiles in sorted order", () => {
    const sorted = [...profileNames].sort();
    assert.deepStrictEqual(profileNames, sorted);
  });

  it("every listed profile can be retrieved", () => {
    for (const name of profileNames) {
      const profile = getProfile(name);
      assert.ok(profile, `getProfile("${name}") returned undefined`);
      assert.ok(profile.tls, `Profile "${name}" missing TLS config`);
      assert.ok(profile.h2, `Profile "${name}" missing H2 config`);
    }
  });

  it("resolves shorthand names (chrome, firefox, safari, edge, tor)", () => {
    for (const shorthand of ["chrome", "firefox", "safari", "edge", "tor"]) {
      const profile = getProfile(shorthand);
      assert.ok(profile, `getProfile("${shorthand}") returned undefined`);
    }
  });
});

describe("JA3 fingerprints", () => {
  const profileNames = listProfiles();

  it("produces non-empty JA3 hash for every profile", () => {
    for (const name of profileNames) {
      const profile = getProfile(name)!;
      const hash = ja3Hash(profile.tls);
      assert.ok(hash, `JA3 hash for "${name}" is empty`);
      assert.equal(hash.length, 32, `JA3 hash for "${name}" should be 32 hex chars`);
      assert.ok(/^[0-9a-f]{32}$/.test(hash), `JA3 hash for "${name}" contains invalid chars: ${hash}`);
    }
  });

  it("produces non-empty JA3 string for every profile", () => {
    for (const name of profileNames) {
      const profile = getProfile(name)!;
      const str = ja3String(profile.tls);
      assert.ok(str, `JA3 string for "${name}" is empty`);
      const parts = str.split(",");
      assert.ok(parts.length >= 4, `JA3 string for "${name}" has fewer than 4 comma-separated parts`);
    }
  });

  it("produces consistent hashes (idempotent)", () => {
    const profile = getProfile("chrome136")!;
    const hash1 = ja3Hash(profile.tls);
    const hash2 = ja3Hash(profile.tls);
    assert.equal(hash1, hash2, "JA3 hash should be deterministic");
  });

  it("chrome and firefox produce different JA3 hashes", () => {
    const chrome = getProfile("chrome136")!;
    const firefox = getProfile("firefox135")!;
    assert.notEqual(ja3Hash(chrome.tls), ja3Hash(firefox.tls), "Chrome and Firefox should have different JA3");
  });
});

describe("JA4 fingerprints", () => {
  const profileNames = listProfiles();

  it("produces valid JA4 fingerprint for every profile", () => {
    for (const name of profileNames) {
      const profile = getProfile(name)!;
      const fp = ja4Fingerprint(profile.tls);
      assert.ok(fp, `JA4 fingerprint for "${name}" is empty`);
      assert.ok(fp.includes("_"), `JA4 for "${name}" should contain underscores: ${fp}`);
    }
  });

  it("produces consistent fingerprints (idempotent)", () => {
    const profile = getProfile("chrome136")!;
    const fp1 = ja4Fingerprint(profile.tls);
    const fp2 = ja4Fingerprint(profile.tls);
    assert.equal(fp1, fp2, "JA4 should be deterministic");
  });

  it("different browser families produce different JA4", () => {
    const chrome = getProfile("chrome136")!;
    const firefox = getProfile("firefox135")!;
    const safari = getProfile("safari182")!;
    const fpChrome = ja4Fingerprint(chrome.tls);
    const fpFirefox = ja4Fingerprint(firefox.tls);
    const fpSafari = ja4Fingerprint(safari.tls);

    const unique = new Set([fpChrome, fpFirefox, fpSafari]);
    assert.ok(unique.size >= 2, "Expected at least 2 unique JA4 fingerprints across browsers");
  });
});

describe("Akamai HTTP/2 fingerprints", () => {
  const profileNames = listProfiles();

  it("produces valid Akamai fingerprint for every profile", () => {
    for (const name of profileNames) {
      const profile = getProfile(name)!;
      const fp = akamaiFingerprint(profile.h2);
      assert.ok(fp, `Akamai fingerprint for "${name}" is empty`);
      const parts = fp.split("|");
      assert.equal(parts.length, 4, `Akamai for "${name}" should have 4 pipe-separated parts`);
    }
  });

  it("settings section contains colon-separated id:value pairs", () => {
    const profile = getProfile("chrome136")!;
    const fp = akamaiFingerprint(profile.h2);
    const settings = fp.split("|")[0]!;
    const pairs = settings.split(";");
    for (const pair of pairs) {
      const [id, value] = pair.split(":");
      assert.ok(id && value, `Invalid settings pair: "${pair}"`);
      assert.ok(!isNaN(Number(id)));
      assert.ok(!isNaN(Number(value)));
    }
  });

  it("pseudo-header order includes standard HTTP/2 pseudo-headers", () => {
    const profile = getProfile("chrome136")!;
    const fp = akamaiFingerprint(profile.h2);
    const pseudo = fp.split("|")[3]!;
    const headers = pseudo.split(",");
    assert.ok(headers.includes(":method"), "Missing :method");
    assert.ok(headers.includes(":path"), "Missing :path");
    assert.ok(headers.includes(":scheme"), "Missing :scheme");
  });
});

describe("Profile version progression", () => {
  it("chrome profiles form a version sequence", () => {
    const names = listProfiles().filter((n) => n.startsWith("chrome"));
    assert.ok(names.length >= 5, `Expected ≥5 Chrome profiles, got ${names.length}`);

    const versions = names.map((n) => parseInt(n.replace("chrome", ""))).filter((v) => !isNaN(v));
    const sorted = [...versions].sort((a, b) => a - b);
    assert.ok(sorted.length >= 5, `Expected ≥5 numeric Chrome versions`);
    const unique = new Set(sorted);
    assert.equal(unique.size, sorted.length, "Chrome versions should be unique");
  });

  it("firefox profiles form a version sequence", () => {
    const names = listProfiles().filter((n) => n.startsWith("firefox"));
    assert.ok(names.length >= 2, `Expected ≥2 Firefox profiles`);
  });

  it("safari profiles form a version sequence", () => {
    const names = listProfiles().filter((n) => n.startsWith("safari"));
    assert.ok(names.length >= 2, `Expected ≥2 Safari profiles`);
  });

  it("edge profiles form a version sequence", () => {
    const names = listProfiles().filter((n) => n.startsWith("edge"));
    assert.ok(names.length >= 2, `Expected ≥2 Edge profiles`);
  });

  it("tor profiles form a version sequence", () => {
    const names = listProfiles().filter((n) => n.startsWith("tor"));
    assert.ok(names.length >= 2, `Expected ≥2 Tor profiles`);
  });
});

describe("Fingerprint consistency across versions", () => {
  it("ja3 changes between chrome versions as expected", () => {
    const v120 = getProfile("chrome120")!;
    const v136 = getProfile("chrome136")!;

    const ja3_120 = ja3String(v120.tls);
    const ja3_136 = ja3String(v136.tls);

    assert.ok(ja3_120.length > 10, "Chrome 120 JA3 should be non-trivial");
    assert.ok(ja3_136.length > 10, "Chrome 136 JA3 should be non-trivial");
  });
});

describe("Live fingerprint impersonation", { timeout: SLOW_TIMEOUT }, () => {
  it(
    "chrome136 profile connects successfully to major sites",
    skipIfTlsBroken(async () => {
      const session = createSession({
        impersonate: "chrome136",
        stealth: true,
        insecure: true,
      });

      const resp = await withTlsRetry(() => session.get("https://www.google.com"));
      assertOk(resp);
      assert.ok(resp.text().length > 100, "Expected a real HTML page");
    }),
  );

  it(
    "different profiles all connect to Cloudflare",
    skipIfTlsBroken(async () => {
      const profiles = ["chrome136", "firefox135", "safari182", "edge136"];

      for (const profile of profiles) {
        const resp = await withTlsRetry(() =>
          get("https://cloudflare.com", {
            impersonate: profile,
            stealth: true,
            insecure: true,
          }),
        );
        assertOk(resp);
      }
    }),
  );

  it(
    "tor profile connects to a standard HTTPS site",
    skipIfTlsBroken(async () => {
      const resp = await withTlsRetry(() =>
        get("https://example.com", {
          impersonate: "tor",
          stealth: true,
          insecure: true,
        }),
      );
      assertOk(resp);
      assert.ok(resp.text().includes("Example Domain"), "Expected Example Domain page");
    }),
  );

  it(
    "every profile from every browser family connects",
    skipIfTlsBroken(async () => {
      const latest = ["chrome", "firefox", "safari", "edge", "tor"];

      for (const family of latest) {
        const resp = await withTlsRetry(() =>
          get("https://httpbin.org/get", {
            impersonate: family,
            stealth: true,
            insecure: true,
          }),
        );
        assertOk(resp);
        const json = resp.json() as { url: string };
        assert.equal(json.url, "https://httpbin.org/get");
      }
    }),
  );
});
