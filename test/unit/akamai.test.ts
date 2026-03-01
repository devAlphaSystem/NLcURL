/**
 * Unit tests for the Akamai HTTP/2 fingerprint.
 */

import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { akamaiFingerprint } from '../../src/fingerprints/akamai.js';
import { getProfile } from '../../src/fingerprints/database.js';

describe('akamaiFingerprint', () => {
  it('returns a string for Chrome profile', () => {
    const profile = getProfile('chrome');
    assert.ok(profile);
    const fp = akamaiFingerprint(profile.h2);
    assert.ok(typeof fp === 'string');
    assert.ok(fp.length > 0);
  });

  it('returns a string for Firefox profile', () => {
    const profile = getProfile('firefox');
    assert.ok(profile);
    const fp = akamaiFingerprint(profile.h2);
    assert.ok(typeof fp === 'string');
    assert.ok(fp.length > 0);
  });

  it('is deterministic', () => {
    const profile = getProfile('chrome');
    assert.ok(profile);
    assert.equal(akamaiFingerprint(profile.h2), akamaiFingerprint(profile.h2));
  });

  it('differs between Chrome and Firefox', () => {
    const chrome = getProfile('chrome');
    const firefox = getProfile('firefox');
    assert.ok(chrome);
    assert.ok(firefox);
    assert.notEqual(akamaiFingerprint(chrome.h2), akamaiFingerprint(firefox.h2));
  });
});
