/**
 * Browser fingerprint database.
 *
 * Provides a unified lookup for all browser profiles by canonical name
 * (e.g. "chrome136", "firefox138", "safari_latest").
 */

import type { BrowserProfile } from './types.js';
import { chromeProfiles, chromeLatest } from './profiles/chrome.js';
import { firefoxProfiles, firefoxLatest } from './profiles/firefox.js';
import { safariProfiles, safariLatest } from './profiles/safari.js';
import { edgeProfiles, edgeLatest } from './profiles/edge.js';
import { torProfiles, torLatest } from './profiles/tor.js';

// ---- Merged database ----

const allProfiles = new Map<string, BrowserProfile>();

for (const source of [
  chromeProfiles,
  firefoxProfiles,
  safariProfiles,
  edgeProfiles,
  torProfiles,
]) {
  for (const [key, profile] of source) {
    allProfiles.set(key, profile);
  }
}

/**
 * Look up a browser profile by canonical name.
 *
 * Accepted formats:
 *   - Exact name: "chrome136", "firefox138"
 *   - Latest alias: "chrome_latest", "firefox_latest"
 *   - Family only: "chrome", "firefox" (resolves to latest)
 *
 * Returns `undefined` if no match is found.
 */
export function getProfile(name: string): BrowserProfile | undefined {
  const lower = name.toLowerCase().replace(/[-\s]/g, '');

  // Direct match
  const direct = allProfiles.get(lower);
  if (direct) return direct;

  // Family-only shorthand
  switch (lower) {
    case 'chrome':
      return chromeLatest;
    case 'firefox':
      return firefoxLatest;
    case 'safari':
      return safariLatest;
    case 'edge':
      return edgeLatest;
    case 'tor':
      return torLatest;
    default:
      return undefined;
  }
}

/**
 * List all available profile names.
 */
export function listProfiles(): string[] {
  return [...allProfiles.keys()].sort();
}

/** The default profile used when `impersonate` is set without a
 *  specific version. */
export const DEFAULT_PROFILE: BrowserProfile = chromeLatest;

// Re-exports for convenience
export { chromeLatest, firefoxLatest, safariLatest, edgeLatest, torLatest };
export type { BrowserProfile } from './types.js';
