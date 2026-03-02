
import type { BrowserProfile } from './types.js';
import { chromeProfiles, chromeLatest } from './profiles/chrome.js';
import { firefoxProfiles, firefoxLatest } from './profiles/firefox.js';
import { safariProfiles, safariLatest } from './profiles/safari.js';
import { edgeProfiles, edgeLatest } from './profiles/edge.js';
import { torProfiles, torLatest } from './profiles/tor.js';

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
 * Looks up a browser profile by name, accepting flexible casing and separators.
 * Returns the latest version of the named browser when given a bare browser
 * family name (e.g. `"chrome"`, `"firefox"`).
 *
 * @param {string} name - Profile identifier such as `"chrome136"`, `"firefox"`, or `"safari"`. Case-insensitive; hyphens and spaces are ignored.
 * @returns {BrowserProfile|undefined} The matching profile, or `undefined` if no profile is registered under that name.
 *
 * @example
 * const profile = getProfile('chrome136');
 * const latest  = getProfile('chrome'); // resolves to the latest Chrome profile
 */
export function getProfile(name: string): BrowserProfile | undefined {
  const lower = name.toLowerCase().replace(/[-\s]/g, '');

  const direct = allProfiles.get(lower);
  if (direct) return direct;

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
 * Returns a sorted list of all registered browser profile identifiers
 * (e.g. `["chrome120", "chrome124", "firefox120", ...]`). Use these names
 * with {@link getProfile} or the `impersonate` request option.
 *
 * @returns {string[]} Alphabetically sorted array of profile names.
 */
export function listProfiles(): string[] {
  return [...allProfiles.keys()].sort();
}

/** The default browser profile used when no `impersonate` option is specified. Points to the latest bundled Chrome profile. */
export const DEFAULT_PROFILE: BrowserProfile = chromeLatest;

export { chromeLatest, firefoxLatest, safariLatest, edgeLatest, torLatest };
export type { BrowserProfile } from './types.js';
