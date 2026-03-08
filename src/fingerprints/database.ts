import type { BrowserProfile } from "./types.js";
import { chromeProfiles, chromeLatest } from "./profiles/chrome.js";
import { firefoxProfiles, firefoxLatest } from "./profiles/firefox.js";
import { safariProfiles, safariLatest } from "./profiles/safari.js";
import { edgeProfiles, edgeLatest } from "./profiles/edge.js";
import { torProfiles, torLatest } from "./profiles/tor.js";

const allProfiles = new Map<string, BrowserProfile>();

for (const source of [chromeProfiles, firefoxProfiles, safariProfiles, edgeProfiles, torProfiles]) {
  for (const [key, profile] of source) {
    allProfiles.set(key, profile);
  }
}

/**
 * Retrieve a browser profile by name.
 *
 * @param {string} name - Profile name (case-insensitive, dashes and spaces ignored).
 * @returns {BrowserProfile|undefined} Matching browser profile, or `undefined` if not found.
 */
export function getProfile(name: string): BrowserProfile | undefined {
  const lower = name.toLowerCase().replace(/[-\s]/g, "");

  const direct = allProfiles.get(lower);
  if (direct) return direct;

  switch (lower) {
    case "chrome":
      return chromeLatest;
    case "firefox":
      return firefoxLatest;
    case "safari":
      return safariLatest;
    case "edge":
      return edgeLatest;
    case "tor":
      return torLatest;
    default:
      return undefined;
  }
}

/**
 * List all available browser profile names.
 *
 * @returns {string[]} Sorted array of profile name strings.
 */
export function listProfiles(): string[] {
  return [...allProfiles.keys()].sort();
}

/** Default browser profile used when none is specified. */
export const DEFAULT_PROFILE: BrowserProfile = chromeLatest;

export { chromeLatest, firefoxLatest, safariLatest, edgeLatest, torLatest };
export type { BrowserProfile } from "./types.js";
