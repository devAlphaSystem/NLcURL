/**
 * Akamai HTTP/2 fingerprint computation.
 *
 * The Akamai fingerprint identifies HTTP/2 clients based on:
 *   S[id:value;...]|WU[value]|P[frames...]|PS[order]
 *
 * - S: SETTINGS frame parameters (id:value pairs, semicolon-separated)
 * - WU: WINDOW_UPDATE value
 * - P: PRIORITY frames (not used by most modern browsers)
 * - PS: Pseudo-header order
 */

import type { H2Profile } from './types.js';

/**
 * Build the Akamai HTTP/2 fingerprint string from an H2 profile.
 */
export function akamaiFingerprint(profile: H2Profile): string {
  // Settings section
  const settings = profile.settings
    .map((s) => `${s.id}:${s.value}`)
    .join(';');

  // Window update section
  const wu = String(profile.windowUpdate);

  // Priority frames section
  const priority = (profile.priorityFrames ?? [])
    .map(
      (f) =>
        `${f.streamId}:${f.exclusive ? 1 : 0}:${f.dependsOn}:${f.weight}`,
    )
    .join(',');

  // Pseudo-header order section
  const pseudo = profile.pseudoHeaderOrder.join(',');

  return `${settings}|${wu}|${priority}|${pseudo}`;
}
