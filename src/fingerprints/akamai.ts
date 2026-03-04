import type { H2Profile } from "./types.js";

/**
 * Computes the Akamai HTTP/2 fingerprint string for a browser profile. The
 * string encodes the SETTINGS frame parameters, connection window update,
 * optional PRIORITY frame configuration, and pseudo-header ordering,
 * separated by pipe characters (`|`).
 *
 * @param {H2Profile} profile - The HTTP/2 profile to fingerprint.
 * @returns {string} The Akamai fingerprint string in the format
 *   `"S1:V1;S2:V2|WU|P1:E1:D1:W1,...|:method,:path,..."`.
 *
 * @example
 * const fp = akamaiFingerprint(chromeLatest.h2);
 * // => "1:65536;2:0;3:1000;4:6291456;6:262144|15663105|0:0:0:255|m,p,a,s"
 */
export function akamaiFingerprint(profile: H2Profile): string {
  const settings = profile.settings.map((s) => `${s.id}:${s.value}`).join(";");

  const wu = String(profile.windowUpdate);

  const priority = (profile.priorityFrames ?? []).map((f) => `${f.streamId}:${f.exclusive ? 1 : 0}:${f.dependsOn}:${f.weight}`).join(",");

  const pseudo = profile.pseudoHeaderOrder.join(",");

  return `${settings}|${wu}|${priority}|${pseudo}`;
}
