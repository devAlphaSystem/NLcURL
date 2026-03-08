import type { H2Profile } from "./types.js";

/**
 * Generate an Akamai HTTP/2 fingerprint string.
 *
 * @param {H2Profile} profile - HTTP/2 connection profile.
 * @returns {string} Pipe-separated fingerprint of settings, window update, priority frames, and pseudo-header order.
 */
export function akamaiFingerprint(profile: H2Profile): string {
  const settings = profile.settings.map((s) => `${s.id}:${s.value}`).join(";");

  const wu = String(profile.windowUpdate);

  const priority = (profile.priorityFrames ?? []).map((f) => `${f.streamId}:${f.exclusive ? 1 : 0}:${f.dependsOn}:${f.weight}`).join(",");

  const pseudo = profile.pseudoHeaderOrder.join(",");

  return `${settings}|${wu}|${priority}|${pseudo}`;
}
