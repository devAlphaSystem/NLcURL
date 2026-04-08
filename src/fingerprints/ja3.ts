import { createHash } from "node:crypto";
import { GREASE_VALUES } from "../tls/constants.js";
import type { TLSProfile } from "./types.js";

const GREASE_SET: ReadonlySet<number> = new Set(GREASE_VALUES);

function isGrease(value: number): boolean {
  return GREASE_SET.has(value);
}

function filterGrease(values: number[]): number[] {
  return values.filter((v) => !isGrease(v));
}

const ja3Cache = new WeakMap<TLSProfile, string>();

/**
 * Generate a JA3 fingerprint string from a TLS profile.
 *
 * @param {TLSProfile} profile - TLS profile to fingerprint.
 * @returns {string} Comma-separated JA3 string of version, ciphers, extensions, groups, and point formats.
 */
export function ja3String(profile: TLSProfile): string {
  const cached = ja3Cache.get(profile);
  if (cached !== undefined) return cached;

  const version = profile.clientVersion;
  const ciphers = filterGrease(profile.cipherSuites).join("-");
  const extensions = filterGrease(profile.extensions.map((e) => e.type)).join("-");
  const groups = filterGrease(profile.supportedGroups).join("-");
  const formats = (profile.ecPointFormats ?? []).join("-");

  const result = `${version},${ciphers},${extensions},${groups},${formats}`;
  ja3Cache.set(profile, result);
  return result;
}

/**
 * Compute the MD5 hash of the JA3 fingerprint string.
 *
 * @param {TLSProfile} profile - TLS profile to fingerprint.
 * @returns {string} Hex-encoded MD5 digest.
 */
export function ja3Hash(profile: TLSProfile): string {
  return createHash("md5").update(ja3String(profile)).digest("hex");
}
