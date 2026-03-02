
import { createHash } from 'node:crypto';
import { GREASE_VALUES } from '../tls/constants.js';
import type { TLSProfile } from './types.js';

const GREASE_SET: ReadonlySet<number> = new Set(GREASE_VALUES);

function isGrease(value: number): boolean {
  return GREASE_SET.has(value);
}

function filterGrease(values: number[]): number[] {
  return values.filter((v) => !isGrease(v));
}

/**
 * Computes the JA3 string representation of a TLS profile. The string is a
 * comma-separated tuple of `version`, cipher codes, extension type codes,
 * supported-group codes, and EC point format codes, all encoded as
 * dash-separated decimal lists (GREASE values filtered out).
 *
 * @param {TLSProfile} profile - The TLS profile to fingerprint.
 * @returns {string} The JA3 fingerprint string.
 *
 * @example
 * const str = ja3String(chromeLatest.tls);
 * // => "771,4865-4866-...,0-23-...,29-23-24,0"
 */
export function ja3String(profile: TLSProfile): string {
  const version = profile.clientVersion;
  const ciphers = filterGrease(profile.cipherSuites).join('-');
  const extensions = filterGrease(
    profile.extensions.map((e) => e.type),
  ).join('-');
  const groups = filterGrease(profile.supportedGroups).join('-');
  const formats = (profile.ecPointFormats ?? []).join('-');

  return `${version},${ciphers},${extensions},${groups},${formats}`;
}

/**
 * Computes the MD5 hash of the JA3 string for the given TLS profile.
 * The resulting 32-character hex digest is the canonical JA3 fingerprint
 * used in network monitoring and fingerprinting detection.
 *
 * @param {TLSProfile} profile - The TLS profile to fingerprint.
 * @returns {string} The 32-character lowercase hex JA3 MD5 hash.
 *
 * @example
 * const hash = ja3Hash(chromeLatest.tls);
 * // => "cd08e31494f9531f560d64c695473da9"
 */
export function ja3Hash(profile: TLSProfile): string {
  return createHash('md5').update(ja3String(profile)).digest('hex');
}

/**
 * Computes the JA3N (normalised) string for a TLS profile. Unlike
 * {@link ja3String}, all numeric lists are sorted before joining, which
 * makes the fingerprint order-independent and useful for comparing profiles
 * that advertise the same capabilities in different orders.
 *
 * @param {TLSProfile} profile - The TLS profile to fingerprint.
 * @returns {string} The JA3N fingerprint string with sorted field lists.
 */
export function ja3nString(profile: TLSProfile): string {
  const version = profile.clientVersion;
  const ciphers = filterGrease(profile.cipherSuites)
    .sort((a, b) => a - b)
    .join('-');
  const extensions = filterGrease(
    profile.extensions.map((e) => e.type),
  )
    .sort((a, b) => a - b)
    .join('-');
  const groups = filterGrease(profile.supportedGroups)
    .sort((a, b) => a - b)
    .join('-');
  const formats = (profile.ecPointFormats ?? []).sort((a, b) => a - b).join('-');

  return `${version},${ciphers},${extensions},${groups},${formats}`;
}

/**
 * Computes the MD5 hash of the JA3N (normalised) string for the given TLS
 * profile. JA3N hashes are order-independent, making them suitable for
 * grouping profiles by capability set regardless of advertisement order.
 *
 * @param {TLSProfile} profile - The TLS profile to fingerprint.
 * @returns {string} The 32-character lowercase hex JA3N MD5 hash.
 */
export function ja3nHash(profile: TLSProfile): string {
  return createHash('md5').update(ja3nString(profile)).digest('hex');
}
