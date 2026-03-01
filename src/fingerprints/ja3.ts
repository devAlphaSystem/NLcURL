/**
 * JA3 and JA3N fingerprint computation.
 *
 * JA3 hashes the TLS ClientHello parameters into a stable identifier
 * that fingerprint detection systems use to identify client software.
 *
 * JA3 format: SSLVersion,Ciphers,Extensions,EllipticCurves,EllipticCurvePointFormats
 * Each field is a dash-separated list of decimal values.
 *
 * GREASE values (RFC 8701) are excluded from the hash, matching the
 * canonical JA3 specification.
 */

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
 * Build the raw JA3 string from TLS profile parameters.
 *
 * The string is not hashed -- call `ja3Hash` for the MD5 digest.
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
 * Compute the JA3 hash (MD5 of the JA3 string).
 */
export function ja3Hash(profile: TLSProfile): string {
  return createHash('md5').update(ja3String(profile)).digest('hex');
}

/**
 * Compute JA3N (normalized) hash.
 *
 * JA3N sorts the cipher suites and extensions before hashing,
 * reducing sensitivity to ordering differences.
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

export function ja3nHash(profile: TLSProfile): string {
  return createHash('md5').update(ja3nString(profile)).digest('hex');
}
