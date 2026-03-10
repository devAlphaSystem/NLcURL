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

function ja4Version(versions: number[]): string {
  const filtered = filterGrease(versions);
  if (filtered.includes(0x0304)) return "13";
  if (filtered.includes(0x0303)) return "12";
  if (filtered.includes(0x0302)) return "11";
  if (filtered.includes(0x0301)) return "10";
  return "00";
}

function ja4Alpn(alpnProtocols: string[]): string {
  if (alpnProtocols.length === 0) return "00";
  const first = alpnProtocols[0]!;
  if (first === "h2") return "h2";
  if (first === "http/1.1") return "h1";
  return first.substring(0, 2);
}

function ja4a(profile: TLSProfile, hasSNI: boolean = true): string {
  const transport = "t";
  const version = ja4Version(profile.supportedVersions);
  const sni = hasSNI ? "d" : "i";
  const ciphers = filterGrease(profile.cipherSuites);
  const extensions = filterGrease(profile.extensions.map((e) => e.type));
  const cipherCount = String(Math.min(ciphers.length, 99)).padStart(2, "0");
  const extCount = String(Math.min(extensions.length, 99)).padStart(2, "0");
  const alpn = ja4Alpn(profile.alpnProtocols);

  return `${transport}${version}${sni}${cipherCount}${extCount}_${alpn}`;
}

function ja4b(profile: TLSProfile): string {
  const ciphers = filterGrease(profile.cipherSuites);
  const sorted = [...ciphers].sort((a, b) => a - b);
  const str = sorted.map((c) => c.toString(16).padStart(4, "0")).join(",");
  return createHash("sha256").update(str).digest("hex").substring(0, 12);
}

function ja4c(profile: TLSProfile): string {
  const extensions = filterGrease(profile.extensions.map((e) => e.type));
  const sorted = [...extensions].sort((a, b) => a - b);
  const extStr = sorted.map((e) => e.toString(16).padStart(4, "0")).join(",");

  const sigAlgs = profile.signatureAlgorithms;
  const sigStr = sigAlgs.map((s) => s.toString(16).padStart(4, "0")).join(",");

  const combined = `${extStr}_${sigStr}`;
  return createHash("sha256").update(combined).digest("hex").substring(0, 12);
}

const ja4Cache = new WeakMap<TLSProfile, Map<boolean, string>>();

/**
 * Generate a complete JA4 fingerprint string.
 *
 * @param {TLSProfile} profile - TLS profile to fingerprint.
 * @param {boolean} hasSNI - Whether the ClientHello includes a Server Name Indication extension.
 * @returns {string} JA4 fingerprint in the format `{a}_{b}_{c}`.
 */
export function ja4Fingerprint(profile: TLSProfile, hasSNI: boolean = true): string {
  let sniMap = ja4Cache.get(profile);
  if (sniMap) {
    const cached = sniMap.get(hasSNI);
    if (cached !== undefined) return cached;
  } else {
    sniMap = new Map();
    ja4Cache.set(profile, sniMap);
  }
  const a = ja4a(profile, hasSNI);
  const b = ja4b(profile);
  const c = ja4c(profile);
  const result = `${a}_${b}_${c}`;
  sniMap.set(hasSNI, result);
  return result;
}

/**
 * Generate only the JA4a section of the fingerprint.
 *
 * @param {TLSProfile} profile - TLS profile to fingerprint.
 * @param {boolean} hasSNI - Whether the ClientHello includes a Server Name Indication extension.
 * @returns {string} JA4a section string containing transport, version, SNI, counts, and ALPN.
 */
export function ja4aSection(profile: TLSProfile, hasSNI: boolean = true): string {
  return ja4a(profile, hasSNI);
}
