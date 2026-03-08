import type { BrowserProfile, HeaderProfile } from "../types.js";
import { chromeProfiles } from "./chrome.js";

function edgeHeaders(edgeVersion: string, chromiumVersion: string): HeaderProfile {
  const ua = `Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/${chromiumVersion} Safari/537.36 Edg/${edgeVersion}`;
  const major = edgeVersion.split(".")[0];
  const chromeMajor = chromiumVersion.split(".")[0];
  return {
    userAgent: ua,
    headers: [
      ["sec-ch-ua-platform", '"Windows"'],
      ["user-agent", ua],
      ["sec-ch-ua", `"Chromium";v="${chromeMajor}", "Not=A?Brand";v="8", "Microsoft Edge";v="${major}"`],
      ["sec-ch-ua-mobile", "?0"],
      ["accept", "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7"],
      ["sec-fetch-site", "none"],
      ["sec-fetch-mode", "navigate"],
      ["sec-fetch-user", "?1"],
      ["sec-fetch-dest", "document"],
      ["accept-encoding", "gzip, deflate, br, zstd"],
      ["accept-language", "en-US,en;q=0.9"],
    ],
  };
}

function edgeProfile(name: string, edgeVersion: string, chromiumVersion: string, baseChromeName: string): BrowserProfile {
  const base = chromeProfiles.get(baseChromeName);
  if (!base) {
    throw new Error(`Base Chrome profile "${baseChromeName}" not found for Edge profile "${name}".`);
  }
  return {
    name,
    browser: "edge",
    version: edgeVersion,
    tls: base.tls,
    h2: base.h2,
    headers: edgeHeaders(edgeVersion, chromiumVersion),
  };
}

/** Edge 99 browser fingerprint profile. */
export const edge99 = edgeProfile("edge99", "99.0.1150.30", "99.0.4844.51", "chrome99");
/** Edge 101 browser fingerprint profile. */
export const edge101 = edgeProfile("edge101", "101.0.1210.39", "101.0.4951.67", "chrome101");
/** Edge 126 browser fingerprint profile. */
export const edge126 = edgeProfile("edge126", "126.0.2592.56", "126.0.6478.55", "chrome126");
/** Edge 131 browser fingerprint profile. */
export const edge131 = edgeProfile("edge131", "131.0.2903.63", "131.0.6778.86", "chrome131");
/** Edge 136 browser fingerprint profile. */
export const edge136 = edgeProfile("edge136", "136.0.3240.50", "136.0.7103.92", "chrome136");

/** Alias for the most recent Edge profile. */
export const edgeLatest = edge136;

/** Map of all available Edge profiles keyed by name. */
export const edgeProfiles: ReadonlyMap<string, BrowserProfile> = new Map([
  ["edge99", edge99],
  ["edge101", edge101],
  ["edge126", edge126],
  ["edge131", edge131],
  ["edge136", edge136],
  ["edge_latest", edge136],
]);
