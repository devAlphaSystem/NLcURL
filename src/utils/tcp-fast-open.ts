import { platform } from "node:os";

/**
 * Check whether TCP Fast Open is supported on the current platform.
 *
 * @returns {boolean} `true` on Linux and macOS.
 */
export function isTFOSupported(): boolean {
  const os = platform();
  return os === "linux" || os === "darwin";
}

/** Configuration for TCP Fast Open (TFO). */
export interface TFOOptions {
  /** Enable TCP Fast Open for the connection. */
  enabled?: boolean;
  /** Data to send during the TCP handshake. */
  connectData?: Buffer;
}

/**
 * Build socket creation options for TCP Fast Open.
 *
 * @param {TFOOptions} [tfo] - TFO configuration.
 * @returns {Record<string, unknown>} Options object to merge into socket creation.
 */
export function buildTFOSocketOptions(tfo?: TFOOptions): Record<string, unknown> {
  if (!tfo?.enabled || !isTFOSupported()) {
    return {};
  }

  return {
    fastOpen: true,
  };
}

/**
 * Return the current TFO support status and platform name.
 *
 * @returns {{ supported: boolean; platform: string }} Object with `supported` flag and `platform` string.
 */
export function getTFOStatus(): { supported: boolean; platform: string } {
  return {
    supported: isTFOSupported(),
    platform: platform(),
  };
}
