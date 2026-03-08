import { NLcURLError } from "../../core/errors.js";

let _quicAvailable: boolean | undefined;

/**
 * Check whether the Node.js runtime supports QUIC (HTTP/3).
 *
 * @returns `true` if QUIC support is detected.
 */
export function isQuicAvailable(): boolean {
  if (_quicAvailable !== undefined) return _quicAvailable;

  _quicAvailable = false;
  try {
    const quic = (globalThis as Record<string, unknown>)["__quic"];
    if (quic) {
      _quicAvailable = true;
      return true;
    }

    const net = require("node:net");
    if (typeof net.createQuicSocket === "function") {
      _quicAvailable = true;
      return true;
    }
  } catch {}
  return false;
}

/**
 * Assert that QUIC is available, throwing if not.
 *
 * @throws {NLcURLError} If QUIC support is not detected.
 */
export function assertQuicAvailable(): void {
  if (isQuicAvailable()) return;
  throw new NLcURLError("HTTP/3 (QUIC) is not available. Node.js does not currently provide a stable QUIC API. " + "Use httpVersion '1.1' or '2', or omit httpVersion to let the library negotiate automatically. " + "Alt-Svc discovery is active — when QUIC becomes available, HTTP/3 will be used automatically.", "ERR_H3_UNAVAILABLE");
}

/** Reset the cached QUIC availability detection result. */
export function resetQuicDetection(): void {
  _quicAvailable = undefined;
}
