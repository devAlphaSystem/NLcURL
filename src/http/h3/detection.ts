/**
 * HTTP/3 (QUIC / RFC 9114) support module.
 *
 * Node.js does not currently expose a stable QUIC API. This module provides:
 * 1. Runtime detection of Node.js native QUIC support.
 * 2. Alt-Svc–based HTTP/3 discovery for upgrade from HTTP/2 or HTTP/1.1.
 * 3. A clear error when HTTP/3 is explicitly forced but unavailable.
 *
 * When the library discovers an Alt-Svc header advertising h3, it records the
 * alternative in the {@link AltSvcStore} so future requests to that origin can
 * attempt HTTP/3 when the runtime supports QUIC.
 *
 * When Node.js ships stable QUIC (behind `--experimental-quic` or natively),
 * this module will transparently use it.
 */
import { NLcURLError } from "../../core/errors.js";

/** Cached detection result to avoid repeated probes. */
let _quicAvailable: boolean | undefined;

/**
 * Checks whether the current Node.js runtime has QUIC/HTTP3 support available.
 *
 * @returns {boolean} `true` if the runtime exposes a usable QUIC API.
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
 * Throws a descriptive error when HTTP/3 is explicitly requested but not available.
 *
 * @throws {NLcURLError} Always, unless QUIC is available.
 */
export function assertQuicAvailable(): void {
  if (isQuicAvailable()) return;
  throw new NLcURLError("HTTP/3 (QUIC) is not available. Node.js does not currently provide a stable QUIC API. " + "Use httpVersion '1.1' or '2', or omit httpVersion to let the library negotiate automatically. " + "Alt-Svc discovery is active — when QUIC becomes available, HTTP/3 will be used automatically.", "ERR_H3_UNAVAILABLE");
}

/**
 * Resets the cached QUIC detection state. Used primarily for testing.
 */
export function resetQuicDetection(): void {
  _quicAvailable = undefined;
}
