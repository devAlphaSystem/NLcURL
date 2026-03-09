/**
 * Subresource Integrity (SRI) verification per W3C spec.
 * https://www.w3.org/TR/SRI/
 */
import { createHash } from "node:crypto";

const SRI_REGEX = /^(sha256|sha384|sha512)-([A-Za-z0-9+/=]+)$/;

/**
 * Verify that a response body matches a Subresource Integrity hash.
 *
 * @param body - The response body buffer.
 * @param integrity - SRI string (e.g. "sha256-Base64Hash==").
 * @returns true if the body matches the integrity hash.
 */
export function verifyIntegrity(body: Buffer, integrity: string): boolean {
  const parts = integrity.trim().split(/\s+/);

  for (const part of parts) {
    const match = SRI_REGEX.exec(part);
    if (!match) continue;
    const algo = match[1]!;
    const expected = match[2]!;
    const actual = createHash(algo).update(body).digest("base64");
    if (actual === expected) return true;
  }

  return false;
}
