/**
 * Certificate public key pinning (RFC 7469 concept, curl-style format).
 *
 * Verifies that a server's leaf certificate matches one of a set of
 * SHA-256 hashes computed over the DER-encoded Subject Public Key Info
 * (SPKI). Pin format: `"sha256//base64hash"` (same as curl `--pinnedpubkey`).
 */
import { createHash, X509Certificate } from "node:crypto";
import { TLSError } from "../core/errors.js";

/**
 * Verifies that the leaf certificate's SPKI SHA-256 hash matches at least
 * one of the supplied pins. Throws {@link TLSError} on mismatch.
 *
 * @param certDer  DER-encoded leaf certificate bytes.
 * @param pins     One or more pins in `"sha256//base64hash"` format.
 */
export function verifyPinnedPublicKey(certDer: Buffer, pins: string | string[]): void {
  const pinArray = typeof pins === "string" ? [pins] : pins;
  if (pinArray.length === 0) return;

  const x509 = new X509Certificate(certDer);
  const spki = Buffer.from(x509.publicKey.export({ type: "spki", format: "der" }));
  const hash = createHash("sha256").update(spki).digest("base64");
  const certPin = `sha256//${hash}`;

  const matches = pinArray.some((pin) => {
    if (!pin.startsWith("sha256//")) return false;
    return pin === certPin;
  });

  if (!matches) {
    throw new TLSError(`Certificate public key pin mismatch. Server pin: ${certPin}`);
  }
}
