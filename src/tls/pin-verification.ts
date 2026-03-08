import { createHash, X509Certificate } from "node:crypto";
import { TLSError } from "../core/errors.js";

/**
 * Verify that a certificate's SPKI hash matches at least one expected pin.
 *
 * Throws a {@link TLSError} if no pin matches.
 *
 * @param {Buffer} certDer - DER-encoded X.509 certificate.
 * @param {string|string[]} pins - One or more `sha256//` base64-encoded SPKI pins.
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
