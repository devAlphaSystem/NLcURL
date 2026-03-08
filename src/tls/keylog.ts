import { appendFileSync, existsSync } from "node:fs";
import { dirname } from "node:path";
import { mkdirSync } from "node:fs";

let _keylogFile: string | undefined;
let _initialized = false;

/**
 * Return the SSLKEYLOGFILE path from the environment or explicit override.
 *
 * @returns {string|undefined} File path string, or `undefined` if not configured.
 */
export function getKeylogFile(): string | undefined {
  if (!_initialized) {
    _initialized = true;
    _keylogFile = process.env["SSLKEYLOGFILE"];
  }
  return _keylogFile;
}

/**
 * Append a single NSS key-log line to the SSLKEYLOGFILE.
 *
 * @param {string} line - Key-log line without trailing newline.
 */
export function writeKeylogLine(line: string): void {
  const file = getKeylogFile();
  if (!file) return;

  try {
    const dir = dirname(file);
    if (!existsSync(dir)) {
      mkdirSync(dir, { recursive: true });
    }
    appendFileSync(file, line + "\n", { encoding: "utf-8" });
  } catch {}
}

/**
 * Log a TLS master secret in NSS key-log format.
 *
 * @param {Buffer} clientRandom - 32-byte client random from the handshake.
 * @param {Buffer} masterSecret - Derived master secret.
 */
export function logMasterSecret(clientRandom: Buffer, masterSecret: Buffer): void {
  writeKeylogLine(`CLIENT_RANDOM ${clientRandom.toString("hex")} ${masterSecret.toString("hex")}`);
}

/**
 * Log a TLS 1.3 traffic secret in NSS key-log format.
 *
 * @param {string} label - Secret label (e.g. `"CLIENT_HANDSHAKE_TRAFFIC_SECRET"`).
 * @param {Buffer} clientRandom - 32-byte client random.
 * @param {Buffer} secret - Derived traffic secret.
 */
export function logTrafficSecret(label: string, clientRandom: Buffer, secret: Buffer): void {
  writeKeylogLine(`${label} ${clientRandom.toString("hex")} ${secret.toString("hex")}`);
}

/**
 * Explicitly set or clear the SSLKEYLOGFILE path.
 *
 * @param {string|undefined} path - File path, or `undefined` to disable key logging.
 */
export function setKeylogFile(path: string | undefined): void {
  _keylogFile = path;
  _initialized = true;
}
