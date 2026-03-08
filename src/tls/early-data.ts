const SAFE_EARLY_DATA_METHODS = new Set(["GET", "HEAD", "OPTIONS"]);

/** Configuration for TLS 1.3 early data (0-RTT). */
export interface EarlyDataConfig {
  /** Enable early data transmission. */
  enabled?: boolean;
  /** Maximum early data payload size in bytes. */
  maxSize?: number;
  /** Restrict early data to safe (idempotent) HTTP methods only. */
  safeOnly?: boolean;
}

/** Outcome of an early data (0-RTT) transmission attempt. */
export interface EarlyDataResult {
  /** Whether the server accepted the early data. */
  accepted: boolean;
  /** Whether early data transmission was attempted. */
  attempted: boolean;
  /** Number of bytes sent as early data. */
  bytesSent: number;
}

/**
 * Determine whether early data can be sent for the given HTTP method.
 *
 * @param {string} method - HTTP method string.
 * @param {EarlyDataConfig} [config] - Early data configuration.
 * @returns {boolean} `true` if early data is permitted.
 */
export function canSendEarlyData(method: string, config?: EarlyDataConfig): boolean {
  if (!config?.enabled) return false;
  if (config.safeOnly !== false && !SAFE_EARLY_DATA_METHODS.has(method.toUpperCase())) {
    return false;
  }
  return true;
}

/**
 * Prepare request data for 0-RTT transmission.
 *
 * @param {Buffer} requestData - Serialized request bytes.
 * @param {EarlyDataConfig} [config] - Early data configuration.
 * @returns {Buffer|null} Buffer to send as early data, or `null` if not applicable.
 */
export function prepareEarlyData(requestData: Buffer, config?: EarlyDataConfig): Buffer | null {
  if (!config?.enabled) return null;

  const maxSize = config.maxSize ?? 16384;
  if (requestData.length > maxSize) return null;

  return requestData;
}

/**
 * Check whether the server accepted early data on a connected socket.
 *
 * @param {{ alpnProtocol?: string | false; earlyData?: boolean }} socket - Socket with optional `earlyData` flag.
 * @returns {EarlyDataResult} Early data acceptance result.
 */
export function checkEarlyDataAccepted(socket: { alpnProtocol?: string | false; earlyData?: boolean }): EarlyDataResult {
  const accepted = socket.earlyData === true;
  return {
    accepted,
    attempted: true,
    bytesSent: 0,
  };
}
